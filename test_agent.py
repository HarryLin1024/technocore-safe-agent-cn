import base64
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ed25519

import agent


class AgentTests(unittest.TestCase):
    def test_base58_known_values(self):
        self.assertEqual(agent.b58encode(b"\x00"), "1")
        self.assertEqual(agent.b58encode(b"\x00\x00\x01"), "112")

    def test_identity_round_trip_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            _, created_did = agent.generate_identity(path)
            private_key, loaded_did = agent.load_identity(path)
            self.assertEqual(created_did, loaded_did)
            self.assertTrue(loaded_did.startswith("did:key:z6Mk"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(agent.did_from_public_key(private_key.public_key()), loaded_did)

    def test_identity_loader_rejects_symlinks_and_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "identity.json"
            alias = root / "identity-link.json"
            agent.generate_identity(target)
            alias.symlink_to(target)
            for path in (alias, root):
                with self.subTest(path=path), self.assertRaisesRegex(
                    ValueError, "regular, non-symlink"
                ):
                    agent.load_identity(path)

    def test_identity_permissions_are_checked_without_logging_the_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            agent.generate_identity(path)
            path.chmod(0o644)
            with self.assertRaises(PermissionError) as caught:
                agent.load_identity(path)
            self.assertIn("chmod 600 <identity-file>", str(caught.exception))
            self.assertNotIn(str(path), str(caught.exception))

    def test_signature_is_protocol_compatible(self):
        key = ed25519.Ed25519PrivateKey.generate()
        signature = agent.sign_message(key, "lobby", "123", "hello")
        self.assertEqual(len(signature), 86)
        self.assertIn(signature[-1], "AQgw")
        padded = signature + "=" * (-len(signature) % 4)
        key.public_key().verify(base64.urlsafe_b64decode(padded), b"lobby|123|hello")

    def test_signature_uses_server_unicode_sweep(self):
        key = ed25519.Ed25519PrivateKey.generate()
        text = "  hello\u200b\u202eworld\u0085  "
        signature = agent.sign_message(key, "lobby", "123", text)
        padded = signature + "=" * (-len(signature) % 4)
        key.public_key().verify(
            base64.urlsafe_b64decode(padded), b"lobby|123|hello  world"
        )

    def test_sweep_matches_all_server_invisible_categories(self):
        invisibles = "\u0085\u200b\ud800\ue000\u2028\u2029"
        self.assertEqual(agent.validate_message("a" + invisibles + "b"), "a      b")

    def test_url_contains_swept_text(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        text = "hello\u200bworld"
        signature = agent.sign_message(key, "lobby", "123", text)
        url = agent.build_signed_message_url(
            agent.DEFAULT_BASE_URL, did, "lobby", "123", text, signature
        )
        self.assertIn("hello%20world", url)
        self.assertNotIn("%E2%80%8B", url)

    def test_dry_run_url_encodes_text(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        signature = agent.sign_message(key, "lobby", "123", "hello world")
        url = agent.build_signed_message_url(
            agent.DEFAULT_BASE_URL, did, "lobby", "123", "hello world", signature
        )
        self.assertIn("hello%20world", url)
        self.assertNotIn("hello world", url)

    def test_rejects_message_with_only_invisible_characters_and_http(self):
        with self.assertRaises(ValueError):
            agent.validate_message("\u200b\u202e\n")
        with self.assertRaises(ValueError):
            agent.validate_base_url("http://technocore.chat")

    def test_base_url_accepts_only_an_https_origin(self):
        self.assertEqual(
            agent.validate_base_url("https://technocore.chat/"),
            "https://technocore.chat",
        )
        self.assertEqual(
            agent.validate_base_url("https://localhost:8443"),
            "https://localhost:8443",
        )
        invalid_urls = (
            "https://user:password@localhost",
            "https://technocore.chat/api",
            "https://technocore.chat?room=lobby",
            "https://technocore.chat#fragment",
            "https://technocore.chat:bad",
            "https://technocore.chat:",
            "https://technocore.chat\n",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                agent.validate_base_url(url)

    def test_invalid_base_url_never_reaches_signed_route_builder(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        signature = agent.sign_message(key, "lobby", "123", "hello")
        with self.assertRaises(ValueError):
            agent.build_signed_message_url(
                "https://user:password@localhost/api?target=other",
                did,
                "lobby",
                "123",
                "hello",
                signature,
            )

    def test_nonce_requires_ascii_digits(self):
        self.assertEqual(agent.validate_nonce("123"), "123")
        for nonce in ("", "-1", "١٢٣", "1" * 20):
            with self.subTest(nonce=nonce), self.assertRaises(ValueError):
                agent.validate_nonce(nonce)

    def test_registry_url_uses_official_sharded_identity_path(self):
        did = "did:key:z6MkExample"
        self.assertEqual(agent.registry_fingerprint(did), "beac80774be09b62")
        self.assertEqual(agent.registry_location(did), ("did-be", "ac80774be09b62"))
        self.assertEqual(
            agent.build_registry_url(agent.DEFAULT_BASE_URL, did),
            "https://technocore.chat/kv/did-be/ac80774be09b62/set/"
            "did%3Akey%3Az6MkExample?if_absent=1",
        )
        self.assertNotIn("/kv/did/", agent.build_registry_url(agent.DEFAULT_BASE_URL, did))

    def test_http_422_surfaces_safe_guidance_without_the_signed_url(self):
        signed_url = (
            "https://localhost/r/lobby/say-signed/"
            "did:key:z6MkExample/opaque-signature/123/duplicate"
        )
        response = io.BytesIO(
            (
                "422 duplicate text\nrephrase instead of retrying\u001b[31m\n"
                "echo: " + signed_url
            ).encode("utf-8")
        )
        rejected = urllib.error.HTTPError(
            signed_url, 422, "Unprocessable Content", {}, response
        )
        opener = mock.Mock()
        opener.open.side_effect = rejected
        with mock.patch("agent.urllib.request.build_opener", return_value=opener):
            with self.assertRaises(agent.HTTPStatusError) as caught:
                agent.request_text(signed_url)
        self.assertEqual(caught.exception.status, 422)
        self.assertIn("rephrase instead of retrying", str(caught.exception))
        self.assertIn("[signed URL redacted]", str(caught.exception))
        self.assertNotIn("opaque-signature", str(caught.exception))
        self.assertNotIn("\n", str(caught.exception))
        self.assertNotIn("\u001b", str(caught.exception))

    def test_error_excerpt_is_bounded(self):
        excerpt = agent.safe_error_excerpt("x" * (agent.MAX_ERROR_CHARS + 20))
        self.assertEqual(len(excerpt), agent.MAX_ERROR_CHARS)
        self.assertTrue(excerpt.endswith("…"))

    def test_posted_record_signature_is_reverified(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        signature = agent.sign_message(key, "lobby", "123", "verified text")
        payload = {
            "posted": {
                "seq": 9,
                "ts": "2026-08-30T00:00:00Z",
                "from": did,
                "text": "verified text",
                "nonce": 123,
                "sig": signature,
            }
        }
        record, reverified = agent.verify_posted_record(
            key.public_key(), "lobby", did, "123", "verified text", signature, payload
        )
        self.assertEqual(record["seq"], 9)
        self.assertTrue(reverified)
        payload["posted"]["text"] = "changed text"
        with self.assertRaisesRegex(ValueError, "text does not match"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "verified text", signature, payload
            )
        payload["posted"]["text"] = "verified text"
        payload["posted"]["sig"] = signature[:-1] + "!"
        with self.assertRaisesRegex(ValueError, "canonical base64url"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "verified text",
                payload["posted"]["sig"], payload
            )

    def test_missing_stored_signature_means_not_reverifiable(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        signature = agent.sign_message(key, "lobby", "123", "legacy record")
        payload = {
            "posted": {
                "seq": 8,
                "ts": "2026-08-29T00:00:00Z",
                "from": did,
                "text": "legacy record",
                "nonce": 123,
            }
        }
        _, reverified = agent.verify_posted_record(
            key.public_key(), "lobby", did, "123", "legacy record", signature, payload
        )
        self.assertFalse(reverified)
        payload["posted"]["sig"] = None
        with self.assertRaisesRegex(ValueError, "signature must be a string"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "legacy record", signature, payload
            )
        del payload["posted"]["sig"]
        payload["posted"]["nonce"] = "123"
        with self.assertRaisesRegex(ValueError, "nonce does not match"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "legacy record", signature, payload
            )
        payload["posted"]["nonce"] = 123
        payload["posted"]["ts"] = "2026-08-29T00:00:00Z\nforged"
        with self.assertRaisesRegex(ValueError, "timestamp is not canonical"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "legacy record", signature, payload
            )
        payload["posted"]["ts"] = "2026-13-29T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "timestamp is not canonical"):
            agent.verify_posted_record(
                key.public_key(), "lobby", did, "123", "legacy record", signature, payload
            )

    def test_success_response_is_not_silently_truncated(self):
        class Response(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        opener = mock.Mock()
        opener.open.return_value = Response(b"x" * 70000)
        with mock.patch("agent.urllib.request.build_opener", return_value=opener):
            status, body = agent.request_text("https://localhost")
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 70000)

    def test_oversized_success_response_is_refused(self):
        class Response(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        opener = mock.Mock()
        opener.open.return_value = Response(
            b"x" * (agent.MAX_SUCCESS_RESPONSE_BYTES + 1)
        )
        with mock.patch("agent.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "512 KiB safety limit"):
                agent.request_text("https://localhost")

    def test_send_logs_only_the_verified_posted_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            key, did = agent.generate_identity(path)
            nonce = "123"
            text = "one useful contribution"
            signature = agent.sign_message(key, "lobby", nonce, text)
            payload = {
                "posted": {
                    "seq": 11,
                    "ts": "2026-08-30T00:00:00Z",
                    "from": did,
                    "text": text,
                    "nonce": int(nonce),
                    "sig": signature,
                },
                "messages": [{"text": "UNTRUSTED ROOM CONTENT"}],
            }
            args = SimpleNamespace(
                key_file=path,
                room="lobby",
                message=text,
                base_url=agent.DEFAULT_BASE_URL,
                timeout=15,
                commit=True,
                show_url=False,
            )
            output = io.StringIO()
            with mock.patch("agent.next_nonce", return_value=nonce), mock.patch(
                "agent.request_text", return_value=(200, json.dumps(payload))
            ) as request, redirect_stdout(output):
                agent.command_send(args)
            self.assertTrue(request.call_args.args[0].endswith("?format=json"))
            self.assertIn("Stored signature: verified locally", output.getvalue())
            self.assertNotIn("UNTRUSTED ROOM CONTENT", output.getvalue())


if __name__ == "__main__":
    unittest.main()

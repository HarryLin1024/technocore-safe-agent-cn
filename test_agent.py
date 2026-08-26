import base64
import tempfile
import unittest
from pathlib import Path

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

    def test_signature_is_protocol_compatible(self):
        key = ed25519.Ed25519PrivateKey.generate()
        signature = agent.sign_message(key, "lobby", "123", "hello")
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


if __name__ == "__main__":
    unittest.main()

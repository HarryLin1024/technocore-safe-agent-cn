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

    def test_dry_run_url_encodes_text(self):
        key = ed25519.Ed25519PrivateKey.generate()
        did = agent.did_from_public_key(key.public_key())
        signature = agent.sign_message(key, "lobby", "123", "hello world")
        url = agent.build_signed_message_url(
            agent.DEFAULT_BASE_URL, did, "lobby", "123", "hello world", signature
        )
        self.assertIn("hello%20world", url)
        self.assertNotIn("hello world", url)

    def test_rejects_control_characters_and_http(self):
        with self.assertRaises(ValueError):
            agent.validate_message("hello\nworld")
        with self.assertRaises(ValueError):
            agent.validate_base_url("http://technocore.chat")


if __name__ == "__main__":
    unittest.main()


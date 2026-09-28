"""Tests for the crypto module."""

import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

import crypto


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = crypto.generate_key()
        self.payload = {"hello": "world"}
        self.aad = "test-sender"

    def test_encrypt_decrypt_roundtrip(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        self.assertIn("nonce", envelope)
        self.assertIn("ciphertext", envelope)
        self.assertIn("sender_id", envelope)

        decrypted = crypto.decrypt_payload(self.key, envelope, self.aad)
        self.assertEqual(decrypted, self.payload)

    def test_decrypt_fails_with_wrong_key(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        wrong_key = crypto.generate_key()

        with self.assertRaises(InvalidTag):
            crypto.decrypt_payload(wrong_key, envelope, self.aad)

    def test_decrypt_fails_with_wrong_aad(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)

        with self.assertRaises(ValueError):
            crypto.decrypt_payload(self.key, envelope, "wrong-sender")

    def test_decrypt_fails_on_tampered_ciphertext(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        # Tamper with base64 ciphertext safely without breaking padding
        tampered = list(envelope["ciphertext"])
        tampered[0] = "A" if tampered[0] != "A" else "B"
        envelope["ciphertext"] = "".join(tampered)

        with self.assertRaises(InvalidTag):
            crypto.decrypt_payload(self.key, envelope, self.aad)

    def test_load_key_from_env_valid(self) -> None:
        with patch.dict(os.environ, {"TEST_KEY": self.key.hex()}):
            loaded = crypto.load_key_from_env("TEST_KEY")
            self.assertEqual(loaded, self.key)

    def test_load_key_from_env_invalid_length(self) -> None:
        with patch.dict(os.environ, {"TEST_KEY": "deadbeef"}):
            with self.assertRaises(ValueError):
                crypto.load_key_from_env("TEST_KEY")

    def test_load_key_from_env_missing(self) -> None:
        with patch.dict(os.environ, clear=True):
            with self.assertRaises(ValueError):
                crypto.load_key_from_env("MISSING_KEY")

    def test_load_key_from_env_invalid_hex(self) -> None:
        with patch.dict(os.environ, {"TEST_KEY": "not-hex-chars"}):
            with self.assertRaisesRegex(ValueError, "Invalid hex encoding"):
                crypto.load_key_from_env("TEST_KEY")

    def test_decrypt_fails_with_invalid_json_plaintext(self) -> None:
        # Encrypt a non-JSON byte string
        aesgcm = crypto.AESGCM(self.key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, b"not json", self.aad.encode("utf-8"))
        
        envelope = {
            "sender_id": self.aad,
            "nonce": crypto.base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": crypto.base64.b64encode(ciphertext).decode("utf-8"),
        }
        
        with self.assertRaisesRegex(ValueError, "not valid JSON"):
            crypto.decrypt_payload(self.key, envelope, self.aad)

    def test_verify_timestamp_without_timezone(self) -> None:
        # Should be treated as UTC
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        crypto.verify_timestamp(now_naive.isoformat())

    def test_verify_timestamp_valid(self) -> None:
        now = datetime.now(timezone.utc)
        crypto.verify_timestamp(now.isoformat())

    def test_verify_timestamp_drift_exceeded(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(seconds=65)
        with self.assertRaisesRegex(ValueError, "exceeds maximum"):
            crypto.verify_timestamp(past.isoformat())

    def test_verify_timestamp_invalid_format(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid timestamp"):
            crypto.verify_timestamp("not-a-timestamp")


if __name__ == "__main__":
    unittest.main()

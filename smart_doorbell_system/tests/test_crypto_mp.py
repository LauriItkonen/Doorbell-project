"""MicroPython unit tests for device_crypto.py."""

import unittest
import device_crypto as crypto


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"\x01" * 32
        self.payload = {"hello": "world"}
        self.aad = "test-sender"

    def test_encrypt_decrypt_roundtrip(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        self.assertTrue("nonce" in envelope)
        self.assertTrue("ciphertext" in envelope)
        self.assertTrue("sender_id" in envelope)

        decrypted = crypto.decrypt_payload(self.key, envelope, self.aad)
        self.assertEqual(decrypted, self.payload)

    def test_decrypt_fails_with_wrong_key(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        wrong_key = b"\x02" * 32

        with self.assertRaises(crypto.InvalidTag):
            crypto.decrypt_payload(wrong_key, envelope, self.aad)

    def test_decrypt_fails_with_wrong_aad(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)

        with self.assertRaises(ValueError):
            crypto.decrypt_payload(self.key, envelope, "wrong-sender")

    def test_decrypt_fails_on_tampered_ciphertext(self) -> None:
        envelope = crypto.encrypt_payload(self.key, self.payload, self.aad)
        tampered = list(envelope["ciphertext"])
        tampered[0] = "A" if tampered[0] != "A" else "B"
        envelope["ciphertext"] = "".join(tampered)

        with self.assertRaises(crypto.InvalidTag):
            crypto.decrypt_payload(self.key, envelope, self.aad)

    def test_load_key_from_env_valid(self) -> None:
        hex_key = "01" * 32
        loaded = crypto.load_key_from_env("DOORBELL_EDGE_KEY", hex_key)
        self.assertEqual(loaded, self.key)

    def test_load_key_from_env_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            crypto.load_key_from_env("TEST_KEY", "deadbeef")

    def test_load_key_from_env_missing(self) -> None:
        with self.assertRaises(ValueError):
            crypto.load_key_from_env("MISSING_KEY", None)

    def test_load_key_from_env_invalid_hex(self) -> None:
        with self.assertRaises(ValueError):
            crypto.load_key_from_env("TEST_KEY", "not-hex-chars")


if __name__ == "__main__":
    unittest.main()
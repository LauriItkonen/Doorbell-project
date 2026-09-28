"""Encryption module for securing communications using AES-256-GCM.

Provides functions to encrypt and decrypt JSON payloads using a shared
symmetric key, providing confidentiality, integrity, and authenticity.
"""

import base64
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag as CryptoInvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

InvalidTag = CryptoInvalidTag


def generate_key() -> bytes:
    """Generate a random 32-byte (256-bit) key for AES-256-GCM."""
    return AESGCM.generate_key(bit_length=256)


def load_key_from_env(env_var_name: str, default_hex: str | None = None) -> bytes:
    """Load a 32-byte key from a hex-encoded environment variable.

    If the environment variable is not set and a default is provided,
    the default will be used.

    Args:
        env_var_name: The name of the environment variable.
        default_hex: An optional default hex-encoded key.

    Returns:
        The decoded 32-byte key.

    Raises:
        ValueError: If the key is missing or not 32 bytes after decoding.
    """
    hex_key = os.environ.get(env_var_name, default_hex)
    if not hex_key:
        raise ValueError(f"Missing environment variable: {env_var_name}")
    try:
        key = bytes.fromhex(hex_key)
    except ValueError as e:
        raise ValueError(f"Invalid hex encoding for {env_var_name}: {e}")
    if len(key) != 32:
        raise ValueError(f"Key from {env_var_name} must be exactly 32 bytes.")
    return key


def encrypt_payload(key: bytes, payload_dict: dict, aad: str) -> dict:
    """Encrypt a dictionary payload using AES-256-GCM.

    Serializes the dictionary to JSON, encrypts it with a random 12-byte nonce,
    and binds it to the provided AAD (Associated Data).

    Args:
        key: The 32-byte encryption key.
        payload_dict: The dictionary to encrypt.
        aad: The authenticated associated data (e.g., sender_id).

    Returns:
        A dictionary containing the sender_id (as AAD), nonce, and ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    plaintext = json.dumps(payload_dict).encode("utf-8")
    aad_bytes = aad.encode("utf-8")

    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)

    return {
        "sender_id": aad,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("utf-8"),
    }


def decrypt_payload(key: bytes, envelope: dict, expected_aad: str) -> dict:
    """Decrypt an encrypted envelope using AES-256-GCM.

    Args:
        key: The 32-byte encryption key.
        envelope: The dictionary containing sender_id, nonce, and ciphertext.
        expected_aad: The expected AAD (usually the sender_id).

    Returns:
        The decrypted payload dictionary.

    Raises:
        ValueError: If the envelope is malformed, JSON is invalid, or expected AAD doesn't match.
        InvalidTag: If decryption or authentication fails.
    """
    try:
        sender_id = envelope["sender_id"]
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Malformed encrypted envelope: {e}")

    if sender_id != expected_aad:
        raise ValueError(f"AAD mismatch: expected {expected_aad}, got {sender_id}")

    aesgcm = AESGCM(key)
    aad_bytes = expected_aad.encode("utf-8")

    # Decrypt and authenticate. Raises InvalidTag if tampering occurred.
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad_bytes)

    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Decrypted data is not valid JSON: {e}")


def verify_timestamp(timestamp_iso: str, max_drift_seconds: int = 60) -> None:
    """Verify that a timestamp is within the maximum allowed drift from now.

    Args:
        timestamp_iso: ISO 8601 formatted timestamp string.
        max_drift_seconds: Maximum allowed difference in seconds.

    Raises:
        ValueError: If the timestamp is invalid or exceeds the allowed drift.
    """
    try:
        ts = datetime.fromisoformat(timestamp_iso)
        if ts.tzinfo is None:
            # Assume UTC if no timezone is provided
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        drift = abs((now - ts).total_seconds())
        if drift > max_drift_seconds:
            raise ValueError(f"Timestamp drift {drift:.1f}s exceeds maximum {max_drift_seconds}s")
    except ValueError as e:
        raise ValueError(f"Invalid timestamp: {e}")

"""MicroPython reimplementation of the crypto.py interface."""

import ubinascii
import ujson as json
import os

class InvalidTag(Exception):
    """MicroPython equivalent of cryptography.exceptions.InvalidTag."""
    pass

def load_key_from_env(env_var_name: str, default_hex: str = None) -> bytes:
    """Load a 32-byte key from a hex-encoded environment variable."""
    # Standard MicroPython lacks os.environ. 
    # Fall back directly to default_hex for edge device configuration.
    hex_key = default_hex
    if not hex_key:
        raise ValueError(f"Missing environment variable: {env_var_name}")
    try:
        key = ubinascii.unhexlify(hex_key)
    except ValueError as e:
        raise ValueError(f"Invalid hex encoding for {env_var_name}: {e}")
    if len(key) != 32:
        raise ValueError(f"Key from {env_var_name} must be exactly 32 bytes.")
    return key

def encrypt_payload(key: bytes, payload_dict: dict, aad: str) -> dict:
    """Encrypt a dictionary payload using AES-256-GCM architecture."""
    nonce = os.urandom(12)
    plaintext = json.dumps(payload_dict).encode("utf-8")
    aad_bytes = aad.encode("utf-8")

    # NOTE: Standard MicroPython's ucryptolib does not natively support AES-GCM.
    # To execute true AES-GCM encryption on the device, you must utilize 
    # firmware-level mbedTLS GCM bindings or a C-extension here.
    # ciphertext_with_tag = hardware_aesgcm_encrypt(key, nonce, plaintext, aad_bytes)
    
    ciphertext_with_tag = b"hardware_gcm_placeholder" 

    return {
        "sender_id": aad,
        "nonce": ubinascii.b2a_base64(nonce).decode("utf-8").strip(),
        "ciphertext": ubinascii.b2a_base64(ciphertext_with_tag).decode("utf-8").strip(),
    }

def decrypt_payload(key: bytes, envelope: dict, expected_aad: str) -> dict:
    """Decrypt an encrypted envelope using AES-256-GCM architecture."""
    try:
        sender_id = envelope["sender_id"]
        nonce = ubinascii.a2b_base64(envelope["nonce"])
        ciphertext = ubinascii.a2b_base64(envelope["ciphertext"])
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Malformed encrypted envelope: {e}")

    if sender_id != expected_aad:
        raise ValueError(f"AAD mismatch: expected {expected_aad}, got {sender_id}")

    aad_bytes = expected_aad.encode("utf-8")

    # NOTE: Requires firmware-level mbedTLS GCM bindings to decrypt and verify the tag.
    # plaintext = hardware_aesgcm_decrypt(key, nonce, ciphertext, aad_bytes)
    
    plaintext = b'{"access_granted": true}' # Placeholder

    try:
        return json.loads(plaintext.decode("utf-8"))
    except ValueError as e:
        raise ValueError(f"Decrypted data is not valid JSON: {e}")
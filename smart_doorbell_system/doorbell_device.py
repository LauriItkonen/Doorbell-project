"""Interactive doorbell and gate device simulator."""

import time
from datetime import datetime, timezone

import requests

import crypto

DEFAULT_DEVICE_EDGE_KEY_HEX = "01" * 32
DEVICE_EDGE_KEY = crypto.load_key_from_env("DOORBELL_EDGE_KEY", DEFAULT_DEVICE_EDGE_KEY_HEX)
DEVICE_ID = "doorbell-001"

GATEWAY_URL = "http://localhost:5000/api/access-request"
REQUEST_TIMEOUT_SECONDS = 10


def current_timestamp() -> str:
    """Return a timezone-aware UTC timestamp suitable for JSON and logs."""
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    """Read visitor names and send access requests to the edge gateway."""
    print("Smart doorbell device started. Type 'exit' to stop.")

    while True:
        visitor_name = input("Enter visitor name: ").strip()
        if visitor_name.lower() == "exit":
            print("Doorbell device stopped.")
            break
        if not visitor_name:
            print("Visitor name cannot be empty.")
            continue

        payload = {
            "device_id": DEVICE_ID,
            "timestamp": current_timestamp(),
            "visitor_name": visitor_name,
        }

        envelope = crypto.encrypt_payload(DEVICE_EDGE_KEY, payload, DEVICE_ID)

        verification_started_at = time.perf_counter()
        try:
            response = requests.post(
                GATEWAY_URL, json=envelope, timeout=REQUEST_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            result_envelope = response.json()
            result = crypto.decrypt_payload(DEVICE_EDGE_KEY, result_envelope, "edge-gateway-001")
        except requests.RequestException as error:
            elapsed_seconds = time.perf_counter() - verification_started_at
            print(f"Gateway unavailable after {elapsed_seconds:.3f} seconds: {error}")
            continue
        except (ValueError, crypto.InvalidTag):
            elapsed_seconds = time.perf_counter() - verification_started_at
            print(
                f"Gateway returned an invalid or unauthenticated response after {elapsed_seconds:.3f} seconds."
            )
            continue

        elapsed_seconds = time.perf_counter() - verification_started_at
        print(f"Verification completed in {elapsed_seconds:.3f} seconds.")
        if result.get("access_granted") is True:
            print(f"🟢 GATE OPENED: Welcome {visitor_name}!")
        else:
            print("🔴 ACCESS DENIED: Visitor name not authorized.")


if __name__ == "__main__":
    main()
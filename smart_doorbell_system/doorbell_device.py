"""Interactive doorbell and gate device simulator for MicroPython."""

import utime
try:
    import urequests as requests
except ImportError:
    import requests

# Import the reimplemented MicroPython-compatible crypto module
import device_crypto as crypto 

DEFAULT_DEVICE_EDGE_KEY_HEX = "01" * 32
DEVICE_EDGE_KEY = crypto.load_key_from_env("DOORBELL_EDGE_KEY", DEFAULT_DEVICE_EDGE_KEY_HEX)
DEVICE_ID = "doorbell-001"

GATEWAY_URL = "http://localhost:5000/api/access-request"
REQUEST_TIMEOUT_SECONDS = 10


def current_timestamp() -> str:
    """Return a UTC timestamp suitable for JSON and logs using utime."""
    # MicroPython's utime.localtime() returns (year, month, mday, hour, minute, second, weekday, yearday)
    y, m, d, hr, min, sec, _, _ = utime.localtime()
    return f"{y:04d}-{m:02d}-{d:02d}T{hr:02d}:{min:02d}:{sec:02d}+00:00"


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

        verification_started_at = utime.ticks_ms()
        try:
            response = requests.post(
                GATEWAY_URL, json=envelope, timeout=REQUEST_TIMEOUT_SECONDS
            )
            # urequests does not have raise_for_status() natively
            if response.status_code >= 400:
                raise ValueError(f"HTTP Error: {response.status_code}")
            
            result_envelope = response.json()
            result = crypto.decrypt_payload(DEVICE_EDGE_KEY, result_envelope, "edge-gateway-001")
        except OSError as error:
            elapsed_seconds = utime.ticks_diff(utime.ticks_ms(), verification_started_at) / 1000.0
            print(f"Gateway unavailable after {elapsed_seconds:.3f} seconds: {error}")
            continue
        except (ValueError, crypto.InvalidTag):
            elapsed_seconds = utime.ticks_diff(utime.ticks_ms(), verification_started_at) / 1000.0
            print(
                f"Gateway returned an invalid or unauthenticated response after {elapsed_seconds:.3f} seconds."
            )
            continue

        elapsed_seconds = utime.ticks_diff(utime.ticks_ms(), verification_started_at) / 1000.0
        print(f"Verification completed in {elapsed_seconds:.3f} seconds.")
        if result.get("access_granted") is True:
            print(f"🟢 GATE OPENED: Welcome {visitor_name}!")
        else:
            print("🔴 ACCESS DENIED: Visitor name not authorized.")


if __name__ == "__main__":
    main()
"""Interactive doorbell and gate device simulator."""

from datetime import datetime, timezone

import requests

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
            "device_id": "doorbell-001",
            "timestamp": current_timestamp(),
            "visitor_name": visitor_name,
        }

        try:
            response = requests.post(
                GATEWAY_URL, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as error:
            print(f"Gateway unavailable: {error}")
            continue
        except ValueError:
            print("Gateway returned an invalid response.")
            continue

        if result.get("access_granted") is True:
            print(f"🟢 GATE OPENED: Welcome {visitor_name}!")
        else:
            print("🔴 ACCESS DENIED: Visitor name not authorized.")


if __name__ == "__main__":
    main()
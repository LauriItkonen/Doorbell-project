"""Edge gateway for validating and forwarding doorbell access requests."""

import json
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
CLOUD_VERIFY_URL = "http://localhost:8000/api/cloud/verify-visitor"
REQUEST_TIMEOUT_SECONDS = 10
LOG_FILE = Path(__file__).with_name("edge_requests.log")


def write_local_log(payload: dict, status_code: int) -> None:
    """Append the request and gateway outcome as one JSON line."""
    entry = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "request": payload,
        "gateway_status": status_code,
    }
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")


@app.post("/api/access-request")
def access_request():
    """Validate a device request, ask the cloud service, and relay its result."""
    payload = request.get_json(silent=True)
    required_fields = ("device_id", "timestamp", "visitor_name")

    if not isinstance(payload, dict) or any(
        not isinstance(payload.get(field), str) or not payload[field].strip()
        for field in required_fields
    ):
        error = {"error": "Payload must contain non-empty device_id, timestamp, and visitor_name."}
        write_local_log(payload if isinstance(payload, dict) else {}, 400)
        return jsonify(error), 400

    try:
        cloud_response = requests.post(
            CLOUD_VERIFY_URL,
            json={
                "device_id": payload["device_id"],
                "timestamp": payload["timestamp"],
                "visitor_name": payload["visitor_name"].strip(),
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        cloud_response.raise_for_status()
        result = cloud_response.json()
    except requests.RequestException:
        write_local_log(payload, 502)
        return jsonify({"error": "Cloud service unavailable."}), 502
    except ValueError:
        write_local_log(payload, 502)
        return jsonify({"error": "Cloud service returned invalid JSON."}), 502

    write_local_log(payload, cloud_response.status_code)
    return jsonify(result), cloud_response.status_code


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
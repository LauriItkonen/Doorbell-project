"""Edge gateway for validating and forwarding doorbell access requests."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, request

import crypto

DEFAULT_DEVICE_EDGE_KEY_HEX = "01" * 32
DEVICE_EDGE_KEY = crypto.load_key_from_env("DOORBELL_EDGE_KEY", DEFAULT_DEVICE_EDGE_KEY_HEX)
DEFAULT_EDGE_CLOUD_KEY_HEX = "02" * 32
EDGE_CLOUD_KEY = crypto.load_key_from_env("DOORBELL_CLOUD_KEY", DEFAULT_EDGE_CLOUD_KEY_HEX)
EDGE_ID = "edge-gateway-001"

app = Flask(__name__)
CLOUD_VERIFY_URL = os.environ.get("CLOUD_VERIFY_URL", "http://localhost:8000/api/cloud/verify-visitor")
REQUEST_TIMEOUT_SECONDS = 10
LOG_FILE = Path(__file__).with_name("edge_requests.log")


def write_local_log(envelope: dict, status_code: int) -> None:
    """Append the encrypted envelope metadata and gateway outcome as one JSON line."""
    ciphertext = envelope.get("ciphertext", "") if isinstance(envelope, dict) else ""
    payload_hash = hashlib.sha256(ciphertext.encode("utf-8")).hexdigest() if ciphertext else None
    entry = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "sender_id": envelope.get("sender_id") if isinstance(envelope, dict) else None,
        "payload_hash": payload_hash,
        "gateway_status": status_code,
    }
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")


@app.post("/api/access-request")
def access_request():
    """Validate an encrypted device request, ask the cloud service, and relay its result."""
    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict):
        write_local_log({}, 400)
        return jsonify({"error": "Invalid JSON envelope."}), 400
        
    try:
        payload = crypto.decrypt_payload(DEVICE_EDGE_KEY, envelope, "doorbell-001")
        crypto.verify_timestamp(payload.get("timestamp", ""))
    except (ValueError, crypto.InvalidTag):
        write_local_log(envelope, 400)
        return jsonify({"error": "Decryption or validation failed."}), 400

    required_fields = ("device_id", "timestamp", "visitor_name")
    if any(
        not isinstance(payload.get(field), str) or not payload[field].strip()
        for field in required_fields
    ):
        error = {"error": "Payload must contain non-empty device_id, timestamp, and visitor_name."}
        write_local_log(envelope, 400)
        return jsonify(error), 400

    try:
        cloud_payload = {
            "device_id": payload["device_id"],
            "timestamp": payload["timestamp"],
            "visitor_name": payload["visitor_name"].strip(),
        }
        cloud_envelope = crypto.encrypt_payload(EDGE_CLOUD_KEY, cloud_payload, EDGE_ID)
        
        cloud_response = requests.post(
            CLOUD_VERIFY_URL,
            json=cloud_envelope,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        cloud_response.raise_for_status()
        result_envelope = cloud_response.json()
        result = crypto.decrypt_payload(EDGE_CLOUD_KEY, result_envelope, "cloud-service")
    except requests.RequestException:
        write_local_log(envelope, 502)
        return jsonify({"error": "Cloud service unavailable."}), 502
    except (ValueError, crypto.InvalidTag):
        write_local_log(envelope, 502)
        return jsonify({"error": "Cloud service returned invalid or unauthenticated response."}), 502

    write_local_log(envelope, cloud_response.status_code)
    
    response_envelope = crypto.encrypt_payload(DEVICE_EDGE_KEY, result, EDGE_ID)
    return jsonify(response_envelope), cloud_response.status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
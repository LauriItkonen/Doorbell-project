"""Edge gateway for validating and forwarding doorbell access requests."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, request
from prometheus_flask_exporter import PrometheusMetrics

import crypto
from json_logging import setup_json_logging

DEFAULT_DEVICE_EDGE_KEY_HEX = "01" * 32
DEVICE_EDGE_KEY = crypto.load_key_from_env("DOORBELL_EDGE_KEY", DEFAULT_DEVICE_EDGE_KEY_HEX)
EDGE_ID = "edge-gateway-001"

logger = setup_json_logging(EDGE_ID)

app = Flask(__name__)
metrics = PrometheusMetrics(app)
CLOUD_BASE_URL = "http://localhost:8000"
CLOUD_VERIFY_URL = f"{CLOUD_BASE_URL}/api/cloud/verify-visitor"
CLOUD_PUBLIC_KEY_URL = f"{CLOUD_BASE_URL}/api/cloud/public-key"
REQUEST_TIMEOUT_SECONDS = 10
LOG_FILE = Path(__file__).with_name("edge_requests.log")

_cached_cloud_pub_key = None


def get_cloud_public_key(force_refresh: bool = False):
    """Fetch and cache the Cloud Service's ML-KEM public key."""
    global _cached_cloud_pub_key
    if _cached_cloud_pub_key is None or force_refresh:
        response = requests.get(CLOUD_PUBLIC_KEY_URL, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or "public_key" not in data:
            raise ValueError("Invalid public key response from cloud service.")
        _cached_cloud_pub_key = crypto.import_kem_public_key(data["public_key"])
    return _cached_cloud_pub_key


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


@app.get("/api/health")
def health():
    """Liveness check for edge gateway."""
    return jsonify({
        "status": "healthy",
        "service": EDGE_ID,
    }), 200


@app.post("/api/access-request")
def access_request():
    """Validate an encrypted device request, ask the cloud service, and relay its result."""
    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict):
        logger.warning("Invalid JSON envelope received from device")
        write_local_log({}, 400)
        return jsonify({"error": "Invalid JSON envelope."}), 400

    try:
        payload = crypto.decrypt_payload(DEVICE_EDGE_KEY, envelope, "doorbell-001")
        crypto.verify_timestamp(payload.get("timestamp", ""))
    except (ValueError, crypto.InvalidTag) as e:
        logger.warning("Decryption or validation failed for device request", extra={"error": str(e)})
        write_local_log(envelope, 400)
        return jsonify({"error": "Decryption or validation failed."}), 400

    required_fields = ("device_id", "timestamp", "visitor_name")
    if any(
        not isinstance(payload.get(field), str) or not payload[field].strip()
        for field in required_fields
    ):
        logger.warning(
            "Payload missing required fields",
            extra={"device_id": payload.get("device_id")},
        )
        error = {"error": "Payload must contain non-empty device_id, timestamp, and visitor_name."}
        write_local_log(envelope, 400)
        return jsonify(error), 400

    try:
        cloud_payload = {
            "device_id": payload["device_id"],
            "timestamp": payload["timestamp"],
            "visitor_name": payload["visitor_name"].strip(),
        }
        cloud_pub_key = get_cloud_public_key()
        kem_ciphertext, shared_secret = crypto.encapsulate_secret(cloud_pub_key)

        cloud_envelope = crypto.encrypt_payload(shared_secret, cloud_payload, EDGE_ID)
        cloud_envelope["kem_ciphertext"] = kem_ciphertext

        cloud_response = requests.post(
            CLOUD_VERIFY_URL,
            json=cloud_envelope,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        cloud_response.raise_for_status()
        result_envelope = cloud_response.json()
        result = crypto.decrypt_payload(shared_secret, result_envelope, "cloud-service")
    except requests.RequestException as e:
        logger.error("Cloud service request failed", extra={"error": str(e)})
        write_local_log(envelope, 502)
        return jsonify({"error": "Cloud service unavailable."}), 502
    except (ValueError, crypto.InvalidTag) as e:
        logger.error("Cloud service response invalid or unauthenticated", extra={"error": str(e)})
        write_local_log(envelope, 502)
        return jsonify({"error": "Cloud service returned invalid or unauthenticated response."}), 502

    logger.info(
        "Forwarded cloud verification outcome",
        extra={
            "visitor_name": payload["visitor_name"].strip(),
            "access_granted": result.get("access_granted"),
            "cloud_status": cloud_response.status_code,
        },
    )
    write_local_log(envelope, cloud_response.status_code)

    response_envelope = crypto.encrypt_payload(DEVICE_EDGE_KEY, result, EDGE_ID)
    return jsonify(response_envelope), cloud_response.status_code


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
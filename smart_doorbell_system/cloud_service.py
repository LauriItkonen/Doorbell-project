"""Cloud verification service backed by SQLite."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from prometheus_flask_exporter import PrometheusMetrics

import crypto
from json_logging import setup_json_logging

DEFAULT_EDGE_CLOUD_KEY_HEX = "02" * 32
EDGE_CLOUD_KEY = crypto.load_key_from_env("DOORBELL_CLOUD_KEY", DEFAULT_EDGE_CLOUD_KEY_HEX)
CLOUD_ID = "cloud-service"

logger = setup_json_logging(CLOUD_ID)
CLOUD_KEM_PRIV_KEY, CLOUD_KEM_PUB_KEY = crypto.generate_kem_keypair()

app = Flask(__name__)
metrics = PrometheusMetrics(app)
DATABASE_PATH = Path(__file__).with_name("access_control.db")


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Open and close a connection configured for named columns."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    """Create tables and seed the default authorized visitors once."""
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS authorized_visitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_name TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                visitor_name TEXT NOT NULL,
                access_granted INTEGER NOT NULL CHECK (access_granted IN (0, 1))
            );
            """
        )
        connection.executemany(
            "INSERT OR IGNORE INTO authorized_visitors (visitor_name) VALUES (?)",
            [(name,) for name in ("Alice", "Bob", "Charlie")],
        )
    logger.info("Database initialized successfully", extra={"database_path": str(DATABASE_PATH)})


@app.get("/api/health")
def health():
    """Liveness and readiness check verifying database connectivity."""
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        return jsonify({
            "status": "healthy",
            "service": CLOUD_ID,
            "database": "connected",
        }), 200
    except Exception as e:
        logger.exception("Health check failed", extra={"error": str(e)})
        return jsonify({
            "status": "unhealthy",
            "service": CLOUD_ID,
            "database": "disconnected",
            "error": str(e),
        }), 503


@app.get("/api/cloud/public-key")
def public_key():
    """Return the cloud service's serialized ML-KEM public key."""
    return jsonify({
        "sender_id": CLOUD_ID,
        "public_key": crypto.export_kem_public_key(CLOUD_KEM_PUB_KEY),
    })


@app.post("/api/cloud/verify-visitor")
def verify_visitor():
    """Check authorization, persist the attempt, and return the encrypted decision."""
    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict):
        logger.warning("Invalid JSON envelope received")
        return jsonify({"error": "Invalid JSON envelope."}), 400

    kem_ciphertext = envelope.get("kem_ciphertext")
    if not kem_ciphertext:
        logger.warning("Missing kem_ciphertext in envelope")
        return jsonify({"error": "Missing kem_ciphertext."}), 400

    try:
        shared_secret = crypto.decapsulate_secret(CLOUD_KEM_PRIV_KEY, kem_ciphertext)
        payload = crypto.decrypt_payload(shared_secret, envelope, "edge-gateway-001")
        crypto.verify_timestamp(payload.get("timestamp", ""))
    except (ValueError, crypto.InvalidTag) as e:
        logger.warning(
            "Decryption or validation failed",
            extra={"sender_id": envelope.get("sender_id"), "error": str(e)},
        )
        return jsonify({"error": "Decryption or validation failed."}), 400

    visitor_name = payload.get("visitor_name", "").strip()
    if not visitor_name:
        logger.warning("Missing or empty visitor_name")
        return jsonify({"error": "visitor_name is required."}), 400

    with get_connection() as connection:
        authorized = connection.execute(
            "SELECT 1 FROM authorized_visitors WHERE visitor_name = ? COLLATE NOCASE",
            (visitor_name,),
        ).fetchone() is not None
        connection.execute(
            """
            INSERT INTO access_logs (timestamp, visitor_name, access_granted)
            VALUES (?, ?, ?)
            """,
            (datetime.now(timezone.utc).isoformat(), visitor_name, int(authorized)),
        )

    logger.info(
        "Processed visitor verification",
        extra={"visitor_name": visitor_name, "access_granted": authorized},
    )

    if authorized:
        response_payload = {"access_granted": True, "message": "Gate opened"}
    else:
        response_payload = {"access_granted": False, "message": "Access denied"}

    response_envelope = crypto.encrypt_payload(shared_secret, response_payload, CLOUD_ID)
    return jsonify(response_envelope)


@app.get("/api/analytics/summary")
def analytics_summary():
    """Return aggregate access-attempt statistics."""
    with get_connection() as connection:
        summary = connection.execute(
            """
            SELECT COUNT(*) AS total_attempts,
                   COALESCE(SUM(access_granted), 0) AS successful_entries,
                   COALESCE(SUM(CASE WHEN access_granted = 0 THEN 1 ELSE 0 END), 0)
                       AS denied_entries
            FROM access_logs
            """
        ).fetchone()

    return jsonify(dict(summary))


if __name__ == "__main__":
    initialize_database()
    app.run(host="localhost", port=8000)
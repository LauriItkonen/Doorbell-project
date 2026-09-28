"""Cloud verification service backed by SQLite."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

import crypto

DEFAULT_EDGE_CLOUD_KEY_HEX = "02" * 32
EDGE_CLOUD_KEY = crypto.load_key_from_env("DOORBELL_CLOUD_KEY", DEFAULT_EDGE_CLOUD_KEY_HEX)
CLOUD_ID = "cloud-service"

app = Flask(__name__)
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


@app.post("/api/cloud/verify-visitor")
def verify_visitor():
    """Check authorization, persist the attempt, and return the encrypted decision."""
    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict):
        return jsonify({"error": "Invalid JSON envelope."}), 400
        
    try:
        payload = crypto.decrypt_payload(EDGE_CLOUD_KEY, envelope, "edge-gateway-001")
        crypto.verify_timestamp(payload.get("timestamp", ""))
    except (ValueError, crypto.InvalidTag):
        return jsonify({"error": "Decryption or validation failed."}), 400

    visitor_name = payload.get("visitor_name", "").strip()
    if not visitor_name:
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

    if authorized:
        response_payload = {"access_granted": True, "message": "Gate opened"}
    else:
        response_payload = {"access_granted": False, "message": "Access denied"}
        
    response_envelope = crypto.encrypt_payload(EDGE_CLOUD_KEY, response_payload, CLOUD_ID)
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
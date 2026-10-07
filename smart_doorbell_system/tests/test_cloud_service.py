"""Tests for cloud visitor verification and analytics."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import cloud_service
import crypto


class CloudServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path_patch = patch.object(
            cloud_service, "DATABASE_PATH", Path(self.temp_directory.name) / "test.db"
        )
        self.database_path_patch.start()
        cloud_service.initialize_database()
        self.client = cloud_service.app.test_client()

    def tearDown(self) -> None:
        self.database_path_patch.stop()
        self.temp_directory.cleanup()
        
    def _make_request(self, visitor_name: str):
        payload = {
            "device_id": "test-device",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": visitor_name,
        }
        kem_ct, shared_secret = crypto.encapsulate_secret(cloud_service.CLOUD_KEM_PUB_KEY)
        envelope = crypto.encrypt_payload(shared_secret, payload, "edge-gateway-001")
        envelope["kem_ciphertext"] = kem_ct
        return self.client.post("/api/cloud/verify-visitor", json=envelope), shared_secret

    def test_public_key_endpoint(self) -> None:
        response = self.client.get("/api/cloud/public-key")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["sender_id"], "cloud-service")
        self.assertIn("public_key", data)
        pub_key = crypto.import_kem_public_key(data["public_key"])
        self.assertIsNotNone(pub_key)

    def test_name_variations_are_checked_against_authorized_visitors(self) -> None:
        cases = (
            ("Alice", True),
            ("alice", True),
            ("iida", False),
            ("12p39", False),
            ("!@#$%^&*()", False),
        )

        for visitor_name, expected_access in cases:
            with self.subTest(visitor_name=visitor_name):
                response, shared_secret = self._make_request(visitor_name)

                self.assertEqual(response.status_code, 200)
                
                response_envelope = response.get_json()
                decrypted = crypto.decrypt_payload(shared_secret, response_envelope, "cloud-service")
                self.assertEqual(decrypted["access_granted"], expected_access)

    def test_empty_and_whitespace_names_are_rejected(self) -> None:
        for visitor_name in ("", "   "):
            with self.subTest(visitor_name=visitor_name):
                response, _ = self._make_request(visitor_name)

                self.assertEqual(response.status_code, 400)

    def test_invalid_json_envelope_is_rejected(self) -> None:
        response = self.client.post("/api/cloud/verify-visitor", json=["not", "a", "dict"])
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_missing_kem_ciphertext_is_rejected(self) -> None:
        payload = {
            "device_id": "test-device",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": "Alice",
        }
        envelope = crypto.encrypt_payload(crypto.generate_key(), payload, "edge-gateway-001")
        response = self.client.post("/api/cloud/verify-visitor", json=envelope)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Missing kem_ciphertext", response.get_json()["error"])

    def test_decryption_failure_is_rejected(self) -> None:
        payload = {
            "device_id": "test-device",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": "Alice",
        }
        # Encapsulate with a DIFFERENT keypair to cause decapsulation/decryption mismatch
        _, diff_pub = crypto.generate_kem_keypair()
        kem_ct, shared_secret = crypto.encapsulate_secret(diff_pub)
        envelope = crypto.encrypt_payload(shared_secret, payload, "edge-gateway-001")
        envelope["kem_ciphertext"] = kem_ct

        response = self.client.post("/api/cloud/verify-visitor", json=envelope)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Decryption or validation failed", response.get_json()["error"])

    def test_missing_name_is_rejected(self) -> None:
        response, _ = self._make_request("")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_analytics_reports_granted_and_denied_attempts(self) -> None:
        self._make_request("Alice")
        self._make_request("Mallory")

        response = self.client.get("/api/analytics/summary")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"total_attempts": 2, "successful_entries": 1, "denied_entries": 1},
        )

    def test_health_check_healthy(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertEqual(data["service"], "cloud-service")

    def test_health_check_unhealthy(self) -> None:
        with patch.object(cloud_service, "get_connection", side_effect=Exception("DB down")):
            response = self.client.get("/api/health")
            self.assertEqual(response.status_code, 503)
            data = response.get_json()
            self.assertEqual(data["status"], "unhealthy")
            self.assertEqual(data["database"], "disconnected")
            self.assertIn("DB down", data["error"])

    def test_metrics_endpoint(self) -> None:
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("flask_http_request_total", response.text)


if __name__ == "__main__":
    unittest.main()
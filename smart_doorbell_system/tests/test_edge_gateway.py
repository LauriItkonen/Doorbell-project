"""Tests for gateway input handling and cloud-service failures."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import requests

import crypto
import edge_gateway


class EdgeGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.log_file_patch = patch.object(
            edge_gateway, "LOG_FILE", Path(self.temp_directory.name) / "requests.log"
        )
        self.log_file_patch.start()

        self.cloud_priv, self.cloud_pub = crypto.generate_kem_keypair()
        self.pub_patch = patch.object(
            edge_gateway, "get_cloud_public_key", return_value=self.cloud_pub
        )
        self.pub_patch.start()

        self.client = edge_gateway.app.test_client()
        self.payload = {
            "device_id": "doorbell-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": "Alice",
        }
        self.envelope = crypto.encrypt_payload(edge_gateway.DEVICE_EDGE_KEY, self.payload, "doorbell-001")

    def tearDown(self) -> None:
        self.pub_patch.stop()
        self.log_file_patch.stop()
        self.temp_directory.cleanup()

    def test_invalid_payload_is_rejected_without_cloud_request(self) -> None:
        with patch.object(edge_gateway.requests, "post") as post:
            response = self.client.post("/api/access-request", json={})

        self.assertEqual(response.status_code, 400)
        post.assert_not_called()

    def test_invalid_envelope_type(self) -> None:
        response = self.client.post("/api/access-request", json=["not", "a", "dict"])
        self.assertEqual(response.status_code, 400)

    def test_missing_required_fields(self) -> None:
        bad_payload = {
            "device_id": "doorbell-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": "", # Empty name
        }
        bad_envelope = crypto.encrypt_payload(edge_gateway.DEVICE_EDGE_KEY, bad_payload, "doorbell-001")
        response = self.client.post("/api/access-request", json=bad_envelope)
        self.assertEqual(response.status_code, 400)

    def test_get_cloud_public_key_fetches_and_caches(self) -> None:
        edge_gateway._cached_cloud_pub_key = None
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "sender_id": "cloud-service",
            "public_key": crypto.export_kem_public_key(self.cloud_pub),
        }
        with patch.object(edge_gateway.requests, "get", return_value=mock_response) as mock_get:
            self.pub_patch.stop()
            try:
                pub1 = edge_gateway.get_cloud_public_key()
                self.assertIsNotNone(pub1)
                mock_get.assert_called_once()
                # Second call should use cache
                pub2 = edge_gateway.get_cloud_public_key()
                self.assertEqual(mock_get.call_count, 1)
                self.assertIsNotNone(pub2)
            finally:
                self.pub_patch.start()

    def test_get_cloud_public_key_failure(self) -> None:
        edge_gateway._cached_cloud_pub_key = None
        with patch.object(edge_gateway.requests, "get", side_effect=requests.RequestException):
            self.pub_patch.stop()
            try:
                response = self.client.post("/api/access-request", json=self.envelope)
                self.assertEqual(response.status_code, 502)
            finally:
                self.pub_patch.start()

    def test_cloud_invalid_response_returns_bad_gateway(self) -> None:
        cloud_response = Mock()
        cloud_response.status_code = 200
        # Return something that decrypt_payload will choke on
        cloud_response.json.return_value = {"error": "not a real envelope"}
        with patch.object(edge_gateway.requests, "post", return_value=cloud_response):
            response = self.client.post("/api/access-request", json=self.envelope)

        self.assertEqual(response.status_code, 502)
        self.assertIn("error", response.get_json())

    def test_cloud_unavailability_returns_bad_gateway(self) -> None:
        with patch.object(
            edge_gateway.requests, "post", side_effect=requests.Timeout
        ):
            response = self.client.post("/api/access-request", json=self.envelope)

        self.assertEqual(response.status_code, 502)
        self.assertIn("error", response.get_json())

    def test_successful_cloud_response_is_forwarded(self) -> None:
        def fake_post(url, json, timeout):
            kem_ct = json["kem_ciphertext"]
            shared_secret = crypto.decapsulate_secret(self.cloud_priv, kem_ct)
            resp_payload = {"access_granted": True, "message": "Gate opened"}
            resp_env = crypto.encrypt_payload(shared_secret, resp_payload, "cloud-service")
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = resp_env
            return mock_resp

        with patch.object(edge_gateway.requests, "post", side_effect=fake_post) as post:
            response = self.client.post("/api/access-request", json=self.envelope)

        self.assertEqual(response.status_code, 200)

        # Verify the forwarded response is encrypted for the device
        returned_envelope = response.get_json()
        decrypted = crypto.decrypt_payload(edge_gateway.DEVICE_EDGE_KEY, returned_envelope, "edge-gateway-001")
        self.assertEqual(decrypted["access_granted"], True)
        self.assertEqual(post.call_args.kwargs["timeout"], edge_gateway.REQUEST_TIMEOUT_SECONDS)

    def test_health_check(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "edge-gateway-001")

    def test_metrics_endpoint(self) -> None:
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("flask_http_request_total", response.text)


if __name__ == "__main__":
    unittest.main()
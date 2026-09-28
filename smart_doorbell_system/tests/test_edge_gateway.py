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
        self.client = edge_gateway.app.test_client()
        self.payload = {
            "device_id": "doorbell-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "visitor_name": "Alice",
        }
        self.envelope = crypto.encrypt_payload(edge_gateway.DEVICE_EDGE_KEY, self.payload, "doorbell-001")

    def tearDown(self) -> None:
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
        cloud_response = Mock()
        cloud_response.status_code = 200
        
        cloud_response_payload = {"access_granted": True, "message": "Gate opened"}
        cloud_envelope = crypto.encrypt_payload(edge_gateway.EDGE_CLOUD_KEY, cloud_response_payload, "cloud-service")
        
        cloud_response.json.return_value = cloud_envelope
        with patch.object(edge_gateway.requests, "post", return_value=cloud_response) as post:
            response = self.client.post("/api/access-request", json=self.envelope)

        self.assertEqual(response.status_code, 200)
        
        # Verify the forwarded response is encrypted for the device
        returned_envelope = response.get_json()
        decrypted = crypto.decrypt_payload(edge_gateway.DEVICE_EDGE_KEY, returned_envelope, "edge-gateway-001")
        self.assertEqual(decrypted["access_granted"], True)
        self.assertEqual(post.call_args.kwargs["timeout"], edge_gateway.REQUEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
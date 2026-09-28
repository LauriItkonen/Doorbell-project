"""Tests for gateway input handling and cloud-service failures."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

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
            "device_id": "test-device",
            "timestamp": "2026-09-28T12:00:00+00:00",
            "visitor_name": "Alice",
        }

    def tearDown(self) -> None:
        self.log_file_patch.stop()
        self.temp_directory.cleanup()

    def test_invalid_payload_is_rejected_without_cloud_request(self) -> None:
        with patch.object(edge_gateway.requests, "post") as post:
            response = self.client.post("/api/access-request", json={})

        self.assertEqual(response.status_code, 400)
        post.assert_not_called()

    def test_cloud_unavailability_returns_bad_gateway(self) -> None:
        with patch.object(
            edge_gateway.requests, "post", side_effect=requests.Timeout
        ):
            response = self.client.post("/api/access-request", json=self.payload)

        self.assertEqual(response.status_code, 502)
        self.assertIn("error", response.get_json())

    def test_successful_cloud_response_is_forwarded(self) -> None:
        cloud_response = Mock()
        cloud_response.status_code = 200
        cloud_response.json.return_value = {"access_granted": True}
        with patch.object(edge_gateway.requests, "post", return_value=cloud_response) as post:
            response = self.client.post("/api/access-request", json=self.payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"access_granted": True})
        self.assertEqual(post.call_args.kwargs["timeout"], edge_gateway.REQUEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
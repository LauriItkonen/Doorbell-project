"""Tests for doorbell verification timing output."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

import crypto
import doorbell_device


class DoorbellDeviceTests(unittest.TestCase):
    def test_main_reports_verification_duration(self) -> None:
        response = Mock()
        
        # Build encrypted response envelope from edge gateway
        cloud_response_payload = {"access_granted": False}
        envelope = crypto.encrypt_payload(doorbell_device.DEVICE_EDGE_KEY, cloud_response_payload, "edge-gateway-001")
        response.json.return_value = envelope
        
        output = io.StringIO()

        with (
            patch("builtins.input", side_effect=("Alice", "exit")),
            patch.object(doorbell_device.requests, "post", return_value=response),
            patch.object(
                doorbell_device.time, "perf_counter", side_effect=(10.0, 10.375)
            ),
            redirect_stdout(output),
        ):
            doorbell_device.main()

        self.assertIn("Verification completed in 0.375 seconds.", output.getvalue())
        self.assertIn("ACCESS DENIED", output.getvalue())

    def test_main_reports_verification_duration_access_granted(self) -> None:
        response = Mock()
        cloud_response_payload = {"access_granted": True}
        envelope = crypto.encrypt_payload(doorbell_device.DEVICE_EDGE_KEY, cloud_response_payload, "edge-gateway-001")
        response.json.return_value = envelope
        
        output = io.StringIO()

        with (
            patch("builtins.input", side_effect=("Alice", "exit")),
            patch.object(doorbell_device.requests, "post", return_value=response),
            patch.object(doorbell_device.time, "perf_counter", side_effect=(10.0, 10.375)),
            redirect_stdout(output),
        ):
            doorbell_device.main()

        self.assertIn("Verification completed in 0.375 seconds.", output.getvalue())
        self.assertIn("GATE OPENED", output.getvalue())

    def test_main_reports_elapsed_time_when_gateway_is_unavailable(self) -> None:
        output = io.StringIO()

        with (
            patch("builtins.input", side_effect=("Alice", "exit")),
            patch.object(
                doorbell_device.requests, "post", side_effect=requests.Timeout
            ),
            patch.object(
                doorbell_device.time, "perf_counter", side_effect=(10.0, 10.25)
            ),
            redirect_stdout(output),
        ):
            doorbell_device.main()

        self.assertIn("Gateway unavailable after 0.250 seconds", output.getvalue())

    def test_main_handles_empty_input_and_invalid_gateway_response(self) -> None:
        output = io.StringIO()
        response = Mock()
        # Invalid response that fails decryption
        response.json.return_value = {"invalid": "envelope"}
        
        with (
            patch("builtins.input", side_effect=("", "Alice", "exit")),
            patch.object(
                doorbell_device.requests, "post", return_value=response
            ),
            patch.object(
                doorbell_device.time, "perf_counter", side_effect=(10.0, 10.1)
            ),
            redirect_stdout(output),
        ):
            doorbell_device.main()

        self.assertIn("Visitor name cannot be empty.", output.getvalue())
        self.assertIn("invalid or unauthenticated response", output.getvalue())


if __name__ == "__main__":
    unittest.main()
"""Tests for doorbell verification timing output."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

import doorbell_device


class DoorbellDeviceTests(unittest.TestCase):
    def test_main_reports_verification_duration(self) -> None:
        response = Mock()
        response.json.return_value = {"access_granted": False}
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


if __name__ == "__main__":
    unittest.main()
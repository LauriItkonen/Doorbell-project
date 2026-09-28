"""MicroPython unit tests for micropython_doorbell.py verification and timing."""

import builtins
import unittest
import utime

import device_crypto as crypto
import micropython_doorbell as doorbell


class MockResponse:
    """Mock container for urequests responses."""

    def __init__(self, json_data: dict, status_code: int = 200) -> None:
        self._json_data = json_data
        self.status_code = status_code

    def json(self) -> dict:
        return self._json_data


class DoorbellDeviceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orig_input = builtins.input
        self.orig_post = doorbell.requests.post
        self.orig_ticks_ms = utime.ticks_ms
        self.orig_print = builtins.print

    def tearDown(self) -> None:
        builtins.input = self.orig_input
        doorbell.requests.post = self.orig_post
        utime.ticks_ms = self.orig_ticks_ms
        builtins.print = self.orig_print

    def _run_with_mocks(self, inputs: list, mock_post, tick_sequence: tuple = (10000, 10375)) -> str:
        # Patch input()
        input_iter = iter(inputs)
        builtins.input = lambda prompt="": next(input_iter)

        # Patch requests.post()
        doorbell.requests.post = mock_post

        # Patch utime.ticks_ms()
        ticks_iter = iter(tick_sequence)
        utime.ticks_ms = lambda: next(ticks_iter)

        # Capture print output
        logs = []
        builtins.print = lambda *args, **kwargs: logs.append(" ".join(str(a) for a in args))

        doorbell.main()
        return "\n".join(logs)

    def test_main_reports_verification_duration(self) -> None:
        cloud_payload = {"access_granted": False}
        envelope = crypto.encrypt_payload(doorbell.DEVICE_EDGE_KEY, cloud_payload, "edge-gateway-001")

        def mock_post(url, json=None, timeout=None):
            return MockResponse(envelope)

        output = self._run_with_mocks(["Alice", "exit"], mock_post)

        self.assertTrue("Verification completed in 0.375 seconds." in output)
        self.assertTrue("ACCESS DENIED" in output)

    def test_main_reports_verification_duration_access_granted(self) -> None:
        cloud_payload = {"access_granted": True}
        envelope = crypto.encrypt_payload(doorbell.DEVICE_EDGE_KEY, cloud_payload, "edge-gateway-001")

        def mock_post(url, json=None, timeout=None):
            return MockResponse(envelope)

        output = self._run_with_mocks(["Alice", "exit"], mock_post)

        self.assertTrue("Verification completed in 0.375 seconds." in output)
        self.assertTrue("GATE OPENED" in output)

    def test_main_reports_elapsed_time_when_gateway_is_unavailable(self) -> None:
        def mock_post(url, json=None, timeout=None):
            raise OSError("Connection timed out")

        output = self._run_with_mocks(["Alice", "exit"], mock_post, tick_sequence=(10000, 10250))

        self.assertTrue("Gateway unavailable after 0.250 seconds" in output)

    def test_main_handles_empty_input_and_invalid_gateway_response(self) -> None:
        def mock_post(url, json=None, timeout=None):
            return MockResponse({"invalid": "envelope"})

        output = self._run_with_mocks(["", "Alice", "exit"], mock_post, tick_sequence=(10000, 10100))

        self.assertTrue("Visitor name cannot be empty." in output)
        self.assertTrue("invalid or unauthenticated response" in output)


if __name__ == "__main__":
    unittest.main()
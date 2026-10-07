"""Tests for the structured JSON logging module."""

import json
import logging
import unittest

from json_logging import JsonFormatter, setup_json_logging


class JsonLoggingTests(unittest.TestCase):
    def test_json_formatter_outputs_valid_json(self) -> None:
        formatter = JsonFormatter(service_name="test-service")
        record = logging.LogRecord(
            name="test-logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Hello, world!",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        self.assertEqual(data["service"], "test-service")
        self.assertEqual(data["logger"], "test-logger")
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["message"], "Hello, world!")
        self.assertIn("timestamp", data)

    def test_json_formatter_includes_extra_fields(self) -> None:
        formatter = JsonFormatter(service_name="test-service")
        record = logging.LogRecord(
            name="test-logger",
            level=logging.WARNING,
            pathname=__file__,
            lineno=25,
            msg="User failed login",
            args=(),
            exc_info=None,
        )
        record.user_id = "user-123"
        record.ip_address = "192.168.1.1"

        output = formatter.format(record)
        data = json.loads(output)

        self.assertEqual(data["user_id"], "user-123")
        self.assertEqual(data["ip_address"], "192.168.1.1")

    def test_json_formatter_includes_exception(self) -> None:
        formatter = JsonFormatter(service_name="test-service")
        try:
            raise ValueError("Something broke")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test-logger",
            level=logging.ERROR,
            pathname=__file__,
            lineno=45,
            msg="Operation failed",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)

        self.assertIn("exception", data)
        self.assertIn("ValueError: Something broke", data["exception"])

    def test_setup_json_logging_configures_logger(self) -> None:
        logger = setup_json_logging("my-service", level=logging.DEBUG)
        self.assertEqual(logger.name, "my-service")

        root = logging.getLogger()
        self.assertEqual(root.level, logging.DEBUG)
        self.assertEqual(len(root.handlers), 1)
        self.assertIsInstance(root.handlers[0].formatter, JsonFormatter)


if __name__ == "__main__":
    unittest.main()

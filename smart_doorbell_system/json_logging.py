"""Structured JSON logging configuration using Python's standard logging module."""

import json
import logging
import sys
from datetime import datetime, timezone

STANDARD_RECORD_ATTRS = frozenset((
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
))


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines."""

    def __init__(self, service_name: str = "doorbell-service") -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        service_name = getattr(record, "service", None)
        if not service_name:
            if record.name in ("cloud-service", "edge-gateway-001"):
                service_name = record.name
            else:
                service_name = self.service_name

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": service_name,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key not in STANDARD_RECORD_ATTRS and not key.startswith("_"):
                log_entry[key] = value

        return json.dumps(log_entry)


def setup_json_logging(service_name: str, level: int = logging.INFO) -> logging.Logger:
    """Configure the root logger with a JsonFormatter writing to sys.stdout."""
    root = logging.getLogger()
    root.setLevel(level)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service_name=service_name))
    root.addHandler(handler)

    return logging.getLogger(service_name)

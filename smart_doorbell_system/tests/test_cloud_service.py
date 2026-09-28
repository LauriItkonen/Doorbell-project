"""Tests for cloud visitor verification and analytics."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cloud_service


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
                response = self.client.post(
                    "/api/cloud/verify-visitor",
                    json={"visitor_name": visitor_name},
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.get_json()["access_granted"], expected_access
                )

    def test_empty_and_whitespace_names_are_rejected(self) -> None:
        for visitor_name in ("", "   "):
            with self.subTest(visitor_name=visitor_name):
                response = self.client.post(
                    "/api/cloud/verify-visitor",
                    json={"visitor_name": visitor_name},
                )

                self.assertEqual(response.status_code, 400)

    def test_missing_name_is_rejected(self) -> None:
        response = self.client.post("/api/cloud/verify-visitor", json={})

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_analytics_reports_granted_and_denied_attempts(self) -> None:
        self.client.post(
            "/api/cloud/verify-visitor", json={"visitor_name": "Alice"}
        )
        self.client.post(
            "/api/cloud/verify-visitor", json={"visitor_name": "Mallory"}
        )

        response = self.client.get("/api/analytics/summary")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"total_attempts": 2, "successful_entries": 1, "denied_entries": 1},
        )


if __name__ == "__main__":
    unittest.main()
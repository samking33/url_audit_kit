import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from url_audit.utils import CheckResult
from webapp.main import app


class WebappApiTests(unittest.TestCase):
    def test_audit_endpoint_returns_normalized_target_and_no_skip_statuses(self):
        client = TestClient(app)

        fake_results = [
            CheckResult(1, "Domain Name Legitimacy", "PASS", evidence="ok"),
            CheckResult(2, "AI Content Analysis", "INFO", evidence="local"),
            CheckResult(3, "Google Safe Browsing", "WARN", evidence="heuristic"),
        ]

        with patch(
            "webapp.main.run_all_with_context",
            return_value=(
                fake_results,
                {
                    "input_url": "example.com",
                    "normalized_url": "https://example.com/",
                    "resolved_url": "https://example.com/",
                },
            ),
        ), patch(
            "webapp.main._run_ai_results_analysis",
            new=AsyncMock(return_value={"enabled": False, "error": "NIM unavailable"}),
        ):
            response = client.post("/api/audit", data={"url": "example.com"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["input_url"], "example.com")
        self.assertEqual(payload["normalized_url"], "https://example.com/")
        self.assertEqual(payload["resolved_url"], "https://example.com/")
        self.assertEqual(payload["target_url"], "https://example.com/")

        statuses = {item["status"] for item in payload["results"]}
        self.assertFalse("SKIP" in statuses)


if __name__ == "__main__":
    unittest.main()

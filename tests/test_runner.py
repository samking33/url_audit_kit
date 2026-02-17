import unittest
from unittest.mock import patch

import url_audit.runner as runner
from url_audit.utils import CheckResult


class RunnerTests(unittest.TestCase):
    def test_runner_emits_result_for_every_step_and_converts_skip(self):
        def returns_none(_url):
            return None

        def returns_skip(_url):
            return CheckResult(2, "Legacy Skip", "SKIP", evidence="legacy")

        def raises_error(_url):
            raise RuntimeError("boom")

        steps = [
            ("None Step", returns_none),
            ("Skip Step", returns_skip),
            ("Crash Step", raises_error),
        ]

        with patch.object(runner, "CHECK_STEPS", steps), patch(
            "url_audit.runner.resolve_audit_target",
            return_value={
                "input_url": "example.com",
                "normalized_url": "https://example.com/",
                "resolved_url": "https://example.com/",
            },
        ):
            results, context = runner.run_all_with_context("example.com")

        self.assertEqual(len(results), len(steps))
        self.assertEqual(context["normalized_url"], "https://example.com/")

        self.assertEqual(results[0].status, "FAIL")
        self.assertEqual(results[1].status, "WARN")
        self.assertIn("converted_from_skip", results[1].evidence)
        self.assertEqual(results[2].status, "FAIL")

        counts = runner.summarize(results)
        self.assertNotIn("SKIP", counts)
        self.assertEqual(sum(counts.values()), len(steps))


if __name__ == "__main__":
    unittest.main()

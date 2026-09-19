"""The exercise scorekeeper must not manufacture a green result."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[2] / "scripts/run-respectability-gauntlet.py"
spec = importlib.util.spec_from_file_location("respectability_runner", PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RespectabilityRunnerTests(unittest.TestCase):
    def test_empty_suite_is_not_a_pass(self):
        result = unittest.TestResult()
        self.assertEqual(runner.summarize(result)["status"], "FAIL")

    def test_clean_executed_suite_is_a_pass(self):
        result = unittest.TestResult()
        result.testsRun = 1
        self.assertEqual(runner.summarize(result)["status"], "PASS")

    def test_skipped_tests_are_visible_not_full_pass(self):
        result = unittest.TestResult()
        result.testsRun = 1
        result.skipped.append((unittest.FunctionTestCase(lambda: None), "needs service"))
        summary = runner.summarize(result)
        self.assertEqual(summary["status"], "PASS_WITH_GAPS")
        self.assertEqual(summary["skipped"], 1)

    def test_expected_failures_remain_visible(self):
        result = unittest.TestResult()
        result.testsRun = 1
        result.expectedFailures.append((unittest.FunctionTestCase(lambda: None), "known failure"))
        self.assertEqual(runner.summarize(result)["status"], "PASS_WITH_GAPS")

    def test_failures_cannot_be_green(self):
        result = unittest.TestResult()
        result.testsRun = 1
        result.failures.append((unittest.FunctionTestCase(lambda: None), "failure"))
        self.assertEqual(runner.summarize(result)["status"], "FAIL")

    def test_report_publication_replaces_complete_json(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "reports/report.json"
            runner.publish(target, {"status": "FAIL"})
            runner.publish(target, {"status": "PASS", "source_commit": "test"})
            self.assertEqual(json.loads(target.read_text()),
                             {"status": "PASS", "source_commit": "test"})
            self.assertEqual(list(target.parent.iterdir()), [target])


if __name__ == "__main__":
    unittest.main()

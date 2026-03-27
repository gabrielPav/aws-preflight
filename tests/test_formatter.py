import json
import unittest
from cli_parser import parse_command
from formatter import (
    _build_suggested,
    exit_code_for_findings,
    format_parse_error,
    format_parse_error_json,
    format_result,
    format_result_json,
)


class TestExitCode(unittest.TestCase):

    def _finding(self, severity):
        return {"severity": severity, "message": "x", "context": "", "suggestion": ""}

    def test_no_findings_always_zero(self):
        for threshold in ("HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(exit_code_for_findings([], threshold), 0)

    def test_high_fires_at_all_thresholds(self):
        findings = [self._finding("HIGH")]
        for threshold in ("HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertEqual(exit_code_for_findings(findings, threshold), 1)

    def test_medium_silent_at_high_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("MEDIUM")], "HIGH"), 0)

    def test_medium_fires_at_medium_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("MEDIUM")], "MEDIUM"), 1)

    def test_low_silent_at_medium_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("LOW")], "MEDIUM"), 0)

    def test_low_fires_at_low_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("LOW")], "LOW"), 1)

    def test_info_silent_at_low_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("INFO")], "LOW"), 0)

    def test_info_fires_at_info_threshold(self):
        self.assertEqual(exit_code_for_findings([self._finding("INFO")], "INFO"), 1)


class TestFormatResult(unittest.TestCase):

    def _parsed(self, cmd):
        return parse_command(cmd)

    def test_clean_result_shows_no_issues_message(self):
        output = format_result(self._parsed("aws s3 ls"), [])
        self.assertIn("No obvious security issues", output)

    def test_result_shows_command_name(self):
        output = format_result(self._parsed("aws ec2 run-instances --image-id ami-12345"), [])
        self.assertIn("ec2 run-instances", output)

    def test_result_shows_severity_and_message(self):
        findings = [{"severity": "HIGH", "message": "Bad thing happened", "context": "", "suggestion": ""}]
        output = format_result(self._parsed("aws s3 ls"), findings)
        self.assertIn("HIGH", output)
        self.assertIn("Bad thing happened", output)

    def test_result_shows_context(self):
        findings = [{"severity": "HIGH", "message": "msg", "context": "more detail here", "suggestion": ""}]
        output = format_result(self._parsed("aws s3 ls"), findings)
        self.assertIn("more detail here", output)

    def test_result_shows_suggestion(self):
        findings = [{"severity": "HIGH", "message": "msg", "context": "", "suggestion": "--fix-flag"}]
        output = format_result(self._parsed("aws s3 ls"), findings)
        self.assertIn("--fix-flag", output)


class TestFormatResultJson(unittest.TestCase):

    def _parsed(self, cmd):
        return parse_command(cmd)

    def test_output_is_valid_json(self):
        output = format_result_json(self._parsed("aws s3 ls"), [])
        data = json.loads(output)
        self.assertIsInstance(data, dict)

    def test_required_keys_present(self):
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), []))
        for key in ("command", "service", "operation", "passed", "findings", "summary"):
            self.assertIn(key, data)

    def test_passed_true_when_no_findings(self):
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), []))
        self.assertTrue(data["passed"])

    def test_passed_false_when_findings(self):
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": ""}]
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), findings))
        self.assertFalse(data["passed"])

    def test_private_fields_not_in_json_output(self):
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "", "_forbidden_flag": "--acl"}]
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), findings))
        for f in data["findings"]:
            for key in f:
                self.assertFalse(key.startswith("_"), f"Private field '{key}' leaked into JSON output")

    def test_summary_counts_are_correct(self):
        findings = [
            {"severity": "HIGH",   "message": "h1", "context": "", "suggestion": ""},
            {"severity": "HIGH",   "message": "h2", "context": "", "suggestion": ""},
            {"severity": "MEDIUM", "message": "m1", "context": "", "suggestion": ""},
            {"severity": "LOW",    "message": "l1", "context": "", "suggestion": ""},
            {"severity": "INFO",   "message": "i1", "context": "", "suggestion": ""},
        ]
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), findings))
        self.assertEqual(data["summary"]["total"],  5)
        self.assertEqual(data["summary"]["high"],   2)
        self.assertEqual(data["summary"]["medium"], 1)
        self.assertEqual(data["summary"]["low"],    1)
        self.assertEqual(data["summary"]["info"],   1)

    def test_suggested_command_present_when_findings(self):
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "--fix"}]
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), findings))
        self.assertIn("suggested_command", data)

    def test_suggested_command_absent_when_no_findings(self):
        data = json.loads(format_result_json(self._parsed("aws s3 ls"), []))
        self.assertNotIn("suggested_command", data)


class TestBuildSuggested(unittest.TestCase):

    def _parsed(self, cmd):
        return parse_command(cmd)

    def test_adds_missing_flag(self):
        parsed = self._parsed("aws ec2 run-instances --image-id ami-12345")
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "--metadata-options HttpTokens=required"}]
        result = _build_suggested(parsed, findings)
        self.assertIn("--metadata-options HttpTokens=required", result)

    def test_removes_forbidden_flag(self):
        parsed = self._parsed("aws s3 cp data.csv s3://bucket/ --acl public-read")
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "--acl private", "_forbidden_flag": "--acl"}]
        result = _build_suggested(parsed, findings)
        self.assertNotIn("public-read", result)
        self.assertIn("private", result)

    def test_preserves_clean_flags(self):
        parsed = self._parsed("aws ec2 run-instances --image-id ami-12345 --count 1")
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "--metadata-options HttpTokens=required"}]
        result = _build_suggested(parsed, findings)
        self.assertIn("--image-id", result)
        self.assertIn("ami-12345", result)
        self.assertIn("--count", result)

    def test_no_duplicate_flags(self):
        parsed = self._parsed("aws ec2 run-instances --image-id ami-12345")
        findings = [{"severity": "HIGH", "message": "x", "context": "", "suggestion": "--metadata-options HttpTokens=required"}]
        result = _build_suggested(parsed, findings)
        self.assertEqual(result.count("--metadata-options"), 1)

    def test_base_command_always_present(self):
        parsed = self._parsed("aws ec2 run-instances --image-id ami-12345")
        result = _build_suggested(parsed, [])
        self.assertTrue(result.startswith("aws ec2 run-instances"))


class TestParseError(unittest.TestCase):

    def test_text_error_truncates_long_input(self):
        output = format_parse_error("x" * 500)
        self.assertLessEqual(len(output), 300)

    def test_json_error_is_valid_json(self):
        data = json.loads(format_parse_error_json("not a command"))
        self.assertFalse(data["passed"])
        self.assertEqual(data["findings"], [])
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)

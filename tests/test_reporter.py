"""Unit tests for console and JSON reporting."""

import json
import re
import unittest

from secretguard.reporter import format_console, format_json, mask, summarize


def finding(
    rule="GitHub Token",
    severity="high",
    value="ghp_secret",
    line=1,
    path="a.py",
):
    return {
        "path": path,
        "value": value,
        "rule": rule,
        "severity": severity,
        "line": line,
        "description": "test",
    }


class MaskTest(unittest.TestCase):
    def test_short_value_fully_masked(self):
        self.assertEqual(mask("abc"), "***")

    def test_masked_value_keeps_length(self):
        value = "a" * 20
        masked = mask(value)
        self.assertEqual(len(masked), len(value))
        self.assertEqual(masked[:6], "a" * 6)
        self.assertEqual(masked[6:], "*" * 14)

    def test_boundary_keeps_prefix_and_masks_rest(self):
        masked = mask("abcdefghijk")  # length 11
        self.assertEqual(masked, "abcdef" + "*" * 5)

    def test_reveal_prefix(self):
        self.assertEqual(mask("abcdefgh", reveal_prefix=4), "abcd****")
        self.assertEqual(mask("abcde", reveal_prefix=4), "abcd*")

    def test_reveal_suffix(self):
        self.assertEqual(mask("abcdefgh", reveal_suffix=4), "****efgh")
        self.assertEqual(mask("abcde", reveal_suffix=4), "*bcde")

    def test_reveal_prefix_and_suffix(self):
        self.assertEqual(mask("abcdefgh", reveal_prefix=2, reveal_suffix=2), "ab****gh")

    def test_reveal_overlap_masks_completely(self):
        # If pref_len + suff_len >= val_len, it should mask completely to prevent full leak
        self.assertEqual(mask("abc", reveal_prefix=4), "***")
        self.assertEqual(mask("abcd", reveal_prefix=4), "****")
        self.assertEqual(mask("abcd", reveal_prefix=2, reveal_suffix=2), "****")
        self.assertEqual(mask("abcde", reveal_prefix=3, reveal_suffix=3), "*****")


class SummarizeTest(unittest.TestCase):
    def test_counts_by_severity(self):
        findings = [
            finding(severity="critical", value="-----BEGIN RSA PRIVATE KEY-----"),
            finding(severity="high"),
            finding(severity="high"),
            finding(severity="medium"),
            finding(severity="low", value="opaque"),
        ]
        summary = summarize(findings)
        self.assertEqual(
            summary,
            {"critical": 1, "high": 2, "medium": 1, "low": 1, "total": 5},
        )

    def test_ignores_unknown_severity(self):
        findings = [finding(severity="urgent")]
        summary = summarize(findings)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(
            sum(summary[k] for k in ("critical", "high", "medium", "low")), 0
        )


class FormatConsoleTest(unittest.TestCase):
    def test_full_value_printed_when_requested(self):
        value = "ghp_" + "a" * 34  # "ghp_" + 34 chars
        report = format_console([finding(value=value)], ".", show_value=True)
        self.assertIn(value, report)

    def test_value_masked_by_default_when_requested(self):
        value = "ghp_" + "a" * 34
        report = format_console([finding(value=value)], ".", show_value=False)
        self.assertNotIn(value, report)
        self.assertIn("GitHub Token", report)

    def test_reveal_findings_are_not_masked(self):
        f = finding(value="GITHUB_TOKEN", severity="high")
        f["reveal"] = True
        report = format_console([f], ".", show_value=False)
        self.assertIn("GITHUB_TOKEN", report)

    def test_include_only_full_value_option(self):
        value = "ghp_" + "a" * 34
        report = format_console([finding(value=value)], ".", show_value=False)
        self.assertIn("a.py:1", report)

    def test_summary_line_reports_totals(self):
        findings = [
            finding(severity="critical", value="-----BEGIN RSA PRIVATE KEY-----"),
            finding(severity="high"),
        ]
        report = format_console(findings, ".", show_value=False)
        self.assertIn("1 critical, 1 high", report)
        self.assertIn("2 total", report)

    def test_sorted_by_path_then_line(self):
        findings = [
            finding(path="b.py", line=2),
            finding(path="a.py", line=9),
            finding(path="a.py", line=1),
        ]
        report = format_console(findings, ".", show_value=False)
        lines = report.splitlines()
        positions = {
            prefix: lines.index(next(ln for ln in lines if ln.startswith(prefix)))
            for prefix in ("a.py:1", "a.py:9", "b.py:2")
        }
        self.assertLess(positions["a.py:1"], positions["a.py:9"])
        self.assertLess(positions["a.py:9"], positions["b.py:2"])

    def test_reveal_prefix_option(self):
        value = "ghp_secretvalue123"
        report = format_console([finding(value=value)], ".", show_value=False, reveal_prefix=4)
        self.assertIn("ghp_**************", report)

    def test_reveal_suffix_option(self):
        value = "ghp_secretvalue123"
        report = format_console([finding(value=value)], ".", show_value=False, reveal_suffix=3)
        self.assertIn("***************123", report)


class FormatJsonTest(unittest.TestCase):
    def test_roundtrip_full_values(self):
        findings = [finding(severity="high", value="ghp_secretvalue123")]
        payload = json.loads(format_json(findings, "/repo", show_value=True))
        self.assertEqual(payload["root"], "/repo")
        self.assertEqual(payload["findings"], findings)

    def test_values_masked_by_default(self):
        findings = [finding(severity="high", value="ghp_secretvalue123")]
        payload = json.loads(format_json(findings, "/repo"))
        self.assertNotEqual(payload["findings"][0]["value"], findings[0]["value"])
        self.assertNotIn("secretvalue", payload["findings"][0]["value"])

    def test_reveal_findings_keep_value_in_json(self):
        f = finding(value="GITHUB_TOKEN")
        f["reveal"] = True
        payload = json.loads(format_json([f], "/repo"))
        self.assertEqual(payload["findings"][0]["value"], "GITHUB_TOKEN")

    def test_reveal_prefix_json(self):
        findings = [finding(severity="high", value="ghp_secretvalue123")]
        payload = json.loads(format_json(findings, "/repo", show_value=False, reveal_prefix=4))
        self.assertEqual(payload["findings"][0]["value"], "ghp_**************")

    def test_reveal_suffix_json(self):
        findings = [finding(severity="high", value="ghp_secretvalue123")]
        payload = json.loads(format_json(findings, "/repo", show_value=False, reveal_suffix=3))
        self.assertEqual(payload["findings"][0]["value"], "***************123")

    def test_valid_json(self):
        report = format_json([], ".")
        self.assertIsNotNone(re.match(r"^\s*\{.*\}\s*$", report, re.DOTALL))

class ColorTest(unittest.TestCase):
    def test_forced_color_true_colors_output(self):
        value = "ghp_" + "a" * 34
        report = format_console(
            [finding(value=value)], ".", show_value=True, color=True
        )
        self.assertIn("\033[", report)

    def test_forced_color_false_is_plain(self):
        value = "ghp_" + "a" * 34
        report = format_console(
            [finding(value=value)], ".", show_value=True, color=False
        )
        self.assertNotIn("\033[", report)

    def test_default_auto_detect_is_plain_when_not_a_tty(self):
        value = "ghp_" + "a" * 34
        report = format_console([finding(value=value)], ".", show_value=True)
        self.assertNotIn("\033[", report)


class JsonSchemaTest(unittest.TestCase):
    def test_schema_version_present(self):
        payload = json.loads(format_json([], "."))
        self.assertEqual(payload["schema_version"], 1)

    def test_findings_sorted_by_path_line_rule(self):
        findings = [
            finding(path="b.py", line=2, rule="Z Rule"),
            finding(path="a.py", line=9, rule="A Rule"),
            finding(path="a.py", line=1, rule="B Rule"),
        ]
        payload = json.loads(format_json(findings, "."))
        paths_lines = [(f["path"], f["line"]) for f in payload["findings"]]
        self.assertEqual(paths_lines, [("a.py", 1), ("a.py", 9), ("b.py", 2)])

    def test_ordering_is_deterministic_across_runs(self):
        findings = [
            finding(path="b.py", line=2),
            finding(path="a.py", line=1),
        ]
        first = format_json(list(findings), ".")
        second = format_json(list(reversed(findings)), ".")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
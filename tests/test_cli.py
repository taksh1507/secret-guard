"""End-to-end tests for the secret-guard command line."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SECRET = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
CUSTOM_SECRET = "acme_tok_0123456789abcdef0123"
CUSTOM_MANIFEST = json.dumps(
    {
        "rules": [
            {
                "name": "Acme Token",
                "pattern": "acme_tok_[a-f0-9]{20,}",
                "severity": "high",
                "description": "Acme platform API token.",
            }
        ]
    }
)


def run_git(repo, *args):
    subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True
    )


class CliTest(unittest.TestCase):
    def run_cli(self, cwd, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        return subprocess.run(
            [sys.executable, "-m", "secretguard", *args],
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
            check=False,
        )

    def test_scan_returns_one_on_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn("GitHub Token", result.stdout)

    def test_scan_returns_zero_when_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 0)
            self.assertIn("0 total", result.stdout)

    def test_scan_json_emits_parseable_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--json", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIsNotNone(__import__("json").loads(result.stdout))

    def test_scan_reveal_prefix_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--reveal-prefix", "4", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn("ghp_************************************", result.stdout)

    def test_scan_reveal_suffix_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--reveal-suffix", "4", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn("************************************wxyz", result.stdout)

    def test_scan_excludes_extra_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "wip").mkdir()
            Path(tmp, "wip", "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--exclude", "wip", ".")
            self.assertEqual(result.returncode, 0)

    def test_scan_detects_dotenv_secret_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                f"GITHUB_TOKEN={SECRET}\n", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn("Environment File Secret", result.stdout)
            self.assertNotIn(SECRET, result.stdout)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_staged_scans_index_blob_not_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "repo")
            repo.mkdir()
            secret = repo / "secret.py"
            secret.write_text(f"TOKEN = '{SECRET}'", encoding="utf-8")
            run_git(repo, "init", "-q")
            run_git(repo, "add", "secret.py")
            secret.unlink()
            result = self.run_cli(str(repo), "scan", "--staged")
            self.assertEqual(result.returncode, 1)
            self.assertIn("GitHub Token", result.stdout)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_staged_clean_when_nothing_suspicious(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "repo")
            repo.mkdir()
            (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")
            run_git(repo, "init", "-q")
            run_git(repo, "add", "main.py")
            result = self.run_cli(str(repo), "scan", "--staged")
            self.assertEqual(result.returncode, 0)

    def test_scan_json_masks_values_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--json", ".")
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(SECRET, result.stdout)

    def test_scan_json_show_value_exposes_full_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", "--json", "--show-value", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn(SECRET, result.stdout)

    def test_help_lists_commands(self):
        result = self.run_cli(str(PROJECT_ROOT), "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("scan", result.stdout)
        self.assertIn("install-hook", result.stdout)

    def test_scan_skip_rule_suppresses_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"aws = AKIAIOSFODNN7EXAMPLE\nTOKEN = '{SECRET}'",
                encoding="utf-8",
            )
            result = self.run_cli(
                tmp, "scan", "--skip-rule", "github-token", "."
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("AWS Access Key ID", result.stdout)
            self.assertNotIn("GitHub Token", result.stdout)

    def test_scan_only_rule_keeps_only_that_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret.py").write_text(
                f"aws = AKIAIOSFODNN7EXAMPLE\nTOKEN = '{SECRET}'",
                encoding="utf-8",
            )
            result = self.run_cli(
                tmp, "scan", "--only-rule", "aws-access-key-id", "."
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("AWS Access Key ID", result.stdout)
            self.assertNotIn("GitHub Token", result.stdout)

    def test_scan_list_rules_lists_rule_ids(self):
        result = self.run_cli(str(PROJECT_ROOT), "scan", "--list-rules")
        self.assertEqual(result.returncode, 0)
        self.assertIn("github-token", result.stdout)
        self.assertIn("entropy", result.stdout)
        self.assertIn("dotenv", result.stdout)

    def test_scan_unknown_rule_id_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text("print('clean')\n", encoding="utf-8")
            result = self.run_cli(tmp, "scan", "--skip-rule", "nope-rule", ".")
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown rule id", result.stderr)

    def test_scan_loads_valid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Set up a config that excludes "wip" directory
            Path(tmp, "secret-guard.json").write_text(
                '{"exclude": ["wip"], "no_entropy": true}',
                encoding="utf-8"
            )
            Path(tmp, "wip").mkdir()
            Path(tmp, "wip", "secret.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 0) # Excluded, so clean!

    def test_scan_cli_overrides_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Config skips "GitHub Token"
            Path(tmp, "secret-guard.json").write_text(
                '{"skip_rules": ["github-token"], "no_entropy": true}',
                encoding="utf-8"
            )
            Path(tmp, "secret.py").write_text(
                f"x = '{SECRET}'", encoding="utf-8"
            )
            # Without CLI flag, it is skipped
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 0)

            # With CLI only-rule, it runs anyway (CLI overrides config)
            result2 = self.run_cli(tmp, "scan", "--only-rule", "github-token", ".")
            self.assertEqual(result2.returncode, 1)
            self.assertIn("GitHub Token", result2.stdout)

    def test_scan_config_warning_on_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret-guard.json").write_text(
                '{"unknown_key": "val"}',
                encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 0)
            self.assertIn(
                "Warning: Unknown configuration key 'unknown_key'",
                result.stderr,
            )

    def test_scan_config_malformed_json_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret-guard.json").write_text(
                '{"exclude": ',
                encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 2)
            self.assertIn("Error parsing", result.stderr)

    def test_init_scaffolds_documented_starter_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli(tmp, "init")
            self.assertEqual(result.returncode, 0)
            config_file = Path(tmp, "secret-guard.json")
            self.assertTrue(config_file.exists())
            content = config_file.read_text(encoding="utf-8")
            self.assertIn("Secret-Guard Configuration File", content)

            # Load and verify it's valid JSON
            data = json.loads(content)
            self.assertIn("exclude", data)
            self.assertIn("//", data)

    def test_init_errors_if_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp, "secret-guard.json")
            config_file.write_text("existing", encoding="utf-8")
            result = self.run_cli(tmp, "init")
            self.assertEqual(result.returncode, 1)
            self.assertIn("already exists", result.stderr)

    def test_scan_baseline_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create a file with a secret
            test_file = Path(tmp, "test.py")
            secret_val = "ghp_123456789012345678901234567890123456"
            test_file.write_text(f"token = '{secret_val}'", encoding="utf-8")
            
            # Without baseline, it detects it
            result = self.run_cli(tmp, "scan", "--only-rule", "github-token", ".")
            self.assertEqual(result.returncode, 1)
            
            # Calculate secret hash
            sec_hash = hashlib.sha256(secret_val.encode("utf-8")).hexdigest()
            
            # Create baseline file (hash matched)
            baseline_file = Path(tmp, "baseline.json")
            baseline_content = {
                "baseline": [
                    {
                        "path": "test.py",
                        "rule_id": "github-token",
                        "hash": sec_hash
                    }
                ]
            }
            baseline_file.write_text(json.dumps(baseline_content), encoding="utf-8")
            
            # With baseline file, it is suppressed (exit code 0)
            result2 = self.run_cli(
                tmp,
                "scan",
                "--only-rule",
                "github-token",
                "--baseline",
                str(baseline_file),
                ".",
            )
            self.assertEqual(result2.returncode, 0)

            # Test baseline in secret-guard.json
            config_file = Path(tmp, "secret-guard.json")
            config_content = {
                "only_rules": ["github-token"],
                "baseline": [
                    {
                        "path": "test.py",
                        "rule_id": "github-token",
                        "hash": sec_hash
                    }
                ]
            }
            config_file.write_text(json.dumps(config_content), encoding="utf-8")
            
            # Runs automatically from config file, suppressed!
            result3 = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result3.returncode, 0)

    def test_scan_severity_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text(
                "opaque = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2'",
                encoding="utf-8",
            )
            result_default = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result_default.returncode, 1)

            result_low = self.run_cli(tmp, "scan", "--severity", "low", ".")
            self.assertEqual(result_low.returncode, 1)

            result_med = self.run_cli(tmp, "scan", "--severity", "medium", ".")
            self.assertEqual(result_med.returncode, 0)
            self.assertIn("High Entropy String", result_med.stdout)

            result_high = self.run_cli(tmp, "scan", "--severity", "high", ".")
            self.assertEqual(result_high.returncode, 0)

            result_crit = self.run_cli(tmp, "scan", "--severity", "critical", ".")
            self.assertEqual(result_crit.returncode, 0)

    def test_scan_severity_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text(
                "password = 'somepassword'", encoding="utf-8"
            )
            result_med = self.run_cli(tmp, "scan", "--severity", "medium", ".")
            self.assertEqual(result_med.returncode, 1)

            result_low = self.run_cli(tmp, "scan", "--severity", "low", ".")
            self.assertEqual(result_low.returncode, 1)

            result_high = self.run_cli(tmp, "scan", "--severity", "high", ".")
            self.assertEqual(result_high.returncode, 0)
            self.assertIn("Credential Assignment", result_high.stdout)

            result_crit = self.run_cli(tmp, "scan", "--severity", "critical", ".")
            self.assertEqual(result_crit.returncode, 0)

    def test_scan_severity_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text(
                f"TOKEN = '{SECRET}'", encoding="utf-8"
            )
            result_high = self.run_cli(tmp, "scan", "--severity", "high", ".")
            self.assertEqual(result_high.returncode, 1)

            result_med = self.run_cli(tmp, "scan", "--severity", "medium", ".")
            self.assertEqual(result_med.returncode, 1)

            result_crit = self.run_cli(tmp, "scan", "--severity", "critical", ".")
            self.assertEqual(result_crit.returncode, 0)
            self.assertIn("GitHub Token", result_crit.stdout)

    def test_scan_severity_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text(
                "-----BEGIN PRIVATE KEY-----", encoding="utf-8"
            )
            result_crit = self.run_cli(tmp, "scan", "--severity", "critical", ".")
            self.assertEqual(result_crit.returncode, 1)

            result_high = self.run_cli(tmp, "scan", "--severity", "high", ".")
            self.assertEqual(result_high.returncode, 1)

    def test_scan_severity_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.py").write_text(
                "password = 'somepassword'", encoding="utf-8"
            )
            config_file = Path(tmp, "secret-guard.json")
            config_content = {"severity": "high"}
            config_file.write_text(json.dumps(config_content), encoding="utf-8")

            result_config = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result_config.returncode, 0)

            result_override = self.run_cli(
                tmp, "scan", "--severity", "medium", "."
            )
            self.assertEqual(result_override.returncode, 1)

    def test_scan_severity_config_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp, "secret-guard.json")
            config_content = {"severity": "invalid-severity"}
            config_file.write_text(json.dumps(config_content), encoding="utf-8")

            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 2)
            self.assertIn("Error: 'severity' in", result.stderr)

    def test_stdin_scan_detects_secret(self):
        result = subprocess.run(
                [sys.executable, "-m", "secretguard", "scan", "--stdin"],
                input=f"TOKEN = '{SECRET}'",
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("GitHub Token", result.stdout)
        self.assertNotIn(SECRET, result.stdout)

    def test_stdin_scan_clean_input_returns_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "secretguard", "scan", "--stdin"],
            input="print('hello')\n",
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("0 total", result.stdout)

    def test_stdin_scan_reports_default_filename(self):
        result = subprocess.run(
            [sys.executable, "-m", "secretguard", "scan", "--stdin"],
            input=f"TOKEN = '{SECRET}'",
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            check=False,
        )
        self.assertIn("stdin:1", result.stdout)

    def test_stdin_scan_reports_custom_filename(self):
        result = subprocess.run(
            [
                sys.executable, "-m", "secretguard", "scan",
                "--stdin", "--filename", "config.js",
            ],
            input=f"TOKEN = '{SECRET}'",
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            check=False,
        )
        self.assertIn("config.js:1", result.stdout)

    def test_stdin_scan_json_masks_by_default(self):
        result = subprocess.run(
            [sys.executable, "-m", "secretguard", "scan", "--stdin", "--json"],
            input=f"TOKEN = '{SECRET}'",
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(SECRET, result.stdout)
        self.assertIsNotNone(json.loads(result.stdout))


class CustomRuleCliTest(unittest.TestCase):
    def run_cli(self, cwd, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        return subprocess.run(
            [sys.executable, "-m", "secretguard", *args],
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
            check=False,
        )

    def test_rules_path_relative_detects_custom_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(CUSTOM_MANIFEST, encoding="utf-8")
            Path(tmp, "app.py").write_text(
                f"api = '{CUSTOM_SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(
                tmp, "scan", "--rules-path", "rules.json", "."
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Acme Token", result.stdout)

    def test_config_embedded_rules_are_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "secret-guard.json").write_text(
                CUSTOM_MANIFEST, encoding="utf-8"
            )
            Path(tmp, "app.py").write_text(
                f"api = '{CUSTOM_SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(tmp, "scan", ".")
            self.assertEqual(result.returncode, 1)
            self.assertIn("Acme Token", result.stdout)

    def test_custom_value_masked_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(CUSTOM_MANIFEST, encoding="utf-8")
            Path(tmp, "app.py").write_text(
                f"api = '{CUSTOM_SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(
                tmp, "scan", "--json", "--rules-path", "rules.json", "."
            )
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(CUSTOM_SECRET, result.stdout)

    def test_custom_value_revealed_with_show_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(CUSTOM_MANIFEST, encoding="utf-8")
            Path(tmp, "app.py").write_text(
                f"api = '{CUSTOM_SECRET}'", encoding="utf-8"
            )
            result = self.run_cli(
                tmp, "scan", "--json", "--show-value",
                "--rules-path", "rules.json", ".",
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn(CUSTOM_SECRET, result.stdout)

    def test_list_rules_includes_custom(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(CUSTOM_MANIFEST, encoding="utf-8")
            result = self.run_cli(
                tmp, "scan", "--rules-path", "rules.json", "--list-rules"
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Custom rules:", result.stdout)
            self.assertIn("acme-token", result.stdout)

    def test_invalid_regex_fails_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(
                '{"rules": [{"name": "Bad", "pattern": "([A-Z"}]}',
                encoding="utf-8",
            )
            Path(tmp, "app.py").write_text("x = 1\n", encoding="utf-8")
            result = self.run_cli(
                tmp, "scan", "--rules-path", "rules.json", "."
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid regex", result.stderr)

    def test_unknown_severity_fails_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(
                '{"rules": [{"name": "X", "pattern": "abc", '
                '"severity": "urgent"}]}',
                encoding="utf-8",
            )
            Path(tmp, "app.py").write_text("x = 1\n", encoding="utf-8")
            result = self.run_cli(
                tmp, "scan", "--rules-path", "rules.json", "."
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid severity", result.stderr)

    def test_duplicate_name_fails_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.json").write_text(
                '{"rules": [{"name": "Dup", "pattern": "a"}, '
                '{"name": "Dup", "pattern": "b"}]}',
                encoding="utf-8",
            )
            Path(tmp, "app.py").write_text("x = 1\n", encoding="utf-8")
            result = self.run_cli(
                tmp, "scan", "--rules-path", "rules.json", "."
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate rule id", result.stderr)

    def test_missing_rules_file_fails_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("x = 1\n", encoding="utf-8")
            result = self.run_cli(
                tmp, "scan", "--rules-path", "nope.json", "."
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("not found", result.stderr)

    def test_init_scaffolds_rules_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli(tmp, "init")
            self.assertEqual(result.returncode, 0)
            data = json.loads(
                Path(tmp, "secret-guard.json").read_text(encoding="utf-8")
            )
            self.assertIn("rules", data)
            self.assertEqual(data["rules"], [])


if __name__ == "__main__":
    unittest.main()
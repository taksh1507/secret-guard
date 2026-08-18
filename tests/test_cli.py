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


if __name__ == "__main__":
    unittest.main()
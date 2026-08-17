"""Unit tests for the filesystem scanner."""

import os
import shutil
import tempfile
import unittest

from secretguard.scanner import HAS_PATHSPEC, Scanner, line_number

TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"


def has_rule(findings, rule):
    return any(f["rule"] == rule for f in findings)


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def write(self, rel, content):
        path = os.path.join(self._tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def make_scanner(self, **kwargs):
        kwargs.setdefault("root", self._tmp)
        return Scanner(**kwargs)

    def test_skip_rule_suppresses_that_rule(self):
        self.write("secret.py", f"token = {TOKEN}\naws = AKIAIOSFODNN7EXAMPLE")
        scanner = self.make_scanner(skip_rules=["github-token"])
        rules = [f["rule"] for f in scanner.scan()]
        self.assertNotIn("GitHub Token", rules)
        self.assertIn("AWS Access Key ID", rules)

    def test_only_rule_runs_only_that_rule(self):
        self.write("secret.py", f"token = {TOKEN}\naws = AKIAIOSFODNN7EXAMPLE")
        scanner = self.make_scanner(only_rules=["aws-access-key-id"])
        rules = [f["rule"] for f in scanner.scan()]
        self.assertIn("AWS Access Key ID", rules)
        self.assertNotIn("GitHub Token", rules)

    def test_only_rule_can_disable_entropy(self):
        high_entropy = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
        self.write("data.py", f"value = '{high_entropy}'")
        self.assertTrue(self.make_scanner().scan())
        scanner = self.make_scanner(only_rules=["github-token"])
        self.assertEqual(scanner.scan(), [])

    def test_skip_entropy_rule_id(self):
        high_entropy = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
        self.write("data.py", f"value = '{high_entropy}'")
        findings = self.make_scanner(skip_rules=["entropy"]).scan()
        self.assertEqual(findings, [])

    def test_skip_dotenv_rule_id(self):
        self.write(".env", "GITHUB_TOKEN=value_that_must_not_leak\n")
        findings = self.make_scanner(skip_rules=["dotenv"]).scan()
        self.assertEqual(findings, [])

    def test_only_dotenv_rule_id(self):
        self.write(".env", "GITHUB_TOKEN=value_that_must_not_leak\n")
        scanner = self.make_scanner(only_rules=["dotenv"])
        rules = [f["rule"] for f in scanner.scan()]
        self.assertIn("Environment File Secret", rules)

    def test_finds_secret_in_source_file(self):
        self.write("src/config.py", f'TOKEN = "{TOKEN}"')
        findings = self.make_scanner().scan()
        self.assertTrue(has_rule(findings, "GitHub Token"))
        self.assertIn(
            ("src/config.py", 1, "GitHub Token"),
            [(f["path"], f["line"], f["rule"]) for f in findings],
        )

    def test_reports_correct_line_number(self):
        self.write("multi.py", f"FIRST = 1\nSECOND = 2\nTOKEN = {TOKEN}")
        paths = [(f["path"], f["line"], f["rule"]) for f in self.make_scanner().scan()]
        self.assertIn(("multi.py", 3, "GitHub Token"), paths)

    def test_skips_binary_files(self):
        self.write("logo.png", TOKEN)
        self.assertEqual(self.make_scanner().scan(), [])

    def test_skips_default_excluded_dirs(self):
        self.write("node_modules/pkg/index.js", TOKEN)
        self.assertEqual(self.make_scanner().scan(), [])

    def test_skips_extra_excluded_dirs(self):
        self.write("secret-cache/key.txt", TOKEN)
        scanner = self.make_scanner(excludes=["secret-cache"])
        self.assertEqual(scanner.scan(), [])

    def test_entropy_can_be_disabled(self):
        self.write("entropy.py", "opaque = 0123456789abcdef0123456789abcdef")
        scanner = self.make_scanner(include_entropy=False)
        self.assertEqual(scanner.scan(), [])

    @unittest.skipUnless(HAS_PATHSPEC, "pathspec is not installed")
    def test_gitignore_is_respected(self):
        self.write("ignored.py", f"token = {TOKEN}")
        self.write("kept.py", f'GITHUB_TOKEN = "{TOKEN}"')
        self.write(".gitignore", "ignored.py\n")
        findings = self.make_scanner().scan()
        self.assertFalse(has_rule(findings, "Credential Assignment"))

    def test_iter_files_uses_forward_slashes(self):
        self.write("a/b/config.py", "x = 1")
        rels = [rel for _, rel in self.make_scanner().iter_files()]
        self.assertIn("a/b/config.py", rels)
        self.assertTrue(all("/" in rel for rel in rels))

    def test_is_binary_by_extension(self):
        scanner = self.make_scanner()
        self.assertTrue(scanner._is_binary("image.PNG"))
        self.assertTrue(scanner._is_binary("data.tar.gz"))
        self.assertFalse(scanner._is_binary("script.py"))
        self.assertFalse(scanner._is_binary("README.md"))

    def test_is_ignored(self):
        scanner = self.make_scanner(excludes=["vendor"])
        self.assertTrue(scanner._is_ignored("node_modules/pkg/x.js"))
        self.assertTrue(scanner._is_ignored("vendor/x.js"))
        self.assertFalse(scanner._is_ignored("src/.env"))
        self.assertFalse(scanner._is_ignored("src/main.py"))

    def test_dotenv_flags_secret_key_by_name(self):
        self.write(".env", f"GITHUB_TOKEN={TOKEN}\nPORT=8080\n")
        dotenv = [
            f for f in self.make_scanner().scan()
            if f["rule"] == "Environment File Secret"
        ]
        self.assertEqual(len(dotenv), 1)
        self.assertEqual(dotenv[0]["value"], "GITHUB_TOKEN")
        self.assertEqual(dotenv[0]["line"], 1)

    def test_dotenv_value_never_exposed(self):
        self.write(".env", f"GITHUB_TOKEN={TOKEN}\n")
        findings = self.make_scanner().scan()
        self.assertTrue(all(TOKEN not in f["value"] for f in findings))
        self.assertTrue(all(f["rule"] == "Environment File Secret" for f in findings))

    def test_line_number(self):
        self.assertEqual(line_number("", 0), 1)
        self.assertEqual(line_number("a\nb\nc", 0), 1)
        self.assertEqual(line_number("a\nb\nc", 4), 3)


if __name__ == "__main__":
    unittest.main()
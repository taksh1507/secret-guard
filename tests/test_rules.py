"""Unit tests for detection rules and entropy heuristics."""

import unittest

from secretguard.rules import (
    dotenv_secret_assignments,
    entropy_candidates,
    is_dotenv_path,
    matches_rules,
    shannon_entropy,
)


def rule_names(text):
    return [rule["name"] for rule, _ in matches_rules(text)]


def candidate_values(text):
    return [value for _, _, _, value in entropy_candidates(text)]


class ShannonEntropyTest(unittest.TestCase):
    def test_empty_string_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_distinct_char_is_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_two_distinct_chars(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0, places=6)

    def test_four_distinct_chars(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=6)


class RuleDetectionTest(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn(
            "AWS Access Key ID",
            rule_names("creds = AKIAIOSFODNN7EXAMPLE"),
        )

    def test_aws_assigned_key(self):
        findings = rule_names("aws = ASIAYXJQ5ODM3LBRYUW5V")
        self.assertIn("AWS Temporary/Assigned Key", findings)

    def test_aws_key_requires_full_length(self):
        self.assertNotIn("AWS Access Key ID", rule_names("AKIA123"))

    def test_github_token(self):
        self.assertIn(
            "GitHub Token",
            rule_names("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        )

    def test_github_fine_grained_token(self):
        findings = rule_names("auth = github_pat_1234567890abcdefghijklmnop")
        self.assertIn("GitHub Fine-grained Token", findings)
        self.assertNotIn("GitHub Token", findings)

    def test_private_key(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAunrA9sgnMZzZ\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertIn("Private Key", rule_names(text))

    def test_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nB3BlbnNzaA1rZXktdjEAAAAA\n"
        self.assertIn("Private Key", rule_names(text))

    def test_slack_token(self):
        self.assertIn(
            "Slack Token",
            rule_names("xoxb-abcdefghijklmnopqrstuvwxyz"),
        )

    def test_google_api_key(self):
        self.assertIn(
            "Google API Key",
            rule_names("key = AIza" + "A" * 35),
        )

    def test_stripe_secret_key(self):
        self.assertIn(
            "Stripe Secret Key",
            rule_names("sk-live-1234567890abcdefghijklmnopqrstuvwxyz"),
        )

    def test_generic_secret_key(self):
        self.assertIn(
            "Generic Secret Key",
            rule_names("sk-0123456789abcdef0123456789abcdef01234567"),
        )

    def test_jwt_token(self):
        text = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dzM9SGx9C9qX2OoI1m2n3o4p5Q6r7s8t9u0"
        )
        self.assertIn("JWT Token", rule_names(text))

    def test_square_access_token(self):
        self.assertIn(
            "Square Access Token",
            rule_names("sq0atp-123456789012345678901234567890"),
        )

    def test_aws_dashed_key(self):
        findings = rule_names("AKIA-ABCDEFGHIJKLMNOP")
        self.assertIn("AWS Key (dashed)", findings)
        self.assertNotIn("AWS Access Key ID", findings)

    def test_credential_assignment_password(self):
        self.assertIn(
            "Credential Assignment",
            rule_names("password = 'hunter2'"),
        )

    def test_credential_assignment_api_key(self):
        self.assertIn(
            "Credential Assignment",
            rule_names("api_key: a1b2c3d4e5f6g7h8i9"),
        )

    def test_credential_assignment_detects_second_line(self):
        text = "config = load()\nsecret: 'kjS8x2mPq7vLt4'"
        self.assertIn("Credential Assignment", rule_names(text))

    def test_credential_assignment_rejects_short_value(self):
        self.assertNotIn("Credential Assignment", rule_names("password = 'x'"))

    def test_plain_word_password_not_flagged(self):
        self.assertNotIn(
            "Credential Assignment",
            rule_names("remember your password"),
        )

    def test_auth_header_not_flagged(self):
        self.assertNotIn(
            "Credential Assignment",
            rule_names("Authorization: Bearer hellothere"),
        )


class EntropyCandidateTest(unittest.TestCase):
    _MIN_HIGH_ENTROPY_LEN = 20

    def test_high_entropy_string_detected(self):
        values = candidate_values("secret = 0123456789abcdef0123456789abcdef")
        self.assertTrue(
            any(len(v) >= self._MIN_HIGH_ENTROPY_LEN for v in values)
        )

    def test_short_string_skipped(self):
        self.assertEqual(candidate_values("abc123"), [])

    def test_low_entropy_long_string_skipped(self):
        self.assertEqual(candidate_values("a" * 40), [])


class DotenvKeyTest(unittest.TestCase):
    def test_flags_secret_key_names(self):
        text = (
            "GITHUB_TOKEN=ghp_abc\n"
            "AWS_SECRET_ACCESS_KEY=xyz\n"
            "PORT=8080\n"
        )
        keys = [key for _line, key, _value in dotenv_secret_assignments(text)]
        self.assertIn("GITHUB_TOKEN", keys)
        self.assertIn("AWS_SECRET_ACCESS_KEY", keys)
        self.assertNotIn("PORT", keys)

    def test_ignores_comments_and_blank_lines(self):
        text = "# comment\n\nAPI_KEY=123\n"
        keys = [key for _l, key, _v in dotenv_secret_assignments(text)]
        self.assertEqual(keys, ["API_KEY"])

    def test_requires_a_value(self):
        keys = [key for _l, key, _v in dotenv_secret_assignments("GITHUB_TOKEN=")]
        self.assertEqual(keys, [])

    def test_reports_line_numbers(self):
        items = list(dotenv_secret_assignments("A=1\nSLACK_TOKEN=xoxb-abc\n"))
        self.assertEqual(items[0][1], "SLACK_TOKEN")
        self.assertEqual(items[0][0], 2)

    def test_is_dotenv_path(self):
        self.assertTrue(is_dotenv_path(".env"))
        self.assertTrue(is_dotenv_path(".env.production"))
        self.assertTrue(is_dotenv_path("config/staging.env"))
        self.assertTrue(is_dotenv_path("config/app.env.development"))
        self.assertTrue(is_dotenv_path("prod.ENV"))
        self.assertFalse(is_dotenv_path("src/main.py"))
        self.assertFalse(is_dotenv_path("environment.py"))
        self.assertFalse(is_dotenv_path("docs/env.md"))


if __name__ == "__main__":
    unittest.main()
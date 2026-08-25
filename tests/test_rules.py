"""Unit tests for detection rules and entropy heuristics."""

import os
import shutil
import tempfile
import unittest

from secretguard.rules import (
    RULES,
    RuleManifestError,
    compile_custom_rules,
    dotenv_secret_assignments,
    entropy_candidates,
    is_dotenv_path,
    load_rules_file,
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

    def test_openai_api_key(self):
        self.assertIn(
            "OpenAI API Key",
            rule_names("key = sk-" + "a" * 48),
        )
        self.assertIn(
            "OpenAI API Key",
            rule_names("key = sk-proj-" + "a" * 20),
        )

    def test_anthropic_api_key(self):
        self.assertIn(
            "Anthropic API Key",
            rule_names("key = sk-ant-" + "a" * 20),
        )

    def test_discord_bot_token(self):
        self.assertIn(
            "Discord Bot Token",
            rule_names(
                "token = 123456789012345678901234."
                "123456.123456789012345678901234567890"
            ),
        )

    def test_npm_token(self):
        self.assertIn(
            "npm Token",
            rule_names("token = npm_" + "a" * 36),
        )

    def test_sendgrid_api_key(self):
        self.assertIn(
            "SendGrid API Key",
            rule_names("key = SG." + "a" * 22 + "." + "b" * 43),
        )

    def test_twilio_api_key(self):
        self.assertIn(
            "Twilio API Key",
            rule_names("api_key = SK" + "a" * 32),
        )

    def test_heroku_api_key(self):
        self.assertIn(
            "Heroku API Key",
            rule_names("heroku_api_key = '00000000-0000-0000-0000-000000000000'"),
        )
        self.assertIn(
            "Heroku API Key",
            rule_names("heroku publish token 00000000-0000-0000-0000-000000000000"),
        )

    def test_digitalocean_token(self):
        self.assertIn(
            "DigitalOcean Token",
            rule_names("token = dop_v1_" + "a" * 64),
        )
        self.assertIn(
            "DigitalOcean Token",
            rule_names("token = doo_v1_" + "a" * 64),
        )

    def test_hubspot_access_token(self):
        self.assertIn(
            "HubSpot Access Token",
            rule_names("token = pat-na1-" + "a" * 32),
        )
        self.assertIn(
            "HubSpot Access Token",
            rule_names("token = pat-eu1-" + "a" * 32),
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

    def test_is_dotenv_path_excludes_committed_templates(self):
        templates = [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.local.example",
            "config/.env.production.example",
            "prod.ENV.example",
        ]
        for path in templates:
            self.assertFalse(
                is_dotenv_path(path), f"{path!r} should not be treated as a dotenv file"
            )

class DotenvValueParsingTest(unittest.TestCase):
    def test_export_prefix_is_detected(self):
        text = "export GITHUB_TOKEN=ghp_abc123\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][1], "GITHUB_TOKEN")
        self.assertEqual(items[0][2], "ghp_abc123")

    def test_double_quoted_value_with_equals_and_spaces(self):
        text = 'API_KEY="quoted with = and spaces"\n'
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][2], "quoted with = and spaces")

    def test_single_quoted_value(self):
        text = "API_KEY='single quoted test value'\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "single quoted test value")

    def test_escaped_quote_inside_quoted_value(self):
        text = r'API_KEY="value with \"escaped\" quote"' + "\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], 'value with "escaped" quote')

    def test_trailing_comment_on_unquoted_value_is_stripped(self):
        text = "API_KEY=abc123 # note about this key\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "abc123")

    def test_trailing_comment_on_quoted_value_is_stripped(self):
        text = 'API_KEY="abc123" # note\n'
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "abc123")

    def test_hash_inside_unquoted_value_without_preceding_space_is_kept(self):
        # Classic false-positive trap: a value containing '#' with no
        # space before it is part of the value, not a comment.
        text = "DB_TOKEN=tok#uvw123\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "tok#uvw123")

    def test_equals_inside_unquoted_value_is_kept(self):
        text = "DB_TOKEN=abc=def\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "abc=def")
        
    def test_interpolated_variable_is_detected_and_not_resolved(self):
        text = "API_KEY=${OTHER_SECRET}\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][2], "${OTHER_SECRET}")

    def test_dollar_variable_without_braces_is_detected(self):
        text = "API_KEY=$OTHER_SECRET\n"
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items[0][2], "$OTHER_SECRET")

    def test_empty_quoted_value_is_not_flagged(self):
        text = 'API_KEY=""\n'
        items = list(dotenv_secret_assignments(text))
        self.assertEqual(items, [])

    def test_non_dotenv_file_behavior_is_unaffected(self):
        # Sanity check: is_dotenv_path still gates which files get parsed
        # this way; parsing logic itself doesn't care about the filename.
        self.assertFalse(is_dotenv_path("config.py"))


class CustomRuleCompileTest(unittest.TestCase):
    def _compile_one(self, **overrides):
        rule = {
            "name": "My API Token",
            "pattern": "mytok_[A-Za-z0-9]{20,}",
            "severity": "high",
            "description": "Acme platform token",
        }
        rule.update(overrides)
        return compile_custom_rules([rule])

    def test_happy_path_compiles_rule(self):
        rules = self._compile_one()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "my-api-token")
        self.assertEqual(rules[0]["severity"], "high")
        self.assertEqual(rules[0]["description"], "Acme platform token")
        self.assertTrue(rules[0]["custom"])

    def test_compiled_rule_detects_via_matches_rules(self):
        rules = self._compile_one()
        names = [
            rule["name"]
            for rule, _ in matches_rules(
                "k = mytok_abcdefghij0123456789", rules=RULES + rules
            )
        ]
        self.assertIn("My API Token", names)

    def test_severity_defaults_to_medium(self):
        rules = compile_custom_rules([{"name": "X", "pattern": "abc"}])
        self.assertEqual(rules[0]["severity"], "medium")

    def test_invalid_regex_raises(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules([{"name": "Bad", "pattern": "([A-Z"}])

    def test_unknown_severity_raises(self):
        with self.assertRaises(RuleManifestError):
            self._compile_one(severity="urgent")

    def test_duplicate_name_raises(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules(
                [{"name": "Dup", "pattern": "a"}, {"name": "Dup", "pattern": "b"}]
            )

    def test_collision_with_builtin_id_raises(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules([{"name": "GitHub Token", "pattern": "a"}])

    def test_missing_pattern_raises(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules([{"name": "NoPattern"}])

    def test_missing_name_raises(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules([{"pattern": "abc"}])

    def test_rules_must_be_a_list(self):
        with self.assertRaises(RuleManifestError):
            compile_custom_rules({"name": "X", "pattern": "abc"})


class LoadRulesFileTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def _write(self, content):
        path = os.path.join(self._tmp, "rules.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_loads_valid_manifest(self):
        path = self._write(
            '{"rules": [{"name": "Tok", "pattern": "tok_[0-9]{4}"}]}'
        )
        rules = load_rules_file(path)
        self.assertEqual(rules[0]["id"], "tok")

    def test_missing_file_raises(self):
        with self.assertRaises(RuleManifestError):
            load_rules_file(os.path.join(self._tmp, "nope.json"))

    def test_malformed_json_raises(self):
        path = self._write('{"rules": [')
        with self.assertRaises(RuleManifestError):
            load_rules_file(path)

    def test_missing_rules_key_raises(self):
        path = self._write('{"other": []}')
        with self.assertRaises(RuleManifestError):
            load_rules_file(path)


if __name__ == "__main__":
    unittest.main()
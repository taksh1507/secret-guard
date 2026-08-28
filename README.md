<div align="center">

# secret-guard

**Zero-dependency secret scanning for Python, CI/CD, and pre-commit hooks.**

Detect hardcoded credentials - AWS keys, GitHub and Slack tokens, private keys,
and dozens of other secrets - before they reach your repository history.

[![CI](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml)
[![secret-guard scan](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml)
[![codecov](https://codecov.io/gh/taksh1507/secret-guard/branch/main/graph/badge.svg)](https://codecov.io/gh/taksh1507/secret-guard)
[![PyPI - Version](https://img.shields.io/pypi/v/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![PyPI - Python Versions](https://img.shields.io/pypi/pyversions/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Overview

secret-guard scans source files for hardcoded credentials using **30 regex
rules** combined with **Shannon-entropy detection**, and reports each finding
with a severity level and a **masked** value. By default, secret values are
never printed.

| Category | Detection rules |
| --- | --- |
| Cloud / SaaS | AWS Access Key IDs, AWS temporary/assigned keys, AWS dashed keys, Google API Keys, Stripe secret keys, SendGrid and Twilio API keys |
| Tokens | GitHub PATs (classic and fine-grained), Slack tokens and webhooks, OpenAI, Anthropic, Discord, Square, HubSpot, GitLab, Hugging Face, npm, PyPI, DigitalOcean tokens |
| Databases | PostgreSQL and MongoDB connection URIs with embedded credentials |
| Key material | RSA / EC / DSA / OpenSSH / PGP private keys (`critical` severity) |
| Heuristics | Generic secret keys, credential assignments, JWT tokens, high-entropy strings |

In addition to pattern matching, secret-guard identifies **`.env` files** that
assign values to secret-looking variable names (`.env`, `.env.local`,
`prod.env`, and similar). It reports the key name and severity but never the
value.

## Features

- **Zero runtime dependencies** - pure Python, no network calls, no build step.
- **Masked by default** - secret values are redacted in both console and JSON
  output; `--show-value` is an explicit opt-in for recovery and rotation work.
- **Git-aware staged scanning** (`--staged`) - reads the git index blob rather
  than the working tree, so secrets that are staged but already deleted from
  disk are still detected.
- **gitignore-aware** - skips `.git`, `node_modules`, `venv`, and anything your
  `.gitignore` already covers; repeatable `--exclude` handles the rest.
- **Entropy detection** - flags high-entropy strings even when no rule matches.
- **Configurable** - command-line flags, a checked-in `secret-guard.json`
  config, custom rule manifests, baselines, and severity thresholds.
- **Fast, single-file deployment** - works in CI with a single `pip install`.

## Why secret-guard?

There are many secret scanners. The following table compares secret-guard with
several popular alternatives.

| Capability | secret-guard | gitleaks | truffleHog | ggshield |
| --- | :---: | :---: | :---: | :---: |
| Zero runtime dependencies | Yes | No (Go binary) | No (Python deps) | No |
| Runs in CI with one `pip install` | Yes | No (download binary) | No | No |
| Regex + Shannon-entropy detection | Yes | Partial | Yes | Partial |
| Values masked by default | Yes | Yes | Yes | Yes |
| Staged git-index scanning | Yes | Partial | No | Yes |
| `.env` files flagged by key name | Yes | No | No | No |
| Native pre-commit hook install | Yes | Yes | No | Yes |
| Rule-level controls (`--skip-rule`) | Yes | Yes | No | No |
| Python 3.8+, no build step | Yes | No | Partial | Partial |

What distinguishes secret-guard:

1. **Zero dependencies and a zero build step** - a single
   `pip install secret-guard-scan` is all that is required, in CI or on a
   laptop. No Go toolchain, no Docker image, and no dependency tree to audit.
2. **Values are masked by default** - including in `.env` files, where the key
   name is reported but the value is never printed, even with `--show-value`.
3. **Git-index-aware staged scanning** - the `--staged` flag scans the staged
   blob (`git show :<path>`), so a secret that was staged and then deleted from
   the working tree is still caught.
4. **Explicit rule-level controls** - `--skip-rule` and `--only-rule` scope a
   scan to exactly the rules that matter, and unknown rule identifiers fail the
   scan instead of being silently ignored.

For teams that already run gitleaks in CI, secret-guard is a natural
complement: a zero-install first line of defense in pre-commit hooks and in any
`pip install`-only CI job.

## Installation

```bash
pip install secret-guard-scan
```

The command-line tool is `secret-guard`. The package can also be run directly
(Python 3.8+) without installation:

```bash
python -m secretguard
```

## Quick start

```bash
# Scan the current directory
secret-guard scan

# Scan a specific path
secret-guard scan ./src

# JSON output for CI and tooling
secret-guard scan --json

# Read content from stdin
cat config.py | secret-guard scan --stdin --filename config.py

# Scan only files staged for commit (reads the git index)
secret-guard scan --staged

# Enforce a severity threshold before failing the scan
secret-guard scan . --severity high

# Guard every future commit with a git pre-commit hook
secret-guard install-hook

# Initialize a starter configuration file
secret-guard init
```

### Example output

```text
config.py:12 [HIGH    ] GitHub Token: ghp_**************
.env:4        [CRITICAL] Private Key: -----BEGIN [REDACTED]-----
app.py:40     [MEDIUM  ] Credential Assignment: password = 'hunter 2'

1 critical, 1 high, 1 medium, 0 low - 3 total
```

Values are masked by default. Use `--show-value` only when the full string is
genuinely required - for example, to rotate a key that was just found.

## GitHub Action

The fastest way to add secret scanning to CI, with no Docker or Python setup:

```yaml
- uses: taksh1507/secret-guard@v1
```

A detected leak fails the job. The scanner and its Python runtime are installed
by the action itself.

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | File or directory to scan |
| `exclude` | *(empty)* | Directory names to skip, one per line |
| `json` | `false` | Emit findings as JSON (values still masked) |
| `no-entropy` | `false` | Disable high-entropy string detection |

Add it to an existing workflow:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: taksh1507/secret-guard@v1
    with:
      path: .
      json: true
      exclude: |
        tests
        .venv
```

## Docker

Run secret-guard in a container without installing Python:

```bash
docker run --rm -v "${PWD}:/code" ghcr.io/taksh1507/secret-guard:latest scan /code
```

The image runs as a non-root user by default. Mount your project directory to
`/code` and pass any normal `secret-guard scan` flags after the path:

```bash
docker run --rm -v "${PWD}:/code" ghcr.io/taksh1507/secret-guard:latest scan /code --no-entropy
```

## Usage

```
secret-guard scan [path] [options]

positional arguments:
  path                Path to scan (default: .)

options:
  --exclude DIR       Additional directory names to skip (repeatable)
  --no-entropy        Disable high-entropy string detection
  --json              Output findings as JSON
  --show-value        Print full secret values (default masks them)
  --no-color          Disable colored console output
  --staged            Scan only files staged in git
  --baseline FILE     Suppress findings listed in a baseline file
  --severity LEVEL    Minimum severity to fail the scan (low, medium, high, critical)
  --max-findings N    Cap the number of findings printed to N; the scan still
                      reports the full summary and exits non-zero when secrets
                      are found
  --skip-rule RULE    Never run the given rule id (repeatable)
  --only-rule RULE    Run only the given rule id (repeatable)
  --rules-path FILE   Add custom rules from a JSON manifest
  --list-rules        List every available rule id and exit
  --stdin             Read content to scan from stdin
  --filename NAME     Reported path for --stdin input (default: stdin)
```

### Taming false positives

Rule-based scanners are only useful when reviewers trust them. Use
`--skip-rule` and `--only-rule` to scope a scan to the rules that matter:

```bash
# Ignore a noisy rule entirely
secret-guard scan . --skip-rule generic-secret-key

# Enforce only the secrets that matter on a given path
secret-guard scan ./infra --only-rule aws-access-key-id --only-rule github-token

# See every rule id a scan can run
secret-guard scan --list-rules
```

Passing an unknown rule id fails the scan with exit code `2`, so a typo in
`--skip-rule` can never silently disable detection.

### Configuration file (`secret-guard.json`)

Prefer a checked-in configuration over repeating flags in CI. secret-guard
discovers `secret-guard.json` in the scanned directory or any parent directory:

```json
{
  "exclude": ["tests", ".venv"],
  "no_entropy": false,
  "skip_rules": ["generic-secret-key"],
  "only_rules": [],
  "rules": [],
  "baseline": [],
  "severity": "low"
}
```

Command-line flags override configuration values. Scaffold a starter file with:

```bash
secret-guard init
```

### Custom rule manifests

Teams can register their own regex detections without forking the project. A
manifest is a JSON object with a `rules` array; each rule requires a `name` and
a `pattern`, with optional `severity` (`low`/`medium`/`high`/`critical`,
default `medium`) and `description`:

```json
{
  "rules": [
    {
      "name": "Acme API Token",
      "pattern": "acme_tok_[a-f0-9]{20,}",
      "severity": "high",
      "description": "Acme platform API token."
    }
  ]
}
```

Point a scan at a manifest with `--rules-path`, or commit rules under the
`rules` key of `secret-guard.json` (discovered automatically). Custom rules flow
through the same pipeline as built-ins: they respect
`--skip-rule`/`--only-rule` (by their slugified id, for example
`acme-api-token`), honor severity thresholds, and mask matched values by
default. A ready-to-copy manifest lives in
[`examples/rules.json`](examples/rules.json).

Manifests fail fast rather than silently: a duplicate rule name, an unreadable
regex, an invalid severity, or a missing or malformed file exits with code `2`
and an actionable message, so a broken manifest can never quietly disable
detection.

### Baselines / allowlists

A baseline acknowledges known, intentional findings so CI stays green while new
leaks still fail. A baseline file is a JSON document:

```json
{
  "baseline": [
    { "path": "config/rules.json", "rule_id": "generic-secret-key" }
  ]
}
```

A `path` and `rule_id` pair suppresses all matching findings; an optional
`hash` (SHA-256 of the secret value) suppresses only that exact value. Load it
with `--baseline baseline.json` or through the `baseline` key of
`secret-guard.json`. Scanned values are hashed client-side, so the baseline
never needs to contain the secret itself.

### Severity and exit codes

- `0` - no secrets found, or all findings are below the `--severity` threshold
  (or `--help`/`--version` was used).
- `1` - at least one secret meeting or exceeding the `--severity` threshold was
  detected (or a runtime error occurred).
- `2` - CLI invocation error or configuration validation failure.

#### Severity levels

The scanner assigns a severity to every finding:

- `critical` - private cryptographic keys.
- `high` - cloud API keys, SaaS tokens, OAuth tokens, and `.env` file credentials.
- `medium` - variable assignments named like credentials, and generic secret keys.
- `low` - high-entropy string detections.

By default the severity threshold is `low`, so any finding fails the scan (exit
code 1). To fail only on high or critical findings:

```bash
secret-guard scan . --severity high
```

Or set it in `secret-guard.json`:

```json
{
  "severity": "high"
}
```

### Scanning staged changes

```bash
secret-guard scan --staged
```

This reads each staged file directly from the git index (`git show :<path>`).
When a secret is added, staged, and then deleted from the working tree, a
working-tree-only scan would miss it; the staged version caught by secret-guard
is exactly what would otherwise be committed.

## Local development

```bash
python -m unittest discover -s tests
python -m ruff check secretguard tests
python -m secretguard scan . --exclude tests --no-entropy
```

The repository enforces these in CI (tests on Python 3.9 / 3.11 / 3.13, linting,
and a self-scan job) and runs GitGuardian on every pull request.

## Contributing

Contributions of any size are welcome - new detection rules, false-positive
reports, documentation, and editor integrations. Start with
[CONTRIBUTING](CONTRIBUTING.md), review the [Contributors](CONTRIBUTORS.md)
list, and read the [Code of Conduct](CODE_OF_CONDUCT.md). Please report security
issues according to the [Security Policy](SECURITY.md).

## Roadmap

- [x] Pattern-based detection (cloud keys, tokens, private keys)
- [x] Entropy-based heuristics
- [x] `.env` support (`.env`, `.env.*`, `*.env`, `*.env.*`)
- [x] Masked output by default
- [x] Git-index-aware staged scanning
- [x] Git hook and pre-commit integration
- [x] Custom rule manifests
- [x] Baseline / allowlist support
- [x] Severity thresholds
- [x] OIDC trusted publishing to PyPI
- [ ] Git history scanning
- [ ] SARIF output for GitHub code scanning

## License

[MIT](LICENSE)

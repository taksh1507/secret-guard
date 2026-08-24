<div align="center">

# secret-guard

**A zero-dependency secret scanner for Python, CI, and pre-commit hooks.**

Detect AWS keys, GitHub tokens, private keys, and hundreds of other secrets
before they reach your git history.

[![CI](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml)
[![secret-guard scan](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml)
[![codecov](https://codecov.io/gh/taksh1507/secret-guard/branch/main/graph/badge.svg)](https://codecov.io/gh/taksh1507/secret-guard)
[![PyPI - Version](https://img.shields.io/pypi/v/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![PyPI - Python Versions](https://img.shields.io/pypi/pyversions/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## What it does

secret-guard scans source files for hardcoded credentials using **13 pattern
rules** plus **Shannon-entropy detection**, and reports each finding with a
severity and a **masked** value. By default it never prints the secret itself.

| Category | Rules |
| --- | --- |
| Cloud / SaaS | AWS Access Key IDs, AWS temporary & dashed keys, Google API Keys, Stripe live keys |
| Tokens | GitHub PAT (classic & fine-grained), Slack tokens, Square access tokens, JWTs |
| Key material | RSA / EC / DSA / OpenSSH / PGP private keys (`CRITICAL`) |
| Heuristics | Generic secret keys, credential assignments, high-entropy strings |

On top of pattern matching, `secret-guard` catches **`.env` files** with
secret-looking variable names (`.env`, `.env.local`, `prod.env`, …). It reports
the *key name* and severity but never the value.

## Features

- **Zero runtime dependencies** — pure Python, no network calls.
- **Masked by default** — secret values are redacted in console and JSON output;
  `--show-value` is an explicit opt-in for recovery/rotation work.
- **Git-aware `--staged`**: scans the git *index blob*, not the working tree, so
  it catches secrets that are staged but already deleted from disk.
- **gitignore-aware**: skips `.git`, `node_modules`, `venv`, and whatever your
  `.gitignore` already covers; repeatable `--exclude` for anything else.
- **Entropy detection**: flags high-entropy strings even when no rule matches.
- **Fast, single-file install**: works in CI in one line.

## Why secret-guard?

There are plenty of secret scanners. Here is where secret-guard sits among the
popular ones:

| | secret-guard | gitleaks | truffleHog | ggshield |
| --- | :---: | :---: | :---: | :---: |
| Zero runtime dependencies | ✅ | ❌ (Go binary) | ❌ (Python deps) | ❌ |
| Runs in CI with one `pip install` | ✅ | ❌ (download binary) | ❌ | ❌ |
| Regex + Shannon-entropy detection | ✅ | ⚠️ entropy via config | ✅ | ⚠️ |
| Values masked by default | ✅ | ✅ | ✅ | ✅ |
| `--staged` git-index scanning | ✅ | ⚠️ staged via git diff | ❌ | ✅ |
| `.env` files flagged by key name | ✅ | ❌ | ❌ | ❌ |
| Native pre-commit hook install | ✅ | ✅ | ❌ | ✅ |
| Rule-level controls (`--skip-rule`) | ✅ | ✅ | ✅ | ✅ |
| Works on Python ≥ 3.8 with no build step | ✅ | ❌ | ⚠️ | ⚠️ |

**What makes secret-guard different:**

1. **Zero dependencies, zero build step** — a single `pip install
   secret-guard-scan` is all it takes, in CI or on a laptop. No Go toolchain,
   no Docker image, no giant dependency tree to audit.
2. **Values are masked by default** — including in `.env` files, where the
   *key name* is reported but the value is never printed, even with
   `--show-value`.
3. **Git-index-aware `--staged`** — scans the staged *blob* (`git show :<path>`),
   so a secret staged and then deleted from the worktree is still caught.
4. **True false-positive controls** — `--skip-rule` and `--only-rule` scope a
   scan to exactly the rules you care about, and unknown rule ids fail the
   scan instead of being silently ignored.

For teams that already run gitleaks in CI, secret-guard is a natural
complement: a zero-install first line of defense in every pre-commit hook and
every `pip install`-only CI job.

## Install

```bash
pip install secret-guard-scan
```

The CLI is `secret-guard`. You can also run the repo without installing
(Python ≥ 3.8):

```bash
python -m secretguard
```

## GitHub Action

The fastest way to add secret scanning to CI, no Docker or Python setup
needed:

```yaml
- uses: taksh1507/secret-guard@v1
```

A leak fails the job. The scanner (and its Python runtime) are installed by
the action itself.

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

### Reusable CI workflow

Wrap the action in a reusable workflow your repos can call:

```yaml
# .github/workflows/secret-scan.yml — call from any repo
on:
  workflow_call:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: taksh1507/secret-guard@v1
```

```yaml
# Consumer: .github/workflows/ci.yml
jobs:
  security:
    uses: taksh1507/secret-guard/.github/workflows/secret-scan.yml@main
```

## Docker

Run secret-guard in a container — no Python install required:

```bash
docker run --rm -v "${PWD}:/code" ghcr.io/taksh1507/secret-guard:latest scan /code
```

The image runs as a non-root user by default. Mount your project directory to `/code` and pass any normal `secret-guard scan` flags after the path, for example:

```bash
docker run --rm -v "${PWD}:/code" ghcr.io/taksh1507/secret-guard:latest scan /code --no-entropy
```

## Quick start

```bash
# Scan the current directory
secret-guard scan

# Scan a specific path
secret-guard scan ./src

# JSON output for CI / tooling
secret-guard scan --json

# Only files staged for commit (reads the git index)
secret-guard scan --staged

# Guard every future commit with a git pre-commit hook
secret-guard install-hook
```

## Example output

```
config.py:12 [HIGH    ] GitHub Token: ghp_**************
.env:4    [CRITICAL] Private Key: -----BEGIN [REDACTED]-----
app.py:40 [MEDIUM  ] Credential Assignment: password = 'hunter 2'

1 critical, 1 high, 1 medium, 0 low — 3 total
```

Values are masked by default. Use `--show-value` only when you actually need the
full string — for example, to rotate the key you just found.

## Usage

```
secret-guard scan [path] [options]

positional arguments:
  path              Path to scan (default: .)

options:
  --exclude DIR     Skip additional directory names (repeatable)
  --no-entropy      Disable high-entropy string detection
  --json            Output findings as JSON
  --show-value      Print full secret values (default masks them)
  --staged          Scan only files staged in git
  --skip-rule RULE  Never run the given rule id (repeatable)
  --only-rule RULE  Run only the given rule id (repeatable)
  --list-rules      List every available rule id and exit
  --baseline FILE   Suppress findings listed in a baseline file
  --severity LEVEL  Minimum severity threshold to fail the scan (low, medium, high, critical) (default: low)
```

### Taming false positives

Rule-based scanners are only useful when reviewers trust them. Use
`--skip-rule` and `--only-rule` to scope a scan to exactly the rules you
care about:

```bash
# Ignore a noisy rule entirely (e.g. GENERIC_SECRET_KEY on a test repo)
secret-guard scan . --skip-rule generic-secret-key

# Enforce only secrets that matter on a given path
secret-guard scan ./infra --only-rule aws-access-key-id --only-rule github-token

# See every rule id a scan can run
secret-guard scan --list-rules
```

Passing an unknown rule id fails the scan with exit code `2` — so a
typo'd `--skip-rule` can never silently disable detection.

### Configuration file (`secret-guard.json`)

Prefer a checked-in config over repeating flags in CI. `secret-guard`
discovers `secret-guard.json` in the scanned directory or any parent:

```json
{
  "exclude": ["tests", ".venv"],
  "no_entropy": false,
  "skip_rules": ["generic-secret-key"],
  "only_rules": [],
  "baseline": [],
  "severity": "low"
}
```

Command-line flags override config values. Scaffold a starter file with:

```bash
secret-guard init
```

### Baselines / allowlist

A baseline lets you acknowledge known, intentional findings so CI stays
green while new leaks still fail. A baseline file is a JSON document:

```json
{
  "baseline": [
    {"path": "config/rules.json", "rule_id": "generic-secret-key"}
  ]
}
```

`path` + `rule_id` suppress all matching findings; an optional `hash`
(sha256 of the secret value) suppresses only that exact value. Load it with
`--baseline baseline.json` or from the `baseline` key of `secret-guard.json`.
Scanned values are hashed client-side, so the baseline never needs to
contain the secret itself.

### Exit codes and Severity Thresholds

- `0` — no secrets found, or all found secrets are below the `--severity` threshold (or `--help`/`--version` was used)
- `1` — at least one secret matching or exceeding the `--severity` threshold was detected (or a runtime error occurred)
- `2` — CLI invocation error or configuration validation failure

#### Severity Levels

The scanner assigns a severity to every finding:
- `critical`: Private cryptographic keys
- `high`: Cloud API keys, SaaS tokens, OAuth tokens, and `.env` file credentials
- `medium`: Variable assignments named like credentials or generic secret keys
- `low`: High-entropy string detections

By default, the severity threshold is `low`, meaning *any* finding fails the scan (exit code 1).

To only fail the scan on high or critical findings (preventing low-entropy strings or credential variable assignments from breaking CI):

```bash
secret-guard scan . --severity high
```

Or set it in your `secret-guard.json` config:

```json
{
  "severity": "high"
}
```

Use this in CI — the job fails the moment a secret shows up:

```yaml
- name: Scan for secrets
  run: |
    pip install secret-guard-scan
    secret-guard scan . \
      --json \
      --exclude tests \
      --exclude .venv
```

## Staged scanning

```bash
secret-guard scan --staged
```

reads each staged file directly from the git index (`git show :<path>`). This
matters when a secret was added, staged, and then deleted from the working tree:
a worktree-only scan would miss it, but the staged version caught by
secret-guard is exactly what would otherwise be committed.

## Local development

```bash
python -m unittest discover -s tests
python -m ruff check secretguard tests
python -m secretguard scan . --exclude tests --no-entropy
```

The repository enforces these in CI (tests on Python 3.9 / 3.11 / 3.13, lint,
and a self-scan job) and runs GitGuardian on every pull request.

## Contributing

Contributions of any size are welcome — new detection rules, false-positive
reports, docs, editor integrations. Start with [CONTRIBUTING](CONTRIBUTING.md).
See our [Contributors](CONTRIBUTORS.md) list for everyone who has helped.
Please read our [Code of Conduct](CODE_OF_CONDUCT.md) and report security
issues per our [Security Policy](SECURITY.md).

## Roadmap

- [x] Rule-based detection (cloud keys, tokens, private keys)
- [x] Entropy-based heuristics
- [x] `.env` support (`.env`, `.env.*`, `*.env`, `*.env.*`)
- [x] Masked output by default
- [x] Git-index-aware `--staged` scanning
- [x] git hook + pre-commit integration
- [x] OIDC trusted publishing to PyPI
- [ ] Git history scanning
- [ ] Baseline / allowlist support
- [ ] SARIF output for GitHub code scanning
- [ ] Custom rule manifests

## License

[MIT](LICENSE)
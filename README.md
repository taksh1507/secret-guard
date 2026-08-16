<div align="center">

# secret-guard

**A zero-dependency secret scanner for Python, CI, and pre-commit hooks.**

Detect AWS keys, GitHub tokens, private keys, and hundreds of other secrets
before they reach your git history.

[![CI](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml)
[![secret-guard scan](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml)
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

## Install

```bash
pip install secret-guard-scan
```

The CLI is `secret-guard`. You can also run the repo without installing
(Python ≥ 3.8):

```bash
python -m secretguard
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
```

### Exit codes

- `0` — no secrets found, or `--help`/`--version`
- `1` — at least one secret detected (or an error occurred)

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
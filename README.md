<div align="center">

# 🛡️ secret-guard

**Scan your codebase for leaked secrets before they ever reach your git history.**

Zero-dependency · Fast · CI-ready · Git-hook ready

[![CI](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/ci.yml)
[![secret-guard scan](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml/badge.svg)](https://github.com/taksh1507/secret-guard/actions/workflows/scan.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![PyPI - Python](https://img.shields.io/pypi/pyversions/secret-guard-scan)](https://pypi.org/project/secret-guard-scan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Why secret-guard?

Hardcoding secrets is the single most common — and most dangerous — mistake
developers make. A leaked `AWS key`, `GitHub token`, or `private key` can cost
you money, trust, and hours of damage control. **secret-guard** catches them in
seconds, right on your own machine or in CI, before the secret goes public.

- 🔒 **20+ detection rules**: AWS keys, GitHub tokens, Stripe, Slack, Google
  API keys, JWTs, private keys, credential assignments, and more.
- 🧠 **Entropy detection**: flags high-entropy strings even when no pattern
  matches.
- 📁 **gitignore-aware**: automatically skips `node_modules`, `.git`, `venv`,
  and whatever your `.gitignore` already covers.
- 🚀 **Zero dependencies** for core scanning. Just `pip install` and go.
- ⚡ **Fast**: written in pure Python, no external services.
- 🪝 **Git-hook guard**: one command protects every future commit.

## Install

```bash
pip install secret-guard-scan
```

Or run without installing (Python ≥ 3.8):

```bash
python -m secretguard
```

## Quick start

```bash
# Scan the current directory
secret-guard scan

# Scan a specific path, show exactly what was found
secret-guard scan ./src

# Machine-readable output for CI / other tools
secret-guard scan --json

# Protect every future commit
cd your-repo
secret-guard install-hook
```

## Example output

```
config.py:12 [HIGH    ] GitHub Token: ghp_**************
.env:4    [CRITICAL] Private Key: -----BEGIN [REDACTED]-----
app.py:40 [MEDIUM  ] Credential Assignment: password = 'hunter 2'

1 critical, 1 high, 1 medium, 0 low — 3 total
```

Secret values are **masked by default** in both the console report and the
`--json` output. Use `--show-value` only when you need the full value (e.g. to
rotate the key you just found).

## Usage

```
$ secret-guard scan [path] [options]

Options:
  --exclude DIR     Skip additional directory names (repeatable)
  --no-entropy      Disable high-entropy string detection
  --json            Output findings as JSON
  --show-value      Print full secret values (default: masked)
  --staged          Scan only files staged for commit
```

### Exit codes

- `0` — no secrets found (or help/version)
- `1` — at least one secret detected

Use this in CI:

```yaml
- run: pip install secret-guard-scan
- run: secret-guard scan .
```

## Why this project matters

Every week, thousands of secrets leak into public repos. Tools like this one
turn "oops, I pushed my key" from a weekly occurrence into a rare event. By
using and contributing to **secret-guard**, you actively make the ecosystem
safer.

## Star the repo ⭐

If secret-guard helps you, starring the repo is the fastest way to help other
developers find it. It's free, takes one click, and keeps the project alive.

## Contributing

We welcome contributions of any size, including new detection rules, editor
integrations, and docs. See [CONTRIBUTING](CONTRIBUTING.md) to get started.
Please also read our [Code of Conduct](CODE_OF_CONDUCT.md) and
[Security Policy](SECURITY.md).

### Development

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [x] Pre-commit framework integration (`pre-commit-hooks.yaml`, `.pre-commit-config.yaml`)
- [x] Editor/CI extensions (GitHub Actions for tests, lint, and secret scan)
- [ ] SARIF output for GitHub code scanning
- [ ] More languages & custom-rule manifests
- [ ] Baseline / allowlist support

## License

[MIT](LICENSE)
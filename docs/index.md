# secret-guard

**Open-source secret scanner for Python, CI, and pre-commit hooks.**

Detect leaked API keys, AWS keys, GitHub tokens, Slack tokens, passwords, JWTs,
and private keys **before** they reach your git history.

- Zero runtime dependencies
- 13 detection rules + Shannon-entropy heuristics
- `.env` support (.env, .env.*, *.env, *.env.*) and committed template files
  (.env.example) are skipped by design
- Git-index-aware `--staged` scanning
- Secret values are **masked by default** in console and JSON output
- One-line install: `pip install secret-guard-scan`

## How it works

`secret-guard` walks a directory (respecting `.gitignore`), runs every rule
against each file, and reports findings with a severity and a **masked** value.
It never sends anything to a network — everything runs locally, in pure Python.

## Quick start

```bash
pip install secret-guard-scan
secret-guard scan .          # scan the current directory
secret-guard scan --json     # JSON output for CI
secret-guard scan --staged   # scan only files staged in git
secret-guard install-hook    # protect every future commit
```

## Why secret-guard?

- **No external services, no Docker, no config file** — one pip package.
- **Masked by default** — a scanner that prints your API key is part of the
  problem. `--show-value` is an explicit opt-in.
- **Catches staged-and-deleted secrets** by reading the git index blob, not the
  working tree.
- **False-positive friendly** — committed `.env.example` templates are ignored;
  entropy findings are reported as `low` severity by default.

## Resources

- [Getting Started](usage.md)
- [CLI Reference](cli.md)
- [Detection Rules](rules.md)
- [CI Integration](ci.md)
- [Contributing](contributing.md)
- [FAQ](faq.md)

## License

[MIT](https://github.com/taksh1507/secret-guard/blob/main/LICENSE)
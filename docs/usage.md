# Getting Started

## Installation

```bash
pip install secret-guard-scan
```

The CLI is `secret-guard`. You can also run the repository directly without
installing (Python >= 3.8):

```bash
python -m secretguard
```

## First scan

```bash
cd your-repo
secret-guard scan
```

This scans the current directory, skips gitignored paths, and prints any
findings with severity and a masked value:

```
config.py:12 [HIGH    ] GitHub Token: ghp_**************
.env:4    [CRITICAL] Private Key: -----BEGIN [REDACTED]-----
app.py:40 [MEDIUM  ] Credential Assignment: password = 'hunter 2'

1 critical, 1 high, 1 medium, 0 low — 3 total
```

## Skipping heavy or generated directories

Large folders such as `node_modules`, `.venv`, build caches, and ML artifacts
should be excluded to keep scans fast:

```bash
secret-guard scan . \
  --exclude node_modules \
  --exclude data \
  --exclude models \
  --exclude reports \
  --exclude .next \
  --exclude __pycache__
```

`node_modules`, `venv`, `dist`, `build`, `__pycache__` and similar are skipped
by default.

## Example output in JSON

```bash
secret-guard scan . --json
```

Values are masked in JSON too unless `--show-value` is passed.

## Exit codes

- `0` — no secrets found
- `1` — at least one secret detected

Use the exit code to gate CI builds.
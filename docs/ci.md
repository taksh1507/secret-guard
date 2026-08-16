# CI Integration

Use the exit code to fail a pipeline the moment a secret appears.

## GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    pip install secret-guard-scan
    secret-guard scan . --json --exclude tests --exclude .venv
```

## Git pre-commit hook

```bash
secret-guard install-hook
```

Or use the pre-commit framework. The repository also publishes a
`pre-commit-hooks.yaml` for use directly:

```yaml
repos:
  - repo: https://github.com/taksh1507/secret-guard
    rev: v0.1.1.post2
    hooks:
      - id: secret-guard
```

## Continuous protection

Apply separate scans for:

- **Working tree** — dev machines (`secret-guard scan`).
- **Staged files** — just before commit (`secret-guard install-hook`).
- **PRs** — CI on pull requests (`secret-guard scan . --json`).

Rotation tip: when a finding is real, rotate the key first, then remove it from
the codebase and commit the fix.
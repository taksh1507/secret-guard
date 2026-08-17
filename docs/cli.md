# CLI Reference

## Global

```
secret-guard --version
secret-guard --help
```

## Commands

### `scan`

```
secret-guard scan [path] [options]
```

| Option | Description |
| --- | --- |
| `path` | Path to scan (default: `.`) |
| `--exclude DIR` | Skip additional directory names (repeatable) |
| `--no-entropy` | Disable high-entropy string detection |
| `--json` | Output findings as JSON |
| `--show-value` | Print full secret values (default masks them) |
| `--staged` | Scan only files staged in git |
| `--skip-rule RULE` | Never run the given rule id (repeatable) |
| `--only-rule RULE` | Run only the given rule id (repeatable) |
| `--list-rules` | List every available rule id and exit |

### `install-hook`

```
secret-guard install-hook
```

Installs a git pre-commit hook so every future commit runs a scan.

## Flags in detail

### `--staged`

Reads each staged file from the **git index** (`git show :<path>`) rather than
the working tree. This catches secrets that were staged and then deleted before
commit — exactly what would otherwise be committed.

### `--json`

Emits stable JSON. `--show-value` controls whether masked or raw values appear.

### `--exclude`

Directory names to skip, in addition to the built-in defaults
(`node_modules`, `venv`, `dist`, `build`, `__pycache__`, and more).

### `--skip-rule` / `--only-rule`

Rule ids are stable slugs (e.g. `github-token`, `aws-access-key-id`,
`entropy`, `dotenv`). `--list-rules` prints every id a scan can run.

- `--skip-rule RULE` removes a rule from the scan.
- `--only-rule RULE` restricts the scan to the given rules.
- Used together, `--only-rule` narrows first, then `--skip-rule` removes
  from that set.

Unknown rule ids abort the scan with exit code `2` so a typo can never
silently disable a rule.
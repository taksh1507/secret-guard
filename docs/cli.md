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
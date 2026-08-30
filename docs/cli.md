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
| `--reveal-prefix N` | Show first N characters of the masked secret |
| `--reveal-suffix N` | Show last N characters of the masked secret |
| `--staged` | Scan only files staged in git |
| `--skip-rule RULE` | Never run the given rule id (repeatable) |
| `--only-rule RULE` | Run only the given rule id (repeatable) |
| `--list-rules` | List every available rule id and exit |
| `--baseline FILE` | Suppress findings listed in a baseline file |

### `init`

```
secret-guard init
```

Writes a documented starter `secret-guard.json` into the current directory.
Fails with exit code `1` if one already exists.

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

### `--reveal-prefix` / `--reveal-suffix`

- `--reveal-prefix N` shows the first `N` characters of the masked secret, keeping the rest masked.
- `--reveal-suffix N` shows the last `N` characters of the masked secret, keeping the rest masked.
- If both are provided, they reveal their respective parts and mask the middle.
- If the sum of prefix and suffix reveal lengths is greater than or equal to the secret length, the secret is completely masked to prevent accidental leakage of the full secret value.
- `--show-value` always takes precedence and will print the full unmasked secret value, ignoring these flags.

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

### `--baseline`

A baseline acknowledges known findings so CI stays green while new leaks
still fail. It is a JSON document:

```json
{
  "baseline": [
    {"path": "config/rules.json", "rule_id": "generic-secret-key"}
  ]
}
```

`path` + `rule_id` suppress all matching findings; an optional `hash` (sha256
of the secret value) suppresses only that exact value. The baseline can also
be read from the `baseline` key of `secret-guard.json`.

### Configuration file (`secret-guard.json`)

`secret-guard` discovers `secret-guard.json` in the scanned directory or any
parent, then merges it with flags (flags win):

| Key | Type | Meaning |
| --- | --- | --- |
| `exclude` | list[str] | Extra directory names to skip |
| `no_entropy` | bool | Disable entropy detection |
| `skip_rules` | list[str] | Rule ids to skip |
| `only_rules` | list[str] | Rule ids to run exclusively |
| `baseline` | list[object] | Baseline entries (see above) |

Unknown keys, wrong types, or malformed JSON abort the scan with exit code
`2` and an error on stderr; unknown keys warn on stderr without failing.
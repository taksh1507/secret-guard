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
| `--include-comments` | Also report secret-like matches that live only inside a comment (default skips them) |
| `--json` | Output findings as JSON |
| `--csv` | Output findings as CSV |
| `--summary` | Print only the severity summary instead of the full report |
| `--xml` | Output findings as a JUnit-style XML report |
| `--html` | Output findings as a self-contained HTML report |
| `--sarif` | Output findings as a SARIF 2.1.0 report, for GitHub Code Scanning |
| `--format FMT` | Output format: `text`, `json`, `csv`, `summary`, `xml`, `html`, or `sarif` |
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

### `baseline`

```
secret-guard baseline [path] [options]
```

Scans like `scan` does, then writes the resulting findings out as a baseline
file instead of a report — the same schema `--baseline`/`secret-guard.json`'s
`baseline` key already accept, so a freshly generated baseline immediately
suppresses every finding it was generated from. Useful for adopting
secret-guard on an existing codebase without being blocked by every
pre-existing finding on day one; new secrets added afterward are still caught
normally.

| Option | Description |
| --- | --- |
| `path` | Path to scan (default: `.`) |
| `--output FILE` | Where to write the baseline (default: `secret-guard-baseline.json`) |
| `--force` | Overwrite `--output` if it already exists |
| `--exclude DIR` | Additional directory names to skip (repeatable) |
| `--no-entropy` | Disable high-entropy string detection |
| `--skip-rule RULE` | Never run the given rule id (repeatable) |
| `--only-rule RULE` | Run only the given rule id (repeatable) |
| `--rules-path FILE` | Add custom rules from a JSON manifest |

Fails with exit code `1` if `--output` already exists (without `--force`), and
exit code `2` for an unknown `--skip-rule`/`--only-rule` id, matching `scan`.

```bash
secret-guard baseline . --output secret-guard-baseline.json
secret-guard scan . --baseline secret-guard-baseline.json  # exits 0 now
```

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

### `--xml`

Emits a JUnit-style XML report — each finding is a failing `<testcase>` whose
attributes carry every finding field. Well-suited for CI dashboards that parse
JUnit XML.

### `--html`

Emits a self-contained HTML report with all styles inlined, so it can be
saved, emailed, or hosted as-is. Shows a severity summary and one table row
per finding.

### `--sarif`

Emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
log, so findings show up in the GitHub **Security** tab via Code Scanning.
Each rule that fired is listed once under `tool.driver.rules` with a
`security-severity` score; each finding becomes a `result` with its file,
line, and a one-way hash of the secret value for fingerprinting.

Secret values in a SARIF report are **always masked**, regardless of
`--show-value` — a SARIF log is meant to be uploaded and retained by Code
Scanning, so raw secret material must never end up in one.

```yaml
# .github/workflows/secret-guard.yml
- run: pip install secret-guard-scan
- run: secret-guard scan . --sarif secret-guard.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secret-guard.sarif
```

Use `continue-on-error: true` on the scan step (or run it in a job that
doesn't gate on the exit code) so the SARIF file still gets uploaded when
secrets are found — `secret-guard scan` exits `1` on findings independent of
which output format was requested.

### `--format`

Selects the output format by name. It is an alias for the dedicated flags:

```bash
secret-guard scan . --format html    # same as --html
secret-guard scan . --format xml     # same as --xml
secret-guard scan . --format json    # same as --json
secret-guard scan . --format sarif   # same as --sarif
```

All output formats mask secret values by default; `--show-value` opts in to
raw values, with the exception of `--sarif`, which always masks.

### `--reveal-prefix` / `--reveal-suffix`

- `--reveal-prefix N` shows the first `N` characters of the masked secret, keeping the rest masked.
- `--reveal-suffix N` shows the last `N` characters of the masked secret, keeping the rest masked.
- If both are provided, they reveal their respective parts and mask the middle.
- If the sum of prefix and suffix reveal lengths is greater than or equal to the secret length, the secret is completely masked to prevent accidental leakage of the full secret value.
- `--show-value` always takes precedence and will print the full unmasked secret value, ignoring these flags.

### `--include-comments`

By default, a secret-like match that falls entirely inside a comment (a
`#`/`//` line comment, a `/* */` or `<!-- -->` block) is not reported — the
same value written in executable code elsewhere in the file still is, since
only the comment's own text is excluded. Comment syntax is inferred from the
file extension; a file type this doesn't recognize gets no special
treatment (nothing is skipped there).

Pass `--include-comments` (or set `"include_comments": true` in
`secret-guard.json`) to report secrets inside comments too.

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

### Inline allowlist pragmas

A line carrying a `secret-guard:ignore` comment is excluded from the report,
regardless of the comment style (`#`, `//`, or any other prefix — the pragma
is matched anywhere on the line):

```python
token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # secret-guard:ignore
```

Scope it to specific rule ids (comma-separated) to suppress only those rules
on that line, leaving any other finding on the same line intact:

```python
token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # secret-guard:ignore github-token
```

Unlike `--skip-rule` (disables a rule everywhere) or `--baseline` (suppresses
by path + rule id, from outside the source), a pragma is a one-line, in-source
allowlist reviewable in the same diff as the secret it exempts.

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
| `include_comments` | bool | Report secrets found only inside comments (default: `false`) |
| `skip_rules` | list[str] | Rule ids to skip |
| `only_rules` | list[str] | Rule ids to run exclusively |
| `baseline` | list[object] | Baseline entries (see above) |

Unknown keys, wrong types, or malformed JSON abort the scan with exit code
`2` and an error on stderr; unknown keys warn on stderr without failing.

### Configuration in `pyproject.toml`

As an alternative to a standalone `secret-guard.json`, the same keys can live
under `[tool.secret-guard]` in `pyproject.toml`:

```toml
[tool.secret-guard]
exclude = ["wip"]
no_entropy = true
skip_rules = ["generic-secret-key"]
```

Discovery walks upward the same way as `secret-guard.json`. If a directory in
that walk has an explicit `secret-guard.json` anywhere, it wins over any
`pyproject.toml`; otherwise the closest `pyproject.toml` with a
`[tool.secret-guard]` table is used. A `pyproject.toml` with no such table is
ignored, so unrelated Python projects are unaffected. The same key validation
and exit-code-`2` behavior applies to values under `[tool.secret-guard]`.

Reading `pyproject.toml` uses the standard-library `tomllib` (Python 3.11+);
on older Pythons it falls back to the `tomli` package if installed, and is
otherwise skipped — `secret-guard.json` remains fully supported everywhere.
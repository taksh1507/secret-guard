# Examples

## Custom rule manifest (`rules.json`)

[`rules.json`](rules.json) is a ready-to-copy [custom rule manifest](../README.md#custom-rule-manifests).
It registers extra regex detections on top of the built-in rules without
forking secret-guard.

A manifest is a JSON object with a `rules` array. Each rule requires:

- `name` — human-readable label; also slugified into the rule id used by
  `--skip-rule` / `--only-rule` (e.g. `Acme API Token` → `acme-api-token`).
- `pattern` — a Python regular expression (matched case-insensitively,
  multiline).

Each rule optionally accepts:

- `severity` — one of `low`, `medium`, `high`, `critical` (default `medium`).
- `description` — shown in reports and `--list-rules` output.

### Try it

```bash
# Add these rules to a scan of the current directory
secret-guard scan . --rules-path examples/rules.json

# Confirm they registered alongside the built-ins
secret-guard scan --rules-path examples/rules.json --list-rules
```

Or commit the same array under the `rules` key of `secret-guard.json` so it
is discovered automatically (no flag needed):

```json
{
  "rules": [
    {
      "name": "Acme API Token",
      "pattern": "acme_tok_[a-f0-9]{20,}",
      "severity": "high",
      "description": "Acme platform API token."
    }
  ]
}
```

Custom rules use the same masking, entropy, severity, and reporting pipeline
as the built-ins. A duplicate name, unreadable regex, or invalid severity
fails the scan with exit code `2` instead of being silently ignored.

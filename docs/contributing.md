# Contributing

Contributions of any size are welcome — new detection rules, false-positive
reports, docs, editor integrations.

## Getting started

```bash
git clone https://github.com/taksh1507/secret-guard.git
cd secret-guard
python -m unittest discover -s tests
python -m ruff check secretguard tests
python -m secretguard scan . --exclude tests --no-entropy
```

## Where things live

| File | Purpose |
| --- | --- |
| `secretguard/rules.py` | Detection rules, entropy heuristics, `.env` logic |
| `secretguard/scanner.py` | Filesystem walk, gitignore filtering, scanning |
| `secretguard/reporter.py` | Console and JSON output (masking) |
| `secretguard/cli.py` | Argument parsing and commands |
| `tests/` | Unit tests (unittest) |

## Adding a rule

1. Add an entry to `RULES` in `secretguard/rules.py` using the `_r` helper.
2. Add a test in `tests/test_rules.py` using a synthetic fixture (never a real
   leaked secret).
3. Run `python -m unittest discover -s tests` and `ruff check secretguard tests`.

## Definition of done

- `python -m unittest discover -s tests` passes
- `python -m ruff check secretguard tests` is clean
- `python -m secretguard scan . --exclude tests --no-entropy` reports
  `0 critical, 0 high, 0 medium, 0 low`
- No raw secret values are added to tests, fixtures, or docs

## Good first issues

Filter the issue tracker:
https://github.com/taksh1507/secret-guard/issues?q=label%3A%22good+first+issue%22

## Recognition

Every merged PR is credited in release notes. Please read our
[Code of Conduct](https://github.com/taksh1507/secret-guard/blob/main/CODE_OF_CONDUCT.md)
and report security issues per our
[Security Policy](https://github.com/taksh1507/secret-guard/blob/main/SECURITY.md).
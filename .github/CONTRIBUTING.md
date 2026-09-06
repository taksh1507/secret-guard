# Contributing to secret-guard

Thanks for helping make secret-guard better! Every PR counts, no matter how
small.

Please read and follow this guide so your contribution lands quickly and
passes the automated checks.

## Your first PR

Welcome! Here's a quick walkthrough to get your first contribution merged in
under 15 minutes.

### 1. Set up your dev environment

```bash
git clone https://github.com/taksh1507/secret-guard.git
cd secret-guard
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### 2. Run the tests

```bash
python -m unittest discover -s tests -v
```

All tests should pass. If not, check your Python version (3.9+).

### 3. Pick an issue

Browse [good first issues](https://github.com/taksh1507/secret-guard/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
and pick one that interests you.

### 4. Make your change

- **Adding a rule?** Edit `secretguard/rules.py`, add a test in
  `tests/test_rules.py`, and run the suite.
- **Fixing a bug?** Write a failing test first, then fix the code.
- **Docs?** Edit the relevant `.md` file under `docs/` or the root.

### 5. Run checks before pushing

```bash
python -m unittest discover -s tests -v
ruff check secretguard tests
python -m secretguard scan . --exclude tests --no-entropy
```

All three must pass.

### 6. Open your PR

```bash
git checkout -b fix/my-change
git add .
git commit -m "fix: brief description of change"
git push origin fix/my-change
```

Fill out the PR template. CI will run automatically. Fix any failures.

---

## Code of conduct

Everyone is expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
Harassment or unprofessional behavior is not tolerated.

## Security issues

Do **not** open a public issue for security problems. Report them privately
via [SECURITY.md](SECURITY.md).

## Getting started

```bash
git clone https://github.com/taksh1507/secret-guard.git
cd secret-guard
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -e .
python -m unittest discover -s tests -v
```

Optional but recommended — local pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

This runs trailing-whitespace, YAML, and ruff checks plus a secret scan on
everything you stage.

## How to add a detection rule

1. Open `secretguard/rules.py`.
2. Add a `_r(...)` entry with a regex, name, `severity` (`low`, `medium`,
   `high`, `critical`) and a description.
3. Add a matching test in `tests/test_rules.py` using a **realistic but fake**
   sample (never a real secret).
4. Run the suite and the checks below.

### Rule-writing tips

- Make patterns specific enough to avoid false positives.
- Never match on the generic word `password` alone — require an assignment
  shape (`password = ...`) and a non-trivial value.
- For patterns that vary, prefer entropy detection over a brittle regex.
- Test values that look like real secrets will be flagged by GitHub's push
  protection and secret scanners (e.g. GitGuardian). Use values that match our
  rules but not real provider formats (e.g. `xoxb-abcdef...`, not
  `xoxb-1234...-abcd...`).

## What gets checked automatically

On every push and pull request, CI runs (see `.github/workflows/`):

- `tests` — unit tests on Python 3.9, 3.11, and 3.13
- `lint` — `ruff check secretguard tests`
- `scan` — `python -m secretguard scan . --exclude tests --no-entropy`
- Smoke test — verifies the installed CLI detects a seeded secret

**A PR must pass all checks before it can be merged.** You can run them
locally:

```bash
python -m unittest discover -s tests -v
ruff check secretguard tests
python -m secretguard scan . --exclude tests --no-entropy
```

## Opening an issue

Use the issue templates:

- [Bug report](.github/ISSUE_TEMPLATE/bug_report.md) — include the command,
  minimal input (with placeholder values), and your OS / Python version.
- [Feature request](.github/ISSUE_TEMPLATE/feature_request.md) — describe the
  problem, the solution, and an example.

## Opening a pull request

1. Branch from `main`: `git checkout -b fix/my-issue`.
2. Make focused changes; keep PRs to one logical change.
3. Add tests for new behavior.
4. Run the local checks above.
5. Fill out the [PR template](.github/pull_request_template.md).
6. Push and open the PR. CI runs automatically; fix anything it flags.

## Release process

Maintainers bump `version` in `pyproject.toml` and
`secretguard/__init__.py`, build with `python -m build`, publish with
`python -m twine upload dist/*`, and tag the release on GitHub.

## Issues and PRs

- Use clear, descriptive titles.
- Keep PRs focused on one change.
- Add tests for new behavior.
- Never commit real secrets.

## Code of conduct (short version)

Be kind and constructive. That's it.

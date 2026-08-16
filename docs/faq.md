# FAQ

## What does secret-guard scan for?

API keys (AWS, Google, Stripe), tokens (GitHub, Slack, Square), JWTs, private
keys, credential assignments, `.env` secrets, and high-entropy strings.

## Is secret-guard really zero-dependency?

Yes. The core scanner uses only the Python standard library. It shells out to
`git` for `--staged` scanning, and to nothing else.

## Does it send my code anywhere?

No. Scanning is 100% local. There are no network calls.

## Why are secret values masked by default?

Because a scanner that prints your API key is part of the problem. Values are
redacted unless you pass `--show-value` (useful for rotating the key).

## Why does my `.env.example` show no findings?

`.env.example`, `.env.sample`, `.env.template`, and `.env.dist` are
commit-intended templates. secret-guard skips them so you can document your
environment without tripping scans. A real `.env` file with secret keys **is**
still detected.

## Why do I see thousands of LOW findings in package-lock.json?

Those are npm `sha512` hashes with high entropy. They are not secrets. Run with
`--no-entropy` to suppress entropy-only findings, or let the baseline feature
(planned) handle them.

## How do I keep scans fast?

Exclude generated folders (`node_modules`, `.next`, `data`, `models`) and use
`--no-entropy` when you only care about pattern matches.

## Does it support pre-commit?

Yes — `secret-guard install-hook` installs a git hook, and the repository ships
a `pre-commit-hooks.yaml` for the pre-commit framework.

## Is there a GitHub Action?

Coming soon (issue
[#10](https://github.com/taksh1507/secret-guard/issues/10)).

## How is this different from gitleaks or trufflehog?

secret-guard is a lightweight, zero-dependency Python package that runs locally,
has a tiny install footprint, works in CI with one line, and masks secrets by
default. It is designed to be installed and forgot — not an agent that needs
config, Docker, or a platform account.
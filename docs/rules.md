# Detection Rules

secret-guard ships with 13 pattern rules plus entropy heuristics.

| Category | Rules |
| --- | --- |
| Cloud / SaaS | AWS Access Key IDs, AWS temporary & dashed keys, Google API Keys, Stripe live keys |
| Tokens | GitHub PAT (classic & fine-grained), Slack tokens, Square access tokens, JWTs |
| Key material | RSA / EC / DSA / OpenSSH / PGP private keys (`CRITICAL`) |
| Heuristics | Generic secret keys, credential assignments, high-entropy strings |

## `.env` files

`.env`, `.env.*`, `*.env`, and `*.env.*` files are special-cased: secret-looking
keys are reported **by name only**, and the value is never echoed.

Committed **template files** — `.env.example`, `.env.sample`, `.env.template`,
`.env.dist`, and their variants — are ignored entirely. These files are meant to
be committed so users can copy them into a real `.env`; flagging them would be a
false positive.

## Entropy detection

Strings of 20+ alphanumeric characters with Shannon entropy >= 3.5 bits/char are
flagged as `low` severity. Use `--no-entropy` to disable:
the npm `sha512` hashes in `package-lock.json` are common `low` findings.

## Severity levels

- `critical` — private key material
- `high` — provider API keys, tokens
- `medium` — generic secret keys, credential assignments
- `low` — high-entropy strings
# Security Policy

## Supported Versions

We currently support the latest published release on PyPI.

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

If you find a security issue — **please do not open a public issue**.
Instead, report it privately:

- Open a private advisory at:
  https://github.com/taksh1507/secret-guard/security/advisories/new

Please include:

- A description of the vulnerability and the impact
- Steps to reproduce (minimal sample code)
- Affected versions / files
- Any suggested fix, if you have one

You will receive a response as soon as possible. We ask that you keep the
details private until the issue is fixed and announced.

## Secret leaks

If you discover that a secret (API key, token, password) has been committed to
this repository, treat it as compromised:

1. **Rotate/revoke it immediately** at the provider.
2. Open a private advisory above so the history can be reviewed and scrubbed.

Never paste a real secret into issues, PRs, or comments. Test fixtures in
`tests/` use obviously fake values and are excluded from scanning via
`.gitguardian.yml`.
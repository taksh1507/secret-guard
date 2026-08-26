# Changelog

## [0.6.0](https://github.com/taksh1507/secret-guard/compare/v0.5.0...v0.6.0) (2026-08-26)


### Features

* custom rule manifests (closes [#9](https://github.com/taksh1507/secret-guard/issues/9)) ([#70](https://github.com/taksh1507/secret-guard/issues/70)) ([9290242](https://github.com/taksh1507/secret-guard/commit/9290242b58e435fe9f7405aff83c3fe9158229ef))
* **rules:** add GitLab PAT, Hugging Face token, and Slack webhook detection ([#72](https://github.com/taksh1507/secret-guard/issues/72)) ([20a7f65](https://github.com/taksh1507/secret-guard/commit/20a7f659ede74b844dba0b84855ea3d9e6152797))

## [0.5.0](https://github.com/taksh1507/secret-guard/compare/v0.4.0...v0.5.0) (2026-08-24)


### Features

* **cli:** add --severity flag to fail scans only past a severity threshold ([0a6d569](https://github.com/taksh1507/secret-guard/commit/0a6d56919526cfa647b8d3de1cde1e6ca835c26a))
* **cli:** add --severity flag to fail scans only past a severity threshold ([#67](https://github.com/taksh1507/secret-guard/issues/67)) ([0a6d569](https://github.com/taksh1507/secret-guard/commit/0a6d56919526cfa647b8d3de1cde1e6ca835c26a))
* **cli:** add --severity threshold support to scan command ([db4fb8a](https://github.com/taksh1507/secret-guard/commit/db4fb8a8a3e33391490eb0205b85a579cab99ff3))
* **cli:** add --stdin and --filename to scan piped input ([#65](https://github.com/taksh1507/secret-guard/issues/65)) ([08c34aa](https://github.com/taksh1507/secret-guard/commit/08c34aa9711f8262a84ea52c7d6e36b6f13a3019))

## [0.4.0](https://github.com/taksh1507/secret-guard/compare/v0.3.1...v0.4.0) (2026-08-20)


### Features

* **rules:** add OpenAI, Anthropic, and Discord bot token detection ([9b04cd4](https://github.com/taksh1507/secret-guard/commit/9b04cd478bd90a36dfd71f914bbb8240198059c1))
* **rules:** add OpenAI, Anthropic, and Discord bot token detection ([0f01ed5](https://github.com/taksh1507/secret-guard/commit/0f01ed5c4844ce266693dced18a29d784929cab5))
* **rules:** add OpenAI, Anthropic, and Discord bot token detection ([#62](https://github.com/taksh1507/secret-guard/issues/62)) ([9b04cd4](https://github.com/taksh1507/secret-guard/commit/9b04cd478bd90a36dfd71f914bbb8240198059c1))

## [0.3.1](https://github.com/taksh1507/secret-guard/compare/v0.3.0...v0.3.1) (2026-08-18)


### Bug Fixes

* point smoke CI and audit at relocated action ([#44](https://github.com/taksh1507/secret-guard/issues/44)) ([bdc4c41](https://github.com/taksh1507/secret-guard/commit/bdc4c41ad9ca467b29a0bb46da468f9b44398ddd))

## [0.3.0](https://github.com/taksh1507/secret-guard/compare/v0.2.0...v0.3.0) (2026-08-18)


### Features

* add one-line GitHub Action ([#39](https://github.com/taksh1507/secret-guard/issues/39)) ([d3bb8a1](https://github.com/taksh1507/secret-guard/commit/d3bb8a11202afffcb3645534f1360ac6be1b3cc4))
* **cli:** add baseline/allowlist support to suppress known intentional findings ([#36](https://github.com/taksh1507/secret-guard/issues/36)) ([9c660a2](https://github.com/taksh1507/secret-guard/commit/9c660a2f845d5fd8c952ab16a83da074e47842b5))


### Bug Fixes

* don't run PyPI publish for non-semver tags like v1 ([#40](https://github.com/taksh1507/secret-guard/issues/40)) ([a4e9c03](https://github.com/taksh1507/secret-guard/commit/a4e9c03c9ac4515626e35c4a0f136e0923299c9e))


### Documentation

* add Docker usage section to README + fix merge conflict marker in tests ([#35](https://github.com/taksh1507/secret-guard/issues/35)) ([a111738](https://github.com/taksh1507/secret-guard/commit/a1117380c7e57b3f222426fa8b0294689c1caccf))

## [0.2.0](https://github.com/taksh1507/secret-guard/compare/v0.1.2...v0.2.0) (2026-08-18)


### Features

* add per-rule scan controls, release automation, and coverage reporting ([#31](https://github.com/taksh1507/secret-guard/issues/31)) ([6a960b5](https://github.com/taksh1507/secret-guard/commit/6a960b569818aab39e42ae58d0a7975904927bdb))


### Bug Fixes

* keep release-please tags in v0.x.x format ([#33](https://github.com/taksh1507/secret-guard/issues/33)) ([d80cc8d](https://github.com/taksh1507/secret-guard/commit/d80cc8d760cb4341f7eb5f38359262dded3e5d6f))

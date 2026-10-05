# Changelog

## [0.11.0](https://github.com/taksh1507/secret-guard/compare/v0.10.0...v0.11.0) (2026-10-05)


### Features

* **action:** post scan findings as a PR comment ([#110](https://github.com/taksh1507/secret-guard/issues/110)) ([3437f99](https://github.com/taksh1507/secret-guard/commit/3437f996245d47c8abcc19304385b31ae72bd4c5))
* **cli:** add baseline command to scaffold a baseline from findings ([#112](https://github.com/taksh1507/secret-guard/issues/112)) ([e2f14d9](https://github.com/taksh1507/secret-guard/commit/e2f14d96b5a32c3e0775c4b8684128224e7fc8a9))
* **cli:** read config from pyproject.toml ([tool.secret-guard]) ([#103](https://github.com/taksh1507/secret-guard/issues/103)) ([b73d656](https://github.com/taksh1507/secret-guard/commit/b73d656f958eba449462a3b5237db93e598834af))
* **report:** add SARIF 2.1.0 output for GitHub Code Scanning ([#104](https://github.com/taksh1507/secret-guard/issues/104)) ([08c4978](https://github.com/taksh1507/secret-guard/commit/08c49788fd5d829d9d8be5012fb7b65f03a8fd92))
* **scanner:** skip hardcoded secrets that live only in comments ([#105](https://github.com/taksh1507/secret-guard/issues/105)) ([e1691c5](https://github.com/taksh1507/secret-guard/commit/e1691c5975169e335a52f0ddc9125377038be596))
* **scanner:** support inline secret-guard:ignore allowlist pragmas ([#102](https://github.com/taksh1507/secret-guard/issues/102)) ([2e1c868](https://github.com/taksh1507/secret-guard/commit/2e1c8681d1638d32dc45ef7695b5acffd690646f))


### Documentation

* document GitLab CI and Azure Pipelines integration ([#101](https://github.com/taksh1507/secret-guard/issues/101)) ([4fafa59](https://github.com/taksh1507/secret-guard/commit/4fafa597a05d2a12c9b37f4bb50e800fa4a342e6))

## [0.10.0](https://github.com/taksh1507/secret-guard/compare/v0.9.0...v0.10.0) (2026-09-06)


### Features

* **cli:** add --summary output to print only the severity summary ([37fa6bf](https://github.com/taksh1507/secret-guard/commit/37fa6bf3deb1f0c76cdc8ee9c969ce0bc2c2a9dd))
* **report:** add XML and HTML report output formats ([7604d04](https://github.com/taksh1507/secret-guard/commit/7604d045762890cacb48d714e89a2f155085d079))
* **rules:** detect Bearer tokens and generic sk- prefixed secret keys ([9eb505c](https://github.com/taksh1507/secret-guard/commit/9eb505cb01fe06060957800181b14d9ae2746746))


### Miscellaneous Chores

* move community docs out of the repo root ([19afa58](https://github.com/taksh1507/secret-guard/commit/19afa58162b7ace7c380d8f9552651a665ee7b2d))

## [0.9.0](https://github.com/taksh1507/secret-guard/compare/v0.8.0...v0.9.0) (2026-09-02)


### Features

* **cli:** add --csv output format for scan results ([77c461e](https://github.com/taksh1507/secret-guard/commit/77c461ea8b0a10e994ea9495927c9c1cb020ab50))
* **cli:** add --quiet flag to suppress scan output ([f02637b](https://github.com/taksh1507/secret-guard/commit/f02637b5e522d6808d40300c4f913571a86388a1))
* **cli:** allow scanning multiple paths with secret-guard scan ([a10c9f7](https://github.com/taksh1507/secret-guard/commit/a10c9f7d26293ab0061af0e61937f68ed8d66814))


### Code Refactoring

* **scanner:** precompute the exclusions set once in __init__ ([126f75f](https://github.com/taksh1507/secret-guard/commit/126f75f455bd6174228278a71e7838b3c1a743a3))

## [0.8.0](https://github.com/taksh1507/secret-guard/compare/v0.7.1...v0.8.0) (2026-08-30)


### Features

* **cli:** add --reveal-prefix and --reveal-suffix for partial masking ([#91](https://github.com/taksh1507/secret-guard/issues/91)) ([64a22a9](https://github.com/taksh1507/secret-guard/commit/64a22a9b5e91853f2a1f42761fdc71f01336ec00))
* support max_findings in secret-guard.json config ([#90](https://github.com/taksh1507/secret-guard/issues/90)) ([a229c02](https://github.com/taksh1507/secret-guard/commit/a229c02f19b3b3ba24b6108293ab753c2afe7a32))


### Documentation

* rewrite README with clean formatting and LF line endings ([043b867](https://github.com/taksh1507/secret-guard/commit/043b867bfd7aaaa569440d1f3603051e7f473e8b))


### Miscellaneous Chores

* streak maintenance ([#87](https://github.com/taksh1507/secret-guard/issues/87)) ([b14a5dd](https://github.com/taksh1507/secret-guard/commit/b14a5dd9f226ea2c0ac265f282122421f26b5af4))

## [0.7.1](https://github.com/taksh1507/secret-guard/compare/v0.7.0...v0.7.1) (2026-08-28)


### Documentation

* professionalize README and sync with current features ([#85](https://github.com/taksh1507/secret-guard/issues/85)) ([eff7b29](https://github.com/taksh1507/secret-guard/commit/eff7b299ff0d77e1004a74a9bb8ccb7920393e29))

## [0.7.0](https://github.com/taksh1507/secret-guard/compare/v0.6.0...v0.7.0) (2026-08-27)


### Features

* add --max-findings to cap scan output ([#77](https://github.com/taksh1507/secret-guard/issues/77)) ([757e842](https://github.com/taksh1507/secret-guard/commit/757e84216bd2aff265efc1dc56da779964eba16c))
* **rules:** add PyPI, Shopify, Mailgun, and database connection URI rules ([#75](https://github.com/taksh1507/secret-guard/issues/75)) ([a9667a6](https://github.com/taksh1507/secret-guard/commit/a9667a67476e50aac1fbf75370b271ff2f6ca90c))

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

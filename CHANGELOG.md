# Changelog

All notable changes to this project will be documented in this file.

## [1.42.0]
- Fixed pagination issue when calling gitlab api
- Expanded directory exclusion handling to interpret plain patterns as prefixes, ensuring options like --exclude .git also skip all nested paths
- Updated baseline management to track encountered findings and remove entries that are no longer present, saving the baseline file whenever entries are pruned or new matches are added
- Added rules for authress, clickhouse, codecov, contentful, curl, dropbox, fly.io, hubspot, firecrawl
- Internal refactoring of rule loader, git enumerator, and filetype guesser
- Improved language detection

## [1.41.0]
- Added support for scanning gitlab subgroups, with `kingfisher scan --gitlab-group my-group --gitlab-include-subgroups`
- Added rule for Vercel

## [1.40.0]
- Dropped the “prevalidated” flag from rule definitions and validation logic so every finding now flows through the standard active/inactive/unknown pipeline, simplifying rule configuration and preventing special‑case bypasses
- Improved Tailscale api key detectors

## [1.39.0]
- Added support for scanning Confluence pages via `--confluence-url` and `--cql`

## [1.38.0]
- `--quiet` now suppresses scan summaries and rule statistics unless `--rule-stats` is explicitly provided
- Added X Consumer key detection and validation

## [1.37.0]
- GitLab: Matched GitLab group repository listings to glab by only enumerating projects that belong directly to each group, without automatically traversing subgroups

## [1.36.0]
- Fixed GitHub organization and GitLab group scans when using `--git-history=none`
- JWT tokens without both `iss` and `aud` are no longer reported as active credentials

## [1.35.0]
- Remote scans with `--git-history=none` now clone repositories with a working tree and scan the current files instead of erroring with "No inputs to scan".
- Fixed issue where `--redact` did not function properly
- Fixed validation logic for clarifai rule

## [1.34.0]
- Use system TLS root certificates to support self-hosted GitLab instances with internal CAs
- Added new rule: Coze personal access token
- Updated Supabase rule to detect project url's and validate their corresponding tokens

## [1.33.0]
- Fixed header precedence so custom HTTP validation headers like `Accept` are preserved
- Added new Heroku rule

## [1.32.0]
- Added support for scanning AWS S3 buckets via `--s3-bucket` and optional `--s3-prefix`
- Added `--role-arn` and `--aws-local-profile` flags for S3 authentication alongside `KF_AWS_KEY`/`KF_AWS_SECRET`
- Added progress bar for scanning s3 buckets
- Refactored output reporting and formatting logic

## [1.31.0]
- New rules: Telegram bot token, OpenWeatherMap, Apify, Groq
- New OpenAI detectors added (@joshlarsen)
- Fixed bug that broke validation when using unnamed group captures

## [1.30.0]
- Fixed validation caching for HTTP validators to include rendered headers so inactive secrets no longer appear active.
- Removed pre-commit installation hook, due to bugs

## [1.29.0]
- Fixed issue when more than 1 named capture group is used in a rule variable
- Added a new liquid template filters: `b64dec`
- Added custom validator for Coinbase, and a Coinbase rule that uses it

## [1.28.0]
- Added support for scanning Slack

## [1.27.0]
- Added Buildkite rule
- Added support for scanning Docker images via `--docker-image`

## [1.26.0]
- Added rule for ElevenLabs
- Added support for scanning Jira issues via a given JQL (Jira Query Language)

## [1.25.0]
- Fixed GitLab authentication bug
- Added pre-commit and pre-receive installation hooks
- MongoDB validator now skips `mongodb+srv://` URIs and returns a message that validation was skipped
- Fixed noisy Baseten rule

## [1.24.0]
- Now generating DEB and RPM packages
- Now releasing Docker images, and updated README
- Added rule for Scale, Deepgram, AssemblyAI


## [1.23.0]
- Updating GitHub Action to generate Docker image
- Added rules for Diffbot, ai21, baseten
- Fixed supabase rule
- Added 'alg' to JWT validation output

## [1.22.0]
- Added rules for Google Gemini AI, Cohere, Stability.ai, Replicate, Runway, Clarifai
- Upgraded dependencies

## [1.21.0]
- Improved Azure Storage rule
- Added rule to detect TravisCI encrypted values
- Added baseline feature with `--baseline-file` and `--manage-baseline` flags
- Introduced `--exclude` option for skipping paths
- Added tests covering baseline and exclude workflow
- Added validation for JWT tokens that checks `exp` and `nbf` claims
- JWT validation performs OpenID Connect discovery using the `iss` claim and verifies signatures via JWKS
- Removed `--ignore-tests` argument, because the `--exclude` flag provides more granular functionality
- DigitalOcean rule update
- Adafruit rule update

## [1.20.0]
- Removed confirmation prompt when user provides --self-update flag
- Added support for HTTP request bodies in rule validation 
- Added new liquid-rs filters: HmacSha1, IsoTimestampNoFracFilter, Replace
- Added rules for mistral, perplexity
- Added validation for Alibaba rule
- Set GIT_TERMINAL_PROMPT=0 when cloning git repos

## [1.19.0]
- JSON output was missing committer name and email
- Fixed Gitlab rule which was incorrectly identifying certain tokens as valid

## [1.18.1]
- Restored --version cli argument
- Added test for the argument

## [1.18.0]
- Added rules for DeepSeek, xAI
- Removed branding
- Added NOTICE file

## [1.17.1]
- Fixed broken sourcegraph rule
- Added test to prevent this and similar issues

## [1.17.0]
- Updated README to give proper attribution to Nosey Parker!
- Added rules for sonarcloud, sonarqube, sourcegraph, shopify, truenas, square, sendgrid, nasa, teamcity, truenas, shopify
- Introduced `--ignore-tests` flag – skip files/dirs whose path resembles tests (`test`, `spec`, `fixture`, `example`, `sample`), reducing noise.
## [1.16.0]
- Fix: HTML detection now requires both HTML content-type and "<html" tag, fixing webhook false negatives
- Removed cargo-nextest installation during test running
- Added rules for 1password, droneci

## [1.15.0]
- Ensuring temp files are cleaned up
- Applying visual style to the update check output
- Fixed bug in --self-update where it was looking for the incorrect binary name on GitHub releases
- Rule cleanup

## [1.14.0]
- Fixed several malformed rules
- Now validating that response_matcher is present in validation section of all rules

## [1.13.0]
- Added new rules for Planetscale, Postman, Openweather, opsgenie, pagerduty, pastebin, paypal, netlify, netrc, newrelic, ngrok, npm, nuget, mandrill, mapbox, microsoft teams, stripe, linkedin, mailchimp, mailgun, linear, line, huggingface, ibm cloud, intercom, ipstack, heroku, gradle, grafana
- Added `--rule-stats` command-line flag that will display rule performance statistics during a scan. Useful when creating or debugging rules


## [1.12.0] 
- Added automatic update checks using GitHub releases.
- New `--self-update` flag installs updates when available
- New `--no-update-check` flag disables update checks
- Updated rules

## [1.11.0] 2025-06-21
- Increased default value for number of scanning jobs to improve validation speed
- Fixed issue where some API responses (e.g. GitHub's `/user` endpoint) include required fields like `"name"` beyond the first 512 bytes. Truncating earlier causes `WordMatch` checks to fail even for active credentials. Increased the limit to keep a larger slice of the body while still bounding memory usage.

## [1.10.0] 2025-06-20
- Updated de-dupe fingerprint to include the content of the match
- Updated Makefile
- Adding GitHub Actions

## [1.9.0] 2025-06-16
- Initial public release of Kingfisher

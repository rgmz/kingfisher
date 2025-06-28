# Changelog

All notable changes to this project will be documented in this file.

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

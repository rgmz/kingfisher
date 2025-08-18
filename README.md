# Kingfisher

<p align="center">
  <img src="docs/kingfisher_logo.png" alt="Kingfisher Logo" width="126" height="173" style="vertical-align: right;" />

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Kingfisher is a blazingly fast secret‑scanning and live validation tool built in Rust. It combines Intel’s hardware‑accelerated Hyperscan regex engine with language‑aware parsing via Tree‑Sitter, and **ships with hundreds of built‑in rules** to detect, validate, and triage secrets before they ever reach production
</p>

Kingfisher originated as a fork of Praetorian's Nosey Parker, and is built atop their incredible work and the work contributed by the Nosey Parker community.

## What Kingfisher Adds
- **Live validation** via cloud-provider APIs
- **Extra targets**: GitLab repos, S3 buckets, Docker images, Jira issues, Confluence pages, and Slack messages
- **Compressed Files**: Supports extracting and scanning compressed files for secrets
- **Baseline mode**: ignore known secrets, flag only new ones
- **Language-aware detection** (source-code parsing) for ~20 languages
- **Native Windows** binary


## Key Features
- **Performance**: multithreaded, Hyperscan‑powered scanning built for huge codebases  
- **Extensible rules**: hundreds of built-in detectors plus YAML-defined custom rules ([docs/RULES.md](/docs/RULES.md))  
- **Multiple targets**:
  - **Git history**: local repos or GitHub/GitLab orgs/users  
  - **Docker images**: public or private via `--docker-image`
  - **Jira issues**: JQL‑driven scans with `--jira-url` and `--jql`
  - **Confluence pages**: CQL‑driven scans with `--confluence-url` and `--cql`
  - **Slack messages**: query‑based scans with `--slack-query`
  - **AWS S3**: bucket scans via `--s3-bucket`/`--s3-prefix` with credentials from `KF_AWS_KEY`/`KF_AWS_SECRET`, `--role-arn`, `--aws-local-profile`, or anonymous
- **Compressed Files**: Supports extracting and scanning compressed files for secrets
- **Baseline management**: generate and track baselines to suppress known secrets ([docs/BASELINE.md](/docs/BASELINE.md))  

**Learn more:** [Introducing Kingfisher: Real‑Time Secret Detection and Validation](https://www.mongodb.com/blog/post/product-release-announcements/introducing-kingfisher-real-time-secret-detection-validation)

# Benchmark Results

See ([docs/COMPARISON.md](docs/COMPARISON.md))

<p align="center">
  <img src="docs/runtime-comparison.png" alt="Kingfisher Runtime Comparison" style="vertical-align: center;" />
</p>

# Getting Started
## Installation

On macOS, you can simply

```bash
brew install kingfisher
```

Pre-built binaries are also available on the [Releases](https://github.com/mongodb/kingfisher/releases) section of this page.

You can also install using [ubi](https://github.com/houseabsolute/ubi), which downloads the correct binary for your platform:

```bash
# Linux, macOS
curl --silent --location \
    https://raw.githubusercontent.com/houseabsolute/ubi/master/bootstrap/bootstrap-ubi.sh | \
    sh && \
  ubi --project mongodb/kingfisher --in "$HOME/bin"
```

```powershell
# Windows
powershell -exec bypass -c "Invoke-WebRequest -URI 'https://raw.githubusercontent.com/houseabsolute/ubi/master/bootstrap/bootstrap-ubi.ps1' -UseBasicParsing | Invoke-Expression" && ubi --project mongodb/kingfisher --in .
```

This installs `ubi` and then places the `kingfisher` executable in `~/bin` on Unix-like
systems (or the current directory on Windows).

Or you may compile for your platform via `make`:

```bash
# NOTE: Requires Docker
make linux

# macOS --- must build from a macOS host
make darwin

# Windows x64 --- requires building from a Windows host with Visual Studio installed
./buildwin.bat -force
```

```bash
# Build all targets
make linux-all # builds both x64 and arm64
make darwin-all # builds both x64 and arm64
make all # builds for every OS and architecture supported
```

### Run Kingfisher in Docker

Run the dockerized Kingfisher container:
```bash
# GitHub Container Registry 
docker run --rm ghcr.io/mongodb/kingfisher:latest --version

# Scan the current working directory
# (mounts your code at /src and scans it)
docker run --rm \
  -v "$PWD":/src \
  ghcr.io/mongodb/kingfisher:latest scan /src


# Scan while providing a GitHub token
# Mounts your working dir at /proj and passes in the token:
docker run --rm \
  -e KF_GITHUB_TOKEN=ghp_… \
  -v "$PWD":/proj \
  ghcr.io/mongodb/kingfisher:latest \
    scan --git-url https://github.com/org/private_repo.git

# Scan an S3 bucket
# Credentials can come from KF_AWS_KEY/KF_AWS_SECRET, --role-arn, or --aws-local-profile
docker run --rm \
  -e KF_AWS_KEY=AKIA... \
  -e KF_AWS_SECRET=g5nYW... \
  ghcr.io/mongodb/kingfisher:latest \
    scan --s3-bucket bucket-name


# Scan and write a JSON report locally
# Here we:
#    1. Mount $PWD → /proj
#    2. Tell Kingfisher to write findings.json inside /proj/reports
#   3. Ensure ./reports exists on your host so Docker can mount it
mkdir -p reports

# run and output into host’s ./reports directory
docker run --rm \
  -v "$PWD":/proj \
  ghcr.io/mongodb/kingfisher:latest \
    scan /proj \
    --format json \
    --output /proj/reports/findings.json


# Tip: you can combine multiple mounts if you prefer separating source vs. output:
# Here /src is read‑only, and /out holds your generated reports
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/reports":/out \
  ghcr.io/mongodb/kingfisher:latest \
    scan /src \
    --format json \
    --output /out/findings.json

```

# 🔐 Detection Rules at a Glance

Kingfisher ships with hundreds of rules that cover everything from classic cloud keys to the latest LLM-API secrets. Below is an overview:

| Category | What we catch |
|----------|---------------|
| **AI / LLM APIs** | OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Stability AI, Replicate, xAI (Grok), and more
| **Cloud Providers** | AWS, Azure, GCP, Alibaba Cloud, DigitalOcean, IBM Cloud, Cloudflare, and more
| **Dev & CI/CD** | GitHub/GitLab tokens, CircleCI, TravisCI, TeamCity, Docker Hub, npm & PyPI publish token, and more
| **Messaging & Comms** | Slack, Discord, Microsoft Teams, Twilio, Mailgun/SendGrid/Mailchimp, and more
| **Databases & Data Ops** | MongoDB Atlas, PlanetScale, Postgres DSNs, Grafana Cloud, Datadog, Dynatrace, and more
| **Payments & Billing** | Stripe, PayPal, Square, GoCardless, and more
| **Security & DevSecOps** | Snyk, Dependency-Track, CodeClimate, Codacy, OpsGenie, PagerDuty, and more
| **Misc. SaaS & Tools** | 1Password, Adobe, Atlassian/Jira, Asana, Netlify, Baremetrics, and more

## Write Custom Rules!

Kingfisher ships with hundreds of rules with HTTP and service‑specific validation checks (AWS, Azure, GCP, etc.) to confirm if a detected string is a live credential.

However, you may want to add your own custom rules, or modify a detection to better suit your needs / environment.

First, review [docs/RULES.md](/docs/RULES.md) to learn how to create custom Kingfisher rules.

Once you've done that, you can provide your custom rules (defined in a YAML file) and provide it to Kingfisher at runtime --- no recompiling required!

# Usage

## Basic Examples

> **Note**  `kingfisher scan` detects whether the input is a Git repository or a plain directory—no extra flags required.

### Scan with secret validation

```bash
kingfisher scan /path/to/code
## NOTE: This path can refer to:
# 1. a local git repo
# 2. a directory with many git repos
# 3. or just a folder with files and subdirectories

## To explicitly prevent scanning git commit history add:
#   `--git-history=none`
```

### Scan a directory containing multiple Git repositories

```bash
kingfisher scan /projects/mono‑repo‑dir
```

### Scan a Git repository without validation

```bash
kingfisher scan ~/src/myrepo --no-validate
```

### Display only secrets confirmed active by third‑party APIs

```bash
kingfisher scan /path/to/repo --only-valid
```

### Output JSON and capture to a file

```bash
kingfisher scan . --format json | tee kingfisher.json
```

### Output SARIF directly to disk

```bash
kingfisher scan /path/to/repo --format sarif --output findings.sarif
```

### Pipe any text directly into Kingfisher by passing `-`

```bash
cat /path/to/file.py | kingfisher scan -

```

### Scan using a rule _family_ with one flag

_(prefix matching: `--rule kingfisher.aws` loads `kingfisher.aws._`)\*

```bash
# Only apply AWS-related rules (kingfisher.aws.1 + kingfisher.aws.2)
kingfisher scan /path/to/repo --rule kingfisher.aws
```

### Display rule performance statistics

```bash
kingfisher scan /path/to/repo --rule-stats
```

### Scan while ignoring likely test files

`--exclude` skips any file or directory whose path matches this glob pattern (repeatable, uses gitignore-style syntax, case sensitive)

```bash
# Scan source but skip likely unit / integration tests
kingfisher scan ./my-project \
  --exclude='[Tt]est' \
  --exclude='spec' \
  --exclude='[Ff]ixture' \
  --exclude='example' \
  --exclude='sample'
```

### Exclude specific paths
```bash
# Skip all Python files and any directory named tests
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude '[Tt]ests'
```

If you want to know which files are being skipped, enable verbose debugging (-v) when scanning, which will report any files being skipped by the baseline file (or via --exclude):

```bash
# Skip all Python files and any directory named tests, and report to stderr any skipped files
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude tests \
  -v
```
## Scan an S3 bucket
You can scan S3 objects directly:

```bash
kingfisher scan --s3-bucket bucket-name [--s3-prefix path/]
```

Credential resolution happens in this order:

1. `KF_AWS_KEY` and `KF_AWS_SECRET` environment variables
2. `--aws-local-profile` pointing to a profile in `~/.aws/config` (works with AWS SSO)
3. anonymous access for public buckets

If `--role-arn` is supplied, the credentials from steps 1–2 are used to assume that role.

Examples:

```bash
# using explicit keys
export KF_AWS_KEY=AKIA...
export KF_AWS_SECRET=g5nYW...
kingfisher scan --s3-bucket some-example-bucket

# Above can also be run as:
KF_AWS_KEY=AKIA... KF_AWS_SECRET=g5nYW... kingfisher scan --s3-bucket some-example-bucket

# using a local profile (e.g., SSO) that exists in your AWS profile (~/.aws/config)
kingfisher scan --s3-bucket some-example-bucket --aws-local-profile default

# anonymous scan of a bucket, while providing an object prefix to only scan subset of the s3 bucket
kingfisher scan \
  --s3-bucket awsglue-datasets \
  --s3-prefix examples/us-legislators/all

# assuming a role when scanning
kingfisher scan --s3-bucket some-example-bucket \
  --role-arn arn:aws:iam::123456789012:role/MyRole

# anonymous scan of a public bucket
kingfisher scan --s3-bucket some-example-bucket
```

Docker example:

```bash
docker run --rm \
  -e KF_AWS_KEY=AKIA... \
  -e KF_AWS_SECRET=g5nYW... \
  ghcr.io/mongodb/kingfisher:latest \
    scan --s3-bucket bucket-name
```
## Scanning Docker Images

Kingfisher will first try to use any locally available image, then fall back to pulling via OCI.  

Authentication happens *in this order*:

1. **`KF_DOCKER_TOKEN`** env var  
   - If it contains `user:pass`, it’s used as Basic auth
   - Otherwise it’s sent as a Bearer token
2. **Docker CLI credentials**  
   - Checks `credHelpers` (per-registry) and `credsStore` in `~/.docker/config.json`.  
   - Falls back to the legacy `auths` → `auth` (base64) entries.  
3. **Anonymous** (no credentials)


```bash
# 1) Scan public or already-pulled image
kingfisher scan --docker-image ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# 2) For private registries, explicitly set KF_DOCKER_TOKEN:
#    - Basic auth:     "user:pass"
#    - Bearer only:    "TOKEN"
export KF_DOCKER_TOKEN="AWS:$(aws ecr get-login-password --region us-east-1)"
kingfisher scan --docker-image some-private-registry.dkr.ecr.us-east-1.amazonaws.com/base/amazonlinux2023:latest

# 3) Or rely on your Docker CLI login/keychain:
#    (e.g. aws ecr get-login-password … | docker login …)
kingfisher scan --docker-image private.registry.example.com/my-image:tag
```

## Scanning GitHub

### Scan GitHub organisation (requires `KF_GITHUB_TOKEN`)

```bash
kingfisher scan --github-organization my-org
```

### Scan remote GitHub repository

```bash
kingfisher scan --git-url https://github.com/org/repo.git

# Optionally provide a GitHub Token
KF_GITHUB_TOKEN="ghp_…" kingfisher scan --git-url https://github.com/org/private_repo.git

```

---

## Scanning GitLab

### Scan GitLab group (requires `KF_GITLAB_TOKEN`)

```bash
kingfisher scan --gitlab-group my-group
# include repositories from all nested subgroups
kingfisher scan --gitlab-group my-group --gitlab-include-subgroups
```

### Scan GitLab user

```bash
kingfisher scan --gitlab-user johndoe
```

### Scan remote GitLab repository by URL

```bash
kingfisher scan --git-url https://gitlab.com/group/project.git
```

### List GitLab repositories

```bash
kingfisher gitlab repos list --group my-group
# include repositories from all nested subgroups
kingfisher gitlab repos list --group my-group --include-subgroups
```

## Scanning Jira

### Scan Jira issues matching a JQL query

```bash
KF_JIRA_TOKEN="token" kingfisher scan \
    --jira-url https://jira.company.com \
    --jql "project = TEST AND status = Open" \
    --max-results 500
```

### Scan the last 1,000 Jira issues:
```bash
KF_JIRA_TOKEN="token" kingfisher scan \
  --jira-url https://jira.mongodb.org \
  --jql 'ORDER BY created DESC' \
  --max-results 1000
```

## Scanning Confluence

### Scan Confluence pages matching a CQL query

```bash
# Bearer token
KF_CONFLUENCE_TOKEN="token" kingfisher scan \
    --confluence-url https://confluence.company.com \
    --cql "label = secret" \
    --max-results 500

# Basic auth with username and token
KF_CONFLUENCE_USER="user@example.com" KF_CONFLUENCE_TOKEN="token" kingfisher scan \
    --confluence-url https://confluence.company.com \
    --cql "text ~ 'password'" \
    --max-results 500
```

Use the base URL of your Confluence site for `--confluence-url`. Kingfisher
automatically adds `/rest/api` to the end, so `https://example.com/wiki` and
`https://example.com` both work depending on your server configuration.

Generate a personal access token and set it in the `KF_CONFLUENCE_TOKEN` environment variable. By default, Kingfisher sends the token as a bearer token in the `Authorization` header.

To use basic authentication instead, also set `KF_CONFLUENCE_USER` to your Confluence email address; Kingfisher will then send the username and `KF_CONFLUENCE_TOKEN` as a Basic auth header. If the server responds with a redirect to a login page, the credentials are invalid or lack the required permissions.

## Scanning Slack

### Scan Slack messages matching a search query

```bash
KF_SLACK_TOKEN="xoxp-1234..." kingfisher scan \
    --slack-query "from:username has:link" \
    --max-results 1000

KF_SLACK_TOKEN="xoxp-1234..." kingfisher scan \
    --slack-query "akia" \
    --max-results 1000
```
*The Slack token must be a user token with the `search:read` scope. Bot tokens (those beginning with `xoxb-`) cannot call the Slack search API.*

## Environment Variables for Tokens

| Variable          | Purpose                      |
| ----------------- | ---------------------------- |
| `KF_GITHUB_TOKEN` | GitHub Personal Access Token |
| `KF_GITLAB_TOKEN` | GitLab Personal Access Token |
| `KF_JIRA_TOKEN`   | Jira API token               |
| `KF_CONFLUENCE_TOKEN` | Confluence API token      |
| `KF_SLACK_TOKEN`  | Slack API token              |
| `KF_DOCKER_TOKEN` | Docker registry token (`user:pass` or bearer token). If unset, credentials from the Docker keychain are used |
| `KF_AWS_KEY` and `KF_AWS_SECRET` | AWS Credentials to use with S3 bucket scanning |

Set them temporarily per command:

```bash
KF_GITLAB_TOKEN="glpat-…" kingfisher scan --gitlab-group my-group
```

Or export for the session:

```bash
export KF_GITLAB_TOKEN="glpat-…"
```

To authenticate Jira requests:
```bash
export KF_JIRA_TOKEN="token"
```

To authenticate Confluence requests:
```bash
export KF_CONFLUENCE_TOKEN="token"
```

_If no token is provided Kingfisher still works for public repositories._

---

## Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |

## Update Checks

Kingfisher automatically queries GitHub for a newer release when it starts and tells you whether an update is available.

- **Hands-free updates** – Add `--self-update` to any Kingfisher command

  * If a newer version exists, Kingfisher will download it, replace the running binary, and re-launch itself with the **exact same arguments**.  
  * If the update fails or no newer release is found, the current run proceeds as normal

- **Disable version checks** – Pass `--no-update-check` to skip both the startup and shutdown checks entirely

# Advanced Options

## Build a Baseline / Detect New Secrets

There are situations where a repository already contains checked‑in secrets, but you want to ensure no **new** secrets are introduced. A baseline file lets you document the known findings so future scans only report anything that is not already in that list.

The easiest way to create a baseline is to run a normal scan with the `--manage-baseline` flag (typically at a low confidence level to capture all potential matches):

```bash
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml
```

Use the same YAML file with the `--baseline-file` option on future scans to hide all recorded findings:

```bash
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yaml
```

Running the scan again with `--manage-baseline` refreshes the baseline by adding new findings and pruning entries for secrets that no longer appear. See [docs/BASELINE.md](docs/BASELINE.md) for full detail.

## List Builtin Rules

```bash
kingfisher rules list
```

## To scan using **only** your own `my_rules.yaml` you could run:

```bash
kingfisher scan \
  --load-builtins=false \
  --rules-path path/to/my_rules.yaml \
  ./src/
```

## To add your rules alongside the built‑ins:

```bash
kingfisher scan \
  --rules-path ./custom-rules/ \
  --rules-path my_rules.yml \
  ~/path/to/project-dir/
```

## Other Examples

```bash
# Check custom rules - this ensures all regular expressions compile, and can match the rule's `examples` in the YML file
kingfisher rules check --rules-path ./my_rules.yml

# List GitHub repos
kingfisher github repos list --user my-user
kingfisher github repos list --organization my-org

```

## Notable Scan Options

- `--no-dedup`: Report every occurrence of a finding (disable the default de-duplicate behavior)
- `--confidence <LEVEL>`: (low|medium|high)
- `--min-entropy <VAL>`: Override default threshold
- `--no-binary`: Skip binary files
- `--no-extract-archives`: Do not scan inside archives
- `--extraction-depth <N>`: Specifies how deep nested archives should be extracted and scanned (default: 2)
- `--redact`: Replaces discovered secrets with a one-way hash for secure output
- `--exclude <PATTERN>`: Skip any file or directory whose path matches this glob pattern (repeatable, uses gitignore-style syntax, case sensitive)
- `--baseline-file <FILE>`: Ignore matches listed in a baseline YAML file
- `--manage-baseline`: Create or update the baseline file with current findings


## Finding Fingerprint

The document below details the four-field formula (rule SHA-1, origin label, start & end offsets) hashed with XXH3-64 to create Kingfisher’s 64-bit finding fingerprint, and explains how this ID powers safe deduplication; plus how `--no-dedup` can be used shows every raw match.
See ([docs/FINGERPRINT.md](docs/FINGERPRINT.md))

## Rule Performance Profiling

Use `--rule-stats` to collect timing information for every rule. After scanning, the summary prints a **Rule Performance Stats** section showing how many matches each rule produced along with its slowest and average match times. Useful when creating rules or debugging rules.

## CLI Options

```bash
kingfisher scan --help
```

## Business Value

By integrating Kingfisher into your development lifecycle, you can:

- **Prevent Costly Breaches**  
  Early detection of embedded credentials avoids expensive incident response, legal fees, and reputation damage
- **Automate Compliance**  
  Enforce secret‑scanning policies across GitOps, CI/CD, and pull requests to help satisfy SOC 2, PCI‑DSS, GDPR, and other standards
- **Reduce Noise, Focus on Real Threats**  
  Validation logic filters out false positives and highlights only active, valid secrets (`--only-valid`)
- **Accelerate Dev Workflows**  
  Run in parallel across dozens of languages, integrate with GitHub Actions or any pipeline, and shift security left to minimize delays

## The Risk of Leaked Secrets

Real breaches show how one exposed key can snowball into a full-scale incident:

- **Uber (2016):** GitHub-hosted AWS key let attackers access data on 57 M riders and 600 k drivers. [[BBC](https://www.bbc.com/news/technology-42075306)] [[Ars](https://arstechnica.com/tech-policy/2017/11/report-uber-paid-hackers-100000-to-keep-2016-data-breach-quiet/)]
- **AWS engineer (2020):** Pushed log files with root credentials to GitHub. [[Register](https://www.theregister.com/2020/01/23/aws_engineer_credentials_github/)] [[UpGuard](https://www.upguard.com/breaches/identity-and-access-misstep-how-an-amazon-engineer-exposed-credentials-and-more)]
- **Infosys (2023):** Full-admin AWS key left in a public PyPI package for a year. [[Stack](https://www.thestack.technology/infosys-leak-aws-key-exposed-on-pypi/)] [[Blog](https://tomforb.es/blog/infosys-leak/)]
- **Microsoft (2023):** Azure SAS token in an AI repo exposed 38 TB of internal data. [[Wiz](https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers)] [[TechCrunch](https://techcrunch.com/2023/09/18/microsoft-ai-researchers-accidentally-exposed-terabytes-of-internal-sensitive-data/)]
- **GitHub (2023):** RSA SSH host key briefly went public; company rotated it. [[GitHub](https://github.blog/news-insights/company-news/we-updated-our-rsa-ssh-host-key/)]

Leaked secrets fuel unauthorized access, lateral movement, regulatory fines, and brand-damaging incident-response costs.

# Roadmap

- More rules
- More targets
- Please file a [feature request](https://github.com/mongodb/kingfisher/issues) if you have specific features you'd like added

# License

[Apache2 License](LICENSE)

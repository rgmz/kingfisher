# Kingfisher

<p align="center">
  <img src="docs/kingfisher_logo.png" alt="Kingfisher Logo" width="126" height="173" style="vertical-align: right;" />

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Kingfisher is a blazingly fast secret‑scanning and validation tool built in Rust. It combines Intel’s hardware‑accelerated Hyperscan regex engine with language‑aware parsing via Tree‑Sitter, and **ships with hundreds of built‑in rules** to detect, validate, and triage secrets before they ever reach production

</p>

Kingfisher originated as a fork of [Nosey Parker](https://github.com/praetorian-inc/noseyparker) by Praetorian Security, Inc, and is built atop their incredible work and the work contributed by the Nosey Parker community.

Kingfisher extends Nosey Parker with live secret validation via cloud-provider APIs, augments regex detection with tree-sitter for code parsing, adds GitLab support, and builds a Windows x64 binary. 

**MongoDB Blog**: [Introducing Kingfisher: Real-Time Secret Detection and Validation](https://www.mongodb.com/blog/post/product-release-announcements/introducing-kingfisher-real-time-secret-detection-validation)

## Key Features

- **Performance**: Multi‑threaded, Hyperscan‑powered scanning for massive codebases
- **Language‑Aware Accuracy**: AST parsing in 20+ languages via Tree‑Sitter reduces contextless regex matches. see [docs/PARSING.md](/docs/PARSING.md)
- **Built-In Validation**: Hundreds of built-in detection rules, many with live-credential validators that call the relevant service APIs (AWS, Azure, GCP, Stripe, etc.) to confirm a secret is active. You can extend or override the library by adding YAML-defined rules on the command line—see [docs/RULES.md](/docs/RULES.md) for details
- **Git History Scanning**: Scan local repos, remote GitHub/GitLab orgs/users, or arbitrary GitHub/GitLab repos
- **Baseline Support:** Generate and manage baseline files to ignore known secrets and report only newly introduced ones. See ([docs/BASELINE.md](docs/BASELINE.md)) for details.

# Getting Started
## Installation

On macOS, you can simply

```bash
brew install kingfisher
```

Pre-built binaries are also available on the [Releases](https://github.com/mongodb/kingfisher/releases) section of this page.

Or you may compile for your platform via `make`:

```bash
# NOTE: Requires Docker
make linux
```

```bash
# macOS
make darwin
```

```bash
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

---

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
```

---

## Environment Variables for Tokens

| Variable          | Purpose                      |
| ----------------- | ---------------------------- |
| `KF_GITHUB_TOKEN` | GitHub Personal Access Token |
| `KF_GITLAB_TOKEN` | GitLab Personal Access Token |

Set them temporarily per command:

```bash
KF_GITLAB_TOKEN="glpat-…" kingfisher scan --gitlab-group my-group
```

Or export for the session:

```bash
export KF_GITLAB_TOKEN="glpat-…"
```

_If no token is provided Kingfisher still works for public repositories._

---

## Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |


## Install a Pre-Commit Hook

Run the provided helper script to add a hook that scans staged files before each commit:

```bash
./install-precommit-hook.sh
```

This creates `.git/hooks/pre-commit` that scans the files staged for commit with `kingfisher scan --no-update-check` and blocks the commit if any secrets are found.

### Install a Pre-Receive Hook

To check incoming pushes on a server-side repository, install the pre-receive hook:

```bash
./install-prereceive-hook.sh
```

The resulting `.git/hooks/pre-receive` script scans the files in each pushed commit and rejects the push if any secrets are detected.


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

See ([docs/BASELINE.md](docs/BASELINE.md)) for full detail.

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

# Benchmark Results

See ([docs/COMPARISON.md](docs/COMPARISON.md))


<p align="center">
  <img src="docs/runtime-comparison.png" alt="Kingfisher Runtime Comparison" style="vertical-align: center;" />
</p>


# Roadmap

- More rules
- Packages for Linux (deb, rpm)
- Please file a [feature request](https://github.com/mongodb/kingfisher/issues) if you have specific features you'd like added

# License

[Apache2 License](LICENSE)

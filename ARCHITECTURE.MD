# GuardLine — Architecture Document

## Overview

GuardLine is a GitHub Action that performs automated security scanning on pull requests. It runs entirely within GitHub Actions infrastructure, requires no external services for core functionality, and produces human-readable security reports as PR comments.

This document describes the system architecture, design decisions, and implementation plan.

---

## Design Principles

**1. Zero-friction adoption.**
A developer should go from "never heard of this" to "running on my repo" in under two minutes. No API keys, no accounts, no configuration files required for default behavior.

**2. Actionable over comprehensive.**
Every finding must include a specific remediation step. A warning without a fix is noise. GuardLine prioritizes telling you what to do over telling you everything that's wrong.

**3. Layered depth.**
The scanning engine is modular. Each scanner operates independently and can be enabled/disabled. This allows scan levels (quick/standard/deep) to simply toggle which scanners run, rather than requiring different codepaths.

**4. No data exfiltration.**
Core scanning runs entirely within the GitHub Actions runner. No code or findings are sent to external services. The optional AI-powered deep scan (v1.1+) will use API calls but will be explicitly opt-in and clearly documented.

**5. Fail-safe defaults.**
If a scanner errors out, it reports the error but does not block the PR. Security tooling that blocks deploys due to its own bugs gets ripped out fast. GuardLine should never be the reason a team removes security scanning.

---

## System Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    GitHub Actions Runner                  │
│                                                          │
│  ┌─────────────┐    ┌──────────────────────────────────┐ │
│  │  Entry Point │───▶│         Core Orchestrator        │ │
│  │  (action.yml)│    │                                  │ │
│  └─────────────┘    │  - Reads config (.guardline.yml) │ │
│                      │  - Resolves scan level           │ │
│                      │  - Dispatches to scanners        │ │
│                      │  - Aggregates results            │ │
│                      │  - Generates report              │ │
│                      └──────────┬───────────────────────┘ │
│                                 │                         │
│              ┌──────────────────┼──────────────────┐      │
│              ▼                  ▼                   ▼      │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │    Secrets     │ │  Dependency   │ │    Config     │   │
│  │    Scanner     │ │   Scanner     │ │   Auditor     │   │
│  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘   │
│          │                  │                  │           │
│          │      ┌───────────────┐ ┌───────────────┐       │
│          │      │   Pattern     │ │  Permission   │       │
│          │      │   Analyzer    │ │   Checker     │       │
│          │      └───────┬───────┘ └───────┬───────┘       │
│          │              │                  │               │
│          ▼              ▼                  ▼               │
│  ┌──────────────────────────────────────────────────┐     │
│  │              Results Aggregator                    │     │
│  │  - Deduplicates findings                          │     │
│  │  - Assigns severity (critical/warning/info)       │     │
│  │  - Attaches remediation text                      │     │
│  │  - Formats output (Markdown / SARIF)              │     │
│  └──────────────────────┬───────────────────────────┘     │
│                          │                                 │
│                          ▼                                 │
│               ┌────────────────────┐                       │
│               │   PR Comment API   │                       │
│               │  (GitHub REST API) │                       │
│               └────────────────────┘                       │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

---

## Scanner Specifications

### 1. Secrets Scanner (v0.1)

**Purpose:** Detect hardcoded credentials, API keys, tokens, and secrets.

**Approach:** Two-pass detection.
- **Pass 1 — Pattern matching.** A library of regex patterns targeting known secret formats (AWS keys, GitHub tokens, Stripe keys, generic passwords in config files, private key headers, etc.). Each pattern includes metadata: name, severity, and remediation text.
- **Pass 2 — Entropy analysis.** For strings that don't match known patterns but appear in suspicious contexts (variable assignments, config values), calculate Shannon entropy. High-entropy strings in security-sensitive contexts get flagged as potential secrets.

**Key design decisions:**
- Patterns are stored in a separate JSON/YAML file for easy community contribution.
- Each pattern has a confidence level (high/medium/low) to reduce false positives.
- Common false positives (test fixtures, example placeholders like "YOUR_API_KEY_HERE") are handled by an allowlist.

**Files scanned:** All text files in the diff, excluding binary files and paths in the ignore list.

```
secrets/
├── patterns.yml          # Regex patterns with metadata
├── allowlist.yml         # Known false positive patterns
├── entropy.py            # Shannon entropy calculator
└── scanner.py            # Main secrets scanning logic
```

### 2. Dependency Scanner (v0.2)

**Purpose:** Check project dependencies against known vulnerability databases.

**Approach:**
- Parse lockfiles (package-lock.json, yarn.lock, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock).
- Extract package names and versions.
- Query the OSV (Open Source Vulnerabilities) database API for known CVEs.
- Map findings to severity levels based on CVSS scores.

**Key design decisions:**
- OSV is used over NVD directly because it provides better package-level mapping and is free with no API key required.
- Results are cached per lockfile hash to avoid redundant API calls across scans.
- Only dependencies that changed in the PR are highlighted, but the full scan runs for context.

```
dependencies/
├── parsers/
│   ├── npm.py            # package-lock.json parser
│   ├── pip.py            # Pipfile.lock / requirements.txt parser
│   ├── go.py             # go.sum parser
│   ├── cargo.py          # Cargo.lock parser
│   └── ruby.py           # Gemfile.lock parser
├── osv_client.py         # OSV API integration
└── scanner.py            # Main dependency scanning logic
```

### 3. Config Auditor (v0.3)

**Purpose:** Identify insecure configurations in infrastructure and deployment files.

**Approach:** Rule-based analysis against a library of known misconfigurations.

**Coverage:**
- **Dockerfiles** — Running as root, using latest tag, exposing unnecessary ports, missing health checks.
- **nginx/Apache** — Missing security headers, directory listing enabled, TLS misconfigurations.
- **Terraform/CloudFormation** — Public S3 buckets, overly permissive IAM policies, unencrypted resources.
- **CI/CD configs** — Secrets in plaintext, overly permissive triggers, missing pin versions on actions.

```
config/
├── rules/
│   ├── docker.yml
│   ├── nginx.yml
│   ├── terraform.yml
│   └── cicd.yml
├── rule_engine.py        # Evaluates rules against file content
└── scanner.py            # Main config scanning logic
```

### 4. Code Pattern Analyzer (v0.4)

**Purpose:** Detect dangerous code patterns that commonly lead to vulnerabilities.

**Approach:** Language-specific analysis using a combination of regex and lightweight AST parsing where available.

**Patterns detected:**
- SQL injection vectors (string concatenation in queries).
- Command injection (unsanitized input passed to shell commands).
- Path traversal (user input in file paths without sanitization).
- Insecure deserialization (pickle.loads, eval, unserialize with user input).
- Weak cryptographic usage (MD5/SHA1 for security purposes, ECB mode, hardcoded IVs).
- Missing input validation on API endpoints.
- SSRF patterns (user-controlled URLs in HTTP requests).

**Key design decisions:**
- Python's `ast` module is used for Python analysis. For JavaScript, a regex-based approach is used initially with tree-sitter integration planned for later versions.
- Each pattern includes a confidence level. Low-confidence findings are shown as "info" rather than "warning" to reduce noise.

```
patterns/
├── rules/
│   ├── python.yml
│   ├── javascript.yml
│   └── go.yml
├── analyzers/
│   ├── python_ast.py     # AST-based analysis for Python
│   ├── js_regex.py       # Regex-based analysis for JS
│   └── go_regex.py       # Regex-based analysis for Go
└── scanner.py            # Main pattern scanning logic
```

### 5. Permission Checker (v0.4)

**Purpose:** Detect overly permissive file permissions and exposed access points.

**Approach:**
- Check file permissions on scripts and config files (world-readable secrets, executable configs).
- Detect exposed debug/admin endpoints in route definitions.
- Flag overly permissive CORS configurations.
- Identify missing authentication on sensitive endpoints.

```
permissions/
├── file_perms.py         # File permission analysis
├── endpoint_audit.py     # Route/endpoint analysis
└── scanner.py            # Main permission scanning logic
```

---

## Core Orchestrator

The orchestrator is the central coordination layer.

```python
# Simplified orchestrator flow

def run_guardline(config):
    # 1. Determine which files changed in the PR
    changed_files = get_pr_diff()

    # 2. Resolve scan level and enabled scanners
    scanners = resolve_scanners(config.scan_level, config.scanners)

    # 3. Run each scanner independently
    all_findings = []
    for scanner in scanners:
        try:
            findings = scanner.scan(changed_files, config)
            all_findings.extend(findings)
        except ScannerError as e:
            all_findings.append(Finding(
                severity="info",
                message=f"Scanner '{scanner.name}' encountered an error: {e}",
                remediation="This is a GuardLine issue, not a code issue."
            ))

    # 4. Aggregate, deduplicate, and sort by severity
    report = aggregate_findings(all_findings)

    # 5. Post as PR comment
    post_pr_comment(report)

    # 6. Set exit code based on thresholds
    return evaluate_thresholds(report, config.thresholds)
```

---

## Data Model

### Finding

Every scanner produces `Finding` objects with a consistent schema:

```python
@dataclass
class Finding:
    scanner: str          # Which scanner produced this ("secrets", "dependencies", etc.)
    severity: str         # "critical", "warning", "info"
    confidence: str       # "high", "medium", "low"
    file: str             # File path relative to repo root
    line: int | None      # Line number (if applicable)
    title: str            # Short description ("Hardcoded AWS Secret Key")
    detail: str           # Longer explanation of why this is a problem
    remediation: str      # Specific fix ("Move to environment variable AWS_SECRET_ACCESS_KEY")
    pattern_id: str       # Unique ID for this rule (for suppressions)
    metadata: dict        # Scanner-specific data (CVE ID, entropy score, etc.)
```

### Report

```python
@dataclass
class Report:
    findings: list[Finding]
    summary: ReportSummary
    scan_duration: float
    scan_level: str
    files_scanned: int
    guardline_version: str

@dataclass
class ReportSummary:
    critical: int
    warning: int
    info: int
    passed: int
```

---

## Directory Structure

```
guardline/
├── action.yml                    # GitHub Action definition
├── Dockerfile                    # Container for running in Actions
├── .guardline.yml                # Default configuration
├── README.md
├── CONTRIBUTING.md
├── LICENSE
│
├── src/
│   ├── __init__.py
│   ├── main.py                   # Entry point
│   ├── orchestrator.py           # Core orchestration logic
│   ├── config.py                 # Configuration loader
│   ├── models.py                 # Finding, Report data models
│   ├── reporter.py               # Markdown/SARIF report generation
│   ├── github_api.py             # PR comment posting
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py               # Base scanner interface
│   │   ├── secrets/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py
│   │   │   ├── patterns.yml
│   │   │   ├── allowlist.yml
│   │   │   └── entropy.py
│   │   ├── dependencies/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py
│   │   │   ├── osv_client.py
│   │   │   └── parsers/
│   │   ├── config/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py
│   │   │   └── rules/
│   │   ├── patterns/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py
│   │   │   └── analyzers/
│   │   └── permissions/
│   │       ├── __init__.py
│   │       └── scanner.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── git.py                # Git diff utilities
│       ├── file_utils.py         # File reading, filtering
│       └── logging.py            # Structured logging
│
├── tests/
│   ├── __init__.py
│   ├── fixtures/                 # Intentionally vulnerable test files
│   │   ├── secrets/
│   │   ├── vulnerable_deps/
│   │   ├── bad_configs/
│   │   └── dangerous_patterns/
│   ├── test_secrets_scanner.py
│   ├── test_dependency_scanner.py
│   ├── test_config_auditor.py
│   ├── test_pattern_analyzer.py
│   ├── test_permission_checker.py
│   ├── test_orchestrator.py
│   └── test_reporter.py
│
└── docs/
    ├── ARCHITECTURE.md           # This document
    ├── PATTERNS.md               # Full list of detection patterns
    └── ADDING_RULES.md           # Guide for contributing new rules
```

---

## Technology Stack

- **Language:** Python 3.11+
- **Execution:** GitHub Actions (Docker container action)
- **External APIs:** OSV (dependency vulnerabilities), GitHub REST API (PR comments)
- **Testing:** pytest
- **Linting:** ruff
- **CI:** GuardLine scans itself (dogfooding)

---

## Build & Release Plan

### v0.1 — Secrets Detection (Target: June 2026)
- Secrets scanner with regex patterns + entropy analysis
- Core orchestrator and report generator
- GitHub Action packaging and PR comment posting
- Test suite with intentionally vulnerable fixtures
- README and documentation

### v0.2 — Dependency Scanning (Target: July 2026)
- Lockfile parsers (npm, pip, go, cargo, ruby)
- OSV API integration
- CVSS-based severity mapping

### v0.3 — Config Auditing (Target: August 2026)
- Rule engine for infrastructure config files
- Docker, nginx, Terraform, CI/CD rule sets

### v0.4 — Code Pattern Analysis (Target: September 2026)
- Python AST-based scanning
- JavaScript regex-based scanning
- Permission and endpoint auditing

### v0.5 — Custom Rules (Target: October 2026)
- User-defined pattern support via .guardline.yml
- Suppression comments (inline ignore directives)

### v1.0 — Stable Release (Target: November 2026)
- Full documentation
- Performance optimization
- Community feedback incorporated

### v1.1 — AI-Powered Deep Scan (Target: December 2026)
- Optional AI analysis for contextual understanding
- Requires opt-in API key configuration
- Explains findings in plain English with full context

---

## Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| Python over Go/Rust | Faster development, easier community contributions, sufficient performance for CI scanning |
| Docker container action | Consistent environment, no dependency on runner's installed packages |
| Modular scanner architecture | Each scanner is independent — easy to add, test, and disable individually |
| Findings include remediation | Security warnings without fixes create frustration, not security |
| Fail-safe on scanner errors | A broken scanner should not block a PR — that gets tools removed |
| OSV over NVD | Better package-level mapping, no API key required, faster response |
| PR comments over status checks | More visible, more informative, lower friction to adopt |
| Entropy analysis for secrets | Catches credentials that don't match known patterns |
| Scan only PR diff by default | Faster scans, more relevant findings, less noise on large repos |

---

## Security Considerations

GuardLine itself must be secure. It runs inside CI pipelines with access to source code.

- **No outbound data for core scans.** Only the dependency scanner makes external API calls (to OSV), and only sends package names and versions, never source code.
- **No secrets stored.** GuardLine uses the GitHub Actions token provided by the runner, no additional credentials required.
- **Finding content is sanitized.** Detected secrets are partially redacted in PR comments to avoid exposing them in the comment itself.
- **Action is pinned.** Users pin to a specific version tag, not a branch, to prevent supply chain attacks.
- **The tool scans itself.** GuardLine runs on its own PRs as part of CI.
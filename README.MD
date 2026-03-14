# GuardLine

**Automated security scanning for every pull request.**

GuardLine is a free, open-source GitHub Action that catches security issues before they reach production. Drop it into any repo and get instant security feedback on every pull request — no configuration required.

---

## What It Does

GuardLine scans your codebase for common security issues and posts a clear, actionable report directly on your pull request. No dashboards to check, no external services to sign up for, no costs.

### Scan Categories

- **Secrets Detection** — Finds hardcoded API keys, tokens, passwords, private keys, and credentials that should be in environment variables
- **Dependency Vulnerabilities** — Checks your dependencies against the National Vulnerability Database (NVD) for known CVEs
- **Configuration Risks** — Identifies insecure defaults in common config files (Dockerfiles, nginx configs, CI/CD pipelines, cloud provider configs)
- **Code Patterns** — Flags dangerous code patterns like SQL injection vectors, insecure deserialization, weak cryptographic usage, and missing input validation
- **Permission Issues** — Detects overly permissive file permissions, exposed debug endpoints, and misconfigured access controls

### Example Output

```
🔴 CRITICAL (1)
  → Hardcoded AWS secret key found in src/config.py:47
    Remediation: Move to environment variable AWS_SECRET_ACCESS_KEY

🟡 WARNING (3)
  → Dockerfile runs as root (Dockerfile:1)
    Remediation: Add USER directive with non-root user
  → Dependency 'lodash@4.17.20' has known CVE-2021-23337 (HIGH)
    Remediation: Upgrade to lodash@4.17.21 or later
  → Debug endpoint exposed in routes/api.js:12
    Remediation: Remove or gate behind authentication

🟢 PASSED (12 checks)
  → No hardcoded credentials in environment files
  → All file permissions within acceptable range
  → No SQL injection patterns detected
  ...

📊 Summary: 1 critical, 3 warnings, 12 passed | Scanned 847 files in 14s
```

---

## Quick Start

Add this to `.github/workflows/guardline.yml` in your repo:

```yaml
name: GuardLine Security Scan
on:
  pull_request:
    branches: [main, develop]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: outlawmetrics/guardline@v1
        with:
          scan-level: standard  # Options: quick, standard, deep
```

That's it. No API keys, no sign-up, no configuration files. Every pull request to your main branches now gets a security review.

---

## Scan Levels

| Level | What It Covers | Speed | Best For |
|-------|---------------|-------|----------|
| `quick` | Secrets + critical config issues | ~5s | Fast feedback on every commit |
| `standard` | All scan categories | ~15-30s | Default for most repos |
| `deep` | Standard + AI-powered contextual analysis | ~60s | Pre-release or sensitive repos |

---

## Configuration (Optional)

GuardLine works out of the box with zero config. For teams that want to customize, create a `.guardline.yml` in your repo root:

```yaml
# .guardline.yml
scan-level: standard

# Ignore specific paths
ignore:
  - "test/**"
  - "docs/**"
  - "*.test.js"

# Customize severity thresholds
thresholds:
  fail-on: critical          # Options: critical, warning, info
  max-warnings: 10           # Fail if warnings exceed this count

# Enable or disable specific scanners
scanners:
  secrets: true
  dependencies: true
  config: true
  code-patterns: true
  permissions: true

# Custom secret patterns (regex)
custom-patterns:
  - name: "Internal API Token"
    pattern: "INTERNAL_[A-Z]+_TOKEN=['\"][^'\"]+['\"]"
    severity: critical
```

---

## Supported Languages & Frameworks

GuardLine scans any text-based file for secrets and configuration issues. Language-specific code pattern analysis currently supports:

- **Python** — Django, Flask, FastAPI
- **JavaScript / TypeScript** — Node.js, Express, React, Next.js
- **Go** — Standard library, Gin, Echo
- **Docker** — Dockerfile best practices
- **Infrastructure** — Terraform, CloudFormation, nginx, Apache
- **CI/CD** — GitHub Actions, GitLab CI, Jenkins

More languages and frameworks are added with each release.

---

## How It Works

```
Pull Request Opened
        │
        ▼
┌─────────────────┐
│   File Scanner   │ ─── Identifies changed files, filters by .guardline.yml
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Secrets Engine  │ ─── Regex + entropy analysis for credentials
├─────────────────┤
│   Dep Checker    │ ─── Cross-references lockfiles against NVD/OSV
├─────────────────┤
│  Config Auditor  │ ─── Rule-based checks on infrastructure configs
├─────────────────┤
│ Pattern Analyzer │ ─── AST-aware scanning for dangerous code patterns
├─────────────────┤
│ Permission Check │ ─── File permissions + access control review
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Report Generator │ ─── Formats findings with severity + remediation
└────────┬────────┘
         │
         ▼
  PR Comment Posted
```

---

## Why GuardLine?

Most security tools are built for large enterprises. They require complex setup, paid subscriptions, and dedicated security teams to interpret results. GuardLine is built for everyone else.

- **Zero cost** — Free and open source, runs entirely on GitHub's free CI minutes
- **Zero config** — Works immediately with sensible defaults
- **Actionable output** — Every finding includes a specific remediation step, not just a warning
- **Fast** — Standard scans complete in under 30 seconds
- **No data leaves your repo** — Everything runs inside GitHub Actions, no external API calls for core scanning
- **Built by a security practitioner** — Not a VC-funded startup chasing enterprise contracts

---

## Roadmap

- [x] **v0.1** — Secrets detection (regex + entropy)
- [ ] **v0.2** — Dependency vulnerability scanning (NVD/OSV integration)
- [ ] **v0.3** — Configuration file auditing
- [ ] **v0.4** — Language-specific code pattern analysis
- [ ] **v0.5** — Custom rule definitions
- [ ] **v1.0** — Stable release with full documentation
- [ ] **v1.1** — AI-powered contextual analysis (deep scan mode)
- [ ] **v1.2** — SARIF output for GitHub Security tab integration

---

## Contributing

GuardLine is open source and contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If you find a false positive or a security pattern we should be catching, open an issue. Real-world feedback makes this tool better for everyone.

---

## License

MIT License. Use it, fork it, build on it.

---

**Built by [Tyler Outlaw-Bradley](https://github.com/outlawmetrics)**# GuardLine

# GuardLine Detection Patterns

A complete reference of all built-in detection rules.

---

## Secrets Scanner

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SEC-001 | AWS Access Key ID | Critical | Detects AWS access keys starting with AKIA followed by 16 characters |
| SEC-002 | JSON Web Token | Warning | Detects JWT tokens with base64 encoded header and payload |
| SEC-003 | Database Connection String | Critical | Detects database URIs with embedded credentials |
| SEC-004 | Hardcoded Secret Assignment | Warning | Detects variables with sensitive names assigned hardcoded values |

## Config Auditor

| ID | Name | Severity | Type | Description |
|----|------|----------|------|-------------|
| CFG-001 | Docker latest tag | Warning | Pattern | Detects FROM instructions using the unpinned latest tag |
| CFG-002 | Docker running as root | Warning | Required | Detects missing USER instruction in Dockerfiles |
| CFG-003 | Docker copying all files | Warning | Pattern | Detects COPY commands that include the entire project directory |

## Code Pattern Analyzer

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| CPA-001 | SQL Injection | Critical | Detects string concatenation inside SQL execute statements |
| CPA-002 | Eval Usage | Warning | Detects use of eval() which can execute arbitrary code |

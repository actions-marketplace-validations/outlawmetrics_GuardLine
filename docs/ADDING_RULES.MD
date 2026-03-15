# Guardline Custom Rule Implementation

A complete guide to add custom rules & patterns to Guardline.

---

## Selecting which file to edit

If you want to add a new secret detection rule, edit:

`src/scanners/secrets/patterns.yml`

If you want to add a new configuration audit rule, edit:

`src/scanners/config/rules.yml`

If you want to add a new code pattern analysis rule, edit:

`src/scanners/patterns/rules.yml`

## What format to follow

### Secrets pattern format
```yaml
  - id: "SEC-005"
    name: "Your pattern name"
    pattern: "your_regex_here"
    severity: "critical"
    confidence: "high"
    description: "What this pattern detects"
    remediation: "How to fix it"
```

### Config audit format — pattern type
```yaml
  - id: "CFG-004"
    name: "Your rule name"
    file_pattern: "Dockerfile"
    type: "pattern"
    pattern: "your_regex_here"
    severity: "warning"
    description: "What insecure configuration this detects"
    remediation: "How to fix it"
```

### Config audit format — required type
```yaml
  - id: "CFG-005"
    name: "Your rule name"
    file_pattern: "Dockerfile"
    type: "required"
    required: "KEYWORD"
    severity: "warning"
    description: "What required keyword is missing"
    remediation: "How to add it"
```

### Code pattern format
```yaml
  - id: "CPA-003"
    name: "Your pattern name"
    pattern: "your_regex_here"
    severity: "critical"
    confidence: "high"
    description: "What dangerous code pattern this detects"
    remediation: "How to fix it"
```
## How to test

1. Create a test file in the appropriate `tests/fixtures/` directory with code that should trigger your new rule.

2. Add the path to your test file in `src/main.py`:
```python
test_files = ["your/test/file/here.py"]
```

3. Run GuardLine from the project root:
```bash
python -m src.main
```

4. Verify that your new rule appears in the output with the correct severity, title, and remediation.

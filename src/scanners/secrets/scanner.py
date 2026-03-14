import re
import yaml
from src.scanners.base import BaseScanner
from src.models import Finding

class SecretsScanner(BaseScanner):    

    def __init__(self):
        self.patterns = self._load_patterns()

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Detects hardcoded credentials, API keys, tokens, and secrets in source code"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".cfg", ".conf", ".toml", ".xml", ".sh"]

    def _load_patterns(self):
        with open("src/scanners/secrets/patterns.yml", "r") as f:
            data = yaml.safe_load(f)
        return data["patterns"]

    def scan(self, changed_files: list[str], config: dict) -> list[Finding]:
        findings = []

        for file_path in changed_files:
            if not any(file_path.endswith(ext) for ext in self.supported_file_extensions):
                continue

            try:
                with open(file_path, "r") as f:
                    lines = f.readlines()
            except (IOError, UnicodeDecodeError):
                continue

            for line_number, line in enumerate(lines, start=1):
                for pattern in self.patterns:
                    if re.search(pattern["pattern"], line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=pattern["severity"],
                            confidence=pattern["confidence"],
                            file=file_path,
                            line=line_number,
                            title=pattern["name"],
                            detail=pattern["description"],
                            remediation=pattern["remediation"],
                            pattern_id=pattern["id"],
                            metadata={"matched_line": line.strip()}
                        ))

        return findings


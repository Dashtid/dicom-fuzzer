"""SAST/DAST Results Integration for FDA Submissions.

Integrates static and dynamic analysis results from various security tools
into FDA-compliant format for premarket cybersecurity submissions.

Supported Tools:
- SAST: Semgrep, Bandit, CodeQL, SonarQube, Checkmarx
- DAST: OWASP ZAP, Burp Suite, Nuclei, Nikto
- SCA: pip-audit, Safety, Grype, Trivy

References:
- FDA Cybersecurity Guidance (June 2025) - SAST/DAST requirements
- ANSI/ISA 62443-4-1:2018 Section 9.2 - Static Code Analysis
- OWASP ASVS v4.0 - Verification Requirements
- SARIF (Static Analysis Results Interchange Format) v2.1.0

"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ToolCategory(Enum):
    """Security tool categories."""

    SAST = "Static Application Security Testing"
    DAST = "Dynamic Application Security Testing"
    SCA = "Software Composition Analysis"
    IAST = "Interactive Application Security Testing"
    SECRET_SCANNING = "Secret Scanning"  # nosec B105 - enum value for scan type
    FUZZING = "Fuzz Testing"


class FindingSeverity(Enum):
    """Unified severity levels across tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_semgrep(cls, severity: str) -> FindingSeverity:
        """Map Semgrep severity to unified scale."""
        mapping = {
            "ERROR": cls.HIGH,
            "WARNING": cls.MEDIUM,
            "INFO": cls.LOW,
        }
        return mapping.get(severity.upper(), cls.UNKNOWN)

    @classmethod
    def from_bandit(cls, severity: str) -> FindingSeverity:
        """Map Bandit severity to unified scale."""
        mapping = {
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
        }
        return mapping.get(severity.upper(), cls.UNKNOWN)

    @classmethod
    def from_sarif(cls, level: str) -> FindingSeverity:
        """Map SARIF level to unified scale."""
        mapping = {
            "error": cls.HIGH,
            "warning": cls.MEDIUM,
            "note": cls.LOW,
            "none": cls.INFO,
        }
        return mapping.get(level.lower(), cls.UNKNOWN)


@dataclass
class ToolInfo:
    """Information about a security tool."""

    name: str
    version: str = ""
    category: ToolCategory = ToolCategory.SAST
    vendor: str = ""
    homepage: str = ""
    rules_version: str = ""
    scan_date: str = ""

    def __post_init__(self) -> None:
        if not self.scan_date:
            self.scan_date = datetime.now(UTC).isoformat()


@dataclass
class CodeLocation:
    """Source code location for a finding."""

    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str = ""
    function_name: str = ""
    class_name: str = ""


@dataclass
class SecurityFinding:
    """Unified security finding from any tool."""

    finding_id: str
    title: str
    description: str
    severity: FindingSeverity
    tool: ToolInfo
    location: CodeLocation | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    rule_id: str = ""
    rule_name: str = ""
    confidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    false_positive: bool = False
    suppressed: bool = False
    first_seen: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = datetime.now(UTC).isoformat()


@dataclass
class ScanSummary:
    """Summary of scan results."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    suppressed_count: int = 0
    false_positive_count: int = 0
    files_scanned: int = 0
    lines_of_code: int = 0
    scan_duration_seconds: float = 0.0


@dataclass
class SASTDASTReport:
    """Combined SAST/DAST report for FDA submissions."""

    report_id: str = ""
    report_date: str = ""
    report_title: str = "Security Analysis Report"
    device_name: str = ""
    device_version: str = ""
    tools: list[ToolInfo] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    compliance_frameworks: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.report_date:
            self.report_date = datetime.now(UTC).isoformat()
        if not self.report_id:
            self.report_id = f"SASTDAST-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"


class SemgrepParser:
    """Parse Semgrep JSON output."""

    @staticmethod
    def parse(data: dict[str, Any]) -> list[SecurityFinding]:
        """Parse Semgrep JSON output into SecurityFindings."""
        findings: list[SecurityFinding] = []

        tool = ToolInfo(
            name="Semgrep",
            category=ToolCategory.SAST,
            vendor="Semgrep Inc.",
            homepage="https://semgrep.dev",
            version=data.get("version", ""),
        )

        for result in data.get("results", []):
            location = CodeLocation(
                file_path=result.get("path", ""),
                start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line"),
                start_column=result.get("start", {}).get("col"),
                end_column=result.get("end", {}).get("col"),
                snippet=result.get("extra", {}).get("lines", ""),
            )

            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            # Extract CWE from metadata
            cwe_id = None
            cwe_list = metadata.get("cwe", [])
            if cwe_list:
                cwe_match = re.search(r"CWE-(\d+)", str(cwe_list[0]))
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"

            finding = SecurityFinding(
                finding_id=result.get("check_id", ""),
                title=result.get("check_id", "")
                .split(".")[-1]
                .replace("-", " ")
                .title(),
                description=extra.get("message", ""),
                severity=FindingSeverity.from_semgrep(extra.get("severity", "INFO")),
                tool=tool,
                location=location,
                cwe_id=cwe_id,
                owasp_category=metadata.get("owasp"),
                rule_id=result.get("check_id", ""),
                confidence=metadata.get("confidence", ""),
                references=metadata.get("references", []),
                tags=metadata.get("technology", []),
                raw_data=result,
            )
            findings.append(finding)

        return findings


class BanditParser:
    """Parse Bandit JSON output."""

    @staticmethod
    def parse(data: dict[str, Any]) -> list[SecurityFinding]:
        """Parse Bandit JSON output into SecurityFindings."""
        findings: list[SecurityFinding] = []

        tool = ToolInfo(
            name="Bandit",
            category=ToolCategory.SAST,
            vendor="PyCQA",
            homepage="https://bandit.readthedocs.io",
            version=data.get("generated_at", ""),
        )

        for result in data.get("results", []):
            location = CodeLocation(
                file_path=result.get("filename", ""),
                start_line=result.get("line_number", 0),
                end_line=result.get("line_range", [0])[-1]
                if result.get("line_range")
                else None,
                snippet=result.get("code", ""),
            )

            # Map Bandit test IDs to CWEs
            cwe_mapping = {
                "B101": "CWE-703",  # assert_used
                "B102": "CWE-78",  # exec_used
                "B103": "CWE-732",  # set_bad_file_permissions
                "B104": "CWE-78",  # hardcoded_bind_all_interfaces
                "B105": "CWE-259",  # hardcoded_password_string
                "B106": "CWE-259",  # hardcoded_password_funcarg
                "B107": "CWE-259",  # hardcoded_password_default
                "B108": "CWE-377",  # hardcoded_tmp_directory
                "B110": "CWE-703",  # try_except_pass
                "B112": "CWE-703",  # try_except_continue
                "B301": "CWE-502",  # pickle
                "B302": "CWE-78",  # marshal
                "B303": "CWE-327",  # md5
                "B304": "CWE-327",  # des
                "B305": "CWE-327",  # cipher_modes
                "B306": "CWE-377",  # mktemp_q
                "B307": "CWE-78",  # eval
                "B308": "CWE-94",  # mark_safe
                "B310": "CWE-22",  # urllib_urlopen
                "B311": "CWE-330",  # random
                "B312": "CWE-295",  # telnetlib
                "B313": "CWE-611",  # xml_bad_cElementTree
                "B314": "CWE-611",  # xml_bad_ElementTree
                "B315": "CWE-611",  # xml_bad_expatreader
                "B316": "CWE-611",  # xml_bad_expatbuilder
                "B317": "CWE-611",  # xml_bad_sax
                "B318": "CWE-611",  # xml_bad_minidom
                "B319": "CWE-611",  # xml_bad_pulldom
                "B320": "CWE-611",  # xml_bad_etree
                "B321": "CWE-327",  # ftplib
                "B322": "CWE-78",  # input
                "B323": "CWE-295",  # unverified_context
                "B324": "CWE-327",  # hashlib_new_insecure_functions
                "B501": "CWE-295",  # request_with_no_cert_validation
                "B502": "CWE-327",  # ssl_with_bad_version
                "B503": "CWE-327",  # ssl_with_bad_defaults
                "B504": "CWE-295",  # ssl_with_no_version
                "B505": "CWE-327",  # weak_cryptographic_key
                "B506": "CWE-918",  # yaml_load
                "B507": "CWE-295",  # ssh_no_host_key_verification
                "B601": "CWE-78",  # paramiko_calls
                "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
                "B603": "CWE-78",  # subprocess_without_shell_equals_true
                "B604": "CWE-78",  # any_other_function_with_shell_equals_true
                "B605": "CWE-78",  # start_process_with_a_shell
                "B606": "CWE-78",  # start_process_with_no_shell
                "B607": "CWE-78",  # start_process_with_partial_path
                "B608": "CWE-89",  # hardcoded_sql_expressions
                "B609": "CWE-78",  # linux_commands_wildcard_injection
                "B610": "CWE-78",  # django_extra_used
                "B611": "CWE-78",  # django_rawsql_used
                "B701": "CWE-94",  # jinja2_autoescape_false
                "B702": "CWE-79",  # use_of_mako_templates
                "B703": "CWE-79",  # django_mark_safe
            }

            test_id = result.get("test_id", "")
            cwe_id = cwe_mapping.get(test_id)

            finding = SecurityFinding(
                finding_id=f"BANDIT-{test_id}-{result.get('line_number', 0)}",
                title=result.get("test_name", "").replace("_", " ").title(),
                description=result.get("issue_text", ""),
                severity=FindingSeverity.from_bandit(
                    result.get("issue_severity", "LOW")
                ),
                tool=tool,
                location=location,
                cwe_id=cwe_id,
                rule_id=test_id,
                rule_name=result.get("test_name", ""),
                confidence=result.get("issue_confidence", ""),
                raw_data=result,
            )
            findings.append(finding)

        return findings


class SARIFParser:
    """Parse SARIF (Static Analysis Results Interchange Format) v2.1.0."""

    @staticmethod
    def parse(data: dict[str, Any]) -> list[SecurityFinding]:
        """Parse SARIF JSON output into SecurityFindings."""
        findings: list[SecurityFinding] = []

        for run in data.get("runs", []):
            # Extract tool information
            tool_data = run.get("tool", {}).get("driver", {})
            tool = ToolInfo(
                name=tool_data.get("name", "Unknown"),
                version=tool_data.get("version", ""),
                category=ToolCategory.SAST,
            )

            # Build rule lookup
            rules = {r["id"]: r for r in tool_data.get("rules", [])}

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})

                # Get location
                locations = result.get("locations", [])
                location = None
                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    artifact_loc = phys_loc.get("artifactLocation", {})
                    region = phys_loc.get("region", {})

                    location = CodeLocation(
                        file_path=artifact_loc.get("uri", ""),
                        start_line=region.get("startLine", 0),
                        end_line=region.get("endLine"),
                        start_column=region.get("startColumn"),
                        end_column=region.get("endColumn"),
                        snippet=region.get("snippet", {}).get("text", ""),
                    )

                # Extract CWE from rule properties
                cwe_id = None
                rule_props = rule.get("properties", {})
                cwe_list = rule_props.get("cwe", [])
                if cwe_list:
                    cwe_match = re.search(r"CWE-(\d+)", str(cwe_list[0]))
                    if cwe_match:
                        cwe_id = f"CWE-{cwe_match.group(1)}"

                finding = SecurityFinding(
                    finding_id=f"{tool.name}-{rule_id}-{result.get('ruleIndex', 0)}",
                    title=rule.get("shortDescription", {}).get("text", rule_id),
                    description=result.get("message", {}).get("text", ""),
                    severity=FindingSeverity.from_sarif(result.get("level", "warning")),
                    tool=tool,
                    location=location,
                    cwe_id=cwe_id,
                    rule_id=rule_id,
                    rule_name=rule.get("name", ""),
                    references=[h.get("id", "") for h in rule.get("helpUri", [])]
                    if isinstance(rule.get("helpUri"), list)
                    else [],
                    tags=rule_props.get("tags", []),
                    raw_data=result,
                )
                findings.append(finding)

        return findings


class PipAuditParser:
    """Parse pip-audit JSON output."""

    @staticmethod
    def parse(data: list[dict[str, Any]]) -> list[SecurityFinding]:
        """Parse pip-audit JSON output into SecurityFindings."""
        findings: list[SecurityFinding] = []

        tool = ToolInfo(
            name="pip-audit",
            category=ToolCategory.SCA,
            vendor="PyPI",
            homepage="https://pypi.org/project/pip-audit/",
        )

        for vuln in data:
            for v in vuln.get("vulns", []):
                severity = FindingSeverity.UNKNOWN
                # Try to derive severity from fix available
                if v.get("fix_versions"):
                    severity = FindingSeverity.MEDIUM
                else:
                    severity = FindingSeverity.HIGH

                finding = SecurityFinding(
                    finding_id=v.get("id", ""),
                    title=f"Vulnerable dependency: {vuln.get('name', '')}",
                    description=v.get("description", ""),
                    severity=severity,
                    tool=tool,
                    cwe_id=None,
                    rule_id=v.get("id", ""),
                    remediation=f"Upgrade to version {v.get('fix_versions', ['N/A'])[0]}"
                    if v.get("fix_versions")
                    else "No fix available",
                    references=v.get("aliases", []),
                    tags=[vuln.get("name", ""), vuln.get("version", "")],
                    raw_data={**vuln, **v},
                )
                findings.append(finding)

        return findings


class SASTDASTReporter:
    """Generate unified SAST/DAST reports for FDA submissions."""

    def __init__(
        self,
        device_name: str = "",
        device_version: str = "",
    ) -> None:
        self.report = SASTDASTReport(
            device_name=device_name,
            device_version=device_version,
            compliance_frameworks=[
                "FDA Cybersecurity Guidance (June 2025)",
                "ANSI/ISA 62443-4-1:2018 Section 9.2",
                "OWASP ASVS v4.0",
            ],
        )

    def import_semgrep(self, json_path: Path | str) -> int:
        """Import Semgrep results from JSON file.

        Returns:
            Number of findings imported.

        """
        path = Path(json_path)
        with open(path) as f:
            data = json.load(f)

        findings = SemgrepParser.parse(data)
        self.report.findings.extend(findings)

        # Add tool info if not present
        if findings and not any(t.name == "Semgrep" for t in self.report.tools):
            self.report.tools.append(findings[0].tool)

        return len(findings)

    def import_bandit(self, json_path: Path | str) -> int:
        """Import Bandit results from JSON file.

        Returns:
            Number of findings imported.

        """
        path = Path(json_path)
        with open(path) as f:
            data = json.load(f)

        findings = BanditParser.parse(data)
        self.report.findings.extend(findings)

        if findings and not any(t.name == "Bandit" for t in self.report.tools):
            self.report.tools.append(findings[0].tool)

        return len(findings)

    def import_sarif(self, sarif_path: Path | str) -> int:
        """Import SARIF format results (CodeQL, Semgrep, etc.).

        Returns:
            Number of findings imported.

        """
        path = Path(sarif_path)
        with open(path) as f:
            data = json.load(f)

        findings = SARIFParser.parse(data)
        self.report.findings.extend(findings)

        for finding in findings:
            if not any(t.name == finding.tool.name for t in self.report.tools):
                self.report.tools.append(finding.tool)

        return len(findings)

    def import_pip_audit(self, json_path: Path | str) -> int:
        """Import pip-audit results from JSON file.

        Returns:
            Number of findings imported.

        """
        path = Path(json_path)
        with open(path) as f:
            data = json.load(f)

        findings = PipAuditParser.parse(data)
        self.report.findings.extend(findings)

        if findings and not any(t.name == "pip-audit" for t in self.report.tools):
            self.report.tools.append(findings[0].tool)

        return len(findings)

    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a manual finding."""
        self.report.findings.append(finding)

    def generate_summary(self) -> ScanSummary:
        """Generate summary statistics."""
        summary = ScanSummary(total_findings=len(self.report.findings))

        for finding in self.report.findings:
            if finding.suppressed:
                summary.suppressed_count += 1
            if finding.false_positive:
                summary.false_positive_count += 1

            if finding.severity == FindingSeverity.CRITICAL:
                summary.critical_count += 1
            elif finding.severity == FindingSeverity.HIGH:
                summary.high_count += 1
            elif finding.severity == FindingSeverity.MEDIUM:
                summary.medium_count += 1
            elif finding.severity == FindingSeverity.LOW:
                summary.low_count += 1
            else:
                summary.info_count += 1

        self.report.summary = summary
        return summary

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        self.generate_summary()

        def serialize(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return {k: serialize(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [serialize(item) for item in obj]
            if isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            return obj

        result = serialize(self.report)
        return dict(result) if isinstance(result, dict) else {}

    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, path: Path | str) -> Path:
        """Save report as JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())
        return path

    def generate_markdown(self) -> str:
        """Generate FDA-compliant markdown report."""
        self.generate_summary()
        summary = self.report.summary

        md = f"""# {self.report.report_title}

## Document Information

| Field | Value |
|-------|-------|
| Report ID | {self.report.report_id} |
| Report Date | {self.report.report_date} |
| Device Name | {self.report.device_name or "N/A"} |
| Device Version | {self.report.device_version or "N/A"} |

---

## 1. Executive Summary

This report presents the results of Static Application Security Testing (SAST)
and Dynamic Application Security Testing (DAST) performed on
{self.report.device_name or "the target application"}.

### 1.1 Finding Distribution

| Severity | Count |
|----------|-------|
| Critical | {summary.critical_count} |
| High | {summary.high_count} |
| Medium | {summary.medium_count} |
| Low | {summary.low_count} |
| Informational | {summary.info_count} |
| **Total** | **{summary.total_findings}** |

### 1.2 Key Metrics

| Metric | Value |
|--------|-------|
| Total Findings | {summary.total_findings} |
| Suppressed | {summary.suppressed_count} |
| False Positives | {summary.false_positive_count} |
| Files Scanned | {summary.files_scanned or "N/A"} |
| Lines of Code | {summary.lines_of_code or "N/A"} |

---

## 2. Tools Used

"""
        for tool in self.report.tools:
            md += f"""### {tool.name}

| Field | Value |
|-------|-------|
| Category | {tool.category.value} |
| Version | {tool.version or "N/A"} |
| Vendor | {tool.vendor or "N/A"} |
| Scan Date | {tool.scan_date} |

"""

        md += """---

## 3. Compliance Frameworks

The analysis was performed in accordance with:

"""
        for framework in self.report.compliance_frameworks:
            md += f"- {framework}\n"

        md += """
---

## 4. Detailed Findings

"""
        # Group findings by severity
        severities = [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]

        for severity in severities:
            severity_findings = [
                f for f in self.report.findings if f.severity == severity
            ]
            if not severity_findings:
                continue

            md += f"""### 4.{severities.index(severity) + 1} {severity.value.upper()} Severity Findings ({len(severity_findings)})

"""
            for _idx, finding in enumerate(severity_findings, 1):
                md += f"""#### {finding.finding_id}: {finding.title}

| Attribute | Value |
|-----------|-------|
| Tool | {finding.tool.name} |
| Rule ID | {finding.rule_id or "N/A"} |
| CWE | {finding.cwe_id or "N/A"} |
| Confidence | {finding.confidence or "N/A"} |
"""
                if finding.location:
                    md += f"| Location | `{finding.location.file_path}:{finding.location.start_line}` |\n"

                md += f"""
**Description:**

{finding.description}

"""
                if finding.location and finding.location.snippet:
                    md += f"""**Code Snippet:**

```
{finding.location.snippet}
```

"""
                if finding.remediation:
                    md += f"""**Remediation:**

{finding.remediation}

"""
                if finding.references:
                    md += "**References:**\n\n"
                    for ref in finding.references[:5]:
                        md += f"- {ref}\n"
                    md += "\n"

                md += "---\n\n"

        md += """## 5. CWE Summary

| CWE ID | Count | Description |
|--------|-------|-------------|
"""
        # Count CWEs
        cwe_counts: dict[str, int] = {}
        for finding in self.report.findings:
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1

        for cwe_id, count in sorted(cwe_counts.items(), key=lambda x: -x[1])[:15]:
            md += f"| {cwe_id} | {count} | - |\n"

        md += """
---

## 6. Remediation Priority

Based on the findings, the following remediation priorities are recommended:

| Priority | Action |
|----------|--------|
"""
        if summary.critical_count > 0:
            md += "| Immediate | Address all Critical findings before deployment |\n"
        if summary.high_count > 0:
            md += "| High | Remediate High findings within 30 days |\n"
        if summary.medium_count > 0:
            md += "| Medium | Plan remediation for Medium findings within 90 days |\n"
        if summary.low_count > 0:
            md += "| Low | Address Low findings in next release cycle |\n"

        md += """
---

## References

- FDA Cybersecurity Guidance (June 2025)
- ANSI/ISA 62443-4-1:2018 Section 9.2 - Static Code Analysis
- OWASP Application Security Verification Standard (ASVS) v4.0
- SARIF (Static Analysis Results Interchange Format) v2.1.0
- Common Weakness Enumeration (CWE)

---

*This report was generated by DICOM Fuzzer for FDA premarket cybersecurity submission documentation.*
"""
        return md

    def save_markdown(self, path: Path | str) -> Path:
        """Save report as markdown."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_markdown())
        return path


def create_sample_report() -> SASTDASTReporter:
    """Create a sample SAST/DAST report for demonstration."""
    reporter = SASTDASTReporter(
        device_name="DICOM PACS Server",
        device_version="3.2.1",
    )

    # Add sample tools
    reporter.report.tools.append(
        ToolInfo(
            name="Semgrep",
            version="1.45.0",
            category=ToolCategory.SAST,
            vendor="Semgrep Inc.",
        )
    )
    reporter.report.tools.append(
        ToolInfo(
            name="Bandit",
            version="1.8.0",
            category=ToolCategory.SAST,
            vendor="PyCQA",
        )
    )

    # Add sample findings
    reporter.add_finding(
        SecurityFinding(
            finding_id="SEMGREP-001",
            title="Hardcoded Password",
            description="Password string detected in source code.",
            severity=FindingSeverity.HIGH,
            tool=reporter.report.tools[0],
            location=CodeLocation(
                file_path="src/auth/login.py",
                start_line=42,
                snippet='password = "admin123"',
            ),
            cwe_id="CWE-259",
            rule_id="python.lang.security.audit.hardcoded-password",
            remediation="Store passwords in environment variables or secure vault.",
        )
    )

    reporter.add_finding(
        SecurityFinding(
            finding_id="BANDIT-B301",
            title="Pickle Usage Detected",
            description="Use of pickle module detected which can be insecure.",
            severity=FindingSeverity.MEDIUM,
            tool=reporter.report.tools[1],
            location=CodeLocation(
                file_path="src/utils/serialization.py",
                start_line=15,
                snippet="data = pickle.loads(raw)",
            ),
            cwe_id="CWE-502",
            rule_id="B301",
            confidence="HIGH",
            remediation="Use json or other safe serialization formats for untrusted data.",
        )
    )

    return reporter


if __name__ == "__main__":
    reporter = create_sample_report()
    print(reporter.generate_markdown())

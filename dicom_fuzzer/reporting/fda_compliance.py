"""FDA Compliance Reporter for DICOM Fuzzer.

Generates compliance reports suitable for FDA premarket cybersecurity submissions
per the June 2025 guidance: "Cybersecurity in Medical Devices: Quality System
Considerations and Content of Premarket Submissions".

This module addresses FDA requirements for:
- Vulnerability testing documentation (ANSI/ISA 62443-4-1 Section 9.4)
- Fuzz testing results and configuration
- Tool identification and settings
- Test case coverage reporting

References:
- FDA Cybersecurity Guidance (June 2025)
- ANSI/ISA 62443-4-1:2018 Section 9.4 (Security Verification and Validation)
- AAMI TIR57:2016 (Medical Device Cybersecurity)

"""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dicom_fuzzer


@dataclass
class ToolConfiguration:
    """Tool identification and configuration for FDA documentation."""

    tool_name: str = "DICOM Fuzzer"
    tool_version: str = ""
    python_version: str = ""
    platform: str = ""
    execution_date: str = ""
    configuration_hash: str = ""

    def __post_init__(self) -> None:
        if not self.tool_version:
            self.tool_version = getattr(dicom_fuzzer, "__version__", "1.4.0")
        if not self.python_version:
            self.python_version = sys.version
        if not self.platform:
            self.platform = f"{platform.system()} {platform.release()}"
        if not self.execution_date:
            self.execution_date = datetime.now(UTC).isoformat()


@dataclass
class FuzzingParameters:
    """Fuzzing campaign parameters for documentation."""

    iterations: int = 0
    duration_seconds: float = 0.0
    timeout_per_test: float = 1.0
    parallel_workers: int = 1
    mutation_strategies: list[str] = field(default_factory=list)
    coverage_guided: bool = True
    dicom_aware: bool = True
    seed_corpus_size: int = 0
    final_corpus_size: int = 0


@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding for FDA reporting."""

    finding_id: str
    category: str
    severity: str
    description: str
    test_case_file: str
    reproduction_steps: str
    cwe_id: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None


@dataclass
class TestCoverage:
    """Test coverage metrics for FDA documentation."""

    total_test_cases: int = 0
    unique_code_paths: int = 0
    branch_coverage_percent: float = 0.0
    mutation_types_tested: list[str] = field(default_factory=list)
    attack_categories_tested: list[str] = field(default_factory=list)
    cve_patterns_tested: list[str] = field(default_factory=list)


@dataclass
class FDAComplianceReport:
    """Complete FDA compliance report structure."""

    # Report metadata
    report_id: str = ""
    report_version: str = "1.0"
    report_date: str = ""
    organization: str = ""
    device_name: str = ""
    device_version: str = ""

    # Tool information (FDA requirement)
    tool_configuration: ToolConfiguration = field(default_factory=ToolConfiguration)

    # Test parameters (FDA requirement)
    fuzzing_parameters: FuzzingParameters = field(default_factory=FuzzingParameters)

    # Results
    test_coverage: TestCoverage = field(default_factory=TestCoverage)
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    crashes_detected: int = 0
    hangs_detected: int = 0

    # Summary statistics
    total_execution_time: float = 0.0
    tests_per_second: float = 0.0
    memory_peak_mb: float = 0.0

    # Compliance assertions
    meets_fda_requirements: bool = False
    compliance_notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.report_date:
            self.report_date = datetime.now(UTC).isoformat()
        if not self.report_id:
            self.report_id = f"FDA-FUZZ-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"


class FDAComplianceReporter:
    """Generate FDA-compliant fuzz testing reports."""

    def __init__(
        self,
        organization: str = "",
        device_name: str = "",
        device_version: str = "",
    ) -> None:
        self.report = FDAComplianceReport(
            organization=organization,
            device_name=device_name,
            device_version=device_version,
        )

    def set_fuzzing_parameters(
        self,
        iterations: int,
        duration_seconds: float,
        timeout_per_test: float = 1.0,
        parallel_workers: int = 1,
        mutation_strategies: list[str] | None = None,
        coverage_guided: bool = True,
        dicom_aware: bool = True,
        seed_corpus_size: int = 0,
        final_corpus_size: int = 0,
    ) -> None:
        """Set fuzzing campaign parameters."""
        self.report.fuzzing_parameters = FuzzingParameters(
            iterations=iterations,
            duration_seconds=duration_seconds,
            timeout_per_test=timeout_per_test,
            parallel_workers=parallel_workers,
            mutation_strategies=mutation_strategies or [],
            coverage_guided=coverage_guided,
            dicom_aware=dicom_aware,
            seed_corpus_size=seed_corpus_size,
            final_corpus_size=final_corpus_size,
        )

    def set_test_coverage(
        self,
        total_test_cases: int,
        unique_code_paths: int = 0,
        branch_coverage_percent: float = 0.0,
        mutation_types_tested: list[str] | None = None,
        attack_categories_tested: list[str] | None = None,
        cve_patterns_tested: list[str] | None = None,
    ) -> None:
        """Set test coverage metrics."""
        self.report.test_coverage = TestCoverage(
            total_test_cases=total_test_cases,
            unique_code_paths=unique_code_paths,
            branch_coverage_percent=branch_coverage_percent,
            mutation_types_tested=mutation_types_tested or [],
            attack_categories_tested=attack_categories_tested or [],
            cve_patterns_tested=cve_patterns_tested or [],
        )

    def add_finding(
        self,
        finding_id: str,
        category: str,
        severity: str,
        description: str,
        test_case_file: str,
        reproduction_steps: str,
        cwe_id: str | None = None,
        cvss_score: float | None = None,
        remediation: str | None = None,
    ) -> None:
        """Add a vulnerability finding."""
        finding = VulnerabilityFinding(
            finding_id=finding_id,
            category=category,
            severity=severity,
            description=description,
            test_case_file=test_case_file,
            reproduction_steps=reproduction_steps,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            remediation=remediation,
        )
        self.report.findings.append(finding)

    def set_results(
        self,
        crashes_detected: int,
        hangs_detected: int,
        total_execution_time: float,
        tests_per_second: float,
        memory_peak_mb: float = 0.0,
    ) -> None:
        """Set execution results."""
        self.report.crashes_detected = crashes_detected
        self.report.hangs_detected = hangs_detected
        self.report.total_execution_time = total_execution_time
        self.report.tests_per_second = tests_per_second
        self.report.memory_peak_mb = memory_peak_mb

    def evaluate_compliance(self) -> bool:
        """Evaluate FDA compliance based on testing parameters."""
        notes: list[str] = []
        compliant = True

        # Check minimum test iterations (FDA recommends substantial testing)
        if self.report.fuzzing_parameters.iterations < 10000:
            notes.append(
                f"[!] Low iteration count ({self.report.fuzzing_parameters.iterations}). "
                "FDA guidance recommends extensive fuzz testing."
            )
            compliant = False
        else:
            notes.append(
                f"[+] Iteration count ({self.report.fuzzing_parameters.iterations}) meets minimum threshold."
            )

        # Check duration (FDA recommends 8+ hours for thorough testing)
        if self.report.fuzzing_parameters.duration_seconds < 3600:
            notes.append(
                f"[!] Short duration ({self.report.fuzzing_parameters.duration_seconds}s). "
                "Consider extended fuzzing campaigns (8+ hours)."
            )
        elif self.report.fuzzing_parameters.duration_seconds >= 28800:
            notes.append("[+] Duration meets FDA recommended 8-hour threshold.")
        else:
            notes.append(
                f"[i] Duration: {self.report.fuzzing_parameters.duration_seconds / 3600:.1f} hours."
            )

        # Check coverage-guided fuzzing
        if self.report.fuzzing_parameters.coverage_guided:
            notes.append("[+] Coverage-guided fuzzing enabled (recommended).")
        else:
            notes.append(
                "[!] Coverage-guided fuzzing disabled. Consider enabling for better coverage."
            )

        # Check DICOM-aware mutations
        if self.report.fuzzing_parameters.dicom_aware:
            notes.append("[+] DICOM-aware mutations enabled.")
        else:
            notes.append(
                "[!] DICOM-aware mutations disabled. May miss protocol-specific issues."
            )

        # Check attack categories
        required_categories = {
            "buffer_overflow",
            "format_string",
            "integer_overflow",
            "path_traversal",
        }
        tested = set(self.report.test_coverage.attack_categories_tested)
        missing = required_categories - tested
        if missing:
            notes.append(f"[!] Missing attack categories: {', '.join(missing)}")
            compliant = False
        else:
            notes.append("[+] All recommended attack categories tested.")

        # Check for CVE pattern testing
        if self.report.test_coverage.cve_patterns_tested:
            notes.append(
                f"[+] Tested against {len(self.report.test_coverage.cve_patterns_tested)} CVE patterns."
            )
        else:
            notes.append(
                "[i] No CVE patterns explicitly tested. Consider adding CVE samples."
            )

        self.report.compliance_notes = notes
        self.report.meets_fda_requirements = compliant
        return compliant

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "report_metadata": {
                "report_id": self.report.report_id,
                "report_version": self.report.report_version,
                "report_date": self.report.report_date,
                "organization": self.report.organization,
                "device_name": self.report.device_name,
                "device_version": self.report.device_version,
            },
            "tool_configuration": asdict(self.report.tool_configuration),
            "fuzzing_parameters": asdict(self.report.fuzzing_parameters),
            "test_coverage": asdict(self.report.test_coverage),
            "results": {
                "crashes_detected": self.report.crashes_detected,
                "hangs_detected": self.report.hangs_detected,
                "total_execution_time": self.report.total_execution_time,
                "tests_per_second": self.report.tests_per_second,
                "memory_peak_mb": self.report.memory_peak_mb,
            },
            "findings": [asdict(f) for f in self.report.findings],
            "compliance": {
                "meets_fda_requirements": self.report.meets_fda_requirements,
                "compliance_notes": self.report.compliance_notes,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path: Path | str) -> Path:
        """Save report as JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())
        return path

    def generate_markdown(self) -> str:
        """Generate FDA-compliant markdown report."""
        self.evaluate_compliance()

        md = f"""# FDA Cybersecurity Fuzz Testing Report

## Report Information

| Field | Value |
|-------|-------|
| Report ID | {self.report.report_id} |
| Report Date | {self.report.report_date} |
| Organization | {self.report.organization or "N/A"} |
| Device Under Test | {self.report.device_name or "N/A"} |
| Device Version | {self.report.device_version or "N/A"} |

---

## 1. Tool Identification

Per FDA guidance, the following tool information is documented:

| Setting | Value |
|---------|-------|
| Tool Name | {self.report.tool_configuration.tool_name} |
| Tool Version | {self.report.tool_configuration.tool_version} |
| Python Version | {self.report.tool_configuration.python_version.split()[0]} |
| Platform | {self.report.tool_configuration.platform} |
| Execution Date | {self.report.tool_configuration.execution_date} |

---

## 2. Fuzzing Configuration

### Parameters

| Parameter | Value |
|-----------|-------|
| Total Iterations | {self.report.fuzzing_parameters.iterations:,} |
| Duration | {self.report.fuzzing_parameters.duration_seconds:.1f} seconds ({self.report.fuzzing_parameters.duration_seconds / 3600:.2f} hours) |
| Timeout per Test | {self.report.fuzzing_parameters.timeout_per_test}s |
| Parallel Workers | {self.report.fuzzing_parameters.parallel_workers} |
| Coverage-Guided | {"Yes" if self.report.fuzzing_parameters.coverage_guided else "No"} |
| DICOM-Aware | {"Yes" if self.report.fuzzing_parameters.dicom_aware else "No"} |

### Mutation Strategies

"""
        if self.report.fuzzing_parameters.mutation_strategies:
            for strategy in self.report.fuzzing_parameters.mutation_strategies:
                md += f"- {strategy}\n"
        else:
            md += "- All default strategies\n"

        md += f"""
### Corpus Management

| Metric | Value |
|--------|-------|
| Seed Corpus Size | {self.report.fuzzing_parameters.seed_corpus_size} |
| Final Corpus Size | {self.report.fuzzing_parameters.final_corpus_size} |

---

## 3. Test Coverage

| Metric | Value |
|--------|-------|
| Total Test Cases | {self.report.test_coverage.total_test_cases:,} |
| Unique Code Paths | {self.report.test_coverage.unique_code_paths:,} |
| Branch Coverage | {self.report.test_coverage.branch_coverage_percent:.1f}% |

### Attack Categories Tested

"""
        if self.report.test_coverage.attack_categories_tested:
            for cat in self.report.test_coverage.attack_categories_tested:
                md += f"- {cat}\n"
        else:
            md += "- Default attack patterns\n"

        md += """
### CVE Patterns Tested

"""
        if self.report.test_coverage.cve_patterns_tested:
            for cve in self.report.test_coverage.cve_patterns_tested:
                md += f"- {cve}\n"
        else:
            md += "- No specific CVE patterns\n"

        md += f"""
---

## 4. Results Summary

| Metric | Value |
|--------|-------|
| Crashes Detected | {self.report.crashes_detected} |
| Hangs Detected | {self.report.hangs_detected} |
| Total Execution Time | {self.report.total_execution_time:.1f}s |
| Tests per Second | {self.report.tests_per_second:.1f} |
| Peak Memory | {self.report.memory_peak_mb:.1f} MB |

---

## 5. Vulnerability Findings

"""
        if self.report.findings:
            for i, finding in enumerate(self.report.findings, 1):
                md += f"""### Finding {i}: {finding.finding_id}

| Field | Value |
|-------|-------|
| Category | {finding.category} |
| Severity | {finding.severity} |
| CWE | {finding.cwe_id or "N/A"} |
| CVSS | {finding.cvss_score or "N/A"} |

**Description:** {finding.description}

**Test Case:** `{finding.test_case_file}`

**Reproduction Steps:**
```
{finding.reproduction_steps}
```

"""
                if finding.remediation:
                    md += f"**Remediation:** {finding.remediation}\n\n"
        else:
            md += "*No vulnerabilities detected during this fuzzing campaign.*\n\n"

        md += f"""---

## 6. FDA Compliance Assessment

**Overall Compliance:** {"PASS" if self.report.meets_fda_requirements else "NEEDS ATTENTION"}

### Compliance Notes

"""
        for note in self.report.compliance_notes:
            md += f"{note}\n"

        md += """
---

## 7. References

- FDA Cybersecurity Guidance (June 2025): "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions"
- ANSI/ISA 62443-4-1:2018 Section 9.4: Security Verification and Validation
- AAMI TIR57:2016: Principles for Medical Device Security - Risk Management

---

*This report was generated by DICOM Fuzzer for FDA premarket cybersecurity submission documentation.*
"""
        return md

    def save_markdown(self, path: Path | str) -> Path:
        """Save report as markdown file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_markdown())
        return path


def create_sample_report() -> FDAComplianceReporter:
    """Create a sample FDA compliance report for demonstration."""
    reporter = FDAComplianceReporter(
        organization="Medical Device Company",
        device_name="DICOM Viewer Application",
        device_version="2.0.0",
    )

    reporter.set_fuzzing_parameters(
        iterations=100000,
        duration_seconds=28800,
        timeout_per_test=1.0,
        parallel_workers=4,
        mutation_strategies=[
            "bit_flip",
            "byte_flip",
            "arithmetic",
            "havoc",
            "dicom_structure",
            "metadata_mutation",
        ],
        coverage_guided=True,
        dicom_aware=True,
        seed_corpus_size=50,
        final_corpus_size=1250,
    )

    reporter.set_test_coverage(
        total_test_cases=100000,
        unique_code_paths=2500,
        branch_coverage_percent=78.5,
        mutation_types_tested=[
            "bit_flip",
            "byte_flip",
            "arithmetic",
            "havoc",
            "structure",
        ],
        attack_categories_tested=[
            "buffer_overflow",
            "format_string",
            "integer_overflow",
            "path_traversal",
            "null_byte_injection",
            "deep_nesting",
        ],
        cve_patterns_tested=[
            "CVE-2019-11687",
            "CVE-2022-2119",
            "CVE-2024-22100",
            "CVE-2024-28877",
            "CVE-2025-5943",
        ],
    )

    reporter.set_results(
        crashes_detected=0,
        hangs_detected=2,
        total_execution_time=28800.0,
        tests_per_second=3.47,
        memory_peak_mb=512.0,
    )

    return reporter


if __name__ == "__main__":
    reporter = create_sample_report()
    reporter.evaluate_compliance()

    print(reporter.generate_markdown())
    print("\n" + "=" * 60)
    print("JSON Output:")
    print(reporter.to_json())

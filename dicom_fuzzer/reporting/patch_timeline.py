"""Patch Timeline Tracking Report Generator.

Generates patch timeline documentation per FDA June 2025 cybersecurity guidance
requirements for vulnerability remediation tracking.

FDA Requirements:
- Define timelines for acknowledgment and remediation
- Track patch deployment based on risk level
- Document vulnerability-to-patch timeline metrics
- Maintain records of remediation actions

References:
- FDA Cybersecurity Guidance (June 2025) Section VII
- CISA Known Exploited Vulnerabilities Catalog
- CVSS v4.0 Scoring Guidelines

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


class SeverityLevel(Enum):
    """Vulnerability severity levels with default remediation timelines."""

    CRITICAL = ("Critical", 15)  # 15 days
    HIGH = ("High", 30)  # 30 days
    MEDIUM = ("Medium", 90)  # 90 days
    LOW = ("Low", 180)  # 180 days
    INFORMATIONAL = ("Informational", 365)  # 1 year

    @property
    def label(self) -> str:
        """Get the human-readable label for this severity level."""
        return self.value[0]

    @property
    def default_days(self) -> int:
        """Get the default remediation timeline in days for this severity."""
        return self.value[1]


class PatchStatus(Enum):
    """Status of vulnerability patch."""

    IDENTIFIED = "Identified"
    ACKNOWLEDGED = "Acknowledged"
    ANALYZING = "Analyzing"
    DEVELOPING = "Developing Fix"
    TESTING = "Testing"
    RELEASED = "Released"
    DEPLOYED = "Deployed"
    VERIFIED = "Verified"
    CLOSED = "Closed"


@dataclass
class VulnerabilityPatch:
    """Track a vulnerability through the patch lifecycle."""

    vuln_id: str
    title: str
    severity: SeverityLevel
    cve_id: str = ""
    cvss_score: float = 0.0

    # Timeline tracking
    identified_date: datetime | None = None
    acknowledged_date: datetime | None = None
    fix_started_date: datetime | None = None
    fix_completed_date: datetime | None = None
    released_date: datetime | None = None
    deployed_date: datetime | None = None
    verified_date: datetime | None = None

    # Status
    status: PatchStatus = PatchStatus.IDENTIFIED
    target_date: datetime | None = None
    affected_versions: list[str] = field(default_factory=list)
    fixed_version: str = ""

    # Details
    description: str = ""
    root_cause: str = ""
    remediation: str = ""
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Calculate target date based on severity."""
        if self.identified_date and not self.target_date:
            self.target_date = self.identified_date + timedelta(
                days=self.severity.default_days
            )

    @property
    def days_to_acknowledge(self) -> int | None:
        """Days from identification to acknowledgment."""
        if self.identified_date and self.acknowledged_date:
            return (self.acknowledged_date - self.identified_date).days
        return None

    @property
    def days_to_fix(self) -> int | None:
        """Days from identification to fix release."""
        if self.identified_date and self.released_date:
            return (self.released_date - self.identified_date).days
        return None

    @property
    def days_to_deploy(self) -> int | None:
        """Days from identification to deployment."""
        if self.identified_date and self.deployed_date:
            return (self.deployed_date - self.identified_date).days
        return None

    @property
    def is_overdue(self) -> bool:
        """Check if patch is overdue based on target date."""
        if not self.target_date:
            return False
        if self.status in [
            PatchStatus.DEPLOYED,
            PatchStatus.VERIFIED,
            PatchStatus.CLOSED,
        ]:
            return False
        return datetime.now(UTC) > self.target_date

    @property
    def days_remaining(self) -> int | None:
        """Days remaining until target date."""
        if not self.target_date:
            return None
        if self.status in [
            PatchStatus.DEPLOYED,
            PatchStatus.VERIFIED,
            PatchStatus.CLOSED,
        ]:
            return None
        delta = self.target_date - datetime.now(UTC)
        return delta.days


@dataclass
class PatchTimelineConfig:
    """Configuration for patch timeline report."""

    organization_name: str = ""
    product_name: str = ""
    report_period_start: datetime | None = None
    report_period_end: datetime | None = None

    # SLA targets (in days)
    critical_ack_sla: int = 1
    critical_fix_sla: int = 15
    high_ack_sla: int = 3
    high_fix_sla: int = 30
    medium_ack_sla: int = 7
    medium_fix_sla: int = 90
    low_ack_sla: int = 14
    low_fix_sla: int = 180


class PatchTimelineReportGenerator:
    """Generate FDA-compliant patch timeline reports."""

    def __init__(self, config: PatchTimelineConfig | None = None) -> None:
        self.config = config or PatchTimelineConfig()
        self.vulnerabilities: list[VulnerabilityPatch] = []

    def add_vulnerability(self, vuln: VulnerabilityPatch) -> None:
        """Add a vulnerability to track."""
        self.vulnerabilities.append(vuln)

    def add_sample_data(self) -> None:
        """Add sample vulnerability data for demonstration."""
        now = datetime.now(UTC)

        samples = [
            VulnerabilityPatch(
                vuln_id="VULN-001",
                title="Buffer Overflow in DICOM Parser",
                severity=SeverityLevel.CRITICAL,
                cve_id="CVE-2025-5943",
                cvss_score=8.8,
                identified_date=now - timedelta(days=45),
                acknowledged_date=now - timedelta(days=44),
                fix_started_date=now - timedelta(days=42),
                fix_completed_date=now - timedelta(days=35),
                released_date=now - timedelta(days=30),
                deployed_date=now - timedelta(days=25),
                verified_date=now - timedelta(days=20),
                status=PatchStatus.CLOSED,
                fixed_version="2.1.1",
                affected_versions=["2.0.0", "2.0.1", "2.1.0"],
                description="Out-of-bounds write in header parsing",
                root_cause="Missing bounds check on VR length field",
                remediation="Added length validation before buffer copy",
            ),
            VulnerabilityPatch(
                vuln_id="VULN-002",
                title="Information Disclosure in JPEG Codec",
                severity=SeverityLevel.HIGH,
                cve_id="CVE-2025-53619",
                cvss_score=7.5,
                identified_date=now - timedelta(days=20),
                acknowledged_date=now - timedelta(days=18),
                fix_started_date=now - timedelta(days=15),
                fix_completed_date=now - timedelta(days=5),
                released_date=now - timedelta(days=3),
                status=PatchStatus.RELEASED,
                fixed_version="2.1.2",
                affected_versions=["2.0.0", "2.0.1", "2.1.0", "2.1.1"],
                description="OOB read in JPEGBITSCodec leaks memory contents",
            ),
            VulnerabilityPatch(
                vuln_id="VULN-003",
                title="Denial of Service via Malformed Sequence",
                severity=SeverityLevel.MEDIUM,
                cve_id="",
                cvss_score=5.3,
                identified_date=now - timedelta(days=30),
                acknowledged_date=now - timedelta(days=25),
                fix_started_date=now - timedelta(days=10),
                status=PatchStatus.DEVELOPING,
                affected_versions=["2.1.0", "2.1.1", "2.1.2"],
                description="Deeply nested sequences cause stack overflow",
            ),
            VulnerabilityPatch(
                vuln_id="VULN-004",
                title="Path Traversal in File Export",
                severity=SeverityLevel.HIGH,
                cve_id="",
                cvss_score=7.1,
                identified_date=now - timedelta(days=5),
                acknowledged_date=now - timedelta(days=4),
                status=PatchStatus.ANALYZING,
                affected_versions=["2.1.2"],
                description="Unsanitized filename allows path traversal",
            ),
        ]

        for sample in samples:
            self.add_vulnerability(sample)

    def _get_sla_compliance(self) -> dict[str, Any]:
        """Calculate SLA compliance metrics."""
        cfg = self.config
        metrics = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "ack_sla_met": 0,
            "ack_sla_missed": 0,
            "fix_sla_met": 0,
            "fix_sla_missed": 0,
            "currently_overdue": 0,
            "by_severity": {},
        }

        by_severity: dict[str, dict[str, int]] = {}
        for severity in SeverityLevel:
            by_severity[severity.label] = {
                "total": 0,
                "ack_met": 0,
                "ack_missed": 0,
                "fix_met": 0,
                "fix_missed": 0,
            }
        metrics["by_severity"] = by_severity

        # Get SLA targets
        sla_targets = {
            SeverityLevel.CRITICAL: (cfg.critical_ack_sla, cfg.critical_fix_sla),
            SeverityLevel.HIGH: (cfg.high_ack_sla, cfg.high_fix_sla),
            SeverityLevel.MEDIUM: (cfg.medium_ack_sla, cfg.medium_fix_sla),
            SeverityLevel.LOW: (cfg.low_ack_sla, cfg.low_fix_sla),
            SeverityLevel.INFORMATIONAL: (14, 365),
        }

        # Use typed counters to avoid dict access issues
        ack_sla_met = 0
        ack_sla_missed = 0
        fix_sla_met = 0
        fix_sla_missed = 0
        currently_overdue = 0

        for vuln in self.vulnerabilities:
            sev_key = vuln.severity.label
            by_severity[sev_key]["total"] += 1

            ack_sla, fix_sla = sla_targets.get(vuln.severity, (14, 90))

            # Check acknowledgment SLA
            if vuln.days_to_acknowledge is not None:
                if vuln.days_to_acknowledge <= ack_sla:
                    ack_sla_met += 1
                    by_severity[sev_key]["ack_met"] += 1
                else:
                    ack_sla_missed += 1
                    by_severity[sev_key]["ack_missed"] += 1

            # Check fix SLA
            if vuln.days_to_fix is not None:
                if vuln.days_to_fix <= fix_sla:
                    fix_sla_met += 1
                    by_severity[sev_key]["fix_met"] += 1
                else:
                    fix_sla_missed += 1
                    by_severity[sev_key]["fix_missed"] += 1

            # Check if currently overdue
            if vuln.is_overdue:
                currently_overdue += 1

        metrics["ack_sla_met"] = ack_sla_met
        metrics["ack_sla_missed"] = ack_sla_missed
        metrics["fix_sla_met"] = fix_sla_met
        metrics["fix_sla_missed"] = fix_sla_missed
        metrics["currently_overdue"] = currently_overdue

        return metrics

    def generate_report_markdown(self) -> str:
        """Generate patch timeline report in Markdown."""
        cfg = self.config
        now = datetime.now(UTC).strftime("%Y-%m-%d")
        metrics = self._get_sla_compliance()

        report = f"""# Patch Timeline Tracking Report

**Organization:** {cfg.organization_name or "[Organization Name]"}
**Product:** {cfg.product_name or "[Product Name]"}
**Report Date:** {now}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities Tracked | {metrics["total_vulnerabilities"]} |
| Acknowledgment SLA Met | {metrics["ack_sla_met"]} |
| Acknowledgment SLA Missed | {metrics["ack_sla_missed"]} |
| Fix SLA Met | {metrics["fix_sla_met"]} |
| Fix SLA Missed | {metrics["fix_sla_missed"]} |
| Currently Overdue | {metrics["currently_overdue"]} |

---

## SLA Targets

| Severity | Acknowledgment | Remediation |
|----------|---------------|-------------|
| Critical | {cfg.critical_ack_sla} days | {cfg.critical_fix_sla} days |
| High | {cfg.high_ack_sla} days | {cfg.high_fix_sla} days |
| Medium | {cfg.medium_ack_sla} days | {cfg.medium_fix_sla} days |
| Low | {cfg.low_ack_sla} days | {cfg.low_fix_sla} days |

---

## Compliance by Severity

| Severity | Total | Ack Met | Ack Missed | Fix Met | Fix Missed |
|----------|-------|---------|------------|---------|------------|
"""
        for severity in SeverityLevel:
            sev_data = metrics["by_severity"].get(severity.label, {})
            report += (
                f"| {severity.label} | {sev_data.get('total', 0)} | "
                f"{sev_data.get('ack_met', 0)} | {sev_data.get('ack_missed', 0)} | "
                f"{sev_data.get('fix_met', 0)} | {sev_data.get('fix_missed', 0)} |\n"
            )

        report += """
---

## Vulnerability Details

"""
        # Sort by severity then by identified date
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: (
                list(SeverityLevel).index(v.severity),
                v.identified_date or datetime.min.replace(tzinfo=UTC),
            ),
        )

        for vuln in sorted_vulns:
            status_icon = "[!]" if vuln.is_overdue else "[+]"
            report += f"""### {status_icon} {vuln.vuln_id}: {vuln.title}

| Attribute | Value |
|-----------|-------|
| Severity | {vuln.severity.label} |
| CVE ID | {vuln.cve_id or "Not assigned"} |
| CVSS Score | {vuln.cvss_score} |
| Status | {vuln.status.value} |
| Identified | {vuln.identified_date.strftime("%Y-%m-%d") if vuln.identified_date else "N/A"} |
| Acknowledged | {vuln.acknowledged_date.strftime("%Y-%m-%d") if vuln.acknowledged_date else "Pending"} |
| Released | {vuln.released_date.strftime("%Y-%m-%d") if vuln.released_date else "In progress"} |
| Fixed Version | {vuln.fixed_version or "TBD"} |
| Days to Acknowledge | {vuln.days_to_acknowledge or "N/A"} |
| Days to Fix | {vuln.days_to_fix or "In progress"} |
"""
            if vuln.is_overdue:
                report += f"| **OVERDUE** | Target was {vuln.target_date.strftime('%Y-%m-%d') if vuln.target_date else 'N/A'} |\n"
            elif vuln.days_remaining is not None:
                report += f"| Days Remaining | {vuln.days_remaining} |\n"

            if vuln.description:
                report += f"\n**Description:** {vuln.description}\n"
            if vuln.remediation:
                report += f"\n**Remediation:** {vuln.remediation}\n"

            report += "\n---\n\n"

        report += f"""
## Patch Timeline Chart

```
Vulnerability Timeline (days from identification)
{"=" * 60}
"""
        max_days = 100
        for vuln in sorted_vulns[:10]:  # Top 10
            days = vuln.days_to_fix or vuln.days_remaining or 0
            bar_len = min(int((abs(days) / max_days) * 50), 50)
            bar = "#" * bar_len
            status = "DONE" if vuln.days_to_fix else f"{days}d"
            report += f"{vuln.vuln_id:<10} |{bar:<50}| {status}\n"

        report += f"""{"=" * 60}
```

---

## FDA Compliance Statement

This patch timeline report demonstrates compliance with FDA Cybersecurity
Guidance (June 2025) requirements for:

- Defined timelines for vulnerability acknowledgment
- Risk-based remediation targets
- Tracking of patch deployment metrics
- Documentation of remediation actions

**Report Generated:** {now}

---

*This report was generated by DICOM Fuzzer for FDA cybersecurity compliance.*
"""
        return report

    def generate_report_json(self) -> dict[str, Any]:
        """Generate report as JSON."""
        metrics = self._get_sla_compliance()
        return {
            "report_date": datetime.now(UTC).isoformat(),
            "organization": self.config.organization_name,
            "product": self.config.product_name,
            "metrics": metrics,
            "sla_targets": {
                "critical": {
                    "ack_days": self.config.critical_ack_sla,
                    "fix_days": self.config.critical_fix_sla,
                },
                "high": {
                    "ack_days": self.config.high_ack_sla,
                    "fix_days": self.config.high_fix_sla,
                },
                "medium": {
                    "ack_days": self.config.medium_ack_sla,
                    "fix_days": self.config.medium_fix_sla,
                },
                "low": {
                    "ack_days": self.config.low_ack_sla,
                    "fix_days": self.config.low_fix_sla,
                },
            },
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "title": v.title,
                    "severity": v.severity.label,
                    "cve_id": v.cve_id,
                    "cvss_score": v.cvss_score,
                    "status": v.status.value,
                    "identified_date": v.identified_date.isoformat()
                    if v.identified_date
                    else None,
                    "acknowledged_date": v.acknowledged_date.isoformat()
                    if v.acknowledged_date
                    else None,
                    "released_date": v.released_date.isoformat()
                    if v.released_date
                    else None,
                    "days_to_acknowledge": v.days_to_acknowledge,
                    "days_to_fix": v.days_to_fix,
                    "is_overdue": v.is_overdue,
                    "fixed_version": v.fixed_version,
                }
                for v in self.vulnerabilities
            ],
        }

    def save_report(self, output_path: Path | str, format: str = "markdown") -> Path:
        """Save the report to file."""
        import json

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(self.generate_report_json(), f, indent=2)
        else:
            output_path.write_text(self.generate_report_markdown())

        return output_path


def generate_patch_timeline_report(
    organization: str = "",
    product: str = "",
    output_path: Path | str | None = None,
    include_samples: bool = False,
) -> str:
    """Generate a patch timeline report with minimal configuration."""
    config = PatchTimelineConfig(
        organization_name=organization,
        product_name=product,
    )

    generator = PatchTimelineReportGenerator(config)

    if include_samples:
        generator.add_sample_data()

    report = generator.generate_report_markdown()

    if output_path:
        generator.save_report(output_path)

    return report


if __name__ == "__main__":
    # Generate sample report
    config = PatchTimelineConfig(
        organization_name="Medical Device Corp",
        product_name="DICOM Viewer Pro",
    )

    generator = PatchTimelineReportGenerator(config)
    generator.add_sample_data()

    print(generator.generate_report_markdown())

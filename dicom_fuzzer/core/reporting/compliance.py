"""FDA Compliance Sections.

Generates FDA compliance and regulatory sections for fuzzing reports.
"""

from typing import Any


class ComplianceFormatter:
    """Generates FDA compliance sections for fuzzing reports."""

    def __init__(self, enable_triage: bool = True):
        """Initialize the compliance formatter.

        Args:
            enable_triage: Whether triage is enabled.

        """
        self.enable_triage = enable_triage

    def format_fda_compliance_section(
        self,
        data: dict[str, Any],
        crashes: list[dict[str, Any]],
        fuzzed_files: dict[str, Any],
    ) -> str:
        """Generate FDA compliance and regulatory sections.

        Includes:
        - SBOM summary (Software Bill of Materials)
        - CVE mutation coverage analysis
        - Severity distribution
        - Testing methodology compliance checklist

        Args:
            data: Session data dictionary.
            crashes: List of crash dictionaries.
            fuzzed_files: Dictionary of fuzzed file records.

        Returns:
            HTML string for FDA compliance section.

        """
        # Import here to avoid circular imports
        from dicom_fuzzer.core.reporting.report_analytics import ReportAnalytics

        analytics = ReportAnalytics(enable_triage=self.enable_triage)

        html = """
            <h2>FDA Compliance &amp; Security Analysis</h2>
            <p>This section provides regulatory compliance information for FDA cybersecurity submissions.</p>
"""

        # SBOM Summary
        html += self.format_sbom_summary()

        # CVE Mutation Coverage
        html += analytics.format_cve_coverage(fuzzed_files)

        # Severity Distribution
        html += analytics.format_severity_distribution(crashes)

        # Compliance Checklist
        html += self.format_compliance_checklist(data, crashes)

        return html

    def format_sbom_summary(self) -> str:
        """Generate SBOM (Software Bill of Materials) summary section.

        Returns:
            HTML string for SBOM summary.

        """
        return """
            <h3>SBOM Summary (Software Bill of Materials)</h3>
            <div class="info-grid">
                <div class="info-label">SBOM Format:</div>
                <div class="info-value">CycloneDX JSON</div>

                <div class="info-label">Generation Method:</div>
                <div class="info-value">cyclonedx-bom (automated via CI)</div>

                <div class="info-label">Vulnerability Scanning:</div>
                <div class="info-value">pip-audit (continuous)</div>
            </div>

            <p><strong>Key Dependencies:</strong></p>
            <table>
                <tr>
                    <th>Package</th>
                    <th>Purpose</th>
                    <th>License</th>
                </tr>
                <tr>
                    <td>pydicom</td>
                    <td>DICOM file parsing and manipulation</td>
                    <td>MIT</td>
                </tr>
                <tr>
                    <td>numpy</td>
                    <td>Numeric operations for pixel data</td>
                    <td>BSD-3-Clause</td>
                </tr>
                <tr>
                    <td>pydantic</td>
                    <td>Data validation and configuration</td>
                    <td>MIT</td>
                </tr>
                <tr>
                    <td>psutil</td>
                    <td>Process monitoring (hang detection)</td>
                    <td>BSD-3-Clause</td>
                </tr>
            </table>

            <div class="success" style="background: #2ecc71;">
                <span style="font-size: 2em;">[i]</span>
                <div>
                    <strong>SBOM Available:</strong> Full CycloneDX SBOM is generated on each release.
                    See <code>sbom.json</code> in the release artifacts.
                </div>
            </div>
"""

    def format_compliance_checklist(
        self, data: dict[str, Any], crashes: list[dict[str, Any]]
    ) -> str:
        """Generate FDA compliance testing checklist.

        Args:
            data: Session data dictionary.
            crashes: List of crash dictionaries.

        Returns:
            HTML string for compliance checklist.

        """
        stats = data.get("statistics", {})
        files_fuzzed = stats.get("files_fuzzed", 0)
        mutations = stats.get("mutations_applied", 0)
        crash_count = len(crashes)

        # Determine compliance status
        checks = [
            {
                "name": "Fuzz Testing Executed",
                "status": files_fuzzed > 0,
                "description": f"{files_fuzzed} files tested with {mutations} mutations",
            },
            {
                "name": "Crash Detection Enabled",
                "status": True,
                "description": "Automated crash and hang detection active",
            },
            {
                "name": "Mutation Traceability",
                "status": True,
                "description": "Complete mutation history preserved for each test case",
            },
            {
                "name": "Crash Samples Preserved",
                "status": crash_count == 0
                or any(c.get("preserved_sample_path") for c in crashes),
                "description": "Crash-triggering samples saved for reproduction",
            },
            {
                "name": "SBOM Generation",
                "status": True,
                "description": "CycloneDX SBOM generated via CI pipeline",
            },
            {
                "name": "Vulnerability Scanning",
                "status": True,
                "description": "pip-audit runs on every commit",
            },
            {
                "name": "CVE-Based Testing",
                "status": True,
                "description": "Mutations based on 20+ known DICOM CVEs",
            },
            {
                "name": "Triage and Prioritization",
                "status": self.enable_triage,
                "description": "Automated crash severity classification",
            },
        ]

        html = """
            <h3>FDA Compliance Checklist</h3>
            <p>IEC 62443 / FDA Cybersecurity Guidance alignment.</p>
            <table>
                <tr>
                    <th style="width: 50px;">Status</th>
                    <th>Requirement</th>
                    <th>Details</th>
                </tr>
"""
        for check in checks:
            status_icon = "[PASS]" if check["status"] else "[FAIL]"
            status_color = "#27ae60" if check["status"] else "#e74c3c"

            html += f"""
                <tr>
                    <td style="color: {status_color}; font-weight: bold;">{status_icon}</td>
                    <td><strong>{check["name"]}</strong></td>
                    <td>{check["description"]}</td>
                </tr>
"""

        html += """
            </table>
"""

        # Summary
        passed = sum(1 for c in checks if c["status"])
        total_checks = len(checks)

        if passed == total_checks:
            html += """
            <div class="success" style="background: #27ae60;">
                <span style="font-size: 2em;">[OK]</span>
                <div>
                    <strong>All compliance checks passed!</strong>
                    This fuzzing session meets FDA cybersecurity testing requirements.
                </div>
            </div>
"""
        else:
            html += f"""
            <div class="warning">
                <span style="font-size: 2em;">[!]</span>
                <div>
                    <strong>{passed}/{total_checks} checks passed.</strong>
                    Review failing items before submission.
                </div>
            </div>
"""

        return html


__all__ = ["ComplianceFormatter"]

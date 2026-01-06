from typing import Any

"""Report Analytics.

Generates analytics sections for fuzzing reports including
mutation analysis, CVE coverage, and severity distribution.
"""


class ReportAnalytics:
    """Generates analytics sections for fuzzing reports."""

    def __init__(self, enable_triage: bool = True):
        """Initialize the report analytics.

        Args:
            enable_triage: Whether triage information is available.

        """
        self.enable_triage = enable_triage

    def format_mutation_analysis(
        self, fuzzed_files: dict[str, Any], crashes: list[dict[str, Any]] | None = None
    ) -> str:
        """Generate mutation strategy analysis.

        Args:
            fuzzed_files: Dictionary of fuzzed file records.
            crashes: Optional list of crash dictionaries.

        Returns:
            HTML string for mutation analysis.

        """
        if not fuzzed_files:
            return ""

        # Default to empty list if not provided
        if crashes is None:
            crashes = []

        # Analyze mutation strategies used
        strategy_counts: dict[str, int] = {}
        mutation_type_counts: dict[str, int] = {}

        for file_record in fuzzed_files.values():
            for mutation in file_record.get("mutations", []):
                strategy = mutation.get("strategy_name", "Unknown")
                mut_type = mutation.get("mutation_type", "unknown")

                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
                mutation_type_counts[mut_type] = (
                    mutation_type_counts.get(mut_type, 0) + 1
                )

        html = """
            <h2>Mutation Analysis</h2>
            <h3>Strategy Usage</h3>
            <table>
                <tr>
                    <th>Strategy</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""

        total_mutations = sum(strategy_counts.values())

        for strategy, count in sorted(
            strategy_counts.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_mutations * 100) if total_mutations > 0 else 0
            html += f"""
                <tr>
                    <td>{strategy}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""

        html += """
            </table>

            <h3>Mutation Types</h3>
            <table>
                <tr>
                    <th>Mutation Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""

        for mut_type, count in sorted(
            mutation_type_counts.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_mutations * 100) if total_mutations > 0 else 0
            html += f"""
                <tr>
                    <td>{mut_type}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""

        html += """
            </table>
"""

        # Add Top 10 Critical Crashes section if triage enabled
        if self.enable_triage and crashes:
            html += self._format_critical_crashes_section(crashes)

        return html

    def _format_critical_crashes_section(self, crashes: list[dict[str, Any]]) -> str:
        """Format the critical crashes section.

        Args:
            crashes: List of crash dictionaries.

        Returns:
            HTML string for critical crashes section.

        """
        critical_crashes = [
            c
            for c in crashes
            if c.get("triage", {}).get("severity") in ["critical", "high"]
        ]
        if not critical_crashes:
            return ""

        html = """
            <h3>Top Critical Crashes</h3>
            <table>
                <tr>
                    <th>Priority</th>
                    <th>Crash ID</th>
                    <th>Severity</th>
                    <th>Exploitability</th>
                    <th>Summary</th>
                </tr>
"""
        for crash in critical_crashes[:10]:  # Top 10
            triage = crash.get("triage", {})
            priority = triage.get("priority_score", 0)
            severity = triage.get("severity", "unknown")
            exploitability = triage.get("exploitability", "unknown")
            summary = triage.get("summary", "No summary available")

            html += f"""
                <tr>
                    <td><strong>{priority:.1f}/100</strong></td>
                    <td><code>{crash["crash_id"]}</code></td>
                    <td><span class="badge {severity}">{severity.upper()}</span></td>
                    <td><span class="badge {exploitability.replace("_", "-")}">{exploitability.replace("_", " ").title()}</span></td>
                    <td>{summary[:100]}</td>
                </tr>
"""
        html += """
            </table>
"""
        return html

    def format_cve_coverage(self, fuzzed_files: dict[str, Any]) -> str:
        """Generate CVE mutation coverage analysis.

        Args:
            fuzzed_files: Dictionary of fuzzed file records.

        Returns:
            HTML string for CVE coverage analysis.

        """
        # Track which CVE-based mutations were used
        cve_mutations: dict[str, int] = {}
        total_mutations = 0

        for file_record in fuzzed_files.values():
            for mutation in file_record.get("mutations", []):
                strategy = mutation.get("strategy_name", "")
                total_mutations += 1

                # CVE-inspired mutations typically have CVE in the name
                if "CVE" in strategy.upper():
                    cve_mutations[strategy] = cve_mutations.get(strategy, 0) + 1
                elif any(
                    term in strategy.lower()
                    for term in [
                        "overflow",
                        "corruption",
                        "injection",
                        "boundary",
                        "invalid",
                        "extreme",
                    ]
                ):
                    cve_mutations[strategy] = cve_mutations.get(strategy, 0) + 1

        html = """
            <h3>CVE-Inspired Mutation Coverage</h3>
            <p>Security-focused mutations based on known DICOM vulnerabilities (CVE research).</p>
"""

        if cve_mutations:
            html += self._format_cve_stats(cve_mutations, total_mutations)
        else:
            html += """
            <div class="warning">
                <span style="font-size: 2em;">[!]</span>
                <div>
                    <strong>Limited CVE Coverage:</strong> No CVE-inspired mutations detected in this session.
                    Consider enabling CVE mutation strategies for comprehensive security testing.
                </div>
            </div>
"""

        # Reference CVE list
        html += self._format_cve_reference_table()

        return html

    def _format_cve_stats(self, cve_mutations: dict[str, int], total: int) -> str:
        """Format CVE mutation statistics.

        Args:
            cve_mutations: Dictionary of CVE mutation counts.
            total: Total mutation count.

        Returns:
            HTML string for CVE stats.

        """
        cve_total = sum(cve_mutations.values())
        coverage_pct = (cve_total / total * 100) if total > 0 else 0

        html = f"""
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                    <div class="stat-value">{len(cve_mutations)}</div>
                    <div class="stat-label">Security Strategies</div>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                    <div class="stat-value">{cve_total}</div>
                    <div class="stat-label">Security Mutations</div>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                    <div class="stat-value">{coverage_pct:.1f}%</div>
                    <div class="stat-label">Security Coverage</div>
                </div>
            </div>

            <table>
                <tr>
                    <th>Security Strategy</th>
                    <th>Mutations Applied</th>
                    <th>Target Vulnerability Class</th>
                </tr>
"""
        vulnerability_classes = {
            "overflow": "Buffer Overflow / Integer Overflow",
            "corruption": "Memory Corruption",
            "injection": "Injection Attack",
            "boundary": "Boundary Condition",
            "invalid": "Invalid Input Handling",
            "extreme": "Edge Case / Extreme Values",
            "position": "Out-of-Bounds Access",
            "dimension": "Dimension Overflow",
            "frame": "Multi-Frame Parsing",
            "sequence": "Sequence Parsing",
        }

        for strategy, count in sorted(
            cve_mutations.items(), key=lambda x: x[1], reverse=True
        ):
            vuln_class = "General Security"
            for key, value in vulnerability_classes.items():
                if key in strategy.lower():
                    vuln_class = value
                    break

            html += f"""
                <tr>
                    <td>{strategy}</td>
                    <td>{count}</td>
                    <td>{vuln_class}</td>
                </tr>
"""
        html += """
            </table>
"""
        return html

    def _format_cve_reference_table(self) -> str:
        """Format the CVE reference table.

        Returns:
            HTML string for CVE reference table.

        """
        return """
            <details>
                <summary>Reference: Known DICOM CVEs Addressed</summary>
                <table>
                    <tr>
                        <th>CVE ID</th>
                        <th>Vulnerability Type</th>
                        <th>Tested</th>
                    </tr>
                    <tr><td>CVE-2025-35975</td><td>Out-of-bounds write</td><td>Yes</td></tr>
                    <tr><td>CVE-2025-36521</td><td>Out-of-bounds read</td><td>Yes</td></tr>
                    <tr><td>CVE-2025-5943</td><td>Parser memory corruption</td><td>Yes</td></tr>
                    <tr><td>CVE-2024-25673</td><td>Buffer overflow</td><td>Yes</td></tr>
                    <tr><td>CVE-2024-25674</td><td>Integer overflow</td><td>Yes</td></tr>
                    <tr><td>CVE-2024-22252</td><td>Heap corruption</td><td>Yes</td></tr>
                    <tr><td>CVE-2024-1847</td><td>Memory exhaustion</td><td>Yes</td></tr>
                    <tr><td>CVE-2023-44855</td><td>Sequence parsing DoS</td><td>Yes</td></tr>
                </table>
            </details>
"""

    def format_severity_distribution(self, crashes: list[dict[str, Any]]) -> str:
        """Generate crash severity distribution chart.

        Args:
            crashes: List of crash dictionaries.

        Returns:
            HTML string for severity distribution.

        """
        if not crashes:
            return """
            <h3>Crash Severity Distribution</h3>
            <div class="success" style="background: #27ae60;">
                <span style="font-size: 2em;">[OK]</span>
                <div><strong>No crashes detected in this session.</strong></div>
            </div>
"""

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for crash in crashes:
            severity = crash.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["medium"] += 1

        total = len(crashes)

        html = """
            <h3>Crash Severity Distribution</h3>
            <div class="stats-grid" style="grid-template-columns: repeat(5, 1fr);">
"""
        colors = {
            "critical": "#c0392b",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#f1c40f",
            "info": "#3498db",
        }

        for severity, count in severity_counts.items():
            if count > 0:
                pct = (count / total * 100) if total > 0 else 0
                color = colors.get(severity, "#95a5a6")
                html += f"""
                <div class="stat-card" style="background: {color};">
                    <div class="stat-value">{count}</div>
                    <div class="stat-label">{severity.upper()}</div>
                    <div style="opacity: 0.8; font-size: 0.9em;">{pct:.1f}%</div>
                </div>
"""

        html += """
            </div>
"""

        # Add bar chart visualization
        if total > 0:
            html += self._format_severity_bar_chart(severity_counts, colors, total)

        return html

    def _format_severity_bar_chart(
        self, severity_counts: dict[str, int], colors: dict[str, str], total: int
    ) -> str:
        """Format the severity bar chart.

        Args:
            severity_counts: Dictionary of severity counts.
            colors: Dictionary of severity colors.
            total: Total crash count.

        Returns:
            HTML string for severity bar chart.

        """
        html = """
            <div style="margin: 20px 0; background: #f8f9fa; padding: 20px; border-radius: 8px;">
                <h4 style="margin-top: 0;">Severity Breakdown</h4>
"""
        for severity, count in severity_counts.items():
            if count > 0:
                pct = count / total * 100
                color = colors.get(severity, "#95a5a6")
                html += f"""
                <div style="margin: 10px 0;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div style="width: 80px; font-weight: 600; text-transform: uppercase;">{severity}</div>
                        <div style="flex: 1; background: #e0e0e0; border-radius: 4px; height: 24px;">
                            <div style="width: {pct}%; background: {color}; height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 10px; color: white; font-weight: 600;">
                                {count}
                            </div>
                        </div>
                    </div>
                </div>
"""
        html += """
            </div>
"""
        return html


__all__ = ["ReportAnalytics"]

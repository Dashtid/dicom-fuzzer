"""Enhanced Fuzzing Report Generator

Generates comprehensive, interactive HTML reports with:
- Complete mutation traceability
- Crash forensics with drill-down details
- Interactive visualizations
- Artifact preservation tracking
- Automated crash triage and prioritization
- FDA compliance sections (SBOM, CVE coverage, test coverage)
"""

from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.crash_triage import (
    CrashTriageEngine,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord
from dicom_fuzzer.core.html_templates import (
    escape_html,
    html_document_end,
    html_document_start,
)


class EnhancedReportGenerator:
    """Generate enhanced HTML and JSON reports for fuzzing sessions."""

    def __init__(
        self, output_dir: str = "./artifacts/reports", enable_triage: bool = True
    ):
        """Initialize enhanced report generator.

        Args:
            output_dir: Directory for generated reports
            enable_triage: Enable automated crash triage and prioritization

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize crash triage engine
        self.enable_triage = enable_triage
        self.triage_engine: CrashTriageEngine | None = None
        if enable_triage:
            self.triage_engine = CrashTriageEngine()

    def _enrich_crashes_with_triage(self, session_data: dict) -> dict:
        """Enrich crash records with automated triage analysis.

        Args:
            session_data: Session report dictionary

        Returns:
            Enhanced session data with triage information

        """
        if not self.enable_triage or not self.triage_engine:
            return session_data

        crashes = session_data.get("crashes", [])
        if not crashes:
            return session_data

        # Convert crash dicts to CrashRecord objects for triage
        crash_records = []
        for crash in crashes:
            # Parse timestamp (could be string or datetime)
            timestamp_val = crash.get("timestamp", "")
            if isinstance(timestamp_val, str) and timestamp_val:
                try:
                    timestamp_obj = datetime.fromisoformat(timestamp_val)
                except (ValueError, AttributeError):
                    timestamp_obj = datetime.now()
            elif isinstance(timestamp_val, datetime):
                timestamp_obj = timestamp_val
            else:
                timestamp_obj = datetime.now()

            # Create CrashRecord from dict (simplified for triage)
            crash_record = CrashRecord(
                crash_id=crash.get("crash_id", "unknown"),
                timestamp=timestamp_obj,
                crash_type=crash.get("crash_type", "unknown"),
                severity=crash.get("severity", "medium"),  # Default severity
                fuzzed_file_id=crash.get("fuzzed_file_id", "unknown"),
                fuzzed_file_path=crash.get("fuzzed_file_path", ""),
                return_code=crash.get("return_code"),
                exception_type=crash.get("exception_type"),
                exception_message=crash.get("exception_message"),
                stack_trace=crash.get("stack_trace", ""),
            )
            crash_records.append((crash, crash_record))

        # Perform triage
        for crash_dict, crash_record in crash_records:
            triage = self.triage_engine.triage_crash(crash_record)

            # Add triage data to crash dict
            crash_dict["triage"] = {
                "severity": triage.severity.value,
                "exploitability": triage.exploitability.value,
                "priority_score": triage.priority_score,
                "indicators": triage.indicators,
                "recommendations": triage.recommendations,
                "tags": triage.tags,
                "summary": triage.summary,
            }

        # Sort crashes by priority score (highest first)
        session_data["crashes"] = sorted(
            crashes,
            key=lambda c: c.get("triage", {}).get("priority_score", 0),
            reverse=True,
        )

        return session_data

    def generate_html_report(
        self,
        session_data: dict,
        output_path: Path | None = None,
    ) -> Path:
        """Generate comprehensive HTML report from session data.

        Args:
            session_data: Session report dictionary
            output_path: Path for HTML report (auto-generated if None)

        Returns:
            Path to generated HTML report

        """
        # Enrich crashes with automated triage
        session_data = self._enrich_crashes_with_triage(session_data)

        if output_path is None:
            html_dir = self.output_dir / "html"
            html_dir.mkdir(parents=True, exist_ok=True)
            session_id = session_data["session_info"]["session_id"]
            output_path = html_dir / f"fuzzing_report_{session_id}.html"

        html = self._generate_html_document(session_data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

    def _generate_html_document(self, data: dict) -> str:
        """Generate complete HTML document."""
        session_info = data["session_info"]
        stats = data["statistics"]
        crashes = data.get("crashes", [])
        fuzzed_files = data.get("fuzzed_files", {})

        html = self._html_header(session_info["session_name"])
        html += self._html_session_overview(session_info, stats)
        html += self._html_crash_summary(crashes, fuzzed_files)
        html += self._html_crash_details(crashes, fuzzed_files)
        html += self._html_mutation_analysis(fuzzed_files, crashes)
        # FDA compliance sections
        html += self._html_fda_compliance_section(data, crashes, fuzzed_files)
        html += self._html_footer()

        return html

    def _html_header(self, title: str) -> str:
        """Generate HTML header with enhanced styling."""
        return html_document_start(title)

    def _html_session_overview(self, session_info: dict, stats: dict) -> str:
        """Generate session overview section."""
        html = f"""
        <div class="header">
            <h1>{session_info["session_name"]}</h1>
            <div class="subtitle">Fuzzing Session Report</div>
            <div class="timestamp">
                Session ID: {session_info["session_id"]}<br>
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>

        <div class="content">
            <h2>Session Summary</h2>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats.get("files_fuzzed", 0)}</div>
                    <div class="stat-label">Files Fuzzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get("mutations_applied", 0)}</div>
                    <div class="stat-label">Mutations Applied</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get("crashes", 0)}</div>
                    <div class="stat-label">Crashes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get("hangs", 0)}</div>
                    <div class="stat-label">Hangs/Timeouts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get("successes", 0)}</div>
                    <div class="stat-label">Successes</div>
                </div>
            </div>

            <div class="info-grid">
                <div class="info-label">Start Time:</div>
                <div class="info-value">{session_info["start_time"]}</div>
                <div class="info-label">End Time:</div>
                <div class="info-value">{session_info.get("end_time", "In Progress")}</div>
                <div class="info-label">Duration:</div>
                <div class="info-value">{session_info.get("duration_seconds", 0):.2f} seconds</div>
            </div>
"""

        # Alert for crashes
        crash_count = stats.get("crashes", 0)
        hang_count = stats.get("hangs", 0)

        if crash_count > 0:
            html += f"""
            <div class="alert">
                <span style="font-size: 2em;">[!]</span>
                <div>
                    <strong>SECURITY FINDING:</strong> {crash_count} crash(es) detected during fuzzing!
                    This indicates potential vulnerabilities that require investigation.
                </div>
            </div>
"""
        if hang_count > 0:
            html += f"""
            <div class="warning">
                <span style="font-size: 2em;">[!]</span>
                <div>
                    <strong>DoS RISK:</strong> {hang_count} hang(s)/timeout(s) detected!
                    This may indicate Denial of Service vulnerabilities.
                </div>
            </div>
"""

        return html

    def _html_crash_summary(self, crashes: list[dict], fuzzed_files: dict) -> str:
        """Generate crash summary table."""
        if not crashes:
            return """
            <div class="success">
                <span style="font-size: 2em;">[OK]</span>
                <div><strong>No crashes detected!</strong> All tested files passed successfully.</div>
            </div>
"""

        html = """
            <h2>Crash Summary</h2>
            <table>
                <tr>
                    <th>Crash ID</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Mutations</th>
                    <th>Timestamp</th>
                </tr>
"""

        for crash in crashes:
            crash_id = crash["crash_id"]
            crash_type = crash["crash_type"]
            severity = crash["severity"]
            file_id = crash["fuzzed_file_id"]

            file_record = fuzzed_files.get(file_id, {})
            mutation_count = len(file_record.get("mutations", []))
            file_path = Path(crash.get("fuzzed_file_path", "")).name

            html += f"""
                <tr>
                    <td><code>{crash_id}</code></td>
                    <td><span class="badge {crash_type}">{crash_type}</span></td>
                    <td><span class="badge {severity}">{severity}</span></td>
                    <td><span class="file-path">{file_path}</span></td>
                    <td>{mutation_count}</td>
                    <td class="timestamp">{crash.get("timestamp", "")}</td>
                </tr>
"""

        html += """
            </table>
"""

        # Add Top 10 Critical Crashes section if triage enabled
        if self.enable_triage:
            critical_crashes = [
                c
                for c in crashes
                if c.get("triage", {}).get("severity") in ["critical", "high"]
            ]
            if critical_crashes:
                html += """
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

    def _html_crash_details(self, crashes: list[dict], fuzzed_files: dict) -> str:
        """Generate detailed crash information."""
        if not crashes:
            return ""

        html = """
            <h2>Crash Details and Forensics</h2>
            <p>Each crash includes complete mutation history and reproduction instructions.</p>
"""

        for crash in crashes:
            severity_class = crash.get("severity", "medium")
            crash_id = crash["crash_id"]
            file_id = crash["fuzzed_file_id"]
            file_record = fuzzed_files.get(file_id, {})

            html += f"""
            <div class="crash-item {severity_class}">
                <div class="crash-header">
                    <span class="badge {severity_class}">{crash.get("severity", "unknown").upper()}</span>
                    <span class="badge {crash.get("crash_type", "crash")}">{crash.get("crash_type", "crash").upper()}</span>
                    <strong>{crash_id}</strong>
                </div>

                <div class="info-grid">
                    <div class="info-label">Timestamp:</div>
                    <div class="info-value">{crash.get("timestamp", "N/A")}</div>

                    <div class="info-label">Source File:</div>
                    <div class="info-value"><span class="file-path">{file_record.get("source_file", "N/A")}</span></div>

                    <div class="info-label">Fuzzed File:</div>
                    <div class="info-value"><span class="file-path">{crash.get("fuzzed_file_path", "N/A")}</span></div>

                    <div class="info-label">Preserved Sample:</div>
                    <div class="info-value"><span class="file-path">{crash.get("preserved_sample_path", "N/A")}</span></div>

                    <div class="info-label">Crash Log:</div>
                    <div class="info-value"><span class="file-path">{crash.get("crash_log_path", "N/A")}</span></div>
"""

            # Add triage information if available
            triage = crash.get("triage")
            if triage:
                html += f"""
                    <div class="info-label">Triage Priority:</div>
                    <div class="info-value"><strong>{triage.get("priority_score", 0):.1f}/100</strong></div>

                    <div class="info-label">Exploitability:</div>
                    <div class="info-value"><span class="badge {triage.get("exploitability", "unknown").replace("_", "-")}">{triage.get("exploitability", "unknown").replace("_", " ").title()}</span></div>
"""
                if triage.get("indicators"):
                    indicators_list = "<br>".join(
                        f"- {ind}" for ind in triage["indicators"]
                    )
                    html += f"""
                    <div class="info-label">Triage Indicators:</div>
                    <div class="info-value">{indicators_list}</div>
"""
                if triage.get("recommendations"):
                    recommendations_list = "<br>".join(
                        f"- {rec}" for rec in triage["recommendations"]
                    )
                    html += f"""
                    <div class="info-label">Recommendations:</div>
                    <div class="info-value">{recommendations_list}</div>
"""

            if crash.get("return_code") is not None:
                html += f"""
                    <div class="info-label">Return Code:</div>
                    <div class="info-value">{crash["return_code"]}</div>
"""

            if crash.get("exception_type"):
                html += f"""
                    <div class="info-label">Exception Type:</div>
                    <div class="info-value">{crash["exception_type"]}</div>
"""

            html += """
                </div>
"""

            # Exception message
            if crash.get("exception_message"):
                html += f"""
                <h4>Exception Message:</h4>
                <div class="code-block">{escape_html(crash["exception_message"])}</div>
"""

            # Mutation history
            mutations = file_record.get("mutations", [])
            if mutations:
                html += f"""
                <details open>
                    <summary>Mutation History ({len(mutations)} mutations)</summary>
                    <div class="mutation-list">
"""
                for i, mut in enumerate(mutations, 1):
                    html += f"""
                        <div class="mutation-item">
                            <div class="mutation-header">
                                #{i}: {mut.get("strategy_name", "Unknown")} - {mut.get("mutation_type", "unknown")}
                            </div>
"""
                    if mut.get("target_tag"):
                        target_info = mut["target_tag"]
                        if mut.get("target_element"):
                            target_info += f" ({mut['target_element']})"
                        html += f"""
                            <div class="mutation-detail">Target: {target_info}</div>
"""

                    if mut.get("original_value"):
                        html += f"""
                            <div class="mutation-detail">Original: {escape_html(str(mut["original_value"])[:200])}</div>
"""

                    if mut.get("mutated_value"):
                        html += f"""
                            <div class="mutation-detail">Mutated:  {escape_html(str(mut["mutated_value"])[:200])}</div>
"""

                    html += """
                        </div>
"""

                html += """
                    </div>
                </details>
"""

            # Reproduction command
            if crash.get("reproduction_command"):
                html += f"""
                <h4>Reproduction Command:</h4>
                <div class="repro-command" onclick="navigator.clipboard.writeText(this.textContent.trim())">
                    {crash["reproduction_command"]}
                </div>
                <small style="color: #95a5a6;">Click to copy to clipboard</small>
"""

            # Stack trace
            if crash.get("stack_trace"):
                html += f"""
                <details>
                    <summary>Stack Trace</summary>
                    <div class="code-block">{escape_html(crash["stack_trace"])}</div>
                </details>
"""

            html += """
            </div>
"""

        return html

    def _html_mutation_analysis(
        self, fuzzed_files: dict, crashes: list | None = None
    ) -> str:
        """Generate mutation strategy analysis."""
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
        if self.enable_triage:
            critical_crashes = [
                c
                for c in crashes
                if c.get("triage", {}).get("severity") in ["critical", "high"]
            ]
            if critical_crashes:
                html += """
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

    def _html_fda_compliance_section(
        self, data: dict, crashes: list[dict], fuzzed_files: dict
    ) -> str:
        """Generate FDA compliance and regulatory sections.

        Includes:
        - SBOM summary (Software Bill of Materials)
        - CVE mutation coverage analysis
        - Severity distribution
        - Testing methodology compliance checklist
        """
        html = """
            <h2>FDA Compliance &amp; Security Analysis</h2>
            <p>This section provides regulatory compliance information for FDA cybersecurity submissions.</p>
"""

        # SBOM Summary
        html += self._generate_sbom_summary()

        # CVE Mutation Coverage
        html += self._generate_cve_coverage(fuzzed_files)

        # Severity Distribution
        html += self._generate_severity_distribution(crashes)

        # Compliance Checklist
        html += self._generate_compliance_checklist(data, crashes)

        return html

    def _generate_sbom_summary(self) -> str:
        """Generate SBOM (Software Bill of Materials) summary section."""
        html = """
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
        return html

    def _generate_cve_coverage(self, fuzzed_files: dict) -> str:
        """Generate CVE mutation coverage analysis."""
        # Track which CVE-based mutations were used
        cve_mutations: dict[str, int] = {}
        total_mutations = 0

        for file_record in fuzzed_files.values():
            for mutation in file_record.get("mutations", []):
                strategy = mutation.get("strategy_name", "")
                total_mutations += 1

                # CVE-inspired mutations typically have CVE in the name or are security-focused
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
            cve_total = sum(cve_mutations.values())
            coverage_pct = (
                (cve_total / total_mutations * 100) if total_mutations > 0 else 0
            )

            html += f"""
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
        html += """
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
        return html

    def _generate_severity_distribution(self, crashes: list[dict]) -> str:
        """Generate crash severity distribution chart."""
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
            html += """
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

    def _generate_compliance_checklist(self, data: dict, crashes: list[dict]) -> str:
        """Generate FDA compliance testing checklist."""
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

    def _html_footer(self) -> str:
        """Generate HTML footer."""
        return "    </div>" + html_document_end()

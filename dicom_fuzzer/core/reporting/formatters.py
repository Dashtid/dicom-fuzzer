"""HTML Section Formatters.

Generates HTML sections for fuzzing reports.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from dicom_fuzzer.core.html_templates import escape_html


class HTMLSectionFormatter:
    """Formats HTML sections for fuzzing reports."""

    def __init__(self, enable_triage: bool = True):
        """Initialize the HTML section formatter.

        Args:
            enable_triage: Whether triage information is available.

        """
        self.enable_triage = enable_triage

    def format_session_overview(
        self, session_info: dict[str, Any], stats: dict[str, Any]
    ) -> str:
        """Generate session overview section.

        Args:
            session_info: Session information dictionary.
            stats: Statistics dictionary.

        Returns:
            HTML string for session overview.

        """
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

    def format_crash_summary(
        self, crashes: list[dict[str, Any]], fuzzed_files: dict[str, Any]
    ) -> str:
        """Generate crash summary table.

        Args:
            crashes: List of crash dictionaries.
            fuzzed_files: Dictionary of fuzzed file records.

        Returns:
            HTML string for crash summary.

        """
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
            html += self._format_critical_crashes_table(crashes)

        return html

    def _format_critical_crashes_table(self, crashes: list[dict[str, Any]]) -> str:
        """Format the critical crashes table.

        Args:
            crashes: List of crash dictionaries.

        Returns:
            HTML string for critical crashes table.

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

    def format_crash_details(
        self, crashes: list[dict[str, Any]], fuzzed_files: dict[str, Any]
    ) -> str:
        """Generate detailed crash information.

        Args:
            crashes: List of crash dictionaries.
            fuzzed_files: Dictionary of fuzzed file records.

        Returns:
            HTML string for crash details.

        """
        if not crashes:
            return ""

        html = """
            <h2>Crash Details and Forensics</h2>
            <p>Each crash includes complete mutation history and reproduction instructions.</p>
"""

        for crash in crashes:
            html += self._format_single_crash(crash, fuzzed_files)

        return html

    def _format_single_crash(
        self, crash: dict[str, Any], fuzzed_files: dict[str, Any]
    ) -> str:
        """Format a single crash detail section.

        Args:
            crash: Crash dictionary.
            fuzzed_files: Dictionary of fuzzed file records.

        Returns:
            HTML string for single crash detail.

        """
        severity_class = crash.get("severity", "medium")
        crash_id = crash["crash_id"]
        file_id = crash["fuzzed_file_id"]
        file_record = fuzzed_files.get(file_id, {})

        html = f"""
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
            html += self._format_triage_info(triage)

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
            html += self._format_mutation_history(mutations)

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

    def _format_triage_info(self, triage: dict[str, Any]) -> str:
        """Format triage information.

        Args:
            triage: Triage dictionary.

        Returns:
            HTML string for triage info.

        """
        html = f"""
                    <div class="info-label">Triage Priority:</div>
                    <div class="info-value"><strong>{triage.get("priority_score", 0):.1f}/100</strong></div>

                    <div class="info-label">Exploitability:</div>
                    <div class="info-value"><span class="badge {triage.get("exploitability", "unknown").replace("_", "-")}">{triage.get("exploitability", "unknown").replace("_", " ").title()}</span></div>
"""
        if triage.get("indicators"):
            indicators_list = "<br>".join(f"- {ind}" for ind in triage["indicators"])
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
        return html

    def _format_mutation_history(self, mutations: list[dict[str, Any]]) -> str:
        """Format mutation history section.

        Args:
            mutations: List of mutation dictionaries.

        Returns:
            HTML string for mutation history.

        """
        html = f"""
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
        return html


__all__ = ["HTMLSectionFormatter"]

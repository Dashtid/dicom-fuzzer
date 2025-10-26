"""
Enhanced Fuzzing Report Generator

Generates comprehensive, interactive HTML reports with:
- Complete mutation traceability
- Crash forensics with drill-down details
- Interactive visualizations
- Artifact preservation tracking
- Automated crash triage and prioritization
"""
# flake8: noqa: E201, E202, E222, E221, E702
# HTML template strings contain intentional CSS formatting

from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.crash_triage import (
    CrashTriageEngine,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord


class EnhancedReportGenerator:
    """Generate enhanced HTML and JSON reports for fuzzing sessions."""

    def __init__(self, output_dir: str = "./reports", enable_triage: bool = True):
        """
        Initialize enhanced report generator.

        Args:
            output_dir: Directory for generated reports
            enable_triage: Enable automated crash triage and prioritization
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize crash triage engine
        self.enable_triage = enable_triage
        if enable_triage:
            self.triage_engine = CrashTriageEngine()
        else:
            self.triage_engine = None

    def _enrich_crashes_with_triage(self, session_data: dict) -> dict:
        """
        Enrich crash records with automated triage analysis.

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
                from datetime import datetime

                try:
                    timestamp_obj = datetime.fromisoformat(timestamp_val)
                except (ValueError, AttributeError):
                    timestamp_obj = datetime.now()
            elif isinstance(timestamp_val, datetime):
                timestamp_obj = timestamp_val
            else:
                from datetime import datetime

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
        """
        Generate comprehensive HTML report from session data.

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
        html += self._html_footer()

        return html

    def _html_header(self, title: str) -> str:
        """Generate HTML header with enhanced styling."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Fuzzing Report</title>
    <style>
        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
        }}

        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 700;
        }}

        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .content {{
            padding: 40px;
        }}

        h2 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 40px;
            font-size: 1.8em;
        }}

        h3 {{
            color: #34495e;
            margin-top: 30px;
            font-size: 1.4em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-value {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .stat-label {{
            opacity: 0.9;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .crash-item {{
            background: white;
            border: 1px solid #e0e0e0;
            border-left: 5px solid #e74c3c;
            margin: 20px 0;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}

        .crash-item.critical {{ border-left-color: #c0392b; background: #fff5f5; }}
        .crash-item.high {{ border-left-color: #e74c3c; background: #fff8f8; }}
        .crash-item.medium {{ border-left-color: #f39c12; background: #fffbf0; }}
        .crash-item.low {{ border-left-color: #f1c40f; background: #fffff0; }}

        .crash-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge.critical {{ background: #c0392b; color: white; }}
        .badge.high {{ background: #e74c3c; color: white; }}
        .badge.medium {{ background: #f39c12; color: white; }}
        .badge.low {{ background: #f1c40f; color: #333; }}
        .badge.crash {{ background: #e74c3c; color: white; }}
        .badge.hang {{ background: #f39c12; color: white; }}

        .mutation-list {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
        }}

        .mutation-item {{
            background: white;
            border-left: 3px solid #3498db;
            padding: 12px;
            margin: 10px 0;
            border-radius: 4px;
            font-size: 0.95em;
        }}

        .mutation-item .mutation-header {{
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
        }}

        .mutation-detail {{
            color: #555;
            margin: 5px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}

        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 10px;
            margin: 15px 0;
        }}

        .info-label {{
            font-weight: 600;
            color: #555;
        }}

        .info-value {{
            color: #2c3e50;
            word-break: break-all;
        }}

        details {{
            margin: 15px 0;
        }}

        summary {{
            cursor: pointer;
            font-weight: 600;
            color: #3498db;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            user-select: none;
        }}

        summary:hover {{
            background: #e9ecef;
        }}

        .alert {{
            background: #e74c3c;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .warning {{
            background: #f39c12;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .success {{
            background: #27ae60;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .file-path {{
            background: #ecf0f1;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}

        .timestamp {{
            color: #95a5a6;
            font-size: 0.9em;
        }}

        .repro-command {{
            background: #2c3e50;
            color: #2ecc71;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            margin: 15px 0;
            cursor: pointer;
        }}

        .repro-command:hover {{
            background: #34495e;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}

        th {{
            background: #34495e;
            color: white;
            font-weight: 600;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
"""

    def _html_session_overview(self, session_info: dict, stats: dict) -> str:
        """Generate session overview section."""
        html = f"""
        <div class="header">
            <h1>🔍 {session_info["session_name"]}</h1>
            <div class="subtitle">Fuzzing Session Report</div>
            <div class="timestamp">
                Session ID: {session_info["session_id"]}<br>
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>

        <div class="content">
            <h2>📊 Session Summary</h2>

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
                <span style="font-size: 2em;">⚠️</span>
                <div>
                    <strong>SECURITY FINDING:</strong> {crash_count} crash(es) detected during fuzzing!
                    This indicates potential vulnerabilities that require investigation.
                </div>
            </div>
"""
        if hang_count > 0:
            html += f"""
            <div class="warning">
                <span style="font-size: 2em;">⏱️</span>
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
                <span style="font-size: 2em;">✓</span>
                <div><strong>No crashes detected!</strong> All tested files passed successfully.</div>
            </div>
"""

        html = """
            <h2>🔥 Crash Summary</h2>
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
            <h3>🚨 Top Critical Crashes</h3>
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
            <h2>🔍 Crash Details & Forensics</h2>
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
                        f"• {ind}" for ind in triage["indicators"]
                    )
                    html += f"""
                    <div class="info-label">Triage Indicators:</div>
                    <div class="info-value">{indicators_list}</div>
"""
                if triage.get("recommendations"):
                    recommendations_list = "<br>".join(
                        f"• {rec}" for rec in triage["recommendations"]
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
                <div class="code-block">{self._escape_html(crash["exception_message"])}</div>
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
                            <div class="mutation-detail">Original: {self._escape_html(str(mut["original_value"])[:200])}</div>
"""

                    if mut.get("mutated_value"):
                        html += f"""
                            <div class="mutation-detail">Mutated:  {self._escape_html(str(mut["mutated_value"])[:200])}</div>
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
                <h4>🔄 Reproduction Command:</h4>
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
                    <div class="code-block">{self._escape_html(crash["stack_trace"])}</div>
                </details>
"""

            html += """
            </div>
"""

        return html

    def _html_mutation_analysis(self, fuzzed_files: dict, crashes: list = None) -> str:
        """Generate mutation strategy analysis."""
        if not fuzzed_files:
            return ""

        # Default to empty list if not provided
        if crashes is None:
            crashes = []

        # Analyze mutation strategies used
        strategy_counts = {}
        mutation_type_counts = {}

        for file_record in fuzzed_files.values():
            for mutation in file_record.get("mutations", []):
                strategy = mutation.get("strategy_name", "Unknown")
                mut_type = mutation.get("mutation_type", "unknown")

                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
                mutation_type_counts[mut_type] = (
                    mutation_type_counts.get(mut_type, 0) + 1
                )

        html = """
            <h2>📈 Mutation Analysis</h2>
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
            <h3>🚨 Top Critical Crashes</h3>
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

    def _html_footer(self) -> str:
        """Generate HTML footer."""
        return """
        </div>
    </div>
</body>
</html>
"""

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

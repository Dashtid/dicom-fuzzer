"""HTML templates and CSS styles for fuzzing reports.

This module contains reusable HTML templates and CSS styles extracted from
enhanced_reporter.py to improve maintainability and separation of concerns.
"""

from __future__ import annotations

from typing import Any, Final

# =============================================================================
# CSS Styles -- used by html_document_start() and enhanced_reporter.py
# =============================================================================

#: Main CSS styles for fuzzing reports
REPORT_CSS: Final[str] = """
* { box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    margin: 0;
    padding: 16px;
    background: #f5f6f8;
    min-height: 100vh;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    border-radius: 6px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    overflow: hidden;
}

.header {
    background: #1a1a2e;
    color: white;
    padding: 28px 32px;
}

.header h1 {
    margin: 0 0 6px 0;
    font-size: 1.8em;
    font-weight: 600;
}

.header .subtitle {
    opacity: 0.85;
    font-size: 0.95em;
}

.content {
    padding: 28px 32px;
}

h2 {
    color: #1a1a2e;
    border-bottom: 2px solid #d0d5dd;
    padding-bottom: 8px;
    margin-top: 32px;
    font-size: 1.4em;
    font-weight: 600;
}

h3 {
    color: #344054;
    margin-top: 24px;
    font-size: 1.15em;
    font-weight: 600;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.stat-card {
    background: white;
    border: 1px solid #e0e0e0;
    color: #1a1a2e;
    padding: 20px;
    border-radius: 6px;
    text-align: center;
}

.stat-card.accent-red { border-left: 4px solid #d32f2f; }
.stat-card.accent-amber { border-left: 4px solid #f59e0b; }

.stat-value {
    font-size: 2em;
    font-weight: 700;
    margin: 6px 0;
    color: #1a1a2e;
}

.stat-label {
    color: #667085;
    font-size: 0.8em;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.crash-item {
    background: white;
    border: 1px solid #e0e0e0;
    border-left: 4px solid #e74c3c;
    margin: 16px 0;
    padding: 20px;
    border-radius: 6px;
}

.crash-item.critical { border-left-color: #c0392b; }
.crash-item.high { border-left-color: #e74c3c; }
.crash-item.medium { border-left-color: #f39c12; }
.crash-item.low { border-left-color: #f1c40f; }

.crash-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
}

.badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.75em;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}

.badge.critical { background: #fde8e8; color: #c0392b; }
.badge.high { background: #fde8e8; color: #e74c3c; }
.badge.medium { background: #fef3cd; color: #b45309; }
.badge.low { background: #fef9c3; color: #92400e; }
.badge.crash { background: #fde8e8; color: #e74c3c; }
.badge.hang { background: #fef3cd; color: #b45309; }

.mutation-list {
    background: #f9fafb;
    border-radius: 4px;
    padding: 12px;
    margin: 12px 0;
}

.mutation-item {
    background: white;
    border-left: 3px solid #3b82f6;
    padding: 10px;
    margin: 8px 0;
    border-radius: 4px;
    font-size: 0.9em;
}

.mutation-item .mutation-header {
    font-weight: 600;
    color: #1a1a2e;
    margin-bottom: 4px;
}

.mutation-detail {
    color: #555;
    margin: 4px 0;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
}

.code-block {
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}

.info-grid {
    display: grid;
    grid-template-columns: 180px 1fr;
    gap: 8px;
    margin: 12px 0;
}

.info-label {
    font-weight: 600;
    color: #555;
    font-size: 0.9em;
}

.info-value {
    color: #1a1a2e;
    word-break: break-all;
    font-size: 0.9em;
}

details {
    margin: 12px 0;
}

summary {
    cursor: pointer;
    font-weight: 600;
    color: #2563eb;
    padding: 8px 10px;
    background: #f9fafb;
    border-radius: 4px;
    user-select: none;
    font-size: 0.9em;
}

summary:hover {
    background: #f0f2f5;
}

.alert {
    background: white;
    border: 1px solid #fca5a5;
    border-left: 4px solid #dc2626;
    color: #1a1a2e;
    padding: 16px;
    border-radius: 6px;
    margin: 16px 0;
    font-size: 0.95em;
    display: flex;
    align-items: center;
    gap: 12px;
}

.warning {
    background: white;
    border: 1px solid #fcd34d;
    border-left: 4px solid #f59e0b;
    color: #1a1a2e;
    padding: 16px;
    border-radius: 6px;
    margin: 16px 0;
    font-size: 0.95em;
    display: flex;
    align-items: center;
    gap: 12px;
}

.success {
    background: white;
    border: 1px solid #86efac;
    border-left: 4px solid #16a34a;
    color: #1a1a2e;
    padding: 16px;
    border-radius: 6px;
    margin: 16px 0;
    font-size: 0.95em;
    display: flex;
    align-items: center;
    gap: 12px;
}

.file-path {
    background: #f1f5f9;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    word-break: break-all;
}

.timestamp {
    color: #6b7280;
    font-size: 0.85em;
}

.repro-command {
    background: #1e293b;
    color: #4ade80;
    padding: 12px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    margin: 12px 0;
    cursor: pointer;
    font-size: 0.85em;
}

.repro-command:hover {
    background: #334155;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 0.9em;
}

th, td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
}

th {
    background: #f0f2f5;
    color: #333;
    font-weight: 600;
    font-size: 0.85em;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}

tr:hover {
    background: #f9fafb;
}
"""

# =============================================================================
# HTML Template Functions
# =============================================================================


def escape_html(text: str) -> str:
    """Escape HTML special characters.

    Args:
        text: Raw text to escape

    Returns:
        HTML-escaped text safe for inclusion in HTML documents

    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# =============================================================================
# Document Structure Templates
# =============================================================================


def html_document_start(title: str) -> str:
    """Generate HTML document start with head and styles.

    Args:
        title: Page title

    Returns:
        HTML string for document start through body opening

    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape_html(title)} - Fuzzing Report</title>
    <style>
        {REPORT_CSS}
    </style>
</head>
<body>
    <div class="container">
"""


def html_document_end() -> str:
    """Generate HTML document end.

    Returns:
        HTML string for document closing tags

    """
    return """
    </div>
</body>
</html>
"""


def legacy_html_document(
    report: dict[str, Any],
    stats: dict[str, Any],
    config: dict[str, Any],
    alert_html: str,
    hang_rate: float,
) -> str:
    """Generate a complete legacy HTML report document.

    Args:
        report: Full session report dict (must contain "timestamp" key)
        stats: Statistics sub-dict from the report
        config: Configuration sub-dict from the report
        alert_html: Pre-rendered alert/warning/success HTML block
        hang_rate: Hang rate as a float (0-100)

    Returns:
        Complete HTML document as a string

    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DICOM Viewer Fuzzing Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2980b9;
        }}
        .metric-label {{
            color: #7f8c8d;
            margin-top: 10px;
            font-size: 0.9em;
        }}
        .alert {{ background: #e74c3c; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .warning {{ background: #f39c12; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .success {{ background: #27ae60; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .config-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .config-table th, .config-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .config-table th {{
            background: #34495e;
            color: white;
        }}
        .timestamp {{ color: #95a5a6; font-size: 0.9em; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DICOM Viewer Security Assessment</h1>
        <p class="timestamp">Generated: {report["timestamp"]}</p>
        {alert_html}
        <h2>Test Configuration</h2>
        <table class="config-table">
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td><strong>Target Application</strong></td><td><code>{config.get("viewer_path", "N/A")}</code></td></tr>
            <tr><td><strong>Input Directory</strong></td><td><code>{config.get("input_dir", "N/A")}</code></td></tr>
            <tr><td><strong>Output Directory</strong></td><td><code>{config.get("output_dir", "N/A")}</code></td></tr>
            <tr><td><strong>Timeout (seconds)</strong></td><td>{config.get("timeout", "N/A")}</td></tr>
        </table>
        <h2>Test Results</h2>
        <div class="summary-grid">
            <div class="metric-card"><div class="metric-value">{stats.get("files_processed", 0)}</div><div class="metric-label">Files Processed</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("files_fuzzed", 0)}</div><div class="metric-label">Files Fuzzed</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("files_generated", 0)}</div><div class="metric-label">Files Generated</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("viewer_crashes", 0)}</div><div class="metric-label">Crashes</div></div>
            <div class="metric-card"><div class="metric-value">{stats.get("viewer_hangs", 0)}</div><div class="metric-label">Hangs/Timeouts</div></div>
            <div class="metric-card"><div class="metric-value">{hang_rate:.1f}%</div><div class="metric-label">Hang Rate</div></div>
        </div>
        <h2>Recommendations</h2>
        <ul>
            <li>Investigate hang logs in <code>{config.get("output_dir", "output")}</code></li>
            <li>Test fuzzed files manually to reproduce and debug</li>
            <li>Implement robust input validation for DICOM file parsing</li>
            <li>Add timeout mechanisms in the DICOM parser</li>
        </ul>
        <p class="timestamp">Report generated by DICOM Fuzzer.</p>
    </div>
</body>
</html>
"""

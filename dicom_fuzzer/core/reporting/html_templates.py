"""HTML templates and CSS styles for fuzzing reports.

This module contains reusable HTML templates and CSS styles extracted from
enhanced_reporter.py to improve maintainability and separation of concerns.
"""

from __future__ import annotations

from typing import Final

# =============================================================================
# CSS Styles
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
# Severity Colors
# =============================================================================

#: Color mapping for severity levels
SEVERITY_COLORS: Final[dict[str, str]] = {
    "critical": "#c0392b",
    "high": "#e74c3c",
    "medium": "#f39c12",
    "low": "#f1c40f",
    "info": "#3498db",
}

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


def render_badge(text: str, css_class: str = "") -> str:
    """Render a styled badge element.

    Args:
        text: Badge text content
        css_class: Additional CSS classes (e.g., 'critical', 'high')

    Returns:
        HTML string for the badge

    """
    return f'<span class="badge {css_class}">{escape_html(text)}</span>'


def render_stat_card(
    value: int | float | str,
    label: str,
    background: str | None = None,
) -> str:
    """Render a statistics card.

    Args:
        value: The statistic value to display
        label: Label describing the statistic
        background: Optional custom background gradient CSS

    Returns:
        HTML string for the stat card

    """
    style = ""
    if background:
        style = f' style="background: {background};"'

    return f"""<div class="stat-card"{style}>
    <div class="stat-value">{value}</div>
    <div class="stat-label">{escape_html(label)}</div>
</div>"""


def render_alert(
    message: str,
    title: str = "",
    alert_type: str = "alert",
    icon: str = "[!]",
) -> str:
    """Render an alert box.

    Args:
        message: Alert message content
        title: Optional bold title prefix
        alert_type: CSS class ('alert', 'warning', 'success')
        icon: Icon text to display

    Returns:
        HTML string for the alert box

    """
    title_html = f"<strong>{escape_html(title)}</strong> " if title else ""
    return f"""<div class="{alert_type}">
    <span style="font-size: 1.4em;">{icon}</span>
    <div>{title_html}{escape_html(message)}</div>
</div>"""


def render_info_row(label: str, value: str, is_file_path: bool = False) -> str:
    """Render an info grid row.

    Args:
        label: Row label
        value: Row value
        is_file_path: If True, wraps value in file-path styling

    Returns:
        HTML string for the info row (label + value divs)

    """
    value_html = escape_html(value)
    if is_file_path:
        value_html = f'<span class="file-path">{value_html}</span>'

    return f"""<div class="info-label">{escape_html(label)}:</div>
<div class="info-value">{value_html}</div>"""


def render_code_block(content: str) -> str:
    """Render a code block.

    Args:
        content: Code or text content

    Returns:
        HTML string for the code block

    """
    return f'<div class="code-block">{escape_html(content)}</div>'


def render_details(summary: str, content: str, open_by_default: bool = False) -> str:
    """Render a collapsible details element.

    Args:
        summary: Summary text (clickable)
        content: Hidden content revealed on expand
        open_by_default: If True, details starts expanded

    Returns:
        HTML string for the details element

    """
    open_attr = " open" if open_by_default else ""
    return f"""<details{open_attr}>
    <summary>{escape_html(summary)}</summary>
    {content}
</details>"""


def render_table_header(columns: list[str]) -> str:
    """Render a table header row.

    Args:
        columns: List of column header texts

    Returns:
        HTML string for the table header

    """
    headers = "".join(f"<th>{escape_html(col)}</th>" for col in columns)
    return f"<tr>{headers}</tr>"


def render_table_row(cells: list[str], escape: bool = True) -> str:
    """Render a table data row.

    Args:
        cells: List of cell contents
        escape: If True, HTML-escapes cell contents

    Returns:
        HTML string for the table row

    """
    if escape:
        cell_html = "".join(f"<td>{escape_html(str(cell))}</td>" for cell in cells)
    else:
        cell_html = "".join(f"<td>{cell}</td>" for cell in cells)
    return f"<tr>{cell_html}</tr>"


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


def html_report_header(title: str, subtitle: str, metadata: str) -> str:
    """Generate the report header section.

    Args:
        title: Main title
        subtitle: Subtitle text
        metadata: Additional metadata (session ID, timestamp, etc.)

    Returns:
        HTML string for the header section

    """
    return f"""<div class="header">
    <h1>{escape_html(title)}</h1>
    <div class="subtitle">{escape_html(subtitle)}</div>
    <div class="timestamp">{metadata}</div>
</div>

<div class="content">
"""

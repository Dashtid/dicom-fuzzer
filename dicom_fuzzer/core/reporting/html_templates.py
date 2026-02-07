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
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    overflow: hidden;
}

.header {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: white;
    padding: 40px;
}

.header h1 {
    margin: 0 0 10px 0;
    font-size: 2.5em;
    font-weight: 700;
}

.header .subtitle {
    opacity: 0.9;
    font-size: 1.1em;
}

.content {
    padding: 40px;
}

h2 {
    color: #2c3e50;
    border-bottom: 3px solid #3498db;
    padding-bottom: 10px;
    margin-top: 40px;
    font-size: 1.8em;
}

h3 {
    color: #34495e;
    margin-top: 30px;
    font-size: 1.4em;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin: 30px 0;
}

.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 25px;
    border-radius: 10px;
    text-align: center;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    transition: transform 0.2s;
}

.stat-card:hover {
    transform: translateY(-5px);
}

.stat-value {
    font-size: 3em;
    font-weight: bold;
    margin: 10px 0;
}

.stat-label {
    opacity: 0.9;
    font-size: 0.9em;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.crash-item {
    background: white;
    border: 1px solid #e0e0e0;
    border-left: 5px solid #e74c3c;
    margin: 20px 0;
    padding: 25px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

.crash-item.critical { border-left-color: #c0392b; background: #fff5f5; }
.crash-item.high { border-left-color: #e74c3c; background: #fff8f8; }
.crash-item.medium { border-left-color: #f39c12; background: #fffbf0; }
.crash-item.low { border-left-color: #f1c40f; background: #fffff0; }

.crash-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 15px;
}

.badge {
    display: inline-block;
    padding: 5px 12px;
    border-radius: 20px;
    font-size: 0.85em;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge.critical { background: #c0392b; color: white; }
.badge.high { background: #e74c3c; color: white; }
.badge.medium { background: #f39c12; color: white; }
.badge.low { background: #f1c40f; color: #333; }
.badge.crash { background: #e74c3c; color: white; }
.badge.hang { background: #f39c12; color: white; }

.mutation-list {
    background: #f8f9fa;
    border-radius: 6px;
    padding: 15px;
    margin: 15px 0;
}

.mutation-item {
    background: white;
    border-left: 3px solid #3498db;
    padding: 12px;
    margin: 10px 0;
    border-radius: 4px;
    font-size: 0.95em;
}

.mutation-item .mutation-header {
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 5px;
}

.mutation-detail {
    color: #555;
    margin: 5px 0;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

.code-block {
    background: #2c3e50;
    color: #ecf0f1;
    padding: 15px;
    border-radius: 6px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}

.info-grid {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 10px;
    margin: 15px 0;
}

.info-label {
    font-weight: 600;
    color: #555;
}

.info-value {
    color: #2c3e50;
    word-break: break-all;
}

details {
    margin: 15px 0;
}

summary {
    cursor: pointer;
    font-weight: 600;
    color: #3498db;
    padding: 10px;
    background: #f8f9fa;
    border-radius: 6px;
    user-select: none;
}

summary:hover {
    background: #e9ecef;
}

.alert {
    background: #e74c3c;
    color: white;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
    font-size: 1.1em;
    display: flex;
    align-items: center;
    gap: 15px;
}

.warning {
    background: #f39c12;
    color: white;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
    font-size: 1.1em;
    display: flex;
    align-items: center;
    gap: 15px;
}

.success {
    background: #27ae60;
    color: white;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
    font-size: 1.1em;
    display: flex;
    align-items: center;
    gap: 15px;
}

.file-path {
    background: #ecf0f1;
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    word-break: break-all;
}

.timestamp {
    color: #95a5a6;
    font-size: 0.9em;
}

.repro-command {
    background: #2c3e50;
    color: #2ecc71;
    padding: 15px;
    border-radius: 6px;
    font-family: 'Courier New', monospace;
    margin: 15px 0;
    cursor: pointer;
}

.repro-command:hover {
    background: #34495e;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #e0e0e0;
}

th {
    background: #34495e;
    color: white;
    font-weight: 600;
}

tr:hover {
    background: #f8f9fa;
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
    <span style="font-size: 2em;">{icon}</span>
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


def render_progress_bar(
    value: float,
    max_value: float,
    label: str,
    color: str = "#667eea",
    show_count: int | None = None,
) -> str:
    """Render a horizontal progress/bar chart item.

    Args:
        value: Current value
        max_value: Maximum value (for percentage calculation)
        label: Label text
        color: Bar color
        show_count: Optional count to display in bar

    Returns:
        HTML string for the progress bar

    """
    pct = (value / max_value * 100) if max_value > 0 else 0
    count_display = str(show_count) if show_count is not None else f"{pct:.1f}%"

    return f"""<div style="margin: 10px 0;">
    <div style="display: flex; align-items: center; gap: 10px;">
        <div style="width: 80px; font-weight: 600; text-transform: uppercase;">{escape_html(label)}</div>
        <div style="flex: 1; background: #e0e0e0; border-radius: 4px; height: 24px;">
            <div style="width: {pct}%; background: {color}; height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 10px; color: white; font-weight: 600;">
                {count_display}
            </div>
        </div>
    </div>
</div>"""


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

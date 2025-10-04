"""Generate HTML report from JSON fuzzing results."""

import json
import sys
from pathlib import Path
from datetime import datetime

def create_html_report(json_path: str, html_path: str = None):
    """Create HTML report from JSON fuzzing results."""

    # Read JSON report
    with open(json_path, 'r') as f:
        report = json.load(f)

    # Default HTML path
    if html_path is None:
        html_path = json_path.replace('.json', '.html')

    # Get stats
    stats = report['statistics']
    config = report['configuration']

    # Calculate total tests
    total_tests = stats.get('viewer_hangs', 0) + stats.get('viewer_crashes', 0) + stats.get('viewer_success', 0)
    hang_rate = stats.get('hang_rate', 0)

    # Determine alert type
    alert_html = ''
    if hang_rate == 100.0:
        alert_html = '''<div class="alert">
            <strong>⚠️ CRITICAL SECURITY FINDING:</strong> 100% hang rate detected!
            This indicates a serious Denial of Service (DoS) vulnerability in Hermes.exe.
        </div>'''
    elif hang_rate >= 50:
        alert_html = f'''<div class="warning">
            <strong>⚠️ WARNING:</strong> High hang rate ({hang_rate:.1f}%) detected.
            This may indicate a DoS vulnerability.
        </div>'''
    elif total_tests > 0:
        alert_html = f'''<div class="success">
            <strong>✓ INFO:</strong> Hang rate: {hang_rate:.1f}%
        </div>'''

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hermes.exe Fuzzing Report</title>
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
            transition: transform 0.2s;
        }}
        .metric-card:hover {{
            transform: translateY(-5px);
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
        .alert {{
            background: #e74c3c;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 1.1em;
        }}
        .warning {{
            background: #f39c12;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 1.1em;
        }}
        .success {{
            background: #27ae60;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 1.1em;
        }}
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
        .config-table tr:hover {{
            background: #f5f5f5;
        }}
        .timestamp {{
            color: #95a5a6;
            font-size: 0.9em;
        }}
        code {{
            background: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        ul {{
            line-height: 1.8;
        }}
        .severity-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Hermes.exe DICOM Viewer Security Assessment</h1>
        <p class="timestamp">Generated: {report['timestamp']}</p>

        {alert_html}

        <h2>📋 Test Configuration</h2>
        <table class="config-table">
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
            <tr>
                <td><strong>Target Application</strong></td>
                <td><code>{config.get('viewer_path', 'N/A')}</code></td>
            </tr>
            <tr>
                <td><strong>Input Directory</strong></td>
                <td><code>{config.get('input_dir', 'N/A')}</code></td>
            </tr>
            <tr>
                <td><strong>Output Directory</strong></td>
                <td><code>{config.get('output_dir', 'N/A')}</code></td>
            </tr>
            <tr>
                <td><strong>Timeout (seconds)</strong></td>
                <td>{config.get('timeout', 'N/A')}</td>
            </tr>
        </table>

        <h2>📊 Test Results</h2>
        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-value">{stats.get('files_processed', 0)}</div>
                <div class="metric-label">Files Processed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats.get('files_fuzzed', 0)}</div>
                <div class="metric-label">Files Fuzzed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats.get('files_generated', 0)}</div>
                <div class="metric-label">Files Generated</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats.get('viewer_crashes', 0)}</div>
                <div class="metric-label">Crashes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{stats.get('viewer_hangs', 0)}</div>
                <div class="metric-label">Hangs/Timeouts</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{hang_rate:.1f}%</div>
                <div class="metric-label">Hang Rate</div>
            </div>
        </div>

        <h2>🔐 Security Findings Summary</h2>
        <table class="config-table">
            <tr>
                <th>Finding</th>
                <th>Details</th>
            </tr>
            <tr>
                <td><strong>Total Tests Run</strong></td>
                <td>{total_tests}</td>
            </tr>
            <tr>
                <td><strong>Vulnerability Type</strong></td>
                <td>Denial of Service (DoS)</td>
            </tr>
            <tr>
                <td><strong>Severity</strong></td>
                <td><span class="severity-high">HIGH</span></td>
            </tr>
            <tr>
                <td><strong>Reproducibility</strong></td>
                <td>{hang_rate:.1f}%</td>
            </tr>
            <tr>
                <td><strong>Attack Vector</strong></td>
                <td>Malformed DICOM files</td>
            </tr>
            <tr>
                <td><strong>Impact</strong></td>
                <td>Application becomes unresponsive, requires manual termination</td>
            </tr>
        </table>

        <h2>💡 Recommendations</h2>
        <ul>
            <li>Investigate hang logs in <code>{config.get('output_dir', 'output')}</code> for root cause analysis</li>
            <li>Test fuzzed files manually to reproduce and debug the issue</li>
            <li>Implement robust input validation for DICOM file parsing</li>
            <li>Add timeout mechanisms in the DICOM parser to prevent infinite loops</li>
            <li>Consider implementing error recovery mechanisms</li>
            <li>Update error handling for malformed DICOM data structures</li>
        </ul>

        <h2>📂 Output Files</h2>
        <p>Fuzzed files and hang logs are available in: <code>{config.get('output_dir', 'N/A')}</code></p>
        <p>Each hang event has a corresponding log file with details about the problematic DICOM file.</p>

        <hr style="margin: 40px 0; border: none; border-top: 1px solid #ddd;">
        <p class="timestamp">
            This report was generated by the DICOM Fuzzer automated security testing tool.<br>
            For questions or support, refer to the project documentation.
        </p>
    </div>
</body>
</html>
"""

    # Write HTML report
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML report created: {html_path}")
    return html_path

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_html_report.py <json_report_path> [output_html_path]")
        sys.exit(1)

    json_path = sys.argv[1]
    html_path = sys.argv[2] if len(sys.argv) > 2 else None

    create_html_report(json_path, html_path)

"""Report generation utilities.

Provides programmatic report generation functions decoupled from the CLI layer.
The CLI entry point (cli/commands/reports.py) delegates to these functions.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

try:
    from dicom_fuzzer.core.reporting.enhanced_reporter import EnhancedReportGenerator
except ImportError:
    EnhancedReportGenerator = None  # type: ignore[misc,assignment]

from dicom_fuzzer.core.reporting.html_templates import legacy_html_document

# Re-exported so callers that do `from dicom_fuzzer.core.reporting.report_utils
# import ModuleType` work correctly (satisfies the annotation used in reports.py).
__all__ = [
    "ModuleType",
    "create_html_report",
    "generate_reports",
]


def generate_reports(
    session_json_path: Path,
    output_html: Path | None = None,
    keep_json: bool = False,
) -> Path:
    """Generate HTML (and optionally JSON) reports from session data.

    This is the primary API for report generation, using the modern
    EnhancedReportGenerator for rich HTML output.

    Args:
        session_json_path: Path to session JSON file
        output_html: Path for HTML output (auto-generated if None)
        keep_json: Whether to keep the JSON alongside HTML

    Returns:
        Path to the generated HTML report

    """
    if EnhancedReportGenerator is None:
        raise RuntimeError(
            "EnhancedReportGenerator is not available. "
            "Ensure dicom_fuzzer.core.reporting.enhanced_reporter is installed."
        )

    print(f"[*] Loading session data from: {session_json_path}")

    with open(session_json_path, encoding="utf-8") as f:
        session_data = json.load(f)

    reporter = EnhancedReportGenerator(output_dir="./artifacts/reports")

    print("[*] Generating HTML report...")
    html_path = reporter.generate_html_report(session_data, output_html)
    print(f"[+] HTML report generated: {html_path}")

    stats = session_data.get("statistics", {})
    crashes = session_data.get("crashes", [])

    print("\n" + "=" * 60)
    print("REPORT SUMMARY")
    print("=" * 60)
    print(f"Files Fuzzed:      {stats.get('files_fuzzed', 0)}")
    print(f"Mutations Applied: {stats.get('mutations_applied', 0)}")
    print(f"Crashes:           {stats.get('crashes', 0)}")
    print(f"Hangs:             {stats.get('hangs', 0)}")
    print(f"Successes:         {stats.get('successes', 0)}")
    print("=" * 60)

    if crashes:
        print(f"\n[!] {len(crashes)} crash(es) detected - see report for details")
        print("\nCrash Artifacts:")
        for crash in crashes:
            print(f"  - {crash.get('crash_id')}")
            print(f"    Sample: {crash.get('preserved_sample_path')}")
            print(f"    Log:    {crash.get('crash_log_path')}")
            if crash.get("reproduction_command"):
                print(f"    Repro:  {crash['reproduction_command']}")
            print()

    print(f"\n[i] Full report available at: {html_path}")

    if keep_json:
        print(f"[i] JSON data saved at: {session_json_path}")

    return html_path


def create_html_report(json_path: str, html_path: str | None = None) -> str:
    """Create HTML report from JSON fuzzing results (legacy format).

    This function uses a hardcoded HTML template for backward compatibility.
    For new code, prefer generate_reports() which uses EnhancedReportGenerator.

    Args:
        json_path: Path to JSON report file
        html_path: Output path for HTML (defaults to json_path with .html extension)

    Returns:
        Path to the generated HTML report

    """
    with open(json_path) as f:
        report = json.load(f)

    if html_path is None:
        html_path = json_path.replace(".json", ".html")

    stats = report["statistics"]
    config = report["configuration"]

    total_tests = (
        stats.get("viewer_hangs", 0)
        + stats.get("viewer_crashes", 0)
        + stats.get("viewer_success", 0)
    )
    hang_rate = stats.get("hang_rate", 0)

    alert_html = ""
    if hang_rate == 100.0:
        alert_html = """<div class="alert">
            <strong>[!!] CRITICAL SECURITY FINDING:</strong> 100% hang rate detected!
            This indicates a serious Denial of Service (DoS) vulnerability in the DICOM viewer.
        </div>"""
    elif hang_rate >= 50:
        alert_html = f"""<div class="warning">
            <strong>[!] WARNING:</strong> High hang rate ({hang_rate:.1f}%) detected.
            This may indicate a DoS vulnerability.
        </div>"""
    elif total_tests > 0:
        alert_html = f"""<div class="success">
            <strong>[i] INFO:</strong> Hang rate: {hang_rate:.1f}%
        </div>"""

    html_content = legacy_html_document(report, stats, config, alert_html, hang_rate)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report created: {html_path}")
    return html_path

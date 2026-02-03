"""Enhanced Fuzzing Report Generator.

Generates comprehensive, interactive HTML reports with:
- Complete mutation traceability
- Crash forensics with drill-down details
- Interactive visualizations
- Artifact preservation tracking
- Automated crash triage and prioritization
- FDA compliance sections (SBOM, CVE coverage, test coverage)

Note: This module is a facade that coordinates the reporting subpackage
components. For direct access to individual formatters, import from the
`reporting` subpackage.
"""

from pathlib import Path
from typing import Any

from dicom_fuzzer.core.crash.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.reporting.compliance import ComplianceFormatter
from dicom_fuzzer.core.reporting.enrichers import CrashTriageEnricher
from dicom_fuzzer.core.reporting.formatters import HTMLSectionFormatter
from dicom_fuzzer.core.reporting.html_templates import (
    html_document_end,
    html_document_start,
)
from dicom_fuzzer.core.reporting.report_analytics import ReportAnalytics


class EnhancedReportGenerator:
    """Generate enhanced HTML and JSON reports for fuzzing sessions."""

    def __init__(
        self, output_dir: str = "./artifacts/reports", enable_triage: bool = True
    ):
        """Initialize enhanced report generator.

        Args:
            output_dir: Directory for generated reports.
            enable_triage: Enable automated crash triage and prioritization.

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize crash triage engine
        self.enable_triage = enable_triage
        self.triage_engine: CrashTriageEngine | None = None
        if enable_triage:
            self.triage_engine = CrashTriageEngine()

        # Initialize component modules
        self._enricher = (
            CrashTriageEnricher(self.triage_engine) if enable_triage else None
        )
        self._formatter = HTMLSectionFormatter(enable_triage=enable_triage)
        self._analytics = ReportAnalytics(enable_triage=enable_triage)
        self._compliance = ComplianceFormatter(enable_triage=enable_triage)

    def _enrich_crashes_with_triage(
        self, session_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enrich crash records with automated triage analysis.

        Args:
            session_data: Session report dictionary.

        Returns:
            Enhanced session data with triage information.

        """
        if not self.enable_triage or not self._enricher:
            return session_data
        return self._enricher.enrich_crashes(session_data)

    def generate_html_report(
        self,
        session_data: dict[str, Any],
        output_path: Path | None = None,
    ) -> Path:
        """Generate comprehensive HTML report from session data.

        Args:
            session_data: Session report dictionary.
            output_path: Path for HTML report (auto-generated if None).

        Returns:
            Path to generated HTML report.

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

    def _generate_html_document(self, data: dict[str, Any]) -> str:
        """Generate complete HTML document."""
        session_info = data["session_info"]
        stats = data["statistics"]
        crashes = data.get("crashes", [])
        fuzzed_files = data.get("fuzzed_files", {})

        html = self._html_header(session_info["session_name"])
        html += self._formatter.format_session_overview(session_info, stats)
        html += self._formatter.format_crash_summary(crashes, fuzzed_files)
        html += self._formatter.format_crash_details(crashes, fuzzed_files)
        html += self._analytics.format_mutation_analysis(fuzzed_files, crashes)
        # FDA compliance sections
        html += self._compliance.format_fda_compliance_section(
            data, crashes, fuzzed_files
        )
        html += self._html_footer()

        return html

    def _html_header(self, title: str) -> str:
        """Generate HTML header with enhanced styling."""
        return html_document_start(title)

    def _html_footer(self) -> str:
        """Generate HTML footer."""
        return "    </div>" + html_document_end()


__all__ = ["EnhancedReportGenerator"]

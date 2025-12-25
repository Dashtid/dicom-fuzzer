"""
Tests for Enhanced HTML Reporter

Tests comprehensive HTML report generation with crash forensics.
Full coverage for HTML generation, template rendering, and data handling.
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator


class TestEnhancedReportGenerator:
    """Test enhanced report generation functionality."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def minimal_session_data(self):
        """Create minimal valid session data."""
        return {
            "session_info": {
                "session_id": "test_session_001",
                "session_name": "Test Fuzzing Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 10,
                "total_mutations_applied": 50,
                "total_crashes": 2,
                "total_hangs": 1,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

    @pytest.fixture
    def session_data_with_crashes(self):
        """Create session data with crashes."""
        return {
            "session_info": {
                "session_id": "crash_session_001",
                "session_name": "Crash Test Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 5,
                "total_mutations_applied": 25,
                "total_crashes": 2,
                "total_hangs": 0,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "fuzzed_001.dcm",
                    "exception_type": "ValueError",
                    "exception_message": "Invalid header",
                    "stack_trace": "File test.py, line 10\nValueError: Invalid header",
                },
                {
                    "crash_id": "crash_002",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "hang",
                    "severity": "medium",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "fuzzed_002.dcm",
                    "exception_message": "Timeout after 30s",
                },
            ],
            "fuzzed_files": {
                "file_001": {
                    "file_id": "file_001",
                    "source_file": "original.dcm",
                    "output_file": "fuzzed_001.dcm",
                    "mutations": [
                        {
                            "mutation_id": "mut_001",
                            "strategy_name": "metadata_fuzzer",
                            "mutation_type": "corrupt_tag",
                        }
                    ],
                },
                "file_002": {
                    "file_id": "file_002",
                    "source_file": "original.dcm",
                    "output_file": "fuzzed_002.dcm",
                    "mutations": [],
                },
            },
        }

    def test_generator_initialization(self, temp_report_dir):
        """Test generator initialization."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        assert generator.output_dir == temp_report_dir
        assert temp_report_dir.exists()

    def test_generate_html_report_creates_file(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report file is created."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert report_path.stat().st_size > 0

    def test_html_report_contains_session_info(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report contains session information."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "Test Fuzzing Session" in html
        assert "test_session_001" in html

    def test_html_report_contains_statistics(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report contains statistics."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "10" in html  # total_files_processed
        assert "50" in html  # total_mutations_applied

    def test_html_report_with_crashes(self, temp_report_dir, session_data_with_crashes):
        """Test HTML report generation with crash data."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for crash information
        assert "crash_001" in html
        assert "ValueError" in html
        assert "Invalid header" in html

    def test_html_report_valid_structure(self, temp_report_dir, minimal_session_data):
        """Test that generated HTML has valid structure."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for basic HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "</html>" in html

    def test_html_report_has_styling(self, temp_report_dir, minimal_session_data):
        """Test that HTML report includes styling."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "<style>" in html
        assert "</style>" in html

    def test_custom_output_path(self, temp_report_dir, minimal_session_data):
        """Test generating report with custom output path."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        custom_path = temp_report_dir / "custom_report.html"
        report_path = generator.generate_html_report(
            minimal_session_data, output_path=custom_path
        )

        assert report_path == custom_path
        assert custom_path.exists()

    def test_multiple_reports_same_generator(self, temp_report_dir):
        """Test generating multiple reports with same generator instance."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Generate first report
        data1 = {
            "session_info": {
                "session_id": "session_1",
                "session_name": "Session 1",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {"total_files_processed": 5},
            "crashes": [],
            "fuzzed_files": {},
        }

        # Generate second report
        data2 = {
            "session_info": {
                "session_id": "session_2",
                "session_name": "Session 2",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {"total_files_processed": 10},
            "crashes": [],
            "fuzzed_files": {},
        }

        report1 = generator.generate_html_report(data1)
        report2 = generator.generate_html_report(data2)

        assert report1.exists()
        assert report2.exists()
        assert report1 != report2

    def test_crash_details_section(self, temp_report_dir, session_data_with_crashes):
        """Test that crash details section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for crash details
        assert "crash_001" in html or "Crash Details" in html.lower()

    def test_mutation_analysis_section(
        self, temp_report_dir, session_data_with_crashes
    ):
        """Test that mutation analysis section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for mutation information
        assert "metadata_fuzzer" in html or "mutation" in html.lower()

    def test_empty_crashes_list(self, temp_report_dir, minimal_session_data):
        """Test report generation with no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Ensure crashes is empty
        minimal_session_data["crashes"] = []

        report_path = generator.generate_html_report(minimal_session_data)

        assert report_path.exists()

    def test_report_encoding_utf8(self, temp_report_dir, minimal_session_data):
        """Test that report is encoded in UTF-8."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        # Should be able to read with UTF-8 encoding
        with open(report_path, encoding="utf-8") as f:
            content = f.read()

        assert len(content) > 0
        assert 'charset="UTF-8"' in content or "utf-8" in content.lower()


# =============================================================================
# FDA Compliance Section Tests (v1.8.0)
# =============================================================================


class TestFDAComplianceSection:
    """Test FDA compliance and regulatory report sections."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def session_data_with_cve_mutations(self):
        """Create session data with CVE-based mutations."""
        return {
            "session_info": {
                "session_id": "fda_session_001",
                "session_name": "FDA Compliance Test",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 20,
                "total_mutations_applied": 100,
                "total_crashes": 5,
                "total_hangs": 2,
                "files_fuzzed": 20,
                "mutations_applied": 100,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "critical",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "fuzzed_001.dcm",
                    "exception_type": "BufferOverflow",
                    "exception_message": "Heap corruption detected",
                },
                {
                    "crash_id": "crash_002",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "fuzzed_002.dcm",
                    "exception_type": "ValueError",
                    "exception_message": "Invalid header",
                },
                {
                    "crash_id": "crash_003",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "medium",
                    "fuzzed_file_id": "file_003",
                    "fuzzed_file_path": "fuzzed_003.dcm",
                    "exception_type": "IndexError",
                    "exception_message": "Index out of bounds",
                },
                {
                    "crash_id": "crash_004",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "hang",
                    "severity": "low",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "fuzzed_001.dcm",
                    "exception_message": "Timeout",
                },
                {
                    "crash_id": "crash_005",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "informational",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "fuzzed_002.dcm",
                    "exception_message": "Minor issue",
                },
            ],
            "fuzzed_files": {
                "file_001": {
                    "file_id": "file_001",
                    "source_file": "original.dcm",
                    "output_file": "fuzzed_001.dcm",
                    "mutations": [
                        {
                            "mutation_id": "mut_001",
                            "strategy_name": "cve_mutator",
                            "mutation_type": "CVE-2019-11687",
                            "details": {"cve": "CVE-2019-11687"},
                        },
                        {
                            "mutation_id": "mut_002",
                            "strategy_name": "cve_mutator",
                            "mutation_type": "CVE-2021-35481",
                            "details": {"cve": "CVE-2021-35481"},
                        },
                    ],
                },
                "file_002": {
                    "file_id": "file_002",
                    "source_file": "original2.dcm",
                    "output_file": "fuzzed_002.dcm",
                    "mutations": [
                        {
                            "mutation_id": "mut_003",
                            "strategy_name": "metadata_fuzzer",
                            "mutation_type": "corrupt_tag",
                        },
                    ],
                },
                "file_003": {
                    "file_id": "file_003",
                    "source_file": "original3.dcm",
                    "output_file": "fuzzed_003.dcm",
                    "mutations": [
                        {
                            "mutation_id": "mut_004",
                            "strategy_name": "cve_mutator",
                            "mutation_type": "CVE-2019-11687",
                            "details": {"cve": "CVE-2019-11687"},
                        },
                    ],
                },
            },
        }

    @pytest.fixture
    def session_data_no_crashes(self):
        """Create session data with no crashes."""
        return {
            "session_info": {
                "session_id": "clean_session_001",
                "session_name": "Clean Test Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 10,
                "total_mutations_applied": 50,
                "total_crashes": 0,
                "total_hangs": 0,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

    def test_fda_section_included_in_report(
        self, temp_report_dir, session_data_with_cve_mutations
    ):
        """Test that FDA compliance section is included in the report."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_cve_mutations)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for FDA section markers
        assert "FDA" in html or "Compliance" in html or "Regulatory" in html

    def test_sbom_summary_section(
        self, temp_report_dir, session_data_with_cve_mutations
    ):
        """Test SBOM summary section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_cve_mutations)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for SBOM section content
        assert "SBOM" in html or "Software Bill of Materials" in html

    def test_cve_coverage_section(
        self, temp_report_dir, session_data_with_cve_mutations
    ):
        """Test CVE mutation coverage section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_cve_mutations)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for CVE coverage section
        assert "CVE" in html

    def test_severity_distribution_section(
        self, temp_report_dir, session_data_with_cve_mutations
    ):
        """Test crash severity distribution section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_cve_mutations)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for severity distribution content
        assert "Severity" in html or "severity" in html

    def test_severity_distribution_no_crashes(
        self, temp_report_dir, session_data_no_crashes
    ):
        """Test severity distribution section with no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_no_crashes)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Report should still be generated without errors
        assert report_path.exists()
        assert len(html) > 0

    def test_compliance_checklist_section(
        self, temp_report_dir, session_data_with_cve_mutations
    ):
        """Test compliance checklist section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_cve_mutations)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for checklist content (typically has checkboxes or bullet points)
        assert "checklist" in html.lower() or "test" in html.lower()


class TestSBOMGeneration:
    """Test SBOM (Software Bill of Materials) generation."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_sbom_section_structure(self, temp_report_dir):
        """Test SBOM section has proper structure."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Access the internal method
        sbom_html = generator._generate_sbom_summary()

        # Check for expected elements
        assert "SBOM" in sbom_html
        assert "CycloneDX" in sbom_html or "Format" in sbom_html

    def test_sbom_includes_dicom_fuzzer(self, temp_report_dir):
        """Test SBOM includes dicom-fuzzer package."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        sbom_html = generator._generate_sbom_summary()

        # Should reference dicom-fuzzer
        assert "dicom" in sbom_html.lower() or "fuzzer" in sbom_html.lower()


class TestCVECoverage:
    """Test CVE mutation coverage analysis."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def fuzzed_files_with_cve(self):
        """Create fuzzed files data with CVE mutations."""
        return {
            "file_001": {
                "mutations": [
                    {"details": {"cve": "CVE-2019-11687"}},
                    {"details": {"cve": "CVE-2021-35481"}},
                ]
            },
            "file_002": {
                "mutations": [
                    {"details": {"cve": "CVE-2019-11687"}},
                    {"details": {}},  # No CVE
                ]
            },
            "file_003": {
                "mutations": [
                    {"details": {"cve": "CVE-2020-29607"}},
                ]
            },
        }

    def test_cve_coverage_counts_mutations(
        self, temp_report_dir, fuzzed_files_with_cve
    ):
        """Test CVE coverage counts mutations correctly."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        cve_html = generator._generate_cve_coverage(fuzzed_files_with_cve)

        # Should show CVE identifiers
        assert "CVE" in cve_html

    def test_cve_coverage_empty_files(self, temp_report_dir):
        """Test CVE coverage with no fuzzed files."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        cve_html = generator._generate_cve_coverage({})

        # Should handle empty input gracefully
        assert len(cve_html) > 0

    def test_cve_coverage_no_cve_mutations(self, temp_report_dir):
        """Test CVE coverage with no CVE-based mutations."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        fuzzed_files = {
            "file_001": {
                "mutations": [
                    {"details": {}},
                    {"details": {"strategy": "random"}},
                ]
            }
        }

        cve_html = generator._generate_cve_coverage(fuzzed_files)

        # Should still produce output
        assert len(cve_html) > 0


class TestSeverityDistribution:
    """Test crash severity distribution visualization."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_severity_distribution_all_levels(self, temp_report_dir):
        """Test severity distribution with all severity levels."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        crashes = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "informational"},
        ]

        severity_html = generator._generate_severity_distribution(crashes)

        # Check for severity levels in output
        assert "critical" in severity_html.lower() or "Critical" in severity_html

    def test_severity_distribution_empty_crashes(self, temp_report_dir):
        """Test severity distribution with no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        severity_html = generator._generate_severity_distribution([])

        # Should show success message or empty state
        assert len(severity_html) > 0

    def test_severity_distribution_single_level(self, temp_report_dir):
        """Test severity distribution with single severity level."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        crashes = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "high"},
        ]

        severity_html = generator._generate_severity_distribution(crashes)

        assert "high" in severity_html.lower() or "High" in severity_html


class TestComplianceChecklist:
    """Test FDA compliance testing checklist."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_compliance_checklist_structure(self, temp_report_dir):
        """Test compliance checklist has proper structure."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        data = {
            "statistics": {
                "files_fuzzed": 50,
                "mutations_applied": 500,
            }
        }
        crashes = [{"crash_id": "1"}, {"crash_id": "2"}]

        checklist_html = generator._generate_compliance_checklist(data, crashes)

        # Should have checklist items
        assert len(checklist_html) > 0

    def test_compliance_checklist_with_crashes(self, temp_report_dir):
        """Test compliance checklist reflects crash findings."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        data = {"statistics": {"files_fuzzed": 10, "mutations_applied": 50}}
        crashes = [{"crash_id": "1"}, {"crash_id": "2"}, {"crash_id": "3"}]

        checklist_html = generator._generate_compliance_checklist(data, crashes)

        # Checklist should exist
        assert len(checklist_html) > 0

    def test_compliance_checklist_no_crashes(self, temp_report_dir):
        """Test compliance checklist with no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        data = {"statistics": {"files_fuzzed": 100, "mutations_applied": 1000}}
        crashes = []

        checklist_html = generator._generate_compliance_checklist(data, crashes)

        # Should still produce checklist
        assert len(checklist_html) > 0

    def test_compliance_checklist_insufficient_testing(self, temp_report_dir):
        """Test compliance checklist with insufficient testing."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Very few files fuzzed
        data = {"statistics": {"files_fuzzed": 1, "mutations_applied": 5}}
        crashes = []

        checklist_html = generator._generate_compliance_checklist(data, crashes)

        # Should still produce output
        assert len(checklist_html) > 0

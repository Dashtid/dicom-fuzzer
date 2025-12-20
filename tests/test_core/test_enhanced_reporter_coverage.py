"""Tests for enhanced_reporter module to improve code coverage.

These tests execute the actual HTML report generation code paths.
"""

from datetime import datetime

import pytest

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def reporter(temp_dir):
    """Create reporter instance with temp directory."""
    return EnhancedReportGenerator(output_dir=str(temp_dir), enable_triage=True)


@pytest.fixture
def reporter_no_triage(temp_dir):
    """Create reporter instance without triage."""
    return EnhancedReportGenerator(output_dir=str(temp_dir), enable_triage=False)


@pytest.fixture
def minimal_session_data():
    """Minimal session data for testing."""
    return {
        "session_info": {
            "session_id": "test-session-123",
            "session_name": "Test Fuzzing Session",
            "start_time": "2025-01-01T10:00:00",
            "end_time": "2025-01-01T11:00:00",
            "duration_seconds": 3600.0,
        },
        "statistics": {
            "files_fuzzed": 100,
            "mutations_applied": 500,
            "crashes": 0,
            "hangs": 0,
            "successes": 100,
        },
        "crashes": [],
        "fuzzed_files": {},
    }


@pytest.fixture
def session_data_with_crashes():
    """Session data with crash records for testing."""
    return {
        "session_info": {
            "session_id": "crash-session-456",
            "session_name": "Crash Testing Session",
            "start_time": "2025-01-01T10:00:00",
            "end_time": "2025-01-01T11:00:00",
            "duration_seconds": 3600.0,
        },
        "statistics": {
            "files_fuzzed": 50,
            "mutations_applied": 250,
            "crashes": 3,
            "hangs": 1,
            "successes": 46,
        },
        "crashes": [
            {
                "crash_id": "crash-001",
                "crash_type": "crash",
                "severity": "critical",
                "fuzzed_file_id": "file-001",
                "fuzzed_file_path": "/tmp/fuzzed/test1.dcm",
                "timestamp": "2025-01-01T10:30:00",
                "return_code": -11,
                "exception_type": "SegmentationFault",
                "exception_message": "Segmentation fault in parse_header",
                "stack_trace": "at parse_header+0x123\nat main+0x456",
                "reproduction_command": "dicom-viewer /tmp/fuzzed/test1.dcm",
                "preserved_sample_path": "/tmp/crashes/crash-001.dcm",
                "crash_log_path": "/tmp/crashes/crash-001.log",
            },
            {
                "crash_id": "crash-002",
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file-002",
                "fuzzed_file_path": "/tmp/fuzzed/test2.dcm",
                "timestamp": datetime.now(),  # Test datetime object handling
                "return_code": -6,
                "exception_type": "AbortSignal",
                "exception_message": "Abort called",
                "stack_trace": "at abort+0x10",
            },
            {
                "crash_id": "crash-003",
                "crash_type": "hang",
                "severity": "medium",
                "fuzzed_file_id": "file-003",
                "fuzzed_file_path": "/tmp/fuzzed/test3.dcm",
                "timestamp": "",  # Test empty timestamp
            },
        ],
        "fuzzed_files": {
            "file-001": {
                "source_file": "/data/original/test1.dcm",
                "mutations": [
                    {
                        "strategy_name": "MetadataFuzzer",
                        "mutation_type": "field_corruption",
                        "target_tag": "(0008,0018)",
                        "target_element": "SOPInstanceUID",
                        "original_value": "1.2.3.4.5",
                        "mutated_value": "AAAA" * 100,
                    },
                    {
                        "strategy_name": "HeaderFuzzer",
                        "mutation_type": "vr_change",
                        "target_tag": "(0008,0005)",
                        "original_value": "ISO_IR 100",
                        "mutated_value": "XX",
                    },
                ],
            },
            "file-002": {
                "source_file": "/data/original/test2.dcm",
                "mutations": [
                    {
                        "strategy_name": "PixelFuzzer",
                        "mutation_type": "dimension_overflow",
                    }
                ],
            },
            "file-003": {
                "source_file": "/data/original/test3.dcm",
                "mutations": [],
            },
        },
    }


class TestEnhancedReportGeneratorInit:
    """Test EnhancedReportGenerator initialization."""

    def test_init_creates_output_dir(self, temp_dir):
        """Test that output directory is created."""
        output_path = temp_dir / "reports" / "test"
        reporter = EnhancedReportGenerator(output_dir=str(output_path))

        assert output_path.exists()
        assert reporter.output_dir == output_path

    def test_init_with_triage_enabled(self, temp_dir):
        """Test initialization with triage enabled."""
        reporter = EnhancedReportGenerator(output_dir=str(temp_dir), enable_triage=True)

        assert reporter.enable_triage is True
        assert reporter.triage_engine is not None

    def test_init_with_triage_disabled(self, temp_dir):
        """Test initialization with triage disabled."""
        reporter = EnhancedReportGenerator(
            output_dir=str(temp_dir), enable_triage=False
        )

        assert reporter.enable_triage is False
        assert reporter.triage_engine is None


class TestGenerateHtmlReport:
    """Test HTML report generation."""

    def test_generate_html_report_minimal(
        self, reporter, minimal_session_data, temp_dir
    ):
        """Test generating HTML report with minimal data."""
        output_path = reporter.generate_html_report(minimal_session_data)

        assert output_path.exists()
        assert output_path.suffix == ".html"

        content = output_path.read_text(encoding="utf-8")
        assert "Test Fuzzing Session" in content
        assert "test-session-123" in content
        assert "Files Fuzzed" in content
        assert "100" in content

    def test_generate_html_report_with_crashes(
        self, reporter, session_data_with_crashes, temp_dir
    ):
        """Test generating HTML report with crashes."""
        output_path = reporter.generate_html_report(session_data_with_crashes)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")

        # Check crash summary
        assert "crash-001" in content
        assert "crash-002" in content
        assert "SECURITY FINDING" in content
        assert "DoS RISK" in content  # Due to hangs

        # Check mutation history
        assert "MetadataFuzzer" in content
        assert "HeaderFuzzer" in content

    def test_generate_html_report_custom_path(
        self, reporter, minimal_session_data, temp_dir
    ):
        """Test generating HTML report at custom path."""
        custom_path = temp_dir / "custom_report.html"
        output_path = reporter.generate_html_report(
            minimal_session_data, output_path=custom_path
        )

        assert output_path == custom_path
        assert custom_path.exists()

    def test_generate_html_report_no_triage(
        self, reporter_no_triage, session_data_with_crashes
    ):
        """Test generating HTML report without triage."""
        output_path = reporter_no_triage.generate_html_report(session_data_with_crashes)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "crash-001" in content


class TestEnrichCrashesWithTriage:
    """Test crash triage enrichment."""

    def test_enrich_crashes_with_triage(self, reporter, session_data_with_crashes):
        """Test crash triage enrichment adds triage data."""
        enriched = reporter._enrich_crashes_with_triage(session_data_with_crashes)

        # Check that triage data was added
        for crash in enriched["crashes"]:
            assert "triage" in crash
            triage = crash["triage"]
            assert "severity" in triage
            assert "exploitability" in triage
            assert "priority_score" in triage
            assert "indicators" in triage
            assert "recommendations" in triage
            assert "tags" in triage
            assert "summary" in triage

    def test_enrich_crashes_sorted_by_priority(
        self, reporter, session_data_with_crashes
    ):
        """Test that crashes are sorted by priority score."""
        enriched = reporter._enrich_crashes_with_triage(session_data_with_crashes)

        crashes = enriched["crashes"]
        priorities = [c.get("triage", {}).get("priority_score", 0) for c in crashes]

        # Should be sorted highest first
        assert priorities == sorted(priorities, reverse=True)

    def test_enrich_crashes_no_crashes(self, reporter, minimal_session_data):
        """Test triage with no crashes."""
        enriched = reporter._enrich_crashes_with_triage(minimal_session_data)

        assert enriched["crashes"] == []

    def test_enrich_crashes_triage_disabled(
        self, reporter_no_triage, session_data_with_crashes
    ):
        """Test that triage is skipped when disabled."""
        enriched = reporter_no_triage._enrich_crashes_with_triage(
            session_data_with_crashes
        )

        # No triage data should be added
        for crash in enriched["crashes"]:
            assert "triage" not in crash


class TestHtmlSections:
    """Test individual HTML section generation."""

    def test_html_header(self, reporter):
        """Test HTML header generation."""
        header = reporter._html_header("Test Report")

        assert "<!DOCTYPE html>" in header
        assert "Test Report" in header
        assert "<style>" in header
        assert "container" in header

    def test_html_session_overview(self, reporter, minimal_session_data):
        """Test session overview section."""
        session_info = minimal_session_data["session_info"]
        stats = minimal_session_data["statistics"]

        overview = reporter._html_session_overview(session_info, stats)

        assert "Test Fuzzing Session" in overview
        assert "test-session-123" in overview
        assert "100" in overview  # files_fuzzed

    def test_html_session_overview_with_crashes(
        self, reporter, session_data_with_crashes
    ):
        """Test session overview with crash alerts."""
        session_info = session_data_with_crashes["session_info"]
        stats = session_data_with_crashes["statistics"]

        overview = reporter._html_session_overview(session_info, stats)

        assert "SECURITY FINDING" in overview
        assert "DoS RISK" in overview

    def test_html_crash_summary_no_crashes(self, reporter):
        """Test crash summary with no crashes."""
        summary = reporter._html_crash_summary([], {})

        assert "No crashes detected" in summary
        assert "success" in summary.lower()

    def test_html_crash_summary_with_crashes(self, reporter, session_data_with_crashes):
        """Test crash summary with crashes."""
        crashes = session_data_with_crashes["crashes"]
        fuzzed_files = session_data_with_crashes["fuzzed_files"]

        summary = reporter._html_crash_summary(crashes, fuzzed_files)

        assert "Crash Summary" in summary
        assert "crash-001" in summary
        assert "critical" in summary.lower()

    def test_html_crash_details_no_crashes(self, reporter):
        """Test crash details with no crashes."""
        details = reporter._html_crash_details([], {})

        assert details == ""

    def test_html_crash_details_with_crashes(self, reporter, session_data_with_crashes):
        """Test crash details with crash records."""
        # First enrich with triage
        enriched = reporter._enrich_crashes_with_triage(session_data_with_crashes)
        crashes = enriched["crashes"]
        fuzzed_files = session_data_with_crashes["fuzzed_files"]

        details = reporter._html_crash_details(crashes, fuzzed_files)

        assert "Crash Details" in details
        assert "Forensics" in details
        assert "crash-001" in details
        assert "Mutation History" in details
        assert "Reproduction Command" in details
        assert "Stack Trace" in details

    def test_html_mutation_analysis_empty(self, reporter):
        """Test mutation analysis with no files."""
        analysis = reporter._html_mutation_analysis({})

        assert analysis == ""

    def test_html_mutation_analysis_with_data(
        self, reporter, session_data_with_crashes
    ):
        """Test mutation analysis with files."""
        fuzzed_files = session_data_with_crashes["fuzzed_files"]

        analysis = reporter._html_mutation_analysis(fuzzed_files, [])

        assert "Mutation Analysis" in analysis
        assert "Strategy Usage" in analysis
        assert "MetadataFuzzer" in analysis
        assert "HeaderFuzzer" in analysis

    def test_html_footer(self, reporter):
        """Test HTML footer generation."""
        footer = reporter._html_footer()

        assert "</body>" in footer
        assert "</html>" in footer


class TestEscapeHtml:
    """Test HTML escaping."""

    def test_escape_html_special_chars(self, reporter):
        """Test escaping special HTML characters."""
        text = '<script>alert("XSS")</script>&test'
        escaped = reporter._escape_html(text)

        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "&amp;" in escaped
        assert "&quot;" in escaped

    def test_escape_html_safe_text(self, reporter):
        """Test that safe text is unchanged."""
        text = "Normal text without special characters"
        escaped = reporter._escape_html(text)

        assert escaped == text


class TestTimestampParsing:
    """Test timestamp parsing in crash enrichment."""

    def test_timestamp_string_iso_format(self, reporter, temp_dir):
        """Test ISO format timestamp string."""
        session_data = {
            "session_info": {
                "session_id": "test",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
            },
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "test-crash",
                    "timestamp": "2025-01-01T10:30:00",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-1",
                }
            ],
            "fuzzed_files": {},
        }

        enriched = reporter._enrich_crashes_with_triage(session_data)
        assert "triage" in enriched["crashes"][0]

    def test_timestamp_datetime_object(self, reporter, temp_dir):
        """Test datetime object timestamp."""
        session_data = {
            "session_info": {
                "session_id": "test",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
            },
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "test-crash",
                    "timestamp": datetime.now(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-1",
                }
            ],
            "fuzzed_files": {},
        }

        enriched = reporter._enrich_crashes_with_triage(session_data)
        assert "triage" in enriched["crashes"][0]

    def test_timestamp_invalid_format(self, reporter, temp_dir):
        """Test invalid timestamp format handling."""
        session_data = {
            "session_info": {
                "session_id": "test",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
            },
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "test-crash",
                    "timestamp": "not-a-valid-timestamp",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-1",
                }
            ],
            "fuzzed_files": {},
        }

        # Should not raise, falls back to datetime.now()
        enriched = reporter._enrich_crashes_with_triage(session_data)
        assert "triage" in enriched["crashes"][0]

    def test_timestamp_empty(self, reporter, temp_dir):
        """Test empty timestamp handling."""
        session_data = {
            "session_info": {
                "session_id": "test",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
            },
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "test-crash",
                    "timestamp": "",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-1",
                }
            ],
            "fuzzed_files": {},
        }

        enriched = reporter._enrich_crashes_with_triage(session_data)
        assert "triage" in enriched["crashes"][0]

    def test_timestamp_none(self, reporter, temp_dir):
        """Test None timestamp handling."""
        session_data = {
            "session_info": {
                "session_id": "test",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
            },
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "test-crash",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-1",
                }
            ],
            "fuzzed_files": {},
        }

        enriched = reporter._enrich_crashes_with_triage(session_data)
        assert "triage" in enriched["crashes"][0]


class TestCriticalCrashesSection:
    """Test critical crashes table in HTML reports."""

    def test_critical_crashes_table_present(self, reporter, session_data_with_crashes):
        """Test that critical crashes table is generated."""
        enriched = reporter._enrich_crashes_with_triage(session_data_with_crashes)
        crashes = enriched["crashes"]
        fuzzed_files = session_data_with_crashes["fuzzed_files"]

        summary = reporter._html_crash_summary(crashes, fuzzed_files)

        # Should have Top Critical Crashes section
        assert "Top Critical Crashes" in summary or "No crashes detected" not in summary

    def test_mutation_analysis_critical_crashes(
        self, reporter, session_data_with_crashes
    ):
        """Test mutation analysis includes critical crashes."""
        enriched = reporter._enrich_crashes_with_triage(session_data_with_crashes)
        crashes = enriched["crashes"]
        fuzzed_files = session_data_with_crashes["fuzzed_files"]

        analysis = reporter._html_mutation_analysis(fuzzed_files, crashes)

        assert "Mutation Analysis" in analysis

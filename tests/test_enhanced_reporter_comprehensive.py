"""Comprehensive tests for enhanced_reporter module.

Tests HTML report generation, session overview, crash details, mutation analysis.
"""

from pathlib import Path
from unittest.mock import patch


from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator


class TestEnhancedReportGeneratorInitialization:
    """Test EnhancedReportGenerator initialization."""

    def test_initialization_default_output_dir(self):
        """Test initialization with default output directory."""
        with patch.object(Path, "mkdir"):
            generator = EnhancedReportGenerator()
            assert generator.output_dir == Path("./reports")

    def test_initialization_custom_output_dir(self, tmp_path):
        """Test initialization with custom output directory."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))
        assert generator.output_dir == tmp_path

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        output_dir = tmp_path / "custom_reports"
        generator = EnhancedReportGenerator(output_dir=str(output_dir))
        assert output_dir.exists()
        assert output_dir.is_dir()


class TestHTMLReportGeneration:
    """Test HTML report generation."""

    def test_generate_html_report_minimal_data(self, tmp_path):
        """Test generating HTML report with minimal session data."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "test-001",
                "session_name": "Test Session",
                "start_time": "2025-01-01 10:00:00",
                "end_time": "2025-01-01 10:30:00",
                "duration_seconds": 1800,
            },
            "statistics": {
                "files_fuzzed": 10,
                "mutations_applied": 30,
                "crashes": 0,
                "hangs": 0,
                "successes": 10,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

        report_path = generator.generate_html_report(session_data)

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "fuzzing_report_test-001.html" in str(report_path)

    def test_generate_html_report_custom_output_path(self, tmp_path):
        """Test generating HTML report with custom output path."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "custom-002",
                "session_name": "Custom Session",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {},
            "crashes": [],
        }

        custom_path = tmp_path / "custom_report.html"
        report_path = generator.generate_html_report(session_data, output_path=custom_path)

        assert report_path == custom_path
        assert custom_path.exists()

    def test_generate_html_report_with_crashes(self, tmp_path):
        """Test generating HTML report with crashes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "crash-003",
                "session_name": "Crash Session",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {
                "files_fuzzed": 5,
                "mutations_applied": 15,
                "crashes": 2,
                "hangs": 0,
                "successes": 3,
            },
            "crashes": [
                {
                    "crash_id": "crash-001",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-001",
                    "fuzzed_file_path": "/tmp/fuzzed_001.dcm",
                    "timestamp": "2025-01-01 10:15:00",
                    "return_code": -11,
                    "exception_type": "SIGSEGV",
                    "exception_message": "Segmentation fault at 0x12345678",
                    "stack_trace": "Frame 1\nFrame 2\nFrame 3",
                    "preserved_sample_path": "/tmp/crashes/crash-001.dcm",
                    "crash_log_path": "/tmp/crashes/crash-001.log",
                    "reproduction_command": "python test.py /tmp/fuzzed_001.dcm",
                }
            ],
            "fuzzed_files": {
                "file-001": {
                    "source_file": "original.dcm",
                    "mutations": [
                        {
                            "strategy_name": "BitFlip",
                            "mutation_type": "bit_flip",
                            "target_tag": "0010,0010",
                            "target_element": "PatientName",
                            "original_value": "John Doe",
                            "mutated_value": "JoÖn Doe",
                        }
                    ],
                }
            },
        }

        report_path = generator.generate_html_report(session_data)

        assert report_path.exists()

        # Verify crash appears in report
        content = report_path.read_text(encoding="utf-8")
        assert "crash-001" in content
        assert "SIGSEGV" in content
        assert "Segmentation fault" in content

    def test_generate_html_report_with_hangs(self, tmp_path):
        """Test generating HTML report with hangs."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "hang-004",
                "session_name": "Hang Session",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {
                "files_fuzzed": 3,
                "mutations_applied": 9,
                "crashes": 0,
                "hangs": 1,
                "successes": 2,
            },
            "crashes": [
                {
                    "crash_id": "hang-001",
                    "crash_type": "hang",
                    "severity": "medium",
                    "fuzzed_file_id": "file-002",
                    "fuzzed_file_path": "/tmp/fuzzed_002.dcm",
                    "timestamp": "2025-01-01 10:20:00",
                }
            ],
            "fuzzed_files": {},
        }

        report_path = generator.generate_html_report(session_data)

        content = report_path.read_text(encoding="utf-8")
        assert "hang-001" in content
        assert "DoS RISK" in content or "hang" in content.lower()


class TestHTMLDocumentGeneration:
    """Test HTML document structure generation."""

    def test_generate_html_document_structure(self, tmp_path):
        """Test complete HTML document structure."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "struct-001",
                "session_name": "Structure Test",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {},
            "crashes": [],
            "fuzzed_files": {},
        }

        html = generator._generate_html_document(session_data)

        # Verify HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html lang=\"en\">" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_generate_html_document_includes_title(self, tmp_path):
        """Test HTML document includes session name in title."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "title-001",
                "session_name": "Unique Title Session",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {},
        }

        html = generator._generate_html_document(session_data)

        assert "Unique Title Session" in html
        assert "Fuzzing Report" in html


class TestHTMLHeader:
    """Test HTML header generation."""

    def test_html_header_structure(self, tmp_path):
        """Test HTML header contains required elements."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_header("Test Campaign")

        assert "<!DOCTYPE html>" in html
        assert '<meta charset="UTF-8">' in html
        assert "Test Campaign - Fuzzing Report" in html
        assert "<style>" in html
        assert "</style>" in html

    def test_html_header_includes_css(self, tmp_path):
        """Test HTML header includes CSS styles."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_header("CSS Test")

        # Verify key CSS classes
        assert ".container" in html
        assert ".header" in html
        assert ".crash-item" in html
        assert ".stat-card" in html
        assert ".badge" in html

    def test_html_header_responsive_design(self, tmp_path):
        """Test HTML header includes responsive design meta tag."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_header("Responsive Test")

        assert 'name="viewport"' in html
        assert "width=device-width" in html


class TestSessionOverview:
    """Test session overview section generation."""

    def test_session_overview_basic_structure(self, tmp_path):
        """Test session overview contains basic information."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_info = {
            "session_id": "overview-001",
            "session_name": "Overview Test",
            "start_time": "2025-01-01 10:00:00",
            "end_time": "2025-01-01 11:00:00",
            "duration_seconds": 3600,
        }

        stats = {
            "files_fuzzed": 100,
            "mutations_applied": 300,
            "crashes": 5,
            "hangs": 2,
            "successes": 93,
        }

        html = generator._html_session_overview(session_info, stats)

        assert "overview-001" in html
        assert "Overview Test" in html
        assert "2025-01-01 10:00:00" in html
        assert "2025-01-01 11:00:00" in html
        assert "3600.00 seconds" in html

    def test_session_overview_statistics_display(self, tmp_path):
        """Test session overview displays all statistics."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_info = {
            "session_id": "stats-001",
            "session_name": "Stats Test",
            "start_time": "2025-01-01 10:00:00",
        }

        stats = {
            "files_fuzzed": 50,
            "mutations_applied": 150,
            "crashes": 3,
            "hangs": 1,
            "successes": 46,
        }

        html = generator._html_session_overview(session_info, stats)

        assert "50" in html  # files_fuzzed
        assert "150" in html  # mutations_applied
        assert "3" in html  # crashes
        assert "1" in html  # hangs
        assert "46" in html  # successes

    def test_session_overview_crash_alert(self, tmp_path):
        """Test session overview shows alert for crashes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_info = {
            "session_id": "alert-001",
            "session_name": "Alert Test",
            "start_time": "2025-01-01 10:00:00",
        }

        stats = {"crashes": 5, "hangs": 0}

        html = generator._html_session_overview(session_info, stats)

        assert "SECURITY FINDING" in html
        assert "5 crash(es) detected" in html

    def test_session_overview_hang_warning(self, tmp_path):
        """Test session overview shows warning for hangs."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_info = {
            "session_id": "warn-001",
            "session_name": "Warning Test",
            "start_time": "2025-01-01 10:00:00",
        }

        stats = {"crashes": 0, "hangs": 3}

        html = generator._html_session_overview(session_info, stats)

        assert "DoS RISK" in html
        assert "3 hang(s)" in html or "3 timeout(s)" in html

    def test_session_overview_no_alerts_when_clean(self, tmp_path):
        """Test session overview has no alerts when no crashes/hangs."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_info = {
            "session_id": "clean-001",
            "session_name": "Clean Test",
            "start_time": "2025-01-01 10:00:00",
        }

        stats = {"crashes": 0, "hangs": 0, "successes": 10}

        html = generator._html_session_overview(session_info, stats)

        assert "SECURITY FINDING" not in html
        assert "DoS RISK" not in html


class TestCrashSummary:
    """Test crash summary table generation."""

    def test_crash_summary_no_crashes(self, tmp_path):
        """Test crash summary when no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_crash_summary([], {})

        assert "No crashes detected" in html
        assert "success" in html.lower()

    def test_crash_summary_single_crash(self, tmp_path):
        """Test crash summary with single crash."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": "crash-001",
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file-001",
                "fuzzed_file_path": "/tmp/fuzzed_001.dcm",
                "timestamp": "2025-01-01 10:15:00",
            }
        ]

        fuzzed_files = {
            "file-001": {
                "mutations": [
                    {"strategy_name": "BitFlip", "mutation_type": "bit_flip"}
                ]
            }
        }

        html = generator._html_crash_summary(crashes, fuzzed_files)

        assert "<table>" in html
        assert "crash-001" in html
        assert "high" in html
        assert "2025-01-01 10:15:00" in html

    def test_crash_summary_multiple_crashes(self, tmp_path):
        """Test crash summary with multiple crashes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": f"crash-{i:03d}",
                "crash_type": "crash",
                "severity": "medium",
                "fuzzed_file_id": f"file-{i:03d}",
                "fuzzed_file_path": f"/tmp/fuzzed_{i:03d}.dcm",
                "timestamp": f"2025-01-01 10:{i:02d}:00",
            }
            for i in range(1, 6)
        ]

        fuzzed_files = {
            f"file-{i:03d}": {"mutations": []} for i in range(1, 6)
        }

        html = generator._html_crash_summary(crashes, fuzzed_files)

        for i in range(1, 6):
            assert f"crash-{i:03d}" in html

    def test_crash_summary_displays_mutation_count(self, tmp_path):
        """Test crash summary displays mutation count."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": "mut-001",
                "crash_type": "crash",
                "severity": "low",
                "fuzzed_file_id": "file-mut",
                "fuzzed_file_path": "/tmp/mut.dcm",
                "timestamp": "2025-01-01 10:00:00",
            }
        ]

        fuzzed_files = {
            "file-mut": {
                "mutations": [
                    {"mutation_type": "flip"},
                    {"mutation_type": "swap"},
                    {"mutation_type": "delete"},
                ]
            }
        }

        html = generator._html_crash_summary(crashes, fuzzed_files)

        assert ">3<" in html  # 3 mutations


class TestCrashDetails:
    """Test detailed crash information generation."""

    def test_crash_details_no_crashes(self, tmp_path):
        """Test crash details when no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_crash_details([], {})

        assert html == ""

    def test_crash_details_includes_crash_info(self, tmp_path):
        """Test crash details includes all crash information."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": "detail-001",
                "crash_type": "crash",
                "severity": "critical",
                "fuzzed_file_id": "file-detail",
                "fuzzed_file_path": "/tmp/detail.dcm",
                "timestamp": "2025-01-01 10:30:00",
                "return_code": -11,
                "exception_type": "SIGSEGV",
                "exception_message": "Null pointer dereference",
                "stack_trace": "Frame 1\nFrame 2",
                "preserved_sample_path": "/tmp/crashes/detail.dcm",
                "crash_log_path": "/tmp/crashes/detail.log",
                "reproduction_command": "python fuzz.py /tmp/detail.dcm",
            }
        ]

        fuzzed_files = {
            "file-detail": {
                "source_file": "original_detail.dcm",
                "mutations": [],
            }
        }

        html = generator._html_crash_details(crashes, fuzzed_files)

        assert "detail-001" in html
        assert "critical" in html
        assert "-11" in html
        assert "SIGSEGV" in html
        assert "Null pointer dereference" in html
        assert "/tmp/crashes/detail.dcm" in html
        assert "python fuzz.py /tmp/detail.dcm" in html

    def test_crash_details_mutation_history(self, tmp_path):
        """Test crash details includes mutation history."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": "history-001",
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file-history",
                "fuzzed_file_path": "/tmp/history.dcm",
                "timestamp": "2025-01-01 10:00:00",
            }
        ]

        fuzzed_files = {
            "file-history": {
                "source_file": "original.dcm",
                "mutations": [
                    {
                        "strategy_name": "BitFlip",
                        "mutation_type": "bit_flip",
                        "target_tag": "0010,0010",
                        "target_element": "PatientName",
                        "original_value": "John Doe",
                        "mutated_value": "Jxhn Doe",
                    },
                    {
                        "strategy_name": "IntOverflow",
                        "mutation_type": "overflow",
                        "target_tag": "0028,0010",
                        "original_value": "512",
                        "mutated_value": "2147483647",
                    },
                ],
            }
        }

        html = generator._html_crash_details(crashes, fuzzed_files)

        assert "Mutation History" in html
        assert "2 mutations" in html
        assert "BitFlip" in html
        assert "IntOverflow" in html
        assert "0010,0010" in html
        assert "PatientName" in html

    def test_crash_details_stack_trace_in_details(self, tmp_path):
        """Test crash details includes stack trace in expandable section."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        crashes = [
            {
                "crash_id": "stack-001",
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file-stack",
                "stack_trace": "Frame 1: main.py:42\nFrame 2: parser.py:123\nFrame 3: reader.py:56",
            }
        ]

        fuzzed_files = {"file-stack": {"mutations": []}}

        html = generator._html_crash_details(crashes, fuzzed_files)

        assert "<details>" in html
        assert "Stack Trace" in html
        assert "main.py:42" in html
        assert "parser.py:123" in html


class TestMutationAnalysis:
    """Test mutation analysis section generation."""

    def test_mutation_analysis_no_files(self, tmp_path):
        """Test mutation analysis when no fuzzed files."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_mutation_analysis({})

        assert html == ""

    def test_mutation_analysis_strategy_counts(self, tmp_path):
        """Test mutation analysis counts strategies."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        fuzzed_files = {
            "file-1": {
                "mutations": [
                    {"strategy_name": "BitFlip", "mutation_type": "flip"},
                    {"strategy_name": "BitFlip", "mutation_type": "flip"},
                    {"strategy_name": "IntOverflow", "mutation_type": "overflow"},
                ]
            },
            "file-2": {
                "mutations": [
                    {"strategy_name": "BitFlip", "mutation_type": "flip"},
                    {"strategy_name": "StringFuzz", "mutation_type": "string"},
                ]
            },
        }

        html = generator._html_mutation_analysis(fuzzed_files)

        assert "Mutation Analysis" in html
        assert "Strategy Usage" in html
        assert "BitFlip" in html
        assert "IntOverflow" in html
        assert "StringFuzz" in html
        # BitFlip: 3 times (60%)
        assert "60.0%" in html

    def test_mutation_analysis_mutation_type_counts(self, tmp_path):
        """Test mutation analysis counts mutation types."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        fuzzed_files = {
            "file-1": {
                "mutations": [
                    {"strategy_name": "BitFlip", "mutation_type": "flip"},
                    {"strategy_name": "BitFlip", "mutation_type": "flip"},
                    {"strategy_name": "IntOverflow", "mutation_type": "overflow"},
                    {"strategy_name": "StringFuzz", "mutation_type": "string"},
                ]
            }
        }

        html = generator._html_mutation_analysis(fuzzed_files)

        assert "Mutation Types" in html
        assert "flip" in html
        assert "overflow" in html
        assert "string" in html
        # flip: 2 times (50%)
        assert "50.0%" in html

    def test_mutation_analysis_percentage_calculation(self, tmp_path):
        """Test mutation analysis calculates correct percentages."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        fuzzed_files = {
            "file-1": {
                "mutations": [
                    {"strategy_name": "A", "mutation_type": "x"},
                    {"strategy_name": "A", "mutation_type": "x"},
                    {"strategy_name": "A", "mutation_type": "x"},
                    {"strategy_name": "B", "mutation_type": "y"},
                ]
            }
        }

        html = generator._html_mutation_analysis(fuzzed_files)

        # A: 3/4 = 75%, B: 1/4 = 25%
        assert "75.0%" in html
        assert "25.0%" in html


class TestHTMLFooter:
    """Test HTML footer generation."""

    def test_html_footer_structure(self, tmp_path):
        """Test HTML footer closes tags properly."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        html = generator._html_footer()

        assert "</div>" in html
        assert "</body>" in html
        assert "</html>" in html


class TestHTMLEscaping:
    """Test HTML special character escaping."""

    def test_escape_html_ampersand(self, tmp_path):
        """Test escaping ampersand."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("A & B")

        assert result == "A &amp; B"

    def test_escape_html_less_than(self, tmp_path):
        """Test escaping less than."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("A < B")

        assert result == "A &lt; B"

    def test_escape_html_greater_than(self, tmp_path):
        """Test escaping greater than."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("A > B")

        assert result == "A &gt; B"

    def test_escape_html_quotes(self, tmp_path):
        """Test escaping quotes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html('He said "Hello"')

        assert result == "He said &quot;Hello&quot;"

    def test_escape_html_single_quotes(self, tmp_path):
        """Test escaping single quotes."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("It's working")

        assert result == "It&#39;s working"

    def test_escape_html_multiple_special_chars(self, tmp_path):
        """Test escaping multiple special characters."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html('<script>alert("XSS & Injection")</script>')

        assert result == "&lt;script&gt;alert(&quot;XSS &amp; Injection&quot;)&lt;/script&gt;"

    def test_escape_html_empty_string(self, tmp_path):
        """Test escaping empty string."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("")

        assert result == ""

    def test_escape_html_no_special_chars(self, tmp_path):
        """Test string without special characters."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        result = generator._escape_html("Normal text 123")

        assert result == "Normal text 123"


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_complete_report_workflow(self, tmp_path):
        """Test complete report generation workflow."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "integration-001",
                "session_name": "Integration Test Campaign",
                "start_time": "2025-01-01 10:00:00",
                "end_time": "2025-01-01 12:00:00",
                "duration_seconds": 7200,
            },
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 350,
                "crashes": 3,
                "hangs": 1,
                "successes": 96,
            },
            "crashes": [
                {
                    "crash_id": "int-crash-001",
                    "crash_type": "crash",
                    "severity": "critical",
                    "fuzzed_file_id": "int-file-001",
                    "fuzzed_file_path": "/tmp/integration/fuzzed_001.dcm",
                    "timestamp": "2025-01-01 10:30:00",
                    "return_code": -11,
                    "exception_type": "SIGSEGV",
                    "exception_message": "Segmentation fault",
                    "stack_trace": "main.py:100\nparser.py:50",
                    "preserved_sample_path": "/tmp/crashes/int-001.dcm",
                    "crash_log_path": "/tmp/crashes/int-001.log",
                    "reproduction_command": "python fuzz.py /tmp/int.dcm",
                }
            ],
            "fuzzed_files": {
                "int-file-001": {
                    "source_file": "original_integration.dcm",
                    "mutations": [
                        {
                            "strategy_name": "BitFlip",
                            "mutation_type": "bit_flip",
                            "target_tag": "0010,0010",
                            "target_element": "PatientName",
                            "original_value": "Test Patient",
                            "mutated_value": "Test Patieñt",
                        },
                        {
                            "strategy_name": "IntOverflow",
                            "mutation_type": "overflow",
                            "target_tag": "0028,0010",
                            "original_value": "512",
                            "mutated_value": "4294967295",
                        },
                    ],
                }
            },
        }

        report_path = generator.generate_html_report(session_data)

        # Verify file exists and is readable
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")

        # Verify structure
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

        # Verify session info
        assert "integration-001" in content
        assert "Integration Test Campaign" in content

        # Verify statistics
        assert "100" in content  # files_fuzzed
        assert "350" in content  # mutations_applied

        # Verify crash details
        assert "int-crash-001" in content
        assert "SIGSEGV" in content
        assert "BitFlip" in content

    def test_report_file_encoding(self, tmp_path):
        """Test report file is saved with UTF-8 encoding."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        session_data = {
            "session_info": {
                "session_id": "encoding-001",
                "session_name": "Encoding Test 你好",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {},
            "crashes": [],
        }

        report_path = generator.generate_html_report(session_data)

        # Should not raise UnicodeDecodeError
        content = report_path.read_text(encoding="utf-8")
        assert "Encoding Test 你好" in content

    def test_large_session_report(self, tmp_path):
        """Test generating report for large fuzzing session."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        # Create large session with many crashes
        crashes = [
            {
                "crash_id": f"large-{i:05d}",
                "crash_type": "crash",
                "severity": "medium",
                "fuzzed_file_id": f"large-file-{i:05d}",
                "fuzzed_file_path": f"/tmp/large_{i:05d}.dcm",
                "timestamp": f"2025-01-01 10:{i % 60:02d}:00",
            }
            for i in range(50)
        ]

        fuzzed_files = {
            f"large-file-{i:05d}": {
                "mutations": [
                    {"strategy_name": f"Strategy{i % 5}", "mutation_type": f"type{i % 3}"}
                ]
            }
            for i in range(50)
        }

        session_data = {
            "session_info": {
                "session_id": "large-001",
                "session_name": "Large Session",
                "start_time": "2025-01-01 10:00:00",
            },
            "statistics": {
                "files_fuzzed": 1000,
                "mutations_applied": 3000,
                "crashes": 50,
                "hangs": 0,
                "successes": 950,
            },
            "crashes": crashes,
            "fuzzed_files": fuzzed_files,
        }

        report_path = generator.generate_html_report(session_data)

        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")

        # Verify all crashes are in report
        assert "large-00000" in content
        assert "large-00049" in content

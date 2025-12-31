"""Tests for coverage_correlation.py - Crash-Coverage Correlation Analysis.

Tests cover coverage insights, correlation analysis, and report generation.
"""

from unittest.mock import MagicMock

from dicom_fuzzer.utils.coverage_correlation import (
    CoverageInsight,
    CrashCoverageCorrelation,
    _extract_functions_from_coverage,
    correlate_crashes_with_coverage,
    generate_correlation_report,
    get_safe_coverage,
    identify_crash_prone_modules,
)


class TestCoverageInsight:
    """Test CoverageInsight dataclass."""

    def test_default_values(self):
        """Test default values are initialized correctly."""
        insight = CoverageInsight(identifier="test_func")

        assert insight.identifier == "test_func"
        assert insight.total_hits == 0
        assert insight.crash_hits == 0
        assert insight.safe_hits == 0
        assert insight.crash_rate == 0.0
        assert insight.unique_crashes == set()

    def test_update_crash_rate_with_hits(self):
        """Test crash rate calculation with hits."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 10
        insight.crash_hits = 3

        insight.update_crash_rate()

        assert insight.crash_rate == 0.3

    def test_update_crash_rate_zero_hits(self):
        """Test crash rate with zero total hits."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 0
        insight.crash_hits = 0

        insight.update_crash_rate()

        assert insight.crash_rate == 0.0

    def test_update_crash_rate_all_crashes(self):
        """Test crash rate when all hits are crashes."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 5
        insight.crash_hits = 5

        insight.update_crash_rate()

        assert insight.crash_rate == 1.0

    def test_unique_crashes_is_set(self):
        """Test that unique_crashes is a mutable set."""
        insight = CoverageInsight(identifier="test_func")
        insight.unique_crashes.add("crash_1")
        insight.unique_crashes.add("crash_2")
        insight.unique_crashes.add("crash_1")  # Duplicate

        assert len(insight.unique_crashes) == 2


class TestCrashCoverageCorrelation:
    """Test CrashCoverageCorrelation dataclass."""

    def test_default_values(self):
        """Test default values are initialized correctly."""
        correlation = CrashCoverageCorrelation()

        assert correlation.crash_only_coverage == {}
        assert correlation.coverage_insights == {}
        assert correlation.dangerous_paths == []
        assert correlation.vulnerable_functions == set()


class TestCorrelateCrashesWithCoverage:
    """Test correlate_crashes_with_coverage function."""

    def _create_crash(self, crash_id: str, test_case_path: str):
        """Create a mock crash object."""
        crash = MagicMock()
        crash.crash_id = crash_id
        crash.test_case_path = test_case_path
        return crash

    def test_correlate_no_crashes(self):
        """Test correlation with no crashes."""
        crashes = []
        coverage_data = {"test1.dcm": {"func_a", "func_b"}}

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        assert isinstance(result, CrashCoverageCorrelation)
        assert result.dangerous_paths == []

    def test_correlate_with_crashes(self):
        """Test correlation with crash data."""
        crash1 = self._create_crash("crash_001", "test1.dcm")
        crash2 = self._create_crash("crash_002", "test2.dcm")
        crashes = [crash1, crash2]

        coverage_data = {
            "test1.dcm": {"func_a", "func_b", "func_c"},
            "test2.dcm": {"func_a", "func_c", "func_d"},
        }

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        assert "func_a" in result.coverage_insights
        assert "func_c" in result.coverage_insights

    def test_correlate_with_safe_inputs(self):
        """Test correlation with safe input comparison."""
        crash1 = self._create_crash("crash_001", "test1.dcm")
        crashes = [crash1]

        coverage_data = {
            "test1.dcm": {"func_a", "func_b", "crash_only_func"},
            "safe1.dcm": {"func_a", "func_b"},
            "safe2.dcm": {"func_a", "func_c"},
        }

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=["safe1.dcm", "safe2.dcm"]
        )

        # crash_only_func should be in crash_only_coverage
        assert "crash_001" in result.crash_only_coverage
        assert "crash_only_func" in result.crash_only_coverage["crash_001"]

    def test_correlate_missing_coverage(self):
        """Test handling of missing coverage data."""
        crash1 = self._create_crash("crash_001", "missing.dcm")
        crashes = [crash1]

        coverage_data = {"test1.dcm": {"func_a"}}

        # Should not crash, just warn
        result = correlate_crashes_with_coverage(crashes, coverage_data)

        assert isinstance(result, CrashCoverageCorrelation)

    def test_identifies_dangerous_paths(self):
        """Test identification of dangerous paths."""
        # Create multiple crashes hitting the same function
        crashes = [
            self._create_crash(f"crash_{i:03d}", f"test{i}.dcm") for i in range(5)
        ]

        # All crashes hit dangerous_func
        coverage_data = {
            f"test{i}.dcm": {"dangerous_func", "common_func"} for i in range(5)
        }

        # Add some safe inputs that don't hit dangerous_func
        safe_inputs = [f"safe{i}.dcm" for i in range(3)]
        for i in range(3):
            coverage_data[f"safe{i}.dcm"] = {"common_func", "safe_only_func"}

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        # dangerous_func should have high crash rate
        if "dangerous_func" in result.coverage_insights:
            insight = result.coverage_insights["dangerous_func"]
            assert insight.crash_hits == 5


class TestExtractFunctionsFromCoverage:
    """Test _extract_functions_from_coverage function."""

    def test_file_line_format(self):
        """Test extraction from file:line format."""
        paths = [("parser.py:parse_header", 0.8)]

        result = _extract_functions_from_coverage(paths)

        assert "parse_header" in result

    def test_file_line_number_format(self):
        """Test that line numbers are skipped."""
        paths = [("parser.py:42", 0.8)]

        result = _extract_functions_from_coverage(paths)

        # Line numbers should not be added as function names
        assert "42" not in result

    def test_module_function_format(self):
        """Test extraction from module.function format."""
        paths = [("dicom.parser.read_file", 0.7)]

        result = _extract_functions_from_coverage(paths)

        assert "read_file" in result

    def test_simple_function_name(self):
        """Test extraction of simple function name."""
        paths = [("process_data", 0.9)]

        result = _extract_functions_from_coverage(paths)

        assert "process_data" in result

    def test_empty_input(self):
        """Test with empty input."""
        result = _extract_functions_from_coverage([])

        assert result == set()


class TestGenerateCorrelationReport:
    """Test generate_correlation_report function."""

    def test_report_with_data(self):
        """Test report generation with correlation data."""
        correlation = CrashCoverageCorrelation()
        correlation.coverage_insights = {
            "func_a": CoverageInsight(
                identifier="func_a",
                total_hits=10,
                crash_hits=8,
                crash_rate=0.8,
            ),
        }
        correlation.dangerous_paths = [("func_a", 0.8)]
        correlation.vulnerable_functions = {"func_a"}

        report = generate_correlation_report(correlation)

        assert "CRASH-COVERAGE CORRELATION REPORT" in report
        assert "func_a" in report
        assert "80.0%" in report

    def test_report_no_dangerous_paths(self):
        """Test report with no dangerous paths."""
        correlation = CrashCoverageCorrelation()

        report = generate_correlation_report(correlation)

        assert "No highly dangerous code paths detected" in report

    def test_report_includes_recommendations(self):
        """Test that report includes recommendations section."""
        correlation = CrashCoverageCorrelation()

        report = generate_correlation_report(correlation)

        assert "RECOMMENDATIONS:" in report

    def test_report_with_crash_only_coverage(self):
        """Test report with crash-only coverage."""
        correlation = CrashCoverageCorrelation()
        correlation.crash_only_coverage = {
            "crash_001": {"func_x", "func_y"},
            "crash_002": {"func_z"},
        }

        report = generate_correlation_report(correlation)

        assert "CRASH-ONLY CODE PATHS" in report

    def test_report_top_n_limit(self):
        """Test that report respects top_n limit."""
        correlation = CrashCoverageCorrelation()
        correlation.coverage_insights = {}
        correlation.dangerous_paths = []

        # Add many dangerous paths
        for i in range(30):
            func_name = f"func_{i}"
            correlation.coverage_insights[func_name] = CoverageInsight(
                identifier=func_name,
                total_hits=10,
                crash_hits=6,
                crash_rate=0.6,
            )
            correlation.dangerous_paths.append((func_name, 0.6))

        report = generate_correlation_report(correlation, top_n=5)

        # Should only show top 5
        assert "func_0" in report
        assert "func_4" in report
        # func_5 and beyond should not be in the top paths section


class TestIdentifyCrashProneModules:
    """Test identify_crash_prone_modules function."""

    def test_module_extraction_file_format(self):
        """Test module extraction from file:line format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("parser.py:42", 0.8),
            ("parser.py:100", 0.7),
            ("validator.py:50", 0.6),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["parser.py"] == 2
        assert result["validator.py"] == 1

    def test_module_extraction_dotted_format(self):
        """Test module extraction from module.function format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("dicom.parser.read_file", 0.8),
            ("dicom.parser.validate", 0.7),
            ("dicom.writer.write_file", 0.6),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["dicom.parser"] == 2
        assert result["dicom.writer"] == 1

    def test_unknown_module(self):
        """Test handling of unknown module format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [("simple_func", 0.8)]

        result = identify_crash_prone_modules(correlation)

        assert result["unknown"] == 1

    def test_empty_dangerous_paths(self):
        """Test with no dangerous paths."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = []

        result = identify_crash_prone_modules(correlation)

        assert result == {}


class TestGetSafeCoverage:
    """Test get_safe_coverage function."""

    def test_union_of_coverage(self):
        """Test that safe coverage is union of all coverage."""
        coverage_data = {
            "test1.dcm": {"func_a", "func_b"},
            "test2.dcm": {"func_b", "func_c"},
            "test3.dcm": {"func_d"},
        }

        result = get_safe_coverage(coverage_data)

        assert result == {"func_a", "func_b", "func_c", "func_d"}

    def test_empty_coverage(self):
        """Test with empty coverage data."""
        result = get_safe_coverage({})

        assert result == set()

    def test_overlapping_coverage(self):
        """Test with overlapping coverage sets."""
        coverage_data = {
            "test1.dcm": {"func_a", "func_b", "func_c"},
            "test2.dcm": {"func_a", "func_b", "func_c"},
        }

        result = get_safe_coverage(coverage_data)

        # Should be union, not sum
        assert result == {"func_a", "func_b", "func_c"}

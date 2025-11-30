"""Tests for dicom_fuzzer.utils.coverage_correlation module.

This module tests the coverage correlation analysis utilities.
"""

from dataclasses import dataclass

import pytest

from dicom_fuzzer.utils.coverage_correlation import (
    CoverageInsight,
    CrashCoverageCorrelation,
    _extract_functions_from_coverage,
    correlate_crashes_with_coverage,
    generate_correlation_report,
    get_safe_coverage,
    identify_crash_prone_modules,
)


# =============================================================================
# Test Data Helpers
# =============================================================================
@dataclass
class MockCrash:
    """Mock crash object for testing."""

    crash_id: str
    test_case_path: str


def create_mock_crash(crash_id: str, test_case_path: str) -> MockCrash:
    """Create a mock crash for testing."""
    return MockCrash(crash_id=crash_id, test_case_path=test_case_path)


# =============================================================================
# Tests for CoverageInsight
# =============================================================================
class TestCoverageInsight:
    """Tests for CoverageInsight dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        insight = CoverageInsight(identifier="test_func")
        assert insight.identifier == "test_func"
        assert insight.total_hits == 0
        assert insight.crash_hits == 0
        assert insight.safe_hits == 0
        assert insight.crash_rate == 0.0
        assert insight.unique_crashes == set()

    def test_update_crash_rate_no_hits(self):
        """Test crash rate is 0 when no hits."""
        insight = CoverageInsight(identifier="test_func")
        insight.update_crash_rate()
        assert insight.crash_rate == 0.0

    def test_update_crash_rate_all_crashes(self):
        """Test crash rate is 1.0 when all hits are crashes."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 10
        insight.crash_hits = 10
        insight.update_crash_rate()
        assert insight.crash_rate == 1.0

    def test_update_crash_rate_half_crashes(self):
        """Test crash rate calculation with mixed hits."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 10
        insight.crash_hits = 5
        insight.update_crash_rate()
        assert insight.crash_rate == 0.5

    def test_update_crash_rate_no_crashes(self):
        """Test crash rate is 0 when no crashes."""
        insight = CoverageInsight(identifier="test_func")
        insight.total_hits = 10
        insight.crash_hits = 0
        insight.update_crash_rate()
        assert insight.crash_rate == 0.0

    def test_unique_crashes_set(self):
        """Test unique crashes tracking."""
        insight = CoverageInsight(identifier="test_func")
        insight.unique_crashes.add("crash_1")
        insight.unique_crashes.add("crash_2")
        insight.unique_crashes.add("crash_1")  # Duplicate
        assert len(insight.unique_crashes) == 2


# =============================================================================
# Tests for CrashCoverageCorrelation
# =============================================================================
class TestCrashCoverageCorrelation:
    """Tests for CrashCoverageCorrelation dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        correlation = CrashCoverageCorrelation()
        assert correlation.crash_only_coverage == {}
        assert correlation.coverage_insights == {}
        assert correlation.dangerous_paths == []
        assert correlation.vulnerable_functions == set()

    def test_mutable_defaults_are_independent(self):
        """Test that mutable defaults are independent per instance."""
        corr1 = CrashCoverageCorrelation()
        corr2 = CrashCoverageCorrelation()

        corr1.dangerous_paths.append(("path1", 0.9))
        assert corr2.dangerous_paths == []

        corr1.vulnerable_functions.add("func1")
        assert corr2.vulnerable_functions == set()


# =============================================================================
# Tests for correlate_crashes_with_coverage
# =============================================================================
class TestCorrelateCrashesWithCoverage:
    """Tests for correlate_crashes_with_coverage function."""

    def test_empty_crashes(self):
        """Test with no crashes."""
        crashes = []
        coverage_data = {"test1.dcm": {"func_a", "func_b"}}

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        assert isinstance(result, CrashCoverageCorrelation)
        assert len(result.dangerous_paths) == 0

    def test_crash_with_coverage_data(self):
        """Test basic crash correlation with coverage."""
        crash = create_mock_crash("crash_001", "test1.dcm")
        crashes = [crash]
        coverage_data = {"test1.dcm": {"func_a", "func_b", "func_c"}}

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        # All paths should be tracked
        assert len(result.coverage_insights) == 3
        assert "func_a" in result.coverage_insights
        assert "func_b" in result.coverage_insights
        assert "func_c" in result.coverage_insights

    def test_crash_without_coverage_data(self):
        """Test handling crash with no coverage data."""
        crash = create_mock_crash("crash_001", "unknown.dcm")
        crashes = [crash]
        coverage_data = {"test1.dcm": {"func_a"}}

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        # No coverage should be tracked for unknown input
        assert len(result.coverage_insights) == 0

    def test_multiple_crashes_same_coverage(self):
        """Test multiple crashes hitting same coverage."""
        crash1 = create_mock_crash("crash_001", "test1.dcm")
        crash2 = create_mock_crash("crash_002", "test1.dcm")
        crashes = [crash1, crash2]
        coverage_data = {"test1.dcm": {"func_a"}}

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        insight = result.coverage_insights["func_a"]
        assert insight.total_hits == 2
        assert insight.crash_hits == 2
        assert len(insight.unique_crashes) == 2

    def test_crash_only_coverage(self):
        """Test identification of crash-only coverage paths."""
        crash = create_mock_crash("crash_001", "crash.dcm")
        crashes = [crash]
        coverage_data = {
            "crash.dcm": {"func_a", "func_b", "crash_path"},
            "safe.dcm": {"func_a", "func_b"},
        }
        safe_inputs = ["safe.dcm"]

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        # crash_path should be identified as crash-only
        assert "crash_001" in result.crash_only_coverage
        assert "crash_path" in result.crash_only_coverage["crash_001"]

    def test_safe_inputs_coverage(self):
        """Test that safe inputs update coverage insights."""
        crash = create_mock_crash("crash_001", "crash.dcm")
        crashes = [crash]
        coverage_data = {
            "crash.dcm": {"func_a"},
            "safe.dcm": {"func_a"},
        }
        safe_inputs = ["safe.dcm"]

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        insight = result.coverage_insights["func_a"]
        assert insight.total_hits == 2
        assert insight.crash_hits == 1
        assert insight.safe_hits == 1
        assert insight.crash_rate == 0.5

    def test_dangerous_paths_identification(self):
        """Test identification of dangerous paths (>50% crash rate, >=3 hits)."""
        # Create multiple crashes hitting same path
        crashes = [
            create_mock_crash("crash_001", "test1.dcm"),
            create_mock_crash("crash_002", "test2.dcm"),
            create_mock_crash("crash_003", "test3.dcm"),
        ]
        coverage_data = {
            "test1.dcm": {"dangerous_func"},
            "test2.dcm": {"dangerous_func"},
            "test3.dcm": {"dangerous_func"},
        }

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        # dangerous_func should be marked as dangerous
        assert len(result.dangerous_paths) == 1
        assert result.dangerous_paths[0][0] == "dangerous_func"
        assert result.dangerous_paths[0][1] == 1.0  # 100% crash rate

    def test_no_dangerous_paths_low_sample_size(self):
        """Test that paths with <3 hits are not marked dangerous."""
        crashes = [
            create_mock_crash("crash_001", "test1.dcm"),
            create_mock_crash("crash_002", "test2.dcm"),
        ]
        coverage_data = {
            "test1.dcm": {"func_a"},
            "test2.dcm": {"func_a"},
        }

        result = correlate_crashes_with_coverage(crashes, coverage_data)

        # Only 2 hits, so shouldn't be marked dangerous
        assert len(result.dangerous_paths) == 0

    def test_no_dangerous_paths_low_crash_rate(self):
        """Test that paths with <=50% crash rate are not marked dangerous."""
        crashes = [
            create_mock_crash("crash_001", "test1.dcm"),
        ]
        coverage_data = {
            "test1.dcm": {"func_a"},
            "safe1.dcm": {"func_a"},
            "safe2.dcm": {"func_a"},
            "safe3.dcm": {"func_a"},
        }
        safe_inputs = ["safe1.dcm", "safe2.dcm", "safe3.dcm"]

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        # 1 crash out of 4 hits = 25% crash rate
        assert len(result.dangerous_paths) == 0

    def test_safe_input_not_in_coverage_data(self):
        """Test handling safe input not in coverage data."""
        crashes = [create_mock_crash("crash_001", "crash.dcm")]
        coverage_data = {"crash.dcm": {"func_a"}}
        safe_inputs = ["nonexistent.dcm"]

        # Should not raise
        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        assert len(result.coverage_insights) == 1

    def test_none_safe_inputs(self):
        """Test with None safe_inputs."""
        crashes = [create_mock_crash("crash_001", "test.dcm")]
        coverage_data = {"test.dcm": {"func_a"}}

        result = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=None
        )

        assert len(result.coverage_insights) == 1


# =============================================================================
# Tests for _extract_functions_from_coverage
# =============================================================================
class TestExtractFunctionsFromCoverage:
    """Tests for _extract_functions_from_coverage function."""

    def test_empty_input(self):
        """Test with empty input."""
        result = _extract_functions_from_coverage([])
        assert result == set()

    def test_file_line_format(self):
        """Test extraction from file:line format."""
        paths = [("file.py:123", 0.9), ("module.py:456", 0.8)]
        result = _extract_functions_from_coverage(paths)
        # Line numbers should not be added as functions
        assert result == set()

    def test_file_function_format(self):
        """Test extraction from file:function format."""
        paths = [("file.py:my_function", 0.9), ("module.py:other_func", 0.8)]
        result = _extract_functions_from_coverage(paths)
        assert "my_function" in result
        assert "other_func" in result

    def test_module_function_format(self):
        """Test extraction from module.function format."""
        paths = [("module.function_name", 0.9), ("pkg.submod.another", 0.8)]
        result = _extract_functions_from_coverage(paths)
        assert "function_name" in result
        assert "another" in result

    def test_bare_function_name(self):
        """Test extraction of bare function names."""
        paths = [("my_function", 0.9), ("another_func", 0.8)]
        result = _extract_functions_from_coverage(paths)
        assert "my_function" in result
        assert "another_func" in result

    def test_mixed_formats(self):
        """Test extraction from mixed formats."""
        paths = [
            ("file.py:parse_data", 0.9),
            ("module.validate", 0.8),
            ("check_input", 0.7),
            ("other.py:42", 0.6),  # Line number, should be skipped
        ]
        result = _extract_functions_from_coverage(paths)
        assert "parse_data" in result
        assert "validate" in result
        assert "check_input" in result
        assert "42" not in result


# =============================================================================
# Tests for generate_correlation_report
# =============================================================================
class TestGenerateCorrelationReport:
    """Tests for generate_correlation_report function."""

    def test_empty_correlation(self):
        """Test report generation with empty correlation."""
        correlation = CrashCoverageCorrelation()
        report = generate_correlation_report(correlation)

        assert "CRASH-COVERAGE CORRELATION REPORT" in report
        assert "Total Coverage Points Analyzed: 0" in report
        assert "Dangerous Paths Found:" in report
        assert "No highly dangerous code paths detected" in report

    def test_report_with_dangerous_paths(self):
        """Test report generation with dangerous paths."""
        correlation = CrashCoverageCorrelation()

        # Add coverage insights
        insight = CoverageInsight(identifier="dangerous_func")
        insight.total_hits = 10
        insight.crash_hits = 9
        insight.crash_rate = 0.9
        correlation.coverage_insights["dangerous_func"] = insight

        # Add dangerous path
        correlation.dangerous_paths = [("dangerous_func", 0.9)]

        report = generate_correlation_report(correlation)

        assert "TOP DANGEROUS CODE PATHS" in report
        assert "dangerous_func" in report
        assert "90.0%" in report

    def test_report_with_vulnerable_functions(self):
        """Test report generation with vulnerable functions."""
        correlation = CrashCoverageCorrelation()
        correlation.vulnerable_functions = {"func_a", "func_b", "func_c"}

        report = generate_correlation_report(correlation)

        assert "VULNERABLE FUNCTIONS" in report
        assert "func_a" in report
        assert "func_b" in report
        assert "func_c" in report

    def test_report_with_crash_only_coverage(self):
        """Test report generation with crash-only coverage."""
        correlation = CrashCoverageCorrelation()
        correlation.crash_only_coverage = {
            "crash_001": {"path_a", "path_b"},
            "crash_002": {"path_c"},
        }

        report = generate_correlation_report(correlation)

        assert "CRASH-ONLY CODE PATHS" in report
        assert "Code paths only executed during crashes: 3" in report
        assert "Crashes with unique paths:" in report

    def test_report_top_n_limit(self):
        """Test that top_n parameter limits output."""
        correlation = CrashCoverageCorrelation()

        # Add many dangerous paths
        for i in range(30):
            insight = CoverageInsight(identifier=f"func_{i}")
            insight.total_hits = 10
            insight.crash_hits = 8
            insight.crash_rate = 0.8
            correlation.coverage_insights[f"func_{i}"] = insight
            correlation.dangerous_paths.append((f"func_{i}", 0.8))

        # Request only top 5
        report = generate_correlation_report(correlation, top_n=5)

        # Report should still be generated
        assert "TOP DANGEROUS CODE PATHS" in report

    def test_report_recommendations_with_issues(self):
        """Test recommendations section with issues."""
        correlation = CrashCoverageCorrelation()

        # Set up a dangerous path with its corresponding insight
        insight = CoverageInsight(identifier="func")
        insight.total_hits = 10
        insight.crash_hits = 9
        insight.crash_rate = 0.9
        correlation.coverage_insights["func"] = insight
        correlation.dangerous_paths = [("func", 0.9)]

        # Set up crash-only coverage
        correlation.crash_only_coverage = {"crash_001": {"path"}}

        report = generate_correlation_report(correlation)

        assert "RECOMMENDATIONS" in report
        assert "Prioritize reviewing" in report
        assert "Investigate" in report

    def test_report_recommendations_no_issues(self):
        """Test recommendations section with no issues."""
        correlation = CrashCoverageCorrelation()

        report = generate_correlation_report(correlation)

        assert "No highly dangerous code paths detected" in report


# =============================================================================
# Tests for identify_crash_prone_modules
# =============================================================================
class TestIdentifyCrashProneModules:
    """Tests for identify_crash_prone_modules function."""

    def test_empty_correlation(self):
        """Test with empty correlation."""
        correlation = CrashCoverageCorrelation()
        result = identify_crash_prone_modules(correlation)
        assert result == {}

    def test_file_line_format(self):
        """Test module extraction from file:line format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("parser.py:123", 0.9),
            ("parser.py:456", 0.8),
            ("validator.py:78", 0.7),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["parser.py"] == 2
        assert result["validator.py"] == 1

    def test_module_function_format(self):
        """Test module extraction from module.function format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("parser.parse_header", 0.9),
            ("parser.parse_body", 0.8),
            ("validator.check", 0.7),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["parser"] == 2
        assert result["validator"] == 1

    def test_bare_function_names(self):
        """Test module extraction from bare function names."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("my_function", 0.9),
            ("another_func", 0.8),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["unknown"] == 2

    def test_mixed_formats(self):
        """Test module extraction from mixed formats."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("file.py:func", 0.9),
            ("module.method", 0.8),
            ("bare_func", 0.7),
        ]

        result = identify_crash_prone_modules(correlation)

        assert "file.py" in result
        assert "module" in result
        assert "unknown" in result

    def test_deep_module_paths(self):
        """Test module extraction from deep module paths."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("pkg.subpkg.module.function", 0.9),
        ]

        result = identify_crash_prone_modules(correlation)

        assert result["pkg.subpkg.module"] == 1


# =============================================================================
# Tests for get_safe_coverage
# =============================================================================
class TestGetSafeCoverage:
    """Tests for get_safe_coverage function."""

    def test_empty_coverage_data(self):
        """Test with empty coverage data."""
        result = get_safe_coverage({})
        assert result == set()

    def test_single_file_coverage(self):
        """Test with single file coverage."""
        coverage_data = {"file1.dcm": {"func_a", "func_b", "func_c"}}
        result = get_safe_coverage(coverage_data)
        assert result == {"func_a", "func_b", "func_c"}

    def test_multiple_files_coverage(self):
        """Test with multiple files coverage (union)."""
        coverage_data = {
            "file1.dcm": {"func_a", "func_b"},
            "file2.dcm": {"func_b", "func_c"},
            "file3.dcm": {"func_c", "func_d"},
        }
        result = get_safe_coverage(coverage_data)
        assert result == {"func_a", "func_b", "func_c", "func_d"}

    def test_overlapping_coverage(self):
        """Test with overlapping coverage sets."""
        coverage_data = {
            "file1.dcm": {"common", "unique_1"},
            "file2.dcm": {"common", "unique_2"},
        }
        result = get_safe_coverage(coverage_data)
        assert result == {"common", "unique_1", "unique_2"}

    def test_empty_coverage_sets(self):
        """Test with empty coverage sets."""
        coverage_data = {
            "file1.dcm": set(),
            "file2.dcm": {"func_a"},
        }
        result = get_safe_coverage(coverage_data)
        assert result == {"func_a"}


# =============================================================================
# Integration Tests
# =============================================================================
class TestCoverageCorrelationIntegration:
    """Integration tests for coverage correlation workflow."""

    def test_full_workflow(self):
        """Test complete coverage correlation workflow."""
        # Setup: multiple crashes and safe inputs
        crashes = [
            create_mock_crash("crash_001", "crash1.dcm"),
            create_mock_crash("crash_002", "crash2.dcm"),
            create_mock_crash("crash_003", "crash3.dcm"),
        ]

        coverage_data = {
            "crash1.dcm": {"common", "dangerous_a", "crash_only"},
            "crash2.dcm": {"common", "dangerous_a"},
            "crash3.dcm": {"common", "dangerous_a", "dangerous_b"},
            "safe1.dcm": {"common"},
            "safe2.dcm": {"common", "safe_only"},
        }

        safe_inputs = ["safe1.dcm", "safe2.dcm"]

        # Correlate
        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=safe_inputs
        )

        # Verify dangerous paths identified
        dangerous_ids = [path for path, _ in correlation.dangerous_paths]
        assert "dangerous_a" in dangerous_ids  # 3 crashes, 0 safe = 100% rate

        # Verify crash-only coverage
        assert "crash_001" in correlation.crash_only_coverage
        assert "crash_only" in correlation.crash_only_coverage["crash_001"]

        # Generate report
        report = generate_correlation_report(correlation)
        assert "dangerous_a" in report
        assert "RECOMMENDATIONS" in report

        # Identify crash-prone modules
        modules = identify_crash_prone_modules(correlation)
        assert len(modules) > 0

    def test_no_crashes_workflow(self):
        """Test workflow with no crashes."""
        crashes = []
        coverage_data = {
            "safe1.dcm": {"func_a", "func_b"},
            "safe2.dcm": {"func_b", "func_c"},
        }

        correlation = correlate_crashes_with_coverage(crashes, coverage_data)

        assert len(correlation.dangerous_paths) == 0
        assert len(correlation.crash_only_coverage) == 0

        report = generate_correlation_report(correlation)
        assert "No highly dangerous code paths detected" in report

    def test_all_crashes_same_coverage(self):
        """Test when all crashes hit exactly the same code paths."""
        crashes = [
            create_mock_crash("crash_001", "test.dcm"),
            create_mock_crash("crash_002", "test.dcm"),
            create_mock_crash("crash_003", "test.dcm"),
        ]

        coverage_data = {"test.dcm": {"always_hit"}}

        correlation = correlate_crashes_with_coverage(crashes, coverage_data)

        # Should have 1 dangerous path with 100% crash rate
        assert len(correlation.dangerous_paths) == 1
        assert correlation.dangerous_paths[0][0] == "always_hit"
        assert correlation.dangerous_paths[0][1] == 1.0

    def test_multiple_different_coverage_paths(self):
        """Test with multiple crashes having different coverage."""
        crashes = [
            create_mock_crash("crash_001", "test1.dcm"),
            create_mock_crash("crash_002", "test2.dcm"),
            create_mock_crash("crash_003", "test3.dcm"),
            create_mock_crash("crash_004", "test4.dcm"),
        ]

        coverage_data = {
            "test1.dcm": {"path_a", "path_b"},
            "test2.dcm": {"path_a", "path_c"},
            "test3.dcm": {"path_a", "path_d"},
            "test4.dcm": {"path_a", "path_e"},
        }

        correlation = correlate_crashes_with_coverage(crashes, coverage_data)

        # path_a should be the most dangerous (100% crash rate, 4 hits)
        dangerous_ids = [path for path, _ in correlation.dangerous_paths]
        assert "path_a" in dangerous_ids

        insight = correlation.coverage_insights["path_a"]
        assert insight.total_hits == 4
        assert insight.crash_hits == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

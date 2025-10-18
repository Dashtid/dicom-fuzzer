"""
Comprehensive tests for coverage correlation analysis.

Achieves 80%+ coverage of coverage_correlation.py module.
"""

import pytest
from dataclasses import dataclass

from dicom_fuzzer.utils.coverage_correlation import (
    CoverageInsight,
    CrashCoverageCorrelation,
    correlate_crashes_with_coverage,
    generate_correlation_report,
    identify_crash_prone_modules,
    get_safe_coverage,
)


@dataclass
class MockCrash:
    """Mock crash record for testing."""

    crash_id: str
    test_case_path: str


class TestCoverageInsight:
    """Tests for CoverageInsight class."""

    def test_initialization(self):
        """Test CoverageInsight initialization."""
        insight = CoverageInsight(identifier="test_func")

        assert insight.identifier == "test_func"
        assert insight.total_hits == 0
        assert insight.crash_hits == 0
        assert insight.safe_hits == 0
        assert insight.crash_rate == 0.0
        assert len(insight.unique_crashes) == 0

    def test_update_crash_rate_zero_hits(self):
        """Test crash rate calculation with zero hits."""
        insight = CoverageInsight(identifier="test")
        insight.update_crash_rate()

        assert insight.crash_rate == 0.0

    def test_update_crash_rate_calculation(self):
        """Test crash rate calculation."""
        insight = CoverageInsight(identifier="test")
        insight.total_hits = 10
        insight.crash_hits = 3
        insight.update_crash_rate()

        assert insight.crash_rate == 0.3

    def test_update_crash_rate_all_crashes(self):
        """Test crash rate when all hits are crashes."""
        insight = CoverageInsight(identifier="test")
        insight.total_hits = 5
        insight.crash_hits = 5
        insight.update_crash_rate()

        assert insight.crash_rate == 1.0

    def test_update_crash_rate_no_crashes(self):
        """Test crash rate when no crashes."""
        insight = CoverageInsight(identifier="test")
        insight.total_hits = 10
        insight.crash_hits = 0
        insight.update_crash_rate()

        assert insight.crash_rate == 0.0

    def test_unique_crashes_tracking(self):
        """Test unique crashes set."""
        insight = CoverageInsight(identifier="test")
        insight.unique_crashes.add("crash_001")
        insight.unique_crashes.add("crash_002")
        insight.unique_crashes.add("crash_001")  # Duplicate

        assert len(insight.unique_crashes) == 2


class TestCrashCoverageCorrelation:
    """Tests for CrashCoverageCorrelation class."""

    def test_initialization(self):
        """Test CrashCoverageCorrelation initialization."""
        correlation = CrashCoverageCorrelation()

        assert len(correlation.crash_only_coverage) == 0
        assert len(correlation.coverage_insights) == 0
        assert len(correlation.dangerous_paths) == 0
        assert len(correlation.vulnerable_functions) == 0


class TestCorrelatecrashesWithCoverage:
    """Tests for correlate_crashes_with_coverage function."""

    def test_empty_crashes(self):
        """Test correlation with no crashes."""
        crashes = []
        coverage_data = {"safe.dcm": {"func_a", "func_b"}}
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        assert len(correlation.crash_only_coverage) == 0
        assert len(correlation.dangerous_paths) == 0

    def test_single_crash(self):
        """Test correlation with single crash."""
        crashes = [MockCrash(crash_id="crash_001", test_case_path="crash.dcm")]
        coverage_data = {
            "safe.dcm": {"func_a", "func_b"},
            "crash.dcm": {"func_a", "func_c"},
        }
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_c is crash-only
        assert "crash_001" in correlation.crash_only_coverage
        assert "func_c" in correlation.crash_only_coverage["crash_001"]

    def test_multiple_crashes(self):
        """Test correlation with multiple crashes."""
        crashes = [
            MockCrash(crash_id="crash_001", test_case_path="crash1.dcm"),
            MockCrash(crash_id="crash_002", test_case_path="crash2.dcm"),
            MockCrash(crash_id="crash_003", test_case_path="crash3.dcm"),
        ]
        coverage_data = {
            "safe.dcm": {"func_a"},
            "crash1.dcm": {"func_a", "func_vuln"},
            "crash2.dcm": {"func_a", "func_vuln"},
            "crash3.dcm": {"func_a", "func_vuln"},
        }
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_vuln should be dangerous (hit by 3 crashes = 75% crash rate with 4 total hits)
        dangerous_ids = [path for path, rate in correlation.dangerous_paths]
        assert "func_vuln" in dangerous_ids

    def test_crash_without_coverage_data(self):
        """Test crash with no coverage data."""
        crashes = [MockCrash(crash_id="crash_001", test_case_path="unknown.dcm")]
        coverage_data = {"safe.dcm": {"func_a"}}
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # Should handle gracefully
        assert "crash_001" not in correlation.crash_only_coverage

    def test_no_safe_inputs(self):
        """Test correlation without safe inputs."""
        crashes = [MockCrash(crash_id="crash_001", test_case_path="crash.dcm")]
        coverage_data = {"crash.dcm": {"func_a", "func_b"}}

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs=None
        )

        # All coverage is crash-only without safe baseline
        assert "crash_001" in correlation.crash_only_coverage

    def test_dangerous_path_threshold(self):
        """Test dangerous path detection threshold (>50% crash rate)."""
        crashes = [
            MockCrash(crash_id=f"crash_{i:03d}", test_case_path=f"crash{i}.dcm")
            for i in range(3)
        ]
        coverage_data = {
            "safe1.dcm": {"func_a", "func_b"},
            "safe2.dcm": {"func_a", "func_b"},
            "crash0.dcm": {"func_a", "func_dangerous"},
            "crash1.dcm": {"func_a", "func_dangerous"},
            "crash2.dcm": {"func_a", "func_dangerous"},
        }
        safe_inputs = ["safe1.dcm", "safe2.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_dangerous: 3 crash hits, 5 total hits = 60% crash rate (>50%)
        dangerous_ids = [path for path, rate in correlation.dangerous_paths]
        assert "func_dangerous" in dangerous_ids

    def test_minimum_sample_size(self):
        """Test dangerous paths require minimum sample size (>=3 hits)."""
        crashes = [MockCrash(crash_id="crash_001", test_case_path="crash.dcm")]
        coverage_data = {
            "safe.dcm": {"func_a"},
            "crash.dcm": {"func_rare"},
        }
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_rare has 100% crash rate but only 1 hit (below minimum of 3)
        dangerous_ids = [path for path, rate in correlation.dangerous_paths]
        assert "func_rare" not in dangerous_ids

    def test_coverage_insights_tracking(self):
        """Test coverage insights are tracked correctly."""
        crashes = [MockCrash(crash_id="crash_001", test_case_path="crash.dcm")]
        coverage_data = {
            "safe.dcm": {"func_a"},
            "crash.dcm": {"func_a"},
        }
        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_a should be tracked
        assert "func_a" in correlation.coverage_insights
        insight = correlation.coverage_insights["func_a"]
        assert insight.total_hits == 2  # 1 crash + 1 safe
        assert insight.crash_hits == 1
        assert insight.safe_hits == 1


class TestGenerateCorrelationReport:
    """Tests for generate_correlation_report function."""

    def test_empty_correlation(self):
        """Test report generation with empty correlation."""
        correlation = CrashCoverageCorrelation()
        report = generate_correlation_report(correlation)

        assert "CRASH-COVERAGE CORRELATION REPORT" in report
        assert "Total Coverage Points Analyzed: 0" in report

    def test_report_with_dangerous_paths(self):
        """Test report with dangerous paths."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("func_vuln", 0.8),
            ("func_bad", 0.6),
        ]
        correlation.coverage_insights = {
            "func_vuln": CoverageInsight(
                identifier="func_vuln", total_hits=10, crash_hits=8
            ),
            "func_bad": CoverageInsight(
                identifier="func_bad", total_hits=10, crash_hits=6
            ),
        }

        report = generate_correlation_report(correlation, top_n=10)

        assert "TOP DANGEROUS CODE PATHS" in report
        assert "func_vuln" in report
        assert "80.0%" in report

    def test_report_with_vulnerable_functions(self):
        """Test report with vulnerable functions."""
        correlation = CrashCoverageCorrelation()
        correlation.vulnerable_functions = {"parse_header", "process_pixels"}

        report = generate_correlation_report(correlation)

        assert "VULNERABLE FUNCTIONS" in report
        assert "parse_header" in report or "process_pixels" in report

    def test_report_with_crash_only_coverage(self):
        """Test report with crash-only coverage."""
        correlation = CrashCoverageCorrelation()
        correlation.crash_only_coverage = {
            "crash_001": {"func_rare1", "func_rare2"},
            "crash_002": {"func_rare3"},
        }

        report = generate_correlation_report(correlation)

        assert "CRASH-ONLY CODE PATHS" in report
        assert "3" in report  # Total crash-only paths

    def test_report_recommendations_with_issues(self):
        """Test recommendations when issues found."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [("func_vuln", 0.9)]
        correlation.coverage_insights = {
            "func_vuln": CoverageInsight(
                identifier="func_vuln", total_hits=10, crash_hits=9
            )
        }
        correlation.crash_only_coverage = {"crash_001": {"func_rare"}}

        report = generate_correlation_report(correlation)

        assert "RECOMMENDATIONS" in report
        assert "Prioritize reviewing" in report or "dangerous" in report.lower()

    def test_report_recommendations_no_issues(self):
        """Test recommendations when no issues found."""
        correlation = CrashCoverageCorrelation()

        report = generate_correlation_report(correlation)

        assert "RECOMMENDATIONS" in report
        assert "No highly dangerous" in report or "detected" in report.lower()

    def test_report_top_n_limit(self):
        """Test report respects top_n limit."""
        correlation = CrashCoverageCorrelation()
        # Create 20 dangerous paths
        for i in range(20):
            rate = 0.9 - (i * 0.01)
            correlation.dangerous_paths.append((f"func_{i}", rate))
            correlation.coverage_insights[f"func_{i}"] = CoverageInsight(
                identifier=f"func_{i}", total_hits=10, crash_hits=int(10 * rate)
            )

        report = generate_correlation_report(correlation, top_n=5)

        # Should only show top 5
        assert "func_0" in report
        assert "func_4" in report
        # func_10+ should not be in report (outside top 5)
        lines = report.split("\n")
        func_count = sum(1 for line in lines if "func_" in line and "%" in line)
        assert func_count <= 5


class TestIdentifyCrashProneModules:
    """Tests for identify_crash_prone_modules function."""

    def test_empty_correlation(self):
        """Test with no dangerous paths."""
        correlation = CrashCoverageCorrelation()
        modules = identify_crash_prone_modules(correlation)

        assert len(modules) == 0

    def test_file_colon_format(self):
        """Test extraction from 'file.py:line' format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("parser.py:42", 0.8),
            ("parser.py:56", 0.7),
            ("mutator.py:100", 0.6),
        ]

        modules = identify_crash_prone_modules(correlation)

        assert modules["parser.py"] == 2
        assert modules["mutator.py"] == 1

    def test_module_dot_function_format(self):
        """Test extraction from 'module.function' format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("dicom_fuzzer.parser.parse_header", 0.8),
            ("dicom_fuzzer.parser.parse_tags", 0.7),
            ("dicom_fuzzer.mutator.mutate", 0.6),
        ]

        modules = identify_crash_prone_modules(correlation)

        assert modules["dicom_fuzzer.parser"] == 2
        assert modules["dicom_fuzzer.mutator"] == 1

    def test_unknown_format(self):
        """Test extraction from unknown format."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [("func_name", 0.8)]

        modules = identify_crash_prone_modules(correlation)

        assert modules["unknown"] == 1


class TestGetSafeCoverage:
    """Tests for get_safe_coverage function."""

    def test_empty_coverage_data(self):
        """Test with empty coverage data."""
        coverage_data = {}
        safe_coverage = get_safe_coverage(coverage_data)

        assert len(safe_coverage) == 0

    def test_single_input(self):
        """Test with single input."""
        coverage_data = {"input1.dcm": {"func_a", "func_b"}}
        safe_coverage = get_safe_coverage(coverage_data)

        assert "func_a" in safe_coverage
        assert "func_b" in safe_coverage
        assert len(safe_coverage) == 2

    def test_multiple_inputs(self):
        """Test with multiple inputs (union)."""
        coverage_data = {
            "input1.dcm": {"func_a", "func_b"},
            "input2.dcm": {"func_b", "func_c"},
            "input3.dcm": {"func_c", "func_d"},
        }
        safe_coverage = get_safe_coverage(coverage_data)

        assert "func_a" in safe_coverage
        assert "func_b" in safe_coverage
        assert "func_c" in safe_coverage
        assert "func_d" in safe_coverage
        assert len(safe_coverage) == 4

    def test_duplicate_coverage(self):
        """Test that duplicates are handled (set union)."""
        coverage_data = {
            "input1.dcm": {"func_a", "func_b"},
            "input2.dcm": {"func_a", "func_b"},
        }
        safe_coverage = get_safe_coverage(coverage_data)

        # Should have 2 unique functions
        assert len(safe_coverage) == 2


class TestIntegrationScenarios:
    """Integration tests for realistic correlation scenarios."""

    def test_complete_workflow(self):
        """Test complete correlation workflow."""
        # Setup: 3 safe inputs, 3 crashes
        crashes = [
            MockCrash(crash_id="crash_001", test_case_path="crash1.dcm"),
            MockCrash(crash_id="crash_002", test_case_path="crash2.dcm"),
            MockCrash(crash_id="crash_003", test_case_path="crash3.dcm"),
        ]

        coverage_data = {
            "safe1.dcm": {"func_a", "func_b", "func_c"},
            "safe2.dcm": {"func_a", "func_b", "func_d"},
            "safe3.dcm": {"func_a", "func_c", "func_d"},
            "crash1.dcm": {"func_a", "func_b", "func_vuln"},
            "crash2.dcm": {"func_a", "func_c", "func_vuln"},
            "crash3.dcm": {"func_a", "func_d", "func_vuln"},
        }

        safe_inputs = ["safe1.dcm", "safe2.dcm", "safe3.dcm"]

        # Correlate
        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # Verify func_vuln is identified as crash-only
        all_crash_only = set()
        for crash_id, paths in correlation.crash_only_coverage.items():
            all_crash_only |= paths
        assert "func_vuln" in all_crash_only

        # Generate report - should mention crash-only paths or dangerous paths
        report = generate_correlation_report(correlation)
        assert "crash-only" in report.lower() or "dangerous" in report.lower()

    def test_high_crash_rate_detection(self):
        """Test detection of high crash rate functions."""
        # Create scenario where func_dangerous has 80% crash rate
        crashes = [
            MockCrash(crash_id=f"crash_{i:03d}", test_case_path=f"crash{i}.dcm")
            for i in range(8)
        ]

        coverage_data = {}
        # 8 crashes hit func_dangerous
        for i in range(8):
            coverage_data[f"crash{i}.dcm"] = {"func_a", "func_dangerous"}

        # 2 safe inputs hit func_dangerous
        coverage_data["safe1.dcm"] = {"func_a", "func_dangerous"}
        coverage_data["safe2.dcm"] = {"func_a", "func_dangerous"}

        safe_inputs = ["safe1.dcm", "safe2.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes, coverage_data, safe_inputs
        )

        # func_dangerous: 8 crashes + 2 safe = 10 total, 80% crash rate
        dangerous_ids = [path for path, rate in correlation.dangerous_paths]
        assert "func_dangerous" in dangerous_ids

        # Verify crash rate
        dangerous_rates = {
            path: rate for path, rate in correlation.dangerous_paths
        }
        assert dangerous_rates["func_dangerous"] == pytest.approx(0.8, rel=0.01)

    def test_module_grouping(self):
        """Test grouping dangerous paths by module."""
        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("parser.py:42", 0.9),
            ("parser.py:56", 0.8),
            ("parser.py:78", 0.7),
            ("mutator.py:100", 0.6),
        ]

        modules = identify_crash_prone_modules(correlation)

        # parser.py is crash-prone (3 dangerous paths)
        assert modules["parser.py"] == 3
        assert modules["mutator.py"] == 1

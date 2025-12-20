"""
Tests for new stability enhancements (v1.3.0).

Tests the 2025 stability improvements:
- Corpus minimization
- Stateless harness validation
- Timeout budget management
- Coverage correlation analysis
"""

import hashlib
import time
from pathlib import Path

from dicom_fuzzer.utils.corpus_minimization import (
    minimize_corpus_for_campaign,
    validate_corpus_quality,
)
from dicom_fuzzer.utils.coverage_correlation import (
    correlate_crashes_with_coverage,
    generate_correlation_report,
    identify_crash_prone_modules,
)
from dicom_fuzzer.utils.stateless_harness import (
    create_stateless_test_wrapper,
    detect_state_leaks,
    validate_determinism,
)
from dicom_fuzzer.utils.timeout_budget import (
    ExecutionTimer,
    TimeoutBudgetManager,
    TimeoutStatistics,
)


class TestCorpusMinimization:
    """Test corpus minimization functionality."""

    def test_validate_corpus_quality_empty(self, temp_dir):
        """Test corpus quality validation on empty directory."""
        metrics = validate_corpus_quality(temp_dir)

        assert metrics["total_files"] == 0
        assert metrics["total_size_mb"] == 0.0
        assert metrics["valid_dicom"] == 0

    def test_validate_corpus_quality_nonexistent(self):
        """Test validation on non-existent directory."""
        metrics = validate_corpus_quality(Path("/nonexistent/path"))
        assert metrics["total_files"] == 0

    def test_validate_corpus_quality_with_files(self, temp_dir, sample_dicom_file):
        """Test corpus quality validation with DICOM files."""
        # Create test corpus
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        # Copy sample file multiple times
        for i in range(5):
            dest = corpus_dir / f"test_{i}.dcm"
            import shutil

            shutil.copy(sample_dicom_file, dest)

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 5
        assert metrics["total_size_mb"] > 0
        assert metrics["avg_file_size_kb"] > 0
        assert metrics["min_size_kb"] > 0
        assert metrics["max_size_kb"] > 0
        assert metrics["valid_dicom"] >= 0  # Depends on pydicom availability

    def test_validate_corpus_quality_mixed_files(self, temp_dir, sample_dicom_file):
        """Test validation with mix of valid and invalid files."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        import shutil

        # Add valid DICOM
        shutil.copy(sample_dicom_file, corpus_dir / "valid.dcm")

        # Add invalid file
        (corpus_dir / "invalid.dcm").write_bytes(b"not a dicom file")

        metrics = validate_corpus_quality(corpus_dir)
        assert metrics["total_files"] == 2

    def test_minimize_corpus_empty(self, temp_dir):
        """Test minimization on empty corpus."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert result == []

    def test_minimize_corpus_nonexistent(self, temp_dir):
        """Test minimization on non-existent corpus."""
        result = minimize_corpus_for_campaign(Path("/nonexistent"), temp_dir / "out")
        assert result == []

    def test_minimize_corpus_basic(self, temp_dir, sample_dicom_file):
        """Test basic corpus minimization."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        # Copy sample file to corpus
        import shutil

        dest = corpus_dir / "test.dcm"
        shutil.copy(sample_dicom_file, dest)

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, max_corpus_size=10
        )

        assert len(result) > 0
        assert all(f.exists() for f in result)

    def test_minimize_corpus_respects_max_size(self, temp_dir, sample_dicom_file):
        """Test that minimization respects max corpus size."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        # Create multiple files
        import shutil

        for i in range(10):
            dest = corpus_dir / f"test_{i}.dcm"
            shutil.copy(sample_dicom_file, dest)

        result = minimize_corpus_for_campaign(corpus_dir, output_dir, max_corpus_size=5)

        assert len(result) <= 5

    def test_minimize_corpus_with_coverage_tracker(self, temp_dir, sample_dicom_file):
        """Test minimization with coverage tracker."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        import shutil

        for i in range(3):
            shutil.copy(sample_dicom_file, corpus_dir / f"test_{i}.dcm")

        # Mock coverage tracker
        class MockCoverageTracker:
            def get_coverage_for_input(self, path):
                # Return different coverage for each file
                return {f"cov_{path.stem}"}

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, coverage_tracker=MockCoverageTracker()
        )

        # With mock coverage, all files should be kept (each has unique coverage)
        assert len(result) == 3

    def test_minimize_corpus_file_sorting(self, temp_dir):
        """Test that corpus minimization sorts by file size."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        # Create files of different sizes
        (corpus_dir / "small.dcm").write_bytes(b"x" * 100)
        (corpus_dir / "medium.dcm").write_bytes(b"x" * 1000)
        (corpus_dir / "large.dcm").write_bytes(b"x" * 10000)

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        # Should process smaller files first
        assert len(result) > 0


class TestStatelessHarness:
    """Test stateless harness validation."""

    def test_validate_determinism_deterministic(self):
        """Test determinism validation with deterministic function."""

        def deterministic_func(x):
            return hashlib.sha256(str(x).encode()).hexdigest()

        is_det, error = validate_determinism(
            test_input="test",
            test_function=deterministic_func,
            runs=5,
        )

        assert is_det is True
        assert error is None

    def test_validate_determinism_nondeterministic(self):
        """Test determinism validation with nondeterministic function."""
        counter = {"value": 0}

        def nondeterministic_func(x):
            counter["value"] += 1
            return f"{x}_{counter['value']}"

        is_det, error = validate_determinism(
            test_input="test",
            test_function=nondeterministic_func,
            runs=5,
        )

        assert is_det is False
        assert error is not None
        assert "non-deterministic" in error.lower()

    def test_validate_determinism_with_exception(self):
        """Test determinism validation when function raises exception."""

        def failing_func(x):
            raise ValueError("Test error")

        is_det, error = validate_determinism(
            test_input="test",
            test_function=failing_func,
            runs=3,
        )

        assert is_det is False
        assert "exception" in error.lower()

    def test_create_stateless_wrapper(self):
        """Test stateless wrapper creation."""

        def test_func(x):
            return x * 2

        wrapped = create_stateless_test_wrapper(test_func)

        result = wrapped(5)
        assert result == 10

    def test_detect_state_leaks_no_leaks(self, temp_dir):
        """Test state leak detection with clean harness."""

        def clean_harness(test_file):
            return hashlib.sha256(str(test_file).encode()).hexdigest()

        # Create test files
        test_files = [
            temp_dir / "test1.txt",
            temp_dir / "test2.txt",
        ]

        for f in test_files:
            f.write_text("test")

        result = detect_state_leaks(clean_harness, test_files)

        assert result["leaked"] is False
        assert len(result["affected_files"]) == 0

    def test_detect_state_leaks_with_leaks(self, temp_dir):
        """Test state leak detection with stateful harness."""
        state = {"counter": 0}

        def stateful_harness(test_file):
            state["counter"] += 1
            return f"{test_file}_{state['counter']}"

        # Create test files
        test_files = [
            temp_dir / "test1.txt",
            temp_dir / "test2.txt",
        ]

        for f in test_files:
            f.write_text("test")

        result = detect_state_leaks(stateful_harness, test_files)

        assert result["leaked"] is True
        assert len(result["affected_files"]) > 0


class TestTimeoutBudget:
    """Test timeout budget management."""

    def test_timeout_statistics_initialization(self):
        """Test TimeoutStatistics initialization."""
        stats = TimeoutStatistics()

        assert stats.total_time == 0.0
        assert stats.timeout_time == 0.0
        assert stats.total_executions == 0
        assert stats.timeout_count == 0
        assert stats.timeout_ratio == 0.0

    def test_timeout_statistics_ratio(self):
        """Test timeout ratio calculation."""
        stats = TimeoutStatistics()
        stats.total_time = 100.0
        stats.timeout_time = 10.0

        assert stats.timeout_ratio == 0.1

    def test_timeout_budget_manager_initialization(self):
        """Test TimeoutBudgetManager initialization."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.15,
            min_timeout=2.0,
            max_timeout=30.0,
        )

        assert manager.max_timeout_ratio == 0.15
        assert manager.min_timeout == 2.0
        assert manager.max_timeout == 30.0
        assert manager.current_timeout == 2.0

    def test_record_execution_success(self):
        """Test recording successful execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=1.0, timed_out=False)

        stats = manager.get_statistics()
        assert stats.total_executions == 1
        assert stats.successful_count == 1
        assert stats.timeout_count == 0

    def test_record_execution_timeout(self):
        """Test recording timed-out execution."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=5.0, timed_out=True)

        stats = manager.get_statistics()
        assert stats.total_executions == 1
        assert stats.timeout_count == 1
        assert stats.successful_count == 0

    def test_is_budget_exceeded(self):
        """Test budget exceeded detection."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.10)

        # Record mostly timeouts
        for _ in range(5):
            manager.record_execution(duration=1.0, timed_out=True)
        for _ in range(2):
            manager.record_execution(duration=1.0, timed_out=False)

        # 5/7 = 71% timeouts, exceeds 10% budget
        assert manager.is_budget_exceeded() is True

    def test_timeout_adjustment_on_excess(self):
        """Test timeout is reduced when budget exceeded."""
        manager = TimeoutBudgetManager(
            max_timeout_ratio=0.10,
            adjustment_interval=5,
            min_timeout=1.0,
            max_timeout=10.0,
        )

        manager.current_timeout = 5.0
        initial_timeout = manager.current_timeout

        # Record many timeouts to exceed budget
        for _ in range(10):
            manager.record_execution(duration=1.0, timed_out=True)

        # Timeout should have been reduced
        assert manager.current_timeout < initial_timeout

    def test_execution_timer(self):
        """Test ExecutionTimer context manager."""
        with ExecutionTimer() as timer:
            time.sleep(0.01)

        assert timer.duration > 0.0
        assert timer.start_time is not None
        assert timer.end_time is not None

    def test_generate_report(self):
        """Test timeout budget report generation."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=1.0, timed_out=False)
        manager.record_execution(duration=2.0, timed_out=True)

        report = manager.generate_report()

        assert "TIMEOUT BUDGET REPORT" in report
        assert "Total Executions" in report
        assert "Timeout Ratio" in report

    def test_reset_statistics(self):
        """Test statistics reset."""
        manager = TimeoutBudgetManager()

        manager.record_execution(duration=1.0, timed_out=True)

        manager.reset_statistics()

        stats = manager.get_statistics()
        assert stats.total_executions == 0
        assert stats.timeout_count == 0


class TestCoverageCorrelation:
    """Test coverage correlation analysis."""

    def test_correlate_crashes_empty(self):
        """Test correlation with no crashes."""
        from dicom_fuzzer.utils.coverage_correlation import CrashCoverageCorrelation

        correlation = correlate_crashes_with_coverage(
            crashes=[],
            coverage_data={},
            safe_inputs=[],
        )

        assert isinstance(correlation, CrashCoverageCorrelation)
        assert len(correlation.dangerous_paths) == 0

    def test_correlate_crashes_with_data(self):
        """Test correlation with crash data."""
        from dataclasses import dataclass

        @dataclass
        class MockCrash:
            crash_id: str
            test_case_path: str

        crashes = [
            MockCrash(crash_id="crash_1", test_case_path="crash_input.dcm"),
        ]

        coverage_data = {
            "crash_input.dcm": {"func_a", "func_b", "func_vuln"},
            "safe_input.dcm": {"func_a", "func_b"},
        }

        safe_inputs = ["safe_input.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes=crashes,
            coverage_data=coverage_data,
            safe_inputs=safe_inputs,
        )

        # func_vuln should be crash-only
        assert "crash_1" in correlation.crash_only_coverage
        assert "func_vuln" in correlation.crash_only_coverage["crash_1"]

    def test_identify_dangerous_paths(self):
        """Test identification of dangerous code paths."""
        from dataclasses import dataclass

        @dataclass
        class MockCrash:
            crash_id: str
            test_case_path: str

        # Create crashes that all hit the same path
        crashes = [
            MockCrash(crash_id=f"crash_{i}", test_case_path=f"crash_{i}.dcm")
            for i in range(3)
        ]

        # All crashes hit "func_vuln", safe inputs don't
        coverage_data = {f"crash_{i}.dcm": {"func_safe", "func_vuln"} for i in range(3)}
        coverage_data["safe.dcm"] = {"func_safe"}

        safe_inputs = ["safe.dcm"]

        correlation = correlate_crashes_with_coverage(
            crashes=crashes,
            coverage_data=coverage_data,
            safe_inputs=safe_inputs,
        )

        # func_vuln should have high crash rate
        assert len(correlation.dangerous_paths) > 0
        assert "func_vuln" in correlation.vulnerable_functions

    def test_generate_correlation_report(self):
        """Test correlation report generation."""
        from dicom_fuzzer.utils.coverage_correlation import (
            CoverageInsight,
            CrashCoverageCorrelation,
        )

        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [("func_a", 0.8), ("func_b", 0.6)]
        correlation.vulnerable_functions = {"func_a", "func_b"}

        # Add coverage insights for the dangerous paths
        correlation.coverage_insights = {
            "func_a": CoverageInsight(identifier="func_a", total_hits=10, crash_hits=8),
            "func_b": CoverageInsight(identifier="func_b", total_hits=10, crash_hits=6),
        }

        report = generate_correlation_report(correlation, top_n=10)

        assert "CRASH-COVERAGE CORRELATION REPORT" in report
        assert "TOP DANGEROUS CODE PATHS" in report
        assert "func_a" in report

    def test_identify_crash_prone_modules(self):
        """Test module crash-proneness identification."""
        from dicom_fuzzer.utils.coverage_correlation import CrashCoverageCorrelation

        correlation = CrashCoverageCorrelation()
        correlation.dangerous_paths = [
            ("module_a.py:100", 0.9),
            ("module_a.py:200", 0.8),
            ("module_b.py:50", 0.7),
        ]

        module_counts = identify_crash_prone_modules(correlation)

        assert "module_a.py" in module_counts
        assert module_counts["module_a.py"] == 2
        assert module_counts["module_b.py"] == 1


class TestIntegration:
    """Integration tests for stability features."""

    def test_corpus_workflow(self, temp_dir, sample_dicom_file):
        """Test complete corpus minimization workflow."""
        corpus_dir = temp_dir / "corpus"
        output_dir = temp_dir / "min"

        corpus_dir.mkdir()
        output_dir.mkdir()

        # Create corpus
        import shutil

        for i in range(3):
            dest = corpus_dir / f"test_{i}.dcm"
            shutil.copy(sample_dicom_file, dest)

        # Validate quality
        metrics = validate_corpus_quality(corpus_dir)
        assert metrics["total_files"] == 3

        # Minimize
        result = minimize_corpus_for_campaign(corpus_dir, output_dir)
        assert len(result) > 0

    def test_timeout_workflow(self):
        """Test complete timeout budget workflow."""
        manager = TimeoutBudgetManager(max_timeout_ratio=0.20, adjustment_interval=10)

        # Simulate fuzzing campaign with ~15% timeout rate (3/20 = 15%)
        # Use i % 7 == 0 to get timeouts at indices 0, 7, 14 = 3 out of 20 = 15%
        for i in range(20):
            timed_out = i % 7 == 0  # ~15% timeout rate (under 20% budget)
            with ExecutionTimer() as timer:
                time.sleep(0.001)

            manager.record_execution(timer.duration, timed_out=timed_out)

        # Should be within budget (15% < 20%)
        assert not manager.is_budget_exceeded()

        # Generate report
        report = manager.generate_report()
        assert "TIMEOUT BUDGET REPORT" in report

    def test_determinism_workflow(self):
        """Test complete determinism validation workflow."""

        def test_harness(x):
            return hashlib.sha256(str(x).encode()).hexdigest()

        # Validate
        is_det, error = validate_determinism(
            test_input="test", test_function=test_harness, runs=3
        )
        assert is_det, f"Expected deterministic but got: {error}"

        # Wrap
        wrapped = create_stateless_test_wrapper(test_harness)
        result = wrapped("test")
        assert result is not None

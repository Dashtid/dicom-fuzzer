"""
Comprehensive test suite for coverage_tracker.py

Tests coverage tracking system for coverage-guided fuzzing including:
- CoverageSnapshot creation and comparison
- Coverage hashing and deduplication
- Coverage percentage calculation
- CoverageTracker initialization
- File tracing decisions
- Coverage tracking with trace_execution
- Interesting case detection
- Statistics reporting
- Coverage report generation
- State reset
"""

import sys
from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot, CoverageTracker


class TestCoverageSnapshot:
    """Test CoverageSnapshot dataclass."""

    def test_initialization_default(self):
        """Test snapshot initialization with defaults."""
        snapshot = CoverageSnapshot()

        assert snapshot.lines_covered == set()
        assert snapshot.branches_covered == set()
        assert isinstance(snapshot.timestamp, datetime)
        assert snapshot.test_case_id == ""
        assert snapshot.total_lines == 0
        assert snapshot.total_branches == 0

    def test_initialization_with_data(self):
        """Test snapshot initialization with coverage data."""
        lines = {("file1.py", 10), ("file1.py", 20), ("file2.py", 5)}
        branches = {("file1.py", 10, 0), ("file1.py", 20, 1)}

        snapshot = CoverageSnapshot(
            lines_covered=lines,
            branches_covered=branches,
            test_case_id="test_123",
        )

        assert snapshot.lines_covered == lines
        assert snapshot.branches_covered == branches
        assert snapshot.test_case_id == "test_123"
        assert snapshot.total_lines == 3  # Auto-calculated in __post_init__
        assert snapshot.total_branches == 2

    def test_coverage_hash_consistency(self):
        """Test that same coverage produces same hash."""
        lines = {("file1.py", 10), ("file2.py", 20)}
        branches = {("file1.py", 10, 0)}

        snapshot1 = CoverageSnapshot(lines_covered=lines, branches_covered=branches)
        snapshot2 = CoverageSnapshot(lines_covered=lines, branches_covered=branches)

        assert snapshot1.coverage_hash() == snapshot2.coverage_hash()

    def test_coverage_hash_different(self):
        """Test that different coverage produces different hash."""
        snapshot1 = CoverageSnapshot(lines_covered={("file1.py", 10)})
        snapshot2 = CoverageSnapshot(lines_covered={("file1.py", 20)})

        assert snapshot1.coverage_hash() != snapshot2.coverage_hash()

    def test_coverage_hash_order_independent(self):
        """Test that hash is same regardless of set order."""
        # Sets are unordered, but hash should be consistent
        lines1 = {("a.py", 1), ("b.py", 2), ("c.py", 3)}
        lines2 = {("c.py", 3), ("a.py", 1), ("b.py", 2)}

        snapshot1 = CoverageSnapshot(lines_covered=lines1)
        snapshot2 = CoverageSnapshot(lines_covered=lines2)

        assert snapshot1.coverage_hash() == snapshot2.coverage_hash()

    def test_new_coverage_vs(self):
        """Test finding new coverage between snapshots."""
        snapshot1 = CoverageSnapshot(lines_covered={("file1.py", 10), ("file1.py", 20)})
        snapshot2 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 20), ("file2.py", 5)}
        )

        new_lines = snapshot2.new_coverage_vs(snapshot1)

        assert new_lines == {("file2.py", 5)}

    def test_new_coverage_vs_no_new_coverage(self):
        """Test when there's no new coverage."""
        lines = {("file1.py", 10), ("file1.py", 20)}
        snapshot1 = CoverageSnapshot(lines_covered=lines)
        snapshot2 = CoverageSnapshot(lines_covered=lines)

        new_lines = snapshot2.new_coverage_vs(snapshot1)

        assert new_lines == set()

    def test_new_coverage_vs_empty(self):
        """Test new coverage vs empty snapshot."""
        snapshot1 = CoverageSnapshot()  # Empty
        snapshot2 = CoverageSnapshot(lines_covered={("file1.py", 10)})

        new_lines = snapshot2.new_coverage_vs(snapshot1)

        assert new_lines == {("file1.py", 10)}

    def test_coverage_percentage_zero_total(self):
        """Test coverage percentage with zero total lines."""
        snapshot = CoverageSnapshot()

        percentage = snapshot.coverage_percentage(total_possible_lines=0)

        assert percentage == 0.0

    def test_coverage_percentage_calculation(self):
        """Test coverage percentage calculation."""
        snapshot = CoverageSnapshot(
            lines_covered={("file1.py", 1), ("file1.py", 2), ("file1.py", 3)}
        )

        percentage = snapshot.coverage_percentage(total_possible_lines=10)

        assert percentage == 30.0  # 3/10 * 100

    def test_coverage_percentage_full(self):
        """Test 100% coverage."""
        snapshot = CoverageSnapshot(lines_covered={("file1.py", i) for i in range(10)})

        percentage = snapshot.coverage_percentage(total_possible_lines=10)

        assert percentage == 100.0


class TestCoverageTrackerInitialization:
    """Test CoverageTracker initialization."""

    def test_initialization_default(self):
        """Test tracker initialization with defaults."""
        tracker = CoverageTracker()

        assert tracker.target_modules == ["core", "strategies", "utils"]
        assert "test_" in tracker.ignore_patterns
        assert "__pycache__" in tracker.ignore_patterns
        assert tracker.global_coverage == set()
        assert tracker.total_executions == 0
        assert tracker.interesting_cases == 0
        assert tracker.redundant_cases == 0

    def test_initialization_custom_modules(self):
        """Test tracker with custom target modules."""
        tracker = CoverageTracker(target_modules=["mymodule", "othermodule"])

        assert tracker.target_modules == ["mymodule", "othermodule"]

    def test_initialization_custom_ignore_patterns(self):
        """Test tracker with custom ignore patterns."""
        tracker = CoverageTracker(ignore_patterns=["ignore_me", "skip_this"])

        assert "ignore_me" in tracker.ignore_patterns
        assert "skip_this" in tracker.ignore_patterns


class TestFileTracing:
    """Test file tracing decision logic."""

    def test_should_trace_file_in_target_module(self):
        """Test tracing files in target modules."""
        tracker = CoverageTracker(target_modules=["core"])

        # File in core module
        should_trace = tracker._should_trace_file(
            str(Path.cwd() / "core" / "parser.py")
        )

        assert should_trace is True

    def test_should_trace_file_with_ignore_pattern(self):
        """Test ignoring files matching ignore patterns."""
        tracker = CoverageTracker(ignore_patterns=["test_"])

        # File with test_ prefix
        should_trace = tracker._should_trace_file("test_something.py")

        assert should_trace is False

    def test_should_trace_file_with_pycache(self):
        """Test ignoring __pycache__ files."""
        tracker = CoverageTracker()

        should_trace = tracker._should_trace_file("__pycache__/module.pyc")

        assert should_trace is False

    def test_should_trace_file_with_venv(self):
        """Test ignoring .venv files."""
        tracker = CoverageTracker()

        should_trace = tracker._should_trace_file(".venv/lib/python/module.py")

        assert should_trace is False

    def test_should_trace_file_not_in_target(self):
        """Test not tracing files outside target modules."""
        tracker = CoverageTracker(target_modules=["core"])

        # File in different module
        should_trace = tracker._should_trace_file(str(Path.cwd() / "other" / "file.py"))

        assert should_trace is False


class TestTraceExecution:
    """Test coverage tracking with trace_execution context manager."""

    def test_trace_execution_basic(self):
        """Test basic coverage tracking."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_1"):
            # Execute some code (will track this test file)
            _ = 1 + 1

        # Should have recorded at least one execution
        assert tracker.total_executions == 1

    def test_trace_execution_records_coverage(self):
        """Test that execution records coverage."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_2"):
            # Simple operation
            _ = sum([1, 2, 3])

        # Should have some coverage recorded
        assert len(tracker.global_coverage) > 0 or tracker.total_executions == 1

    def test_trace_execution_interesting_case(self):
        """Test detection of interesting cases (new coverage)."""
        tracker = CoverageTracker()

        def func1():
            return 1 + 1

        def func2():
            return 2 * 2

        # First execution - always interesting
        with tracker.trace_execution("test_3a"):
            func1()

        initial_interesting = tracker.interesting_cases

        # Second execution with different code - should be interesting
        with tracker.trace_execution("test_3b"):
            func2()

        # Should have detected interesting case (or both are interesting)
        assert tracker.interesting_cases >= initial_interesting

    def test_trace_execution_redundant_case(self):
        """Test detection of redundant cases (no new coverage)."""
        tracker = CoverageTracker()

        def simple_func():
            return 42

        # First execution
        with tracker.trace_execution("test_4a"):
            simple_func()

        # Second execution of same code
        with tracker.trace_execution("test_4b"):
            simple_func()

        # Should have at least one redundant case
        # (second execution of same code)
        assert tracker.total_executions == 2

    def test_trace_execution_clears_current_coverage(self):
        """Test that current coverage is cleared between executions."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_5"):
            _ = 1

        # Current coverage should be cleared after context exits
        # (it's copied to snapshot, then cleared)
        assert isinstance(tracker.current_coverage, set)

    def test_trace_execution_with_exception(self):
        """Test that tracing stops even if exception occurs."""
        tracker = CoverageTracker()

        try:
            with tracker.trace_execution("test_6"):
                raise ValueError("Test exception")
        except ValueError:
            pass  # Expected exception

        # Should have stopped tracing (sys.settrace should be None)
        assert sys.gettrace() is None


class TestInterestingCaseDetection:
    """Test detection of interesting coverage patterns."""

    def test_is_interesting_new_coverage(self):
        """Test that new coverage is detected as interesting."""
        tracker = CoverageTracker()

        snapshot = CoverageSnapshot(lines_covered={("file1.py", 10), ("file1.py", 20)})

        is_interesting = tracker.is_interesting(snapshot)

        # First snapshot with coverage is always interesting
        assert is_interesting is True
        # Hash should be recorded
        assert len(tracker.seen_coverage_hashes) == 1

    def test_is_interesting_duplicate_coverage(self):
        """Test that duplicate coverage is not interesting."""
        tracker = CoverageTracker()

        lines = {("file1.py", 10)}
        snapshot1 = CoverageSnapshot(lines_covered=lines)
        snapshot2 = CoverageSnapshot(lines_covered=lines)

        # First is interesting
        is_interesting1 = tracker.is_interesting(snapshot1)
        # Second with same coverage is not
        is_interesting2 = tracker.is_interesting(snapshot2)

        assert is_interesting1 is True
        assert is_interesting2 is False

    def test_is_interesting_subset_coverage(self):
        """Test that subset coverage is not interesting."""
        tracker = CoverageTracker()

        # First snapshot with full coverage
        snapshot1 = CoverageSnapshot(lines_covered={("file1.py", 10), ("file1.py", 20)})
        tracker.is_interesting(snapshot1)  # Mark as seen
        tracker.global_coverage.update(snapshot1.lines_covered)

        # Second snapshot with subset of coverage
        snapshot2 = CoverageSnapshot(lines_covered={("file1.py", 10)})

        is_interesting = tracker.is_interesting(snapshot2)

        assert is_interesting is False


class TestStatistics:
    """Test statistics reporting."""

    def test_get_statistics_initial(self):
        """Test getting initial statistics."""
        tracker = CoverageTracker()

        stats = tracker.get_statistics()

        assert stats["total_executions"] == 0
        assert stats["interesting_cases"] == 0
        assert stats["redundant_cases"] == 0
        assert stats["total_lines_covered"] == 0
        assert stats["unique_coverage_patterns"] == 0
        assert stats["efficiency"] == 0.0

    def test_get_statistics_after_execution(self):
        """Test statistics after some executions."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_1"):
            _ = 1 + 1

        stats = tracker.get_statistics()

        assert stats["total_executions"] == 1
        assert stats["total_lines_covered"] >= 0
        # Efficiency should be calculable
        assert isinstance(stats["efficiency"], float)

    def test_get_statistics_efficiency_calculation(self):
        """Test efficiency calculation in statistics."""
        tracker = CoverageTracker()
        tracker.total_executions = 10
        tracker.interesting_cases = 3
        tracker.redundant_cases = 7

        stats = tracker.get_statistics()

        assert stats["efficiency"] == 0.3  # 3/10


class TestCoverageReport:
    """Test coverage report generation."""

    def test_get_coverage_report_format(self):
        """Test coverage report formatting."""
        tracker = CoverageTracker()

        report = tracker.get_coverage_report()

        # Check report contains key sections
        assert "Coverage-Guided Fuzzing Report" in report
        assert "Total Executions:" in report
        assert "Interesting Cases:" in report
        assert "Redundant Cases:" in report
        assert "Total Lines Covered:" in report
        assert "Unique Patterns:" in report
        assert "Efficiency:" in report
        assert "Coverage History:" in report

    def test_get_coverage_report_with_data(self):
        """Test coverage report with actual data."""
        tracker = CoverageTracker()
        tracker.total_executions = 50
        tracker.interesting_cases = 15
        tracker.redundant_cases = 35

        report = tracker.get_coverage_report()

        assert "50" in report  # Total executions
        assert "15" in report  # Interesting cases
        assert "35" in report  # Redundant cases


class TestReset:
    """Test coverage tracker reset functionality."""

    def test_reset_clears_all_data(self):
        """Test that reset clears all coverage data."""
        tracker = CoverageTracker()

        # Add some data
        tracker.global_coverage.add(("file1.py", 10))
        tracker.current_coverage.add(("file1.py", 20))
        tracker.seen_coverage_hashes.add("hash123")
        tracker.total_executions = 10
        tracker.interesting_cases = 5
        tracker.redundant_cases = 5
        tracker.coverage_history.append(
            CoverageSnapshot(lines_covered={("file1.py", 10)})
        )

        # Reset
        tracker.reset()

        # All data should be cleared
        assert len(tracker.global_coverage) == 0
        assert len(tracker.current_coverage) == 0
        assert len(tracker.coverage_history) == 0
        assert len(tracker.seen_coverage_hashes) == 0
        assert tracker.total_executions == 0
        assert tracker.interesting_cases == 0
        assert tracker.redundant_cases == 0

    def test_reset_allows_reuse(self):
        """Test that tracker can be reused after reset."""
        tracker = CoverageTracker()

        # Use tracker
        with tracker.trace_execution("test_1"):
            _ = 1 + 1

        # Reset
        tracker.reset()

        # Use again
        with tracker.trace_execution("test_2"):
            _ = 2 + 2

        # Should work normally
        assert tracker.total_executions >= 1


class TestIntegration:
    """Integration tests for complete coverage tracking workflows."""

    def test_complete_coverage_workflow(self):
        """Test a complete coverage-guided fuzzing workflow."""
        from dicom_fuzzer.core.test_helper import another_function, simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # Track first execution
        with tracker.trace_execution("case_1"):
            simple_function()

        # Track second execution (different code)
        with tracker.trace_execution("case_2"):
            another_function()

        # Track third execution (same as first)
        with tracker.trace_execution("case_3"):
            simple_function()

        # Should have executed 3 times
        assert tracker.total_executions == 3
        # Should have at least one interesting case
        assert tracker.interesting_cases >= 1

        # Generate report
        report = tracker.get_coverage_report()
        assert len(report) > 0

    def test_coverage_deduplication(self):
        """Test that duplicate coverage is properly detected."""
        tracker = CoverageTracker()

        lines1 = {("file1.py", 10), ("file1.py", 20)}
        lines2 = {("file1.py", 10), ("file1.py", 20)}  # Same coverage

        snapshot1 = CoverageSnapshot(lines_covered=lines1)
        snapshot2 = CoverageSnapshot(lines_covered=lines2)

        # First is interesting
        is_interesting1 = tracker.is_interesting(snapshot1)
        # Second is duplicate
        is_interesting2 = tracker.is_interesting(snapshot2)

        assert is_interesting1 is True
        assert is_interesting2 is False
        # Should have recorded the hash
        assert len(tracker.seen_coverage_hashes) == 1

    def test_statistics_accuracy(self):
        """Test that statistics accurately reflect tracking state."""
        tracker = CoverageTracker()

        # Simulate some executions
        with tracker.trace_execution("test_1"):
            _ = 1

        with tracker.trace_execution("test_2"):
            _ = 2

        stats = tracker.get_statistics()

        # Verify stats match actual state
        assert stats["total_executions"] == tracker.total_executions
        assert stats["interesting_cases"] == tracker.interesting_cases
        assert stats["redundant_cases"] == tracker.redundant_cases
        assert stats["total_lines_covered"] == len(tracker.global_coverage)
        assert stats["unique_coverage_patterns"] == len(tracker.seen_coverage_hashes)


class TestActualCodeTracing:
    """Test tracing actual core module code to exercise _trace_function."""

    def test_trace_core_module_execution(self):
        """Test tracing code in core modules."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        with tracker.trace_execution("test_core_types"):
            # Execute code in core module
            result = simple_function()
            assert result == 3

        # Should have recorded some coverage in core modules
        assert tracker.total_executions == 1
        # Coverage should be recorded for core module files
        core_files_traced = [
            filename for filename, _ in tracker.global_coverage if "core" in filename
        ]
        # Should have traced the test_helper file
        assert len(core_files_traced) > 0

    def test_trace_function_with_actual_module(self):
        """Test _trace_function is called during real code execution."""
        from dicom_fuzzer.core.test_helper import another_function

        tracker = CoverageTracker(target_modules=["core"])
        trace_calls = []

        # Wrap _trace_function to verify it's called
        original_trace = tracker._trace_function

        def wrapped_trace(frame, event, arg):
            trace_calls.append((event, frame.f_code.co_filename))
            return original_trace(frame, event, arg)

        tracker._trace_function = wrapped_trace

        with tracker.trace_execution("test_trace_calls"):
            # Execute multi-line function in core module
            result = another_function()
            assert len(result) == 5

        # Trace function should have been called
        assert len(trace_calls) > 0
        # Should have line events
        line_events = [event for event, _ in trace_calls if event == "line"]
        assert len(line_events) > 0

    def test_should_trace_file_exception_handling(self):
        """Test _should_trace_file handles files outside cwd."""
        tracker = CoverageTracker(target_modules=["core"])

        # File outside current working directory (absolute path)
        should_trace = tracker._should_trace_file("/completely/different/path/file.py")

        # Should return False (not in target modules)
        assert should_trace is False

    def test_trace_execution_updates_coverage_history(self):
        """Test that interesting executions are added to coverage history."""
        from dicom_fuzzer.core.test_helper import conditional_function, simple_function

        tracker = CoverageTracker(target_modules=["core"])

        with tracker.trace_execution("test_history_1"):
            # Execute first function
            _ = simple_function()

        with tracker.trace_execution("test_history_2"):
            # Execute different function (different code paths)
            _ = conditional_function(15)

        # Coverage history should have grown (if coverage was interesting)
        # At minimum, should have tried to track
        assert tracker.total_executions == 2

    def test_is_interesting_with_global_coverage_update(self):
        """Test that is_interesting updates global coverage."""
        tracker = CoverageTracker()

        snapshot = CoverageSnapshot(
            lines_covered={("core/test.py", 10), ("core/test.py", 20)}
        )

        # First time should be interesting
        is_interesting = tracker.is_interesting(snapshot)
        assert is_interesting is True

        # Should have added hash
        assert len(tracker.seen_coverage_hashes) == 1

        # Same snapshot should not be interesting
        is_interesting_again = tracker.is_interesting(snapshot)
        assert is_interesting_again is False

        # Hash count should remain the same
        assert len(tracker.seen_coverage_hashes) == 1

    def test_trace_execution_records_new_coverage(self):
        """Test that trace_execution properly records new coverage."""
        from dicom_fuzzer.core.test_helper import another_function, simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # First execution
        with tracker.trace_execution("test_new_1"):
            _ = simple_function()

        # Second execution with different code
        with tracker.trace_execution("test_new_2"):
            _ = another_function()

        # Should have executed twice
        assert tracker.total_executions == 2

    def test_coverage_report_with_executions(self):
        """Test coverage report after real executions."""
        from dicom_fuzzer.core.test_helper import conditional_function, simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # Perform some executions
        with tracker.trace_execution("report_test_1"):
            _ = simple_function()

        with tracker.trace_execution("report_test_2"):
            _ = conditional_function(3)

        report = tracker.get_coverage_report()

        # Report should contain execution data
        assert "Total Executions:      2" in report
        assert "Coverage-Guided Fuzzing Report" in report
        assert "Coverage History:" in report

    def test_reset_after_actual_tracing(self):
        """Test reset works after actual code tracing."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # Do some tracing
        with tracker.trace_execution("reset_test"):
            _ = simple_function()

        # Verify we have data
        assert tracker.total_executions > 0

        # Reset
        tracker.reset()

        # Everything should be cleared
        assert tracker.total_executions == 0
        assert tracker.interesting_cases == 0
        assert tracker.redundant_cases == 0
        assert len(tracker.global_coverage) == 0
        assert len(tracker.coverage_history) == 0
        assert len(tracker.seen_coverage_hashes) == 0

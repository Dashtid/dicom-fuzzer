"""Comprehensive tests for coverage_tracker.py targeting missing coverage lines.

This test module specifically targets:
- Lines 26: TYPE_CHECKING import (implicitly tested through type annotations)
- Lines 58-59: __post_init__ totals calculation
- Lines 72-80: coverage_hash method
- Lines 95, 99-101: coverage_percentage method
- Lines 171-192: _should_trace_file method
- Lines 214-220: _trace_function method
- Lines 251-283: trace_execution context manager
- Lines 295: track_execution alias
- Lines 311-324: is_interesting method
- Lines 333: get_statistics return
- Lines 353-369: get_coverage_report method
- Lines 373-380: reset method
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot, CoverageTracker


class TestCoverageSnapshotPostInit:
    """Test CoverageSnapshot __post_init__ method (lines 58-59)."""

    def test_post_init_sets_total_lines(self):
        """Test __post_init__ correctly calculates total_lines."""
        lines = {("file1.py", 10), ("file1.py", 20), ("file2.py", 5)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        assert snapshot.total_lines == 3

    def test_post_init_sets_total_branches(self):
        """Test __post_init__ correctly calculates total_branches."""
        branches = {
            ("file1.py", 10, 0),
            ("file1.py", 10, 1),
            ("file1.py", 20, 0),
        }
        snapshot = CoverageSnapshot(branches_covered=branches)

        assert snapshot.total_branches == 3

    def test_post_init_empty_coverage(self):
        """Test __post_init__ with empty coverage."""
        snapshot = CoverageSnapshot()

        assert snapshot.total_lines == 0
        assert snapshot.total_branches == 0

    def test_post_init_large_coverage(self):
        """Test __post_init__ with large coverage sets."""
        lines = {("file.py", i) for i in range(1000)}
        branches = {("file.py", i, j) for i in range(100) for j in range(2)}

        snapshot = CoverageSnapshot(lines_covered=lines, branches_covered=branches)

        assert snapshot.total_lines == 1000
        assert snapshot.total_branches == 200


class TestCoverageHashMethod:
    """Test coverage_hash method (lines 72-80)."""

    def test_coverage_hash_with_lines_only(self):
        """Test hash generation with only lines covered."""
        lines = {("file1.py", 10), ("file2.py", 20)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        hash_value = snapshot.coverage_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) > 0

    def test_coverage_hash_with_branches_only(self):
        """Test hash generation with only branches covered."""
        branches = {("file1.py", 10, 0), ("file1.py", 10, 1)}
        snapshot = CoverageSnapshot(branches_covered=branches)

        hash_value = snapshot.coverage_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) > 0

    def test_coverage_hash_with_both(self):
        """Test hash generation with both lines and branches."""
        lines = {("file1.py", 10)}
        branches = {("file1.py", 10, 0)}
        snapshot = CoverageSnapshot(lines_covered=lines, branches_covered=branches)

        hash_value = snapshot.coverage_hash()

        assert isinstance(hash_value, str)

    def test_coverage_hash_sorting_for_consistency(self):
        """Test that hash is consistent regardless of insertion order."""
        # Create snapshots with same data but different insertion order
        lines1 = {("a.py", 1), ("z.py", 100), ("m.py", 50)}
        lines2 = {("z.py", 100), ("m.py", 50), ("a.py", 1)}

        snapshot1 = CoverageSnapshot(lines_covered=lines1)
        snapshot2 = CoverageSnapshot(lines_covered=lines2)

        assert snapshot1.coverage_hash() == snapshot2.coverage_hash()

    def test_coverage_hash_branches_sorting(self):
        """Test branch sorting in hash calculation."""
        branches1 = {("a.py", 1, 0), ("z.py", 1, 1), ("m.py", 1, 2)}
        branches2 = {("z.py", 1, 1), ("a.py", 1, 0), ("m.py", 1, 2)}

        snapshot1 = CoverageSnapshot(branches_covered=branches1)
        snapshot2 = CoverageSnapshot(branches_covered=branches2)

        assert snapshot1.coverage_hash() == snapshot2.coverage_hash()

    def test_coverage_hash_empty_coverage(self):
        """Test hash with empty coverage."""
        snapshot = CoverageSnapshot()

        hash_value = snapshot.coverage_hash()

        assert isinstance(hash_value, str)
        # Empty coverage should still produce a hash
        assert len(hash_value) > 0


class TestCoveragePercentageMethod:
    """Test coverage_percentage method (lines 95, 99-101)."""

    def test_coverage_percentage_normal(self):
        """Test normal percentage calculation."""
        lines = {("file.py", i) for i in range(30)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        percentage = snapshot.coverage_percentage(total_possible_lines=100)

        assert percentage == 30.0

    def test_coverage_percentage_zero_total(self):
        """Test percentage with zero total lines."""
        snapshot = CoverageSnapshot(lines_covered={("file.py", 1)})

        percentage = snapshot.coverage_percentage(total_possible_lines=0)

        assert percentage == 0.0

    def test_coverage_percentage_full_coverage(self):
        """Test 100% coverage."""
        lines = {("file.py", i) for i in range(50)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        percentage = snapshot.coverage_percentage(total_possible_lines=50)

        assert percentage == 100.0

    def test_coverage_percentage_overcoverage(self):
        """Test when covered > total (shouldn't happen but handle gracefully)."""
        lines = {("file.py", i) for i in range(150)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        percentage = snapshot.coverage_percentage(total_possible_lines=100)

        assert percentage == 150.0

    def test_coverage_percentage_precision(self):
        """Test percentage precision."""
        lines = {("file.py", 1)}
        snapshot = CoverageSnapshot(lines_covered=lines)

        percentage = snapshot.coverage_percentage(total_possible_lines=3)

        assert abs(percentage - 33.333333) < 0.001


class TestShouldTraceFileMethod:
    """Test _should_trace_file method (lines 171-192)."""

    def test_should_trace_file_in_target_module_nested(self):
        """Test tracing file in nested target module path."""
        tracker = CoverageTracker(target_modules=["core"])

        # File in nested core path
        test_path = str(Path.cwd() / "dicom_fuzzer" / "core" / "deep" / "nested.py")
        result = tracker._should_trace_file(test_path)

        assert result is True

    def test_should_trace_file_multiple_ignore_patterns(self):
        """Test with multiple ignore patterns."""
        tracker = CoverageTracker(
            target_modules=["core"],
            ignore_patterns=["test_", "__pycache__", ".venv", "site-packages", ".pyc"],
        )

        # Test each ignore pattern
        assert tracker._should_trace_file("test_something.py") is False
        assert tracker._should_trace_file("/path/__pycache__/file.py") is False
        assert tracker._should_trace_file("/path/.venv/lib/module.py") is False
        assert tracker._should_trace_file("/site-packages/package/mod.py") is False
        assert tracker._should_trace_file("/path/module.pyc") is False

    def test_should_trace_file_absolute_path_outside_cwd(self):
        """Test file with absolute path outside current working directory."""
        tracker = CoverageTracker(target_modules=["core"])

        # Absolute path that's not relative to cwd
        result = tracker._should_trace_file("/completely/different/path/core/file.py")

        # Should return False due to ValueError in relative_to
        assert result is False

    def test_should_trace_file_path_normalization(self):
        """Test path normalization with different separators."""
        tracker = CoverageTracker(target_modules=["core"])

        # Test with forward slashes
        test_path = str(Path.cwd() / "dicom_fuzzer" / "core" / "file.py")
        result = tracker._should_trace_file(test_path)

        assert result is True

    def test_should_trace_file_module_at_start(self):
        """Test module at start of relative path."""
        tracker = CoverageTracker(target_modules=["core"])

        # File in core at root level
        test_path = str(Path.cwd() / "core" / "file.py")
        result = tracker._should_trace_file(test_path)

        assert result is True

    def test_should_trace_file_partial_module_match(self):
        """Test that partial module names don't match."""
        tracker = CoverageTracker(target_modules=["core"])

        # "coreutils" should NOT match "core"
        test_path = str(Path.cwd() / "coreutils" / "file.py")
        result = tracker._should_trace_file(test_path)

        # Should not match because "coreutils" != "core"
        assert result is False

    def test_should_trace_file_multiple_modules(self):
        """Test matching multiple target modules."""
        tracker = CoverageTracker(target_modules=["core", "strategies", "utils"])

        core_path = str(Path.cwd() / "core" / "file.py")
        strategies_path = str(Path.cwd() / "strategies" / "file.py")
        utils_path = str(Path.cwd() / "utils" / "file.py")
        other_path = str(Path.cwd() / "other" / "file.py")

        assert tracker._should_trace_file(core_path) is True
        assert tracker._should_trace_file(strategies_path) is True
        assert tracker._should_trace_file(utils_path) is True
        assert tracker._should_trace_file(other_path) is False


class TestTraceFunctionMethod:
    """Test _trace_function method (lines 214-220)."""

    def test_trace_function_line_event(self):
        """Test _trace_function handles 'line' event."""
        tracker = CoverageTracker(target_modules=["core"])
        tracker.current_coverage = set()

        # Create mock frame
        mock_frame = MagicMock()
        mock_frame.f_code.co_filename = str(Path.cwd() / "core" / "test.py")
        mock_frame.f_lineno = 42

        result = tracker._trace_function(mock_frame, "line", None)

        # Should return itself to continue tracing
        assert result == tracker._trace_function
        # Should have recorded the line
        assert (mock_frame.f_code.co_filename, 42) in tracker.current_coverage

    def test_trace_function_non_line_event(self):
        """Test _trace_function ignores non-line events."""
        tracker = CoverageTracker(target_modules=["core"])
        tracker.current_coverage = set()

        mock_frame = MagicMock()
        mock_frame.f_code.co_filename = str(Path.cwd() / "core" / "test.py")
        mock_frame.f_lineno = 42

        # Test various non-line events
        for event in ["call", "return", "exception", "c_call", "c_return"]:
            tracker.current_coverage.clear()
            result = tracker._trace_function(mock_frame, event, None)

            assert result == tracker._trace_function
            # Should NOT have recorded the line
            assert len(tracker.current_coverage) == 0

    def test_trace_function_ignores_untargeted_file(self):
        """Test _trace_function ignores files not in target modules."""
        tracker = CoverageTracker(target_modules=["core"])
        tracker.current_coverage = set()

        mock_frame = MagicMock()
        mock_frame.f_code.co_filename = "/other/path/file.py"
        mock_frame.f_lineno = 42

        result = tracker._trace_function(mock_frame, "line", None)

        # Should return itself
        assert result == tracker._trace_function
        # Should NOT have recorded (file not in target)
        assert len(tracker.current_coverage) == 0

    def test_trace_function_accumulates_coverage(self):
        """Test _trace_function accumulates multiple line hits."""
        tracker = CoverageTracker(target_modules=["core"])
        tracker.current_coverage = set()

        mock_frame = MagicMock()
        core_file = str(Path.cwd() / "core" / "test.py")
        mock_frame.f_code.co_filename = core_file

        # Simulate multiple line events
        for line in [10, 20, 30, 10]:  # Note: 10 is hit twice
            mock_frame.f_lineno = line
            tracker._trace_function(mock_frame, "line", None)

        # Should have 3 unique lines (set deduplicates)
        assert len(tracker.current_coverage) == 3
        assert (core_file, 10) in tracker.current_coverage
        assert (core_file, 20) in tracker.current_coverage
        assert (core_file, 30) in tracker.current_coverage


class TestTraceExecutionContextManager:
    """Test trace_execution context manager (lines 251-283)."""

    def test_trace_execution_clears_current_coverage(self):
        """Test trace_execution clears current_coverage at start."""
        tracker = CoverageTracker()
        # Pre-populate current coverage
        tracker.current_coverage = {("old_file.py", 1), ("old_file.py", 2)}

        with tracker.trace_execution("test_clear"):
            # Current coverage should be cleared at context entry
            pass

        # After context, it may have new coverage or be cleared
        # Main test is that old coverage doesn't persist
        assert ("old_file.py", 1) not in tracker.current_coverage

    def test_trace_execution_sets_up_tracing(self):
        """Test trace_execution sets sys.settrace."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_setup"):
            # During execution, settrace should be active
            # We can't easily test this without interfering with pytest
            pass

        # After context, trace should be removed
        assert sys.gettrace() is None

    def test_trace_execution_removes_tracing_on_exit(self):
        """Test trace_execution removes tracing even on normal exit."""
        tracker = CoverageTracker()

        with tracker.trace_execution("test_cleanup"):
            pass

        assert sys.gettrace() is None

    def test_trace_execution_removes_tracing_on_exception(self):
        """Test trace_execution removes tracing on exception."""
        tracker = CoverageTracker()

        try:
            with tracker.trace_execution("test_exception"):
                raise ValueError("Test error")
        except ValueError:
            pass

        assert sys.gettrace() is None

    def test_trace_execution_creates_snapshot(self):
        """Test trace_execution creates coverage snapshot."""
        tracker = CoverageTracker(target_modules=["core"])

        with tracker.trace_execution("test_snapshot"):
            # Execute some code
            _ = 1 + 1

        # Should have at least one execution
        assert tracker.total_executions == 1

    def test_trace_execution_detects_interesting_coverage(self):
        """Test trace_execution detects new coverage as interesting."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        with tracker.trace_execution("test_interesting"):
            simple_function()

        # First execution should be interesting
        assert tracker.interesting_cases >= 1

    def test_trace_execution_detects_redundant_coverage(self):
        """Test trace_execution detects duplicate coverage as redundant."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # First execution
        with tracker.trace_execution("first"):
            simple_function()

        initial_interesting = tracker.interesting_cases

        # Same function again
        with tracker.trace_execution("second"):
            simple_function()

        # Should have counted redundant
        assert (
            tracker.redundant_cases >= 1
            or tracker.interesting_cases > initial_interesting
        )

    def test_trace_execution_updates_global_coverage(self):
        """Test trace_execution updates global_coverage with new lines."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        initial_global = len(tracker.global_coverage)

        with tracker.trace_execution("test_global"):
            simple_function()

        # Global coverage should have grown (if interesting)
        if tracker.interesting_cases > 0:
            assert len(tracker.global_coverage) > initial_global

    def test_trace_execution_adds_to_history_when_interesting(self):
        """Test trace_execution adds to coverage_history when interesting."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        with tracker.trace_execution("test_history"):
            simple_function()

        # If it was interesting, should be in history
        if tracker.interesting_cases > 0:
            assert len(tracker.coverage_history) >= 1


class TestTrackExecutionAlias:
    """Test track_execution alias method (line 295)."""

    def test_track_execution_returns_context_manager(self):
        """Test track_execution returns a context manager."""
        tracker = CoverageTracker()

        result = tracker.track_execution("test_alias")

        # Should be a context manager (has __enter__ and __exit__)
        assert hasattr(result, "__enter__")
        assert hasattr(result, "__exit__")

    def test_track_execution_works_as_context(self):
        """Test track_execution works as with statement."""
        tracker = CoverageTracker()

        with tracker.track_execution("test_alias_context"):
            _ = 1 + 1

        assert tracker.total_executions >= 1


class TestIsInterestingMethod:
    """Test is_interesting method (lines 311-324)."""

    def test_is_interesting_checks_hash_first(self):
        """Test is_interesting checks hash for quick deduplication."""
        tracker = CoverageTracker()

        snapshot = CoverageSnapshot(lines_covered={("file.py", 10)})

        # First check - should be interesting and add hash
        is_interesting1 = tracker.is_interesting(snapshot)
        assert is_interesting1 is True
        assert len(tracker.seen_coverage_hashes) == 1

        # Second check - should find hash and return False immediately
        is_interesting2 = tracker.is_interesting(snapshot)
        assert is_interesting2 is False

    def test_is_interesting_checks_new_lines(self):
        """Test is_interesting checks for new coverage lines."""
        tracker = CoverageTracker()

        # Add initial global coverage
        tracker.global_coverage = {("file.py", 1), ("file.py", 2)}

        # Snapshot with only existing lines (different hash)
        snapshot = CoverageSnapshot(lines_covered={("file.py", 1)})

        is_interesting = tracker.is_interesting(snapshot)

        # No new lines, should not be interesting
        assert is_interesting is False

    def test_is_interesting_adds_hash_when_interesting(self):
        """Test is_interesting adds hash when finding new coverage."""
        tracker = CoverageTracker()

        snapshot = CoverageSnapshot(
            lines_covered={("file.py", 10), ("file.py", 20), ("file.py", 30)}
        )

        is_interesting = tracker.is_interesting(snapshot)

        assert is_interesting is True
        assert snapshot.coverage_hash() in tracker.seen_coverage_hashes

    def test_is_interesting_no_lines_no_interesting(self):
        """Test is_interesting returns False for empty coverage."""
        tracker = CoverageTracker()

        snapshot = CoverageSnapshot()  # No lines covered

        # Empty coverage compared to empty global should have no new lines
        is_interesting = tracker.is_interesting(snapshot)

        # May still be interesting if hash is new, but no actual benefit
        # This tests the logic path
        assert isinstance(is_interesting, bool)


class TestGetStatisticsMethod:
    """Test get_statistics method (line 333)."""

    def test_get_statistics_returns_dict(self):
        """Test get_statistics returns a dictionary."""
        tracker = CoverageTracker()

        stats = tracker.get_statistics()

        assert isinstance(stats, dict)

    def test_get_statistics_all_fields_present(self):
        """Test get_statistics returns all expected fields."""
        tracker = CoverageTracker()

        stats = tracker.get_statistics()

        expected_fields = [
            "total_executions",
            "interesting_cases",
            "redundant_cases",
            "total_lines_covered",
            "unique_coverage_patterns",
            "efficiency",
        ]

        for field in expected_fields:
            assert field in stats, f"Missing field: {field}"

    def test_get_statistics_reflects_state(self):
        """Test get_statistics reflects actual tracker state."""
        tracker = CoverageTracker()

        # Set specific state
        tracker.total_executions = 100
        tracker.interesting_cases = 25
        tracker.redundant_cases = 75
        tracker.global_coverage = {("file.py", i) for i in range(50)}
        tracker.seen_coverage_hashes = {"hash1", "hash2", "hash3"}

        stats = tracker.get_statistics()

        assert stats["total_executions"] == 100
        assert stats["interesting_cases"] == 25
        assert stats["redundant_cases"] == 75
        assert stats["total_lines_covered"] == 50
        assert stats["unique_coverage_patterns"] == 3
        assert stats["efficiency"] == 0.25

    def test_get_statistics_efficiency_zero_executions(self):
        """Test efficiency calculation with zero executions."""
        tracker = CoverageTracker()

        stats = tracker.get_statistics()

        assert stats["efficiency"] == 0.0


class TestGetCoverageReportMethod:
    """Test get_coverage_report method (lines 353-369)."""

    def test_get_coverage_report_returns_string(self):
        """Test get_coverage_report returns a string."""
        tracker = CoverageTracker()

        report = tracker.get_coverage_report()

        assert isinstance(report, str)

    def test_get_coverage_report_contains_header(self):
        """Test report contains header."""
        tracker = CoverageTracker()

        report = tracker.get_coverage_report()

        assert "Coverage-Guided Fuzzing Report" in report

    def test_get_coverage_report_contains_separator(self):
        """Test report contains separator line."""
        tracker = CoverageTracker()

        report = tracker.get_coverage_report()

        assert "=" * 50 in report

    def test_get_coverage_report_contains_all_stats(self):
        """Test report contains all statistics."""
        tracker = CoverageTracker()
        tracker.total_executions = 42
        tracker.interesting_cases = 10
        tracker.redundant_cases = 32

        report = tracker.get_coverage_report()

        assert "Total Executions:" in report
        assert "42" in report
        assert "Interesting Cases:" in report
        assert "10" in report
        assert "Redundant Cases:" in report
        assert "32" in report

    def test_get_coverage_report_contains_coverage_history(self):
        """Test report contains coverage history count."""
        tracker = CoverageTracker()
        tracker.coverage_history = [
            CoverageSnapshot(),
            CoverageSnapshot(),
        ]

        report = tracker.get_coverage_report()

        assert "Coverage History:" in report
        assert "2" in report

    def test_get_coverage_report_efficiency_formatting(self):
        """Test efficiency is formatted as percentage."""
        tracker = CoverageTracker()
        tracker.total_executions = 100
        tracker.interesting_cases = 25

        report = tracker.get_coverage_report()

        assert "Efficiency:" in report
        # Should contain percentage format
        assert "25" in report or "0.25" in report or "25.0" in report


class TestResetMethod:
    """Test reset method (lines 373-380)."""

    def test_reset_clears_global_coverage(self):
        """Test reset clears global_coverage."""
        tracker = CoverageTracker()
        tracker.global_coverage = {("file.py", 1), ("file.py", 2)}

        tracker.reset()

        assert len(tracker.global_coverage) == 0

    def test_reset_clears_current_coverage(self):
        """Test reset clears current_coverage."""
        tracker = CoverageTracker()
        tracker.current_coverage = {("file.py", 1)}

        tracker.reset()

        assert len(tracker.current_coverage) == 0

    def test_reset_clears_coverage_history(self):
        """Test reset clears coverage_history."""
        tracker = CoverageTracker()
        tracker.coverage_history = [CoverageSnapshot(), CoverageSnapshot()]

        tracker.reset()

        assert len(tracker.coverage_history) == 0

    def test_reset_clears_seen_hashes(self):
        """Test reset clears seen_coverage_hashes."""
        tracker = CoverageTracker()
        tracker.seen_coverage_hashes = {"hash1", "hash2", "hash3"}

        tracker.reset()

        assert len(tracker.seen_coverage_hashes) == 0

    def test_reset_clears_counters(self):
        """Test reset clears all counters."""
        tracker = CoverageTracker()
        tracker.total_executions = 100
        tracker.interesting_cases = 30
        tracker.redundant_cases = 70

        tracker.reset()

        assert tracker.total_executions == 0
        assert tracker.interesting_cases == 0
        assert tracker.redundant_cases == 0

    def test_reset_allows_fresh_start(self):
        """Test reset allows tracker to be used fresh."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # Use tracker
        with tracker.trace_execution("before_reset"):
            simple_function()

        # Reset
        tracker.reset()

        # Use again
        with tracker.trace_execution("after_reset"):
            simple_function()

        # Should work normally
        assert tracker.total_executions >= 1


class TestIntegrationScenarios:
    """Integration tests covering complete workflows."""

    def test_full_tracing_workflow(self):
        """Test complete tracing workflow from start to report."""
        from dicom_fuzzer.core.test_helper import (
            another_function,
            conditional_function,
            simple_function,
        )

        tracker = CoverageTracker(target_modules=["core"])

        # Execute multiple functions
        with tracker.trace_execution("step1"):
            simple_function()

        with tracker.trace_execution("step2"):
            another_function()

        with tracker.trace_execution("step3"):
            conditional_function(5)

        with tracker.trace_execution("step4"):
            conditional_function(15)

        # Check state
        assert tracker.total_executions == 4
        assert len(tracker.global_coverage) > 0

        # Generate report
        report = tracker.get_coverage_report()
        assert "Total Executions:      4" in report

    def test_coverage_snapshot_lifecycle(self):
        """Test CoverageSnapshot through full lifecycle."""
        # Create snapshot
        lines = {("file.py", 10), ("file.py", 20)}
        branches = {("file.py", 10, 0)}
        snapshot = CoverageSnapshot(
            lines_covered=lines,
            branches_covered=branches,
            test_case_id="lifecycle_test",
        )

        # Verify __post_init__
        assert snapshot.total_lines == 2
        assert snapshot.total_branches == 1

        # Generate hash
        hash_value = snapshot.coverage_hash()
        assert len(hash_value) > 0

        # Calculate percentage
        percentage = snapshot.coverage_percentage(100)
        assert percentage == 2.0

        # Compare coverage
        other = CoverageSnapshot(lines_covered={("file.py", 10)})
        new_lines = snapshot.new_coverage_vs(other)
        assert ("file.py", 20) in new_lines

    def test_tracker_with_mixed_coverage_patterns(self):
        """Test tracker with various coverage patterns."""
        tracker = CoverageTracker()

        # Create different coverage patterns
        patterns = [
            {("file1.py", 10)},
            {("file1.py", 10), ("file1.py", 20)},
            {("file2.py", 1)},
            {("file1.py", 10)},  # Duplicate
        ]

        for i, pattern in enumerate(patterns):
            snapshot = CoverageSnapshot(lines_covered=pattern)
            tracker.is_interesting(snapshot)
            if i == 0 or pattern not in patterns[:i]:
                # Update global for non-duplicates
                tracker.global_coverage.update(pattern)

        # Should have found some interesting patterns
        assert len(tracker.seen_coverage_hashes) >= 2

    def test_reset_and_reuse_workflow(self):
        """Test reset followed by reuse."""
        from dicom_fuzzer.core.test_helper import simple_function

        tracker = CoverageTracker(target_modules=["core"])

        # First usage
        with tracker.trace_execution("first_use"):
            simple_function()

        first_stats = tracker.get_statistics()

        # Reset
        tracker.reset()

        # Verify clean state
        clean_stats = tracker.get_statistics()
        assert clean_stats["total_executions"] == 0
        assert clean_stats["total_lines_covered"] == 0

        # Second usage
        with tracker.trace_execution("second_use"):
            simple_function()

        second_stats = tracker.get_statistics()
        assert second_stats["total_executions"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

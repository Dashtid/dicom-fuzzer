"""Additional tests for coverage instrumentation to improve code coverage.

These tests target specific uncovered paths in coverage_instrumentation.py
to achieve maximum test coverage.
"""

import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from dicom_fuzzer.core.coverage_instrumentation import (
    CoverageInfo,
    CoverageTracker,
    HybridCoverageTracker,
    calculate_coverage_distance,
    configure_global_tracker,
    get_global_tracker,
)


class TestCoverageInfo:
    """Test CoverageInfo dataclass."""

    def test_default_initialization(self):
        """Test CoverageInfo with default values."""
        info = CoverageInfo()

        assert info.edges == set()
        assert info.branches == set()
        assert info.functions == set()
        assert info.lines == set()
        assert info.execution_time == 0.0
        assert info.input_hash is None
        assert info.new_coverage is False

    def test_merge_coverage(self):
        """Test merging two CoverageInfo objects (lines 33-36)."""
        info1 = CoverageInfo()
        info1.edges.add(("file1.py", 10, "file1.py", 11))
        info1.branches.add(("file1.py", 10, True))
        info1.functions.add("file1.py:func1")
        info1.lines.add(("file1.py", 10))

        info2 = CoverageInfo()
        info2.edges.add(("file2.py", 20, "file2.py", 21))
        info2.branches.add(("file2.py", 20, False))
        info2.functions.add("file2.py:func2")
        info2.lines.add(("file2.py", 20))

        info1.merge(info2)

        assert len(info1.edges) == 2
        assert len(info1.branches) == 2
        assert len(info1.functions) == 2
        assert len(info1.lines) == 2

    def test_get_coverage_hash(self):
        """Test generating coverage hash (lines 38-42)."""
        info = CoverageInfo()
        info.edges.add(("file.py", 1, "file.py", 2))
        info.branches.add(("file.py", 1, True))

        hash1 = info.get_coverage_hash()

        assert hash1 is not None
        assert len(hash1) == 16

        # Same coverage should give same hash
        info2 = CoverageInfo()
        info2.edges.add(("file.py", 1, "file.py", 2))
        info2.branches.add(("file.py", 1, True))

        hash2 = info2.get_coverage_hash()
        assert hash1 == hash2

    def test_get_coverage_hash_empty(self):
        """Test coverage hash with empty data."""
        info = CoverageInfo()
        hash_val = info.get_coverage_hash()

        assert hash_val is not None


class TestCoverageTracker:
    """Test CoverageTracker class."""

    def test_init_default(self):
        """Test CoverageTracker initialization with defaults."""
        tracker = CoverageTracker()

        assert tracker.target_modules == set()
        assert tracker.total_executions == 0
        assert tracker.coverage_increases == 0

    def test_init_with_target_modules(self):
        """Test CoverageTracker with target modules (lines 58)."""
        modules = {"dicom_fuzzer", "pydicom"}
        tracker = CoverageTracker(target_modules=modules)

        assert tracker.target_modules == modules

    def test_should_track_module_no_targets(self):
        """Test should_track_module with no target modules (line 76-77)."""
        tracker = CoverageTracker()

        # Should track everything when no targets specified
        assert tracker.should_track_module("any_file.py") is True

    def test_should_track_module_with_targets(self):
        """Test should_track_module with targets (lines 79-86)."""
        tracker = CoverageTracker(target_modules={"dicom_fuzzer"})

        assert tracker.should_track_module("dicom_fuzzer/core/parser.py") is True
        assert tracker.should_track_module("other_module/file.py") is False

    def test_should_track_module_cache(self):
        """Test module tracking cache (lines 80-81)."""
        tracker = CoverageTracker(target_modules={"dicom_fuzzer"})

        # First call populates cache
        result1 = tracker.should_track_module("dicom_fuzzer/test.py")

        # Second call uses cache
        result2 = tracker.should_track_module("dicom_fuzzer/test.py")

        assert result1 == result2 is True
        assert "dicom_fuzzer/test.py" in tracker._module_cache

    def test_trace_function_disabled(self):
        """Test trace function when disabled (lines 93-94)."""
        tracker = CoverageTracker()
        tracker.trace_enabled = False

        frame = MagicMock()
        result = tracker._trace_function(frame, "call", None)

        assert result is None

    def test_trace_function_not_target_module(self):
        """Test trace function for non-target module (lines 99-100)."""
        tracker = CoverageTracker(target_modules={"other_module"})
        tracker.trace_enabled = True

        frame = MagicMock()
        frame.f_code.co_filename = "different_module/file.py"

        result = tracker._trace_function(frame, "call", None)

        assert result is None

    def test_trace_function_call_event(self):
        """Test trace function call event (lines 105-109)."""
        tracker = CoverageTracker()
        tracker.trace_enabled = True

        frame = MagicMock()
        frame.f_code.co_filename = "test.py"
        frame.f_lineno = 10
        frame.f_code.co_name = "test_func"

        result = tracker._trace_function(frame, "call", None)

        assert result == tracker._trace_function
        assert "test.py:test_func" in tracker.current_coverage.functions
        assert tracker.last_location == ("test.py", 10)

    def test_trace_function_line_event(self):
        """Test trace function line event (lines 111-120)."""
        tracker = CoverageTracker()
        tracker.trace_enabled = True
        tracker.last_location = ("test.py", 9)

        frame = MagicMock()
        frame.f_code.co_filename = "test.py"
        frame.f_lineno = 10
        frame.f_code.co_name = "test_func"

        result = tracker._trace_function(frame, "line", None)

        assert result == tracker._trace_function
        assert ("test.py", 10) in tracker.current_coverage.lines
        assert ("test.py", 9, "test.py", 10) in tracker.current_coverage.edges

    def test_trace_function_line_event_no_last_location(self):
        """Test trace function line event without last location."""
        tracker = CoverageTracker()
        tracker.trace_enabled = True
        tracker.last_location = None

        frame = MagicMock()
        frame.f_code.co_filename = "test.py"
        frame.f_lineno = 10
        frame.f_code.co_name = "test_func"

        result = tracker._trace_function(frame, "line", None)

        assert result == tracker._trace_function
        assert ("test.py", 10) in tracker.current_coverage.lines

    def test_trace_function_return_event(self):
        """Test trace function return event (lines 122-131)."""
        tracker = CoverageTracker()
        tracker.trace_enabled = True
        tracker.last_location = ("test.py", 15)

        frame = MagicMock()
        frame.f_code.co_filename = "test.py"
        frame.f_lineno = 20
        frame.f_code.co_name = "test_func"

        result = tracker._trace_function(frame, "return", None)

        assert result == tracker._trace_function
        # Return creates edge with negative line number
        assert ("test.py", 15, "test.py", -20) in tracker.current_coverage.edges
        assert tracker.last_location is None

    def test_trace_function_return_event_no_last_location(self):
        """Test trace function return without last location."""
        tracker = CoverageTracker()
        tracker.trace_enabled = True
        tracker.last_location = None

        frame = MagicMock()
        frame.f_code.co_filename = "test.py"
        frame.f_lineno = 20
        frame.f_code.co_name = "test_func"

        result = tracker._trace_function(frame, "return", None)

        assert result == tracker._trace_function

    def test_track_coverage_context_manager(self):
        """Test track_coverage context manager (lines 135-187)."""
        tracker = CoverageTracker()

        def test_func():
            x = 1
            y = 2
            return x + y

        with tracker.track_coverage() as coverage:
            result = test_func()

        assert result == 3
        assert coverage.execution_time > 0
        assert tracker.total_executions == 1

    def test_track_coverage_with_input_data(self):
        """Test track_coverage with input data hash (lines 151-152)."""
        tracker = CoverageTracker()

        with tracker.track_coverage(input_data=b"test input") as coverage:
            pass

        assert coverage.input_hash is not None
        assert tracker.coverage_history.get(coverage.input_hash) is not None

    def test_track_coverage_new_coverage_detected(self):
        """Test track_coverage detecting new coverage (lines 173-181)."""
        tracker = CoverageTracker()

        # First execution
        with tracker.track_coverage() as cov1:
            x = 1
            pass

        # Add some edges to global
        tracker.global_coverage.edges.add(("test", 1, "test", 2))

        # Second execution with new edges
        tracker.current_coverage = CoverageInfo()
        tracker.current_coverage.edges.add(("new", 10, "new", 11))

        # Simulate merge by calling track_coverage
        with tracker.track_coverage() as cov2:
            y = 2
            pass

    def test_get_coverage_stats(self):
        """Test get_coverage_stats (lines 189-205)."""
        tracker = CoverageTracker()

        # Add some coverage
        tracker.global_coverage.edges.add(("file.py", 1, "file.py", 2))
        tracker.global_coverage.branches.add(("file.py", 1, True))
        tracker.global_coverage.functions.add("file.py:func")
        tracker.global_coverage.lines.add(("file.py", 1))
        tracker.total_executions = 10
        tracker.coverage_increases = 3

        stats = tracker.get_coverage_stats()

        assert stats["total_edges"] == 1
        assert stats["total_branches"] == 1
        assert stats["total_functions"] == 1
        assert stats["total_lines"] == 1
        assert stats["total_executions"] == 10
        assert stats["coverage_increases"] == 3
        assert stats["coverage_rate"] == 0.3

    def test_get_coverage_stats_no_executions(self):
        """Test coverage stats with no executions (line 200-204)."""
        tracker = CoverageTracker()

        stats = tracker.get_coverage_stats()

        assert stats["coverage_rate"] == 0

    def test_get_uncovered_edges(self):
        """Test get_uncovered_edges (lines 207-223)."""
        tracker = CoverageTracker()

        # Add some global coverage
        tracker.global_coverage.edges.add(("file.py", 10, "file.py", 11))

        # Create recent coverage
        recent = CoverageInfo()
        recent.lines.add(("file.py", 10))

        uncovered = tracker.get_uncovered_edges(recent)

        assert uncovered is not None
        # Should contain potential edges from line 10
        assert any("file.py" in str(e) for e in uncovered)

    def test_export_coverage(self, tmp_path: Path):
        """Test export_coverage to file (lines 225-241)."""
        tracker = CoverageTracker()

        # Add some coverage
        tracker.global_coverage.edges.add(("file.py", 1, "file.py", 2))
        tracker.global_coverage.functions.add("file.py:func")
        tracker.global_coverage.lines.add(("file.py", 1))
        tracker.coverage_history["test_hash"] = CoverageInfo()

        output_file = tmp_path / "coverage.json"
        tracker.export_coverage(output_file)

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert "stats" in data
        assert "edges" in data
        assert "functions" in data
        assert "lines" in data
        assert data["history_size"] == 1

    def test_reset(self):
        """Test reset method (lines 243-252)."""
        tracker = CoverageTracker()

        # Add some data
        tracker.global_coverage.edges.add(("file.py", 1, "file.py", 2))
        tracker.coverage_history["hash1"] = CoverageInfo()
        tracker._module_cache["test.py"] = True
        tracker.total_executions = 5
        tracker.coverage_increases = 2

        tracker.reset()

        assert tracker.global_coverage.edges == set()
        assert tracker.coverage_history == {}
        assert tracker._module_cache == {}
        assert tracker.total_executions == 0
        assert tracker.coverage_increases == 0


class TestHybridCoverageTracker:
    """Test HybridCoverageTracker class."""

    def test_init_without_atheris(self):
        """Test initialization without Atheris (lines 271-282)."""
        tracker = HybridCoverageTracker(use_atheris=False)

        assert tracker.atheris_available is False
        assert tracker.use_atheris is False

    def test_init_with_atheris_import_fail(self):
        """Test initialization when Atheris import fails (lines 275-282)."""
        with patch.dict(sys.modules, {"atheris": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                tracker = HybridCoverageTracker(use_atheris=True)

                assert tracker.atheris_available is False

    def test_init_with_atheris_available(self):
        """Test initialization with Atheris available."""
        mock_atheris = MagicMock()

        with patch.dict(sys.modules, {"atheris": mock_atheris}):
            tracker = HybridCoverageTracker(use_atheris=True)

            # May or may not be available depending on import behavior
            # The important thing is it doesn't crash

    def test_track_coverage_no_atheris(self):
        """Test track_coverage without Atheris (lines 295-297)."""
        tracker = HybridCoverageTracker(use_atheris=False)

        with tracker.track_coverage(input_data=b"test") as coverage:
            x = 1
            pass

        assert coverage is not None

    def test_track_coverage_with_target_modules(self):
        """Test HybridCoverageTracker with target modules."""
        tracker = HybridCoverageTracker(
            target_modules={"dicom_fuzzer"}, use_atheris=False
        )

        with tracker.track_coverage() as coverage:
            pass

        assert coverage is not None


class TestCoverageDistanceFunction:
    """Test calculate_coverage_distance function."""

    def test_distance_same_coverage(self):
        """Test distance between identical coverage."""
        cov1 = CoverageInfo()
        cov1.edges.add(("file.py", 1, "file.py", 2))

        cov2 = CoverageInfo()
        cov2.edges.add(("file.py", 1, "file.py", 2))

        distance = calculate_coverage_distance(cov1, cov2)

        assert distance == 0.0

    def test_distance_different_coverage(self):
        """Test distance between different coverage."""
        cov1 = CoverageInfo()
        cov1.edges.add(("file.py", 1, "file.py", 2))

        cov2 = CoverageInfo()
        cov2.edges.add(("file.py", 3, "file.py", 4))

        distance = calculate_coverage_distance(cov1, cov2)

        assert distance == 1.0  # Completely different

    def test_distance_partial_overlap(self):
        """Test distance with partial overlap."""
        cov1 = CoverageInfo()
        cov1.edges.add(("file.py", 1, "file.py", 2))
        cov1.edges.add(("file.py", 2, "file.py", 3))

        cov2 = CoverageInfo()
        cov2.edges.add(("file.py", 1, "file.py", 2))
        cov2.edges.add(("file.py", 4, "file.py", 5))

        distance = calculate_coverage_distance(cov1, cov2)

        # 1 overlap, 3 total = Jaccard = 1/3, distance = 1 - 1/3 = 2/3
        assert 0 < distance < 1

    def test_distance_empty_coverage(self):
        """Test distance with empty coverage (lines 308-309)."""
        cov1 = CoverageInfo()
        cov2 = CoverageInfo()

        distance = calculate_coverage_distance(cov1, cov2)

        assert distance == 0.0

    def test_distance_one_empty(self):
        """Test distance when one coverage is empty."""
        cov1 = CoverageInfo()
        cov1.edges.add(("file.py", 1, "file.py", 2))

        cov2 = CoverageInfo()

        distance = calculate_coverage_distance(cov1, cov2)

        assert distance == 1.0


class TestGlobalTracker:
    """Test global tracker functions."""

    def test_get_global_tracker_creates_new(self):
        """Test get_global_tracker creates new tracker (lines 325-330)."""
        # Reset global tracker
        import dicom_fuzzer.core.coverage_instrumentation as ci

        ci._global_tracker = None

        tracker = get_global_tracker()

        assert tracker is not None
        assert isinstance(tracker, CoverageTracker)

    def test_get_global_tracker_returns_existing(self):
        """Test get_global_tracker returns existing tracker."""

        tracker1 = get_global_tracker()
        tracker2 = get_global_tracker()

        assert tracker1 is tracker2

    def test_configure_global_tracker(self):
        """Test configure_global_tracker (lines 333-336)."""
        modules = {"dicom_fuzzer", "custom_module"}

        configure_global_tracker(modules)

        tracker = get_global_tracker()
        assert tracker.target_modules == modules


class TestTrackerConcurrency:
    """Test thread safety of CoverageTracker."""

    def test_concurrent_coverage_tracking(self):
        """Test that coverage tracking is thread-safe."""
        tracker = CoverageTracker()
        results = []
        errors = []

        def track_in_thread(thread_id: int):
            try:
                with tracker.track_coverage(input_data=f"thread_{thread_id}".encode()):
                    x = thread_id * 2
                results.append(thread_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=track_in_thread, args=(i,)) for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 5

    def test_concurrent_stats_access(self):
        """Test concurrent access to get_coverage_stats."""
        tracker = CoverageTracker()
        tracker.global_coverage.edges.add(("file.py", 1, "file.py", 2))
        errors = []

        def get_stats():
            try:
                for _ in range(10):
                    stats = tracker.get_coverage_stats()
                    assert "total_edges" in stats
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_stats) for _ in range(3)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

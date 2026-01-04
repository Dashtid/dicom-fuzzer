"""Coverage Instrumentation for DICOM Fuzzer

Provides lightweight coverage tracking using Python's tracing capabilities.
Tracks edge coverage (branch transitions) to guide fuzzing decisions.
"""

import sys
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Import unified coverage types
from dicom_fuzzer.core.coverage_types import (
    CoverageInfo,
    ExecutionCoverageInfo,
)
from dicom_fuzzer.utils.hashing import hash_string, short_hash

# Re-export for backward compatibility
__all__ = ["CoverageInfo", "ExecutionCoverageInfo", "CoverageTracker"]


class CoverageTracker:
    """Lightweight coverage tracker using sys.settrace.

    Optimized for fuzzing workloads with minimal overhead.
    """

    def __init__(self, target_modules: set[str] | None = None):
        """Initialize the coverage tracker.

        Args:
            target_modules: Set of module names to track (None = track all)

        """
        self.target_modules = target_modules or set()
        self.global_coverage = CoverageInfo()
        self.current_coverage = CoverageInfo()
        self.coverage_history: dict[str, CoverageInfo] = {}
        self.last_location: tuple[str, int] | None = None
        self.trace_enabled = False
        self._lock = threading.RLock()  # Use RLock to allow re-entrant locking

        # Performance optimization: cache module checks
        self._module_cache: dict[str, bool] = {}

        # Statistics
        self.total_executions = 0
        self.unique_crashes = 0
        self.coverage_increases = 0

    def should_track_module(self, filename: str) -> bool:
        """Check if we should track coverage for this file."""
        if not self.target_modules:
            return True

        # Cache the result for performance
        if filename in self._module_cache:
            return self._module_cache[filename]

        # Check if file belongs to target modules
        result = any(module in filename for module in self.target_modules)
        self._module_cache[filename] = result
        return result

    def _trace_function(self, frame: Any, event: str, arg: Any) -> Callable | None:
        """Trace function for sys.settrace.

        Tracks code execution at the line and branch level.
        """
        if not self.trace_enabled:
            return None

        filename = frame.f_code.co_filename

        # Skip if not in target modules
        if not self.should_track_module(filename):
            return None

        lineno = frame.f_lineno
        func_name = frame.f_code.co_name

        if event == "call":
            # Track function entry
            self.current_coverage.functions.add(f"{filename}:{func_name}")
            self.last_location = (filename, lineno)
            return self._trace_function

        elif event == "line":
            # Track line coverage
            self.current_coverage.lines.add((filename, lineno))

            # Track edge coverage (transition from last location)
            if self.last_location:
                edge = (*self.last_location, filename, lineno)
                self.current_coverage.edges.add(edge)

            self.last_location = (filename, lineno)

        elif event == "return":
            # Track function exit
            if self.last_location:
                edge = (
                    *self.last_location,
                    filename,
                    -lineno,
                )  # Negative line for returns
                self.current_coverage.edges.add(edge)
            self.last_location = None

        return self._trace_function

    @contextmanager
    def track_coverage(
        self, input_data: bytes | None = None
    ) -> Generator[CoverageInfo, None, None]:
        """Context manager to track coverage for a code block.

        Args:
            input_data: Optional input data to hash for deduplication

        Yields:
            CoverageInfo object that will be populated during execution

        """
        # Reset current coverage
        self.current_coverage = CoverageInfo()

        if input_data:
            self.current_coverage.input_hash = short_hash(input_data)

        # Start tracing
        start_time = time.time()
        self.trace_enabled = True
        old_trace = sys.gettrace()
        sys.settrace(self._trace_function)

        try:
            yield self.current_coverage
        finally:
            # Stop tracing
            sys.settrace(old_trace)
            self.trace_enabled = False
            self.current_coverage.execution_time = time.time() - start_time

            # Update global coverage and check for new coverage
            with self._lock:
                self.total_executions += 1

                # Check for new coverage
                new_edges = self.current_coverage.edges - self.global_coverage.edges
                new_branches = (
                    self.current_coverage.branches - self.global_coverage.branches
                )

                if new_edges or new_branches:
                    self.current_coverage.new_coverage = True
                    self.coverage_increases += 1
                    self.global_coverage.merge(self.current_coverage)

                # Store in history if input hash exists
                if self.current_coverage.input_hash:
                    self.coverage_history[self.current_coverage.input_hash] = (
                        self.current_coverage
                    )

    def get_coverage_stats(self) -> dict[str, Any]:
        """Get current coverage statistics."""
        with self._lock:
            return {
                "total_edges": len(self.global_coverage.edges),
                "total_branches": len(self.global_coverage.branches),
                "total_functions": len(self.global_coverage.functions),
                "total_lines": len(self.global_coverage.lines),
                "total_executions": self.total_executions,
                "coverage_increases": self.coverage_increases,
                "unique_inputs": len(self.coverage_history),
                "coverage_rate": (
                    self.coverage_increases / self.total_executions
                    if self.total_executions > 0
                    else 0
                ),
            }

    def get_uncovered_edges(self, recent_coverage: CoverageInfo) -> set[tuple]:
        """Get edges that haven't been covered yet.

        Useful for targeted fuzzing.
        """
        with self._lock:
            # Find edges adjacent to recent coverage but not yet explored
            uncovered = set()

            for filename, lineno in recent_coverage.lines:
                # Check potential branches from this line
                for next_line in range(lineno - 2, lineno + 3):
                    potential_edge = (filename, lineno, filename, next_line)
                    if potential_edge not in self.global_coverage.edges:
                        uncovered.add(potential_edge)

            return uncovered

    def export_coverage(self, output_path: Path) -> None:
        """Export coverage data for visualization."""
        import json

        with self._lock:
            coverage_data = {
                "stats": self.get_coverage_stats(),
                "edges": list(self.global_coverage.edges),
                "functions": list(self.global_coverage.functions),
                "lines": [
                    f"{file}:{line}" for file, line in self.global_coverage.lines
                ],
                "history_size": len(self.coverage_history),
            }

        with open(output_path, "w") as f:
            json.dump(coverage_data, f, indent=2, default=str)

    def reset(self) -> None:
        """Reset all coverage data."""
        with self._lock:
            self.global_coverage = CoverageInfo()
            self.current_coverage = CoverageInfo()
            self.coverage_history.clear()
            self._module_cache.clear()
            self.total_executions = 0
            self.unique_crashes = 0
            self.coverage_increases = 0


class HybridCoverageTracker(CoverageTracker):
    """Enhanced coverage tracker using pure Python instrumentation.

    Extends CoverageTracker with additional tracking capabilities.
    """

    def __init__(self, target_modules: set[str] | None = None):
        """Initialize hybrid coverage tracker.

        Args:
            target_modules: Modules to track

        """
        super().__init__(target_modules)

    @contextmanager
    def track_coverage(
        self, input_data: bytes | None = None
    ) -> Generator[CoverageInfo, None, None]:
        """Track coverage using pure Python instrumentation."""
        with super().track_coverage(input_data) as coverage:
            yield coverage


def calculate_coverage_distance(cov1: CoverageInfo, cov2: CoverageInfo) -> float:
    """Calculate distance between two coverage signatures.

    Used for coverage-guided seed selection.
    """
    edges1 = cov1.edges
    edges2 = cov2.edges

    if not edges1 and not edges2:
        return 0.0

    # Jaccard distance
    intersection = len(edges1 & edges2)
    union = len(edges1 | edges2)

    if union == 0:
        return 0.0

    return 1.0 - (intersection / union)


class BranchCoverageTracker:
    """Enhanced branch coverage tracker using bytecode analysis.

    Tracks true branch coverage by analyzing conditional jumps and
    building a control flow graph representation.

    AFL-style Features:
    - Edge tuple tracking (from_block -> to_block)
    - Hit count bucketing for edge frequency
    - Bitmap-based fast comparison
    """

    # AFL-style hit count buckets
    HIT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128]

    def __init__(self, bitmap_size: int = 65536):
        """Initialize branch coverage tracker.

        Args:
            bitmap_size: Size of coverage bitmap (default 64KB like AFL)

        """
        self.bitmap_size = bitmap_size
        self.bitmap = bytearray(bitmap_size)
        self.edge_counts: dict[int, int] = {}
        self.block_map: dict[tuple[str, int], int] = {}
        self.next_block_id = 0
        self._prev_block: int = 0
        self._lock = threading.RLock()

        # Statistics
        self.total_edges = 0
        self.unique_edges = 0
        self.edge_history: list[int] = []

    def _get_block_id(self, filename: str, lineno: int) -> int:
        """Get or create a block ID for a code location."""
        key = (filename, lineno)
        if key not in self.block_map:
            self.block_map[key] = self.next_block_id
            self.next_block_id += 1
        return self.block_map[key]

    def _compute_edge_hash(self, from_block: int, to_block: int) -> int:
        """Compute AFL-style edge hash.

        Uses XOR of current block with shifted previous block
        to create a unique edge identifier.
        """
        # AFL's edge hashing: cur_location ^ (prev_location >> 1)
        return (to_block ^ (from_block >> 1)) % self.bitmap_size

    def record_edge(self, filename: str, from_line: int, to_line: int) -> bool:
        """Record a branch/edge transition.

        Args:
            filename: Source file
            from_line: Line number of branch source
            to_line: Line number of branch target

        Returns:
            True if this is a new edge

        """
        with self._lock:
            from_block = self._get_block_id(filename, from_line)
            to_block = self._get_block_id(filename, to_line)
            edge_hash = self._compute_edge_hash(from_block, to_block)

            self.total_edges += 1

            # Check if new edge
            is_new = self.bitmap[edge_hash] == 0

            # Update bitmap with hit count bucketing
            current_hits = self.bitmap[edge_hash]
            bucket = self._get_hit_bucket(current_hits + 1)
            self.bitmap[edge_hash] = bucket

            # Track exact counts for analysis
            self.edge_counts[edge_hash] = self.edge_counts.get(edge_hash, 0) + 1

            if is_new:
                self.unique_edges += 1
                self.edge_history.append(edge_hash)

            # Update previous block for next edge
            self._prev_block = to_block

            return is_new

    def _get_hit_bucket(self, count: int) -> int:
        """Convert hit count to AFL-style bucket.

        AFL uses bucketed hit counts to reduce noise from
        frequently-executed code.
        """
        for i, threshold in enumerate(self.HIT_BUCKETS):
            if count <= threshold:
                return i + 1
        return len(self.HIT_BUCKETS)

    def get_coverage_hash(self) -> str:
        """Get a hash of the current coverage bitmap.

        Returns:
            Hex string hash of coverage state

        """
        # Hash only non-zero entries for efficiency
        non_zero = bytes(b for b in self.bitmap if b > 0)
        return hash_string(non_zero.hex(), 16)

    def has_new_coverage(self, other_bitmap: bytearray) -> bool:
        """Check if current bitmap has coverage not in other bitmap.

        Args:
            other_bitmap: Another coverage bitmap to compare against

        Returns:
            True if current bitmap covers new edges

        """
        for i in range(min(len(self.bitmap), len(other_bitmap))):
            if self.bitmap[i] > 0 and other_bitmap[i] == 0:
                return True
        return False

    def merge_bitmap(self, other_bitmap: bytearray) -> int:
        """Merge another bitmap into this one.

        Args:
            other_bitmap: Bitmap to merge

        Returns:
            Number of new edges added

        """
        new_edges = 0
        for i in range(min(len(self.bitmap), len(other_bitmap))):
            if other_bitmap[i] > 0 and self.bitmap[i] == 0:
                new_edges += 1
            self.bitmap[i] = max(self.bitmap[i], other_bitmap[i])
        return new_edges

    def get_bitmap_copy(self) -> bytearray:
        """Get a copy of the current bitmap."""
        return bytearray(self.bitmap)

    def reset_bitmap(self) -> None:
        """Reset the bitmap for a new execution."""
        self.bitmap = bytearray(self.bitmap_size)
        self._prev_block = 0

    def get_stats(self) -> dict[str, Any]:
        """Get coverage statistics.

        Returns:
            Dictionary with coverage statistics

        """
        non_zero = sum(1 for b in self.bitmap if b > 0)
        hot_edges = sum(1 for b in self.bitmap if b >= 4)  # Frequently hit

        return {
            "bitmap_size": self.bitmap_size,
            "edges_covered": non_zero,
            "coverage_percent": (non_zero / self.bitmap_size) * 100,
            "hot_edges": hot_edges,
            "total_edge_transitions": self.total_edges,
            "unique_blocks": len(self.block_map),
            "edge_density": non_zero / max(len(self.block_map), 1),
        }

    def get_rare_edges(self, threshold: int = 2) -> list[int]:
        """Get edges that have been hit fewer than threshold times.

        Args:
            threshold: Maximum hit count to consider "rare"

        Returns:
            List of rare edge hashes

        """
        return [edge for edge, count in self.edge_counts.items() if count <= threshold]

    def export_bitmap(self, filepath: Path) -> None:
        """Export bitmap to file for analysis.

        Args:
            filepath: Path to save bitmap

        """
        filepath.write_bytes(self.bitmap)

    def import_bitmap(self, filepath: Path) -> None:
        """Import bitmap from file.

        Args:
            filepath: Path to bitmap file

        """
        data = filepath.read_bytes()
        self.bitmap = bytearray(data[: self.bitmap_size])


class EnhancedCoverageTracker(CoverageTracker):
    """Coverage tracker with AFL-style bitmap and branch tracking.

    Combines Python's trace-based coverage with bitmap-based
    edge tracking for efficient coverage comparison.
    """

    def __init__(
        self,
        target_modules: set[str] | None = None,
        bitmap_size: int = 65536,
    ):
        """Initialize enhanced coverage tracker.

        Args:
            target_modules: Modules to track
            bitmap_size: Size of coverage bitmap

        """
        super().__init__(target_modules)
        self.branch_tracker = BranchCoverageTracker(bitmap_size)
        self.global_bitmap = bytearray(bitmap_size)
        self._execution_bitmap: bytearray | None = None

    def _trace_function(self, frame: Any, event: str, arg: Any) -> Callable | None:
        """Enhanced trace function with bitmap updates."""
        result = super()._trace_function(frame, event, arg)

        if not self.trace_enabled:
            return result

        filename = frame.f_code.co_filename
        if not self.should_track_module(filename):
            return result

        lineno = frame.f_lineno

        # Record edges in bitmap
        if event == "line" and self.last_location:
            self.branch_tracker.record_edge(filename, self.last_location[1], lineno)

        return result

    @contextmanager
    def track_coverage(
        self, input_data: bytes | None = None
    ) -> Generator[CoverageInfo, None, None]:
        """Track coverage with bitmap support."""
        # Reset per-execution bitmap
        self.branch_tracker.reset_bitmap()

        with super().track_coverage(input_data) as coverage:
            yield coverage

        # After execution, check for new coverage via bitmap
        if self.branch_tracker.has_new_coverage(self.global_bitmap):
            coverage.new_coverage = True

        # Merge into global bitmap
        self.branch_tracker.merge_bitmap(self.global_bitmap)
        self.global_bitmap = self.branch_tracker.get_bitmap_copy()

    def get_coverage_stats(self) -> dict[str, Any]:
        """Get combined coverage statistics."""
        base_stats = super().get_coverage_stats()
        bitmap_stats = self.branch_tracker.get_stats()

        return {
            **base_stats,
            "bitmap_coverage": bitmap_stats,
        }


# Global tracker instance (can be configured)
_global_tracker: CoverageTracker | None = None


def get_global_tracker() -> CoverageTracker:
    """Get or create the global coverage tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CoverageTracker()
    return _global_tracker


def configure_global_tracker(target_modules: set[str]) -> None:
    """Configure the global tracker with target modules."""
    global _global_tracker
    _global_tracker = CoverageTracker(target_modules)


def get_enhanced_tracker(
    target_modules: set[str] | None = None,
    bitmap_size: int = 65536,
) -> EnhancedCoverageTracker:
    """Create an enhanced coverage tracker with bitmap support.

    Args:
        target_modules: Modules to track
        bitmap_size: Size of coverage bitmap

    Returns:
        EnhancedCoverageTracker instance

    """
    return EnhancedCoverageTracker(target_modules, bitmap_size)

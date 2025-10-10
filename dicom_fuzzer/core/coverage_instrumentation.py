"""
Coverage Instrumentation for DICOM Fuzzer

Provides lightweight coverage tracking using Python's tracing capabilities.
Tracks edge coverage (branch transitions) to guide fuzzing decisions.
"""

import sys
import hashlib
import time
from typing import Set, Dict, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
import threading
from contextlib import contextmanager


@dataclass
class CoverageInfo:
    """Stores coverage information for a single execution."""

    edges: Set[Tuple[str, int, str, int]] = field(default_factory=set)
    branches: Set[Tuple[str, int, bool]] = field(default_factory=set)
    functions: Set[str] = field(default_factory=set)
    lines: Set[Tuple[str, int]] = field(default_factory=set)
    execution_time: float = 0.0
    input_hash: Optional[str] = None
    new_coverage: bool = False

    def merge(self, other: 'CoverageInfo') -> None:
        """Merge another coverage info into this one."""
        self.edges.update(other.edges)
        self.branches.update(other.branches)
        self.functions.update(other.functions)
        self.lines.update(other.lines)

    def get_coverage_hash(self) -> str:
        """Generate a unique hash for this coverage signature."""
        coverage_data = sorted(self.edges) + sorted(self.branches)
        coverage_str = str(coverage_data)
        return hashlib.sha256(coverage_str.encode()).hexdigest()[:16]


class CoverageTracker:
    """
    Lightweight coverage tracker using sys.settrace.

    Optimized for fuzzing workloads with minimal overhead.
    """

    def __init__(self, target_modules: Optional[Set[str]] = None):
        """
        Initialize the coverage tracker.

        Args:
            target_modules: Set of module names to track (None = track all)
        """
        self.target_modules = target_modules or set()
        self.global_coverage = CoverageInfo()
        self.current_coverage = CoverageInfo()
        self.coverage_history: Dict[str, CoverageInfo] = {}
        self.last_location: Optional[Tuple[str, int]] = None
        self.trace_enabled = False
        self._lock = threading.Lock()

        # Performance optimization: cache module checks
        self._module_cache: Dict[str, bool] = {}

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

    def _trace_function(self, frame: Any, event: str, arg: Any) -> Optional[Callable]:
        """
        Trace function for sys.settrace.

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

        if event == 'call':
            # Track function entry
            self.current_coverage.functions.add(f"{filename}:{func_name}")
            self.last_location = (filename, lineno)
            return self._trace_function

        elif event == 'line':
            # Track line coverage
            self.current_coverage.lines.add((filename, lineno))

            # Track edge coverage (transition from last location)
            if self.last_location:
                edge = (*self.last_location, filename, lineno)
                self.current_coverage.edges.add(edge)

            self.last_location = (filename, lineno)

        elif event == 'return':
            # Track function exit
            if self.last_location:
                edge = (*self.last_location, filename, -lineno)  # Negative line for returns
                self.current_coverage.edges.add(edge)
            self.last_location = None

        return self._trace_function

    @contextmanager
    def track_coverage(self, input_data: Optional[bytes] = None):
        """
        Context manager to track coverage for a code block.

        Args:
            input_data: Optional input data to hash for deduplication

        Yields:
            CoverageInfo object that will be populated during execution
        """
        # Reset current coverage
        self.current_coverage = CoverageInfo()

        if input_data:
            self.current_coverage.input_hash = hashlib.sha256(input_data).hexdigest()[:16]

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
                new_branches = self.current_coverage.branches - self.global_coverage.branches

                if new_edges or new_branches:
                    self.current_coverage.new_coverage = True
                    self.coverage_increases += 1
                    self.global_coverage.merge(self.current_coverage)

                # Store in history if input hash exists
                if self.current_coverage.input_hash:
                    self.coverage_history[self.current_coverage.input_hash] = self.current_coverage

    def get_coverage_stats(self) -> Dict[str, Any]:
        """Get current coverage statistics."""
        with self._lock:
            return {
                'total_edges': len(self.global_coverage.edges),
                'total_branches': len(self.global_coverage.branches),
                'total_functions': len(self.global_coverage.functions),
                'total_lines': len(self.global_coverage.lines),
                'total_executions': self.total_executions,
                'coverage_increases': self.coverage_increases,
                'unique_inputs': len(self.coverage_history),
                'coverage_rate': (
                    self.coverage_increases / self.total_executions
                    if self.total_executions > 0 else 0
                )
            }

    def get_uncovered_edges(self, recent_coverage: CoverageInfo) -> Set[Tuple]:
        """
        Get edges that haven't been covered yet.

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
                'stats': self.get_coverage_stats(),
                'edges': list(self.global_coverage.edges),
                'functions': list(self.global_coverage.functions),
                'lines': [f"{file}:{line}" for file, line in self.global_coverage.lines],
                'history_size': len(self.coverage_history)
            }

        with open(output_path, 'w') as f:
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
    """
    Enhanced coverage tracker with optional Atheris integration.

    Falls back to pure Python tracking if Atheris is not available.
    """

    def __init__(self, target_modules: Optional[Set[str]] = None, use_atheris: bool = False):
        """
        Initialize hybrid coverage tracker.

        Args:
            target_modules: Modules to track
            use_atheris: Try to use Atheris for coverage if available
        """
        super().__init__(target_modules)
        self.atheris_available = False
        self.use_atheris = use_atheris

        if use_atheris:
            try:
                import atheris
                self.atheris_available = True
                self.atheris = atheris
            except ImportError:
                print("Atheris not available, falling back to pure Python coverage")

    @contextmanager
    def track_coverage(self, input_data: Optional[bytes] = None):
        """
        Track coverage with Atheris integration if available.
        """
        if self.atheris_available and self.use_atheris:
            # Use Atheris coverage tracking
            # This would integrate with Atheris's coverage-guided fuzzing
            # For now, we'll use the parent implementation
            pass

        # Fall back to pure Python tracking
        with super().track_coverage(input_data) as coverage:
            yield coverage


def calculate_coverage_distance(cov1: CoverageInfo, cov2: CoverageInfo) -> float:
    """
    Calculate distance between two coverage signatures.

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


# Global tracker instance (can be configured)
_global_tracker: Optional[CoverageTracker] = None


def get_global_tracker() -> CoverageTracker:
    """Get or create the global coverage tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CoverageTracker()
    return _global_tracker


def configure_global_tracker(target_modules: Set[str]) -> None:
    """Configure the global tracker with target modules."""
    global _global_tracker
    _global_tracker = CoverageTracker(target_modules)
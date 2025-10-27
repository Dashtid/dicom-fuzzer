"""Coverage-Guided Fuzzing - Coverage Tracking System

LEARNING OBJECTIVE: This module demonstrates how coverage-guided fuzzing works by
tracking which code paths are executed during testing.

CONCEPT: Coverage-guided fuzzing is like exploring a maze - we want to find new
paths we haven't explored yet. Every time we find a new path, we remember the
input that got us there and try variations of it.

WHY: Traditional fuzzing is random - like throwing darts blindfolded. Coverage-guided
fuzzing is intelligent - it learns which inputs are interesting and focuses on them.
This dramatically increases the effectiveness of fuzzing.
"""

import hashlib
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CoverageSnapshot:
    """Represents the coverage state at a point in time.

    CONCEPT: A snapshot is like a photograph of which code lines were executed.
    We use this to compare different test cases and find which ones explore new code.

    Attributes:
        lines_covered: Set of (filename, line_number) tuples that were executed
        branches_covered: Set of (filename, line_number, branch_id) tuples
        timestamp: When this snapshot was taken
        test_case_id: Identifier for the test case that produced this coverage

    """

    lines_covered: set[tuple[str, int]] = field(default_factory=set)
    branches_covered: set[tuple[str, int, int]] = field(default_factory=set)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    test_case_id: str = ""
    total_lines: int = 0
    total_branches: int = 0

    def __post_init__(self):
        """Calculate totals after initialization."""
        self.total_lines = len(self.lines_covered)
        self.total_branches = len(self.branches_covered)

    def coverage_hash(self) -> str:
        """Generate a unique hash for this coverage pattern.

        CONCEPT: We use a hash to quickly check if two test cases have the
        same coverage. If they do, one is redundant.

        Returns:
            SHA-256 hash of the coverage pattern

        """
        # Sort for consistency
        lines_str = ",".join(
            f"{filename}:{line}" for filename, line in sorted(self.lines_covered)
        )
        branches_str = ",".join(
            f"{filename}:{line}:{branch}"
            for filename, line, branch in sorted(self.branches_covered)
        )
        combined = f"{lines_str}|{branches_str}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def new_coverage_vs(self, other: "CoverageSnapshot") -> set[tuple[str, int]]:
        """Find lines covered by this snapshot but not the other.

        CONCEPT: This tells us what new code paths a test case discovered.
        If a test case covers new lines, it's "interesting" and worth keeping.

        Args:
            other: Another coverage snapshot to compare against

        Returns:
            Set of newly covered (filename, line_number) tuples

        """
        return self.lines_covered - other.lines_covered

    def coverage_percentage(self, total_possible_lines: int) -> float:
        """Calculate coverage as a percentage."""
        if total_possible_lines == 0:
            return 0.0
        return (self.total_lines / total_possible_lines) * 100.0


class CoverageTracker:
    """Tracks code coverage during fuzzing to guide mutation selection.

    LEARNING: This is the core of coverage-guided fuzzing. It's like a GPS
    that tells us which routes (code paths) we've explored and which are new.

    CONCEPT: We hook into Python's tracing system to monitor which lines of
    code are executed. When we find new coverage, we know that test case is
    valuable for finding bugs.

    WHY: Without coverage guidance, we waste time testing the same code paths
    repeatedly. With it, we systematically explore all possible paths.
    """

    def __init__(
        self,
        target_modules: list[str] | None = None,
        ignore_patterns: list[str] | None = None,
    ):
        """Initialize the coverage tracker.

        Args:
            target_modules: List of module prefixes to track (e.g., ['core', 'strategies'])
            ignore_patterns: List of patterns to ignore (e.g., ['test_', '__pycache__'])

        """
        self.target_modules = target_modules or ["core", "strategies", "utils"]
        self.ignore_patterns = ignore_patterns or [
            "test_",
            "__pycache__",
            ".venv",
            "site-packages",
        ]

        # Coverage data
        self.global_coverage: set[tuple[str, int]] = set()
        self.current_coverage: set[tuple[str, int]] = set()
        self.coverage_history: list[CoverageSnapshot] = []

        # Statistics
        self.total_executions = 0
        self.interesting_cases = 0
        self.redundant_cases = 0

        # Coverage hashes for deduplication
        self.seen_coverage_hashes: set[str] = set()

        logger.info(
            "Coverage tracker initialized",
            target_modules=self.target_modules,
            ignore_patterns=self.ignore_patterns,
        )

    def _should_trace_file(self, filename: str) -> bool:
        """Determine if a file should be traced.

        CONCEPT: We only want to track coverage in our code, not in Python's
        standard library or third-party packages.

        Args:
            filename: Path to the file being executed

        Returns:
            True if this file should be traced

        """
        # Ignore patterns
        for pattern in self.ignore_patterns:
            if pattern in filename:
                return False

        # Check if it's in our target modules
        path = Path(filename)
        try:
            relative_path = str(path.relative_to(Path.cwd()))
            # Normalize path separators to forward slashes for consistent matching
            normalized_path = relative_path.replace("\\", "/")
            for module in self.target_modules:
                # Check if module is in the path (e.g., "core" matches "dicom_fuzzer/core/parser.py")
                if (
                    f"/{module}/" in f"/{normalized_path}/"
                    or normalized_path.startswith(f"{module}/")
                ):
                    return True
        except ValueError:
            # File is not relative to cwd
            pass

        return False

    def _trace_function(self, frame, event, arg):
        """Tracing function called by sys.settrace.

        LEARNING: Python's sys.settrace calls this function for every line of code executed.
        It's very powerful but also has performance overhead.

        CONCEPT: We record (filename, line_number) for every line executed.
        This builds up our coverage map.

        Args:
            frame: Current stack frame
            event: Type of event ('line', 'call', 'return', etc.)
            arg: Event argument

        Returns:
            self._trace_function to continue tracing

        """
        if event == "line":
            filename = frame.f_code.co_filename
            if self._should_trace_file(filename):
                line_number = frame.f_lineno
                self.current_coverage.add((filename, line_number))

        return self._trace_function

    @contextmanager
    def trace_execution(self, test_case_id: str):
        """Context manager to track coverage during code execution.

        LEARNING: Context managers (with/as) ensure cleanup happens even if errors occur.

        USAGE:
            with tracker.trace_execution("test_1"):
                # Your code here
                result = parse_dicom(file)

        Args:
            test_case_id: Identifier for this test case

        Yields:
            CoverageSnapshot after execution completes

        """
        # Clear current coverage
        self.current_coverage = set()

        # Start tracing
        sys.settrace(self._trace_function)
        logger.debug(f"Started coverage tracing for test case: {test_case_id}")

        try:
            yield
        finally:
            # Stop tracing
            sys.settrace(None)

            # Create snapshot
            snapshot = CoverageSnapshot(
                lines_covered=self.current_coverage.copy(),
                test_case_id=test_case_id,
            )

            # Check if this is interesting (new coverage)
            new_lines = snapshot.new_coverage_vs(
                CoverageSnapshot(lines_covered=self.global_coverage)
            )

            if new_lines:
                # This test case found new coverage!
                self.global_coverage.update(snapshot.lines_covered)
                self.coverage_history.append(snapshot)
                self.interesting_cases += 1

                logger.info(
                    "New coverage discovered",
                    test_case_id=test_case_id,
                    new_lines=len(new_lines),
                    total_coverage=len(self.global_coverage),
                )
            else:
                self.redundant_cases += 1
                logger.debug(
                    f"No new coverage from test case: {test_case_id}",
                    redundant_count=self.redundant_cases,
                )

            self.total_executions += 1

    def is_interesting(self, snapshot: CoverageSnapshot) -> bool:
        """Determine if a coverage snapshot is interesting (provides new coverage).

        CONCEPT: A test case is "interesting" if it explores code we haven't
        seen before. These are the cases worth keeping and mutating further.

        Args:
            snapshot: Coverage snapshot to evaluate

        Returns:
            True if this snapshot provides new coverage

        """
        # Check coverage hash for quick deduplication
        coverage_hash = snapshot.coverage_hash()
        if coverage_hash in self.seen_coverage_hashes:
            return False

        # Check for new lines
        new_lines = snapshot.new_coverage_vs(
            CoverageSnapshot(lines_covered=self.global_coverage)
        )

        if new_lines:
            self.seen_coverage_hashes.add(coverage_hash)
            return True

        return False

    def get_statistics(self) -> dict[str, Any]:
        """Get coverage tracking statistics.

        Returns:
            Dictionary with coverage statistics

        """
        return {
            "total_executions": self.total_executions,
            "interesting_cases": self.interesting_cases,
            "redundant_cases": self.redundant_cases,
            "total_lines_covered": len(self.global_coverage),
            "unique_coverage_patterns": len(self.seen_coverage_hashes),
            "efficiency": (
                self.interesting_cases / self.total_executions
                if self.total_executions > 0
                else 0.0
            ),
        }

    def get_coverage_report(self) -> str:
        """Generate a human-readable coverage report.

        Returns:
            Formatted coverage report string

        """
        stats = self.get_statistics()

        report = f"""
Coverage-Guided Fuzzing Report
{"=" * 50}

Total Executions:      {stats["total_executions"]}
Interesting Cases:     {stats["interesting_cases"]}
Redundant Cases:       {stats["redundant_cases"]}
Total Lines Covered:   {stats["total_lines_covered"]}
Unique Patterns:       {stats["unique_coverage_patterns"]}
Efficiency:            {stats["efficiency"]:.1%}

Coverage History: {len(self.coverage_history)} snapshots
        """

        return report.strip()

    def reset(self):
        """Reset all coverage data."""
        self.global_coverage.clear()
        self.current_coverage.clear()
        self.coverage_history.clear()
        self.seen_coverage_hashes.clear()
        self.total_executions = 0
        self.interesting_cases = 0
        self.redundant_cases = 0
        logger.info("Coverage tracker reset")

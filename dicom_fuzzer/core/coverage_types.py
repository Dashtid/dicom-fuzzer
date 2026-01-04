"""Unified Coverage Types for DICOM Fuzzer.

This module provides a single source of truth for all coverage-related types,
consolidating definitions from multiple modules to eliminate duplication.

Type Hierarchy:
- ExecutionCoverageInfo: Runtime execution coverage (edges, branches, lines)
- SeedCoverageInfo: Corpus seed coverage metadata
- CoverageSnapshot: Point-in-time coverage state
- CoverageMap: AFL-style shared memory bitmap
- GUIStateTransition: State transition for GUI monitoring
- ProtocolStateTransition: State transition for DICOM protocol
- StateCoverage: Protocol state coverage tracking

"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.core.constants import MAP_SIZE
from dicom_fuzzer.utils.hashing import hash_string

if TYPE_CHECKING:
    pass


# =============================================================================
# Execution Coverage Types
# =============================================================================


@dataclass
class ExecutionCoverageInfo:
    """Coverage information collected during a single execution.

    Used for tracking what code was executed during fuzzing.
    Consolidates the CoverageInfo from coverage_instrumentation.py.

    Attributes:
        edges: Set of (from_file, from_line, to_file, to_line) edge transitions
        branches: Set of (file, line, direction) branch coverage
        functions: Set of function names that were called
        lines: Set of (file, line) that were executed
        execution_time: Time in seconds for execution
        input_hash: Hash of the input that produced this coverage
        new_coverage: Whether this execution found new coverage

    """

    edges: set[tuple[str, int, str, int]] = field(default_factory=set)
    branches: set[tuple[str, int, bool]] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    lines: set[tuple[str, int]] = field(default_factory=set)
    execution_time: float = 0.0
    input_hash: str | None = None
    new_coverage: bool = False

    def merge(self, other: ExecutionCoverageInfo) -> None:
        """Merge another coverage info into this one."""
        self.edges.update(other.edges)
        self.branches.update(other.branches)
        self.functions.update(other.functions)
        self.lines.update(other.lines)

    def get_coverage_hash(self) -> str:
        """Generate a unique hash for this coverage signature."""
        coverage_data = sorted(self.edges) + sorted(self.branches)
        coverage_str = str(coverage_data)
        return hash_string(coverage_str, 16)


# Backward compatibility alias
CoverageInfo = ExecutionCoverageInfo


@dataclass
class SeedCoverageInfo:
    """Coverage metadata for a corpus seed.

    Used for corpus minimization and seed management.
    Consolidates the CoverageInfo from corpus_minimizer.py.

    Attributes:
        seed_path: Path to the seed file
        coverage_hash: Hash of coverage bitmap (16 chars)
        edges_hit: Number of unique edges covered
        branches_hit: Number of unique branches covered
        bitmap: Raw coverage bitmap bytes
        exec_time_us: Execution time in microseconds
        file_size: Size of seed file in bytes

    """

    seed_path: Path
    coverage_hash: str = ""
    edges_hit: int = 0
    branches_hit: int = 0
    bitmap: bytes = b""
    exec_time_us: float = 0.0
    file_size: int = 0

    def __post_init__(self) -> None:
        if not self.coverage_hash and self.bitmap:
            self.coverage_hash = hashlib.sha256(self.bitmap).hexdigest()[:16]
        if self.seed_path and self.seed_path.exists():
            self.file_size = self.seed_path.stat().st_size


@dataclass
class CoverageSnapshot:
    """Point-in-time coverage state for comparison.

    Represents a snapshot of coverage that can be compared with others
    to find new coverage. Consolidates from coverage_tracker.py.

    Attributes:
        lines_covered: Set of (filename, line_number) tuples executed
        branches_covered: Set of (filename, line_number, branch_id) tuples
        timestamp: When this snapshot was taken
        test_case_id: Identifier for the test case
        total_lines: Count of lines covered
        total_branches: Count of branches covered

    """

    lines_covered: set[tuple[str, int]] = field(default_factory=set)
    branches_covered: set[tuple[str, int, int]] = field(default_factory=set)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    test_case_id: str = ""
    total_lines: int = 0
    total_branches: int = 0

    def __post_init__(self) -> None:
        """Calculate totals after initialization."""
        self.total_lines = len(self.lines_covered)
        self.total_branches = len(self.branches_covered)

    def coverage_hash(self) -> str:
        """Generate a unique hash for this coverage pattern."""
        lines_str = ",".join(
            f"{filename}:{line}" for filename, line in sorted(self.lines_covered)
        )
        branches_str = ",".join(
            f"{filename}:{line}:{branch}"
            for filename, line, branch in sorted(self.branches_covered)
        )
        combined = f"{lines_str}|{branches_str}"
        return hash_string(combined)

    def new_coverage_vs(self, other: CoverageSnapshot) -> set[tuple[str, int]]:
        """Find lines covered by this snapshot but not the other."""
        return self.lines_covered - other.lines_covered

    def coverage_percentage(self, total_possible_lines: int) -> float:
        """Calculate coverage as a percentage."""
        if total_possible_lines == 0:
            return 0.0
        return (self.total_lines / total_possible_lines) * 100.0


@dataclass
class CoverageMap:
    """AFL-style shared memory coverage bitmap.

    Used for persistent mode fuzzing with fast coverage tracking.
    Consolidates from persistent_fuzzer.py.

    Attributes:
        size: Size of the bitmap (default: MAP_SIZE = 65536)
        virgin_bits: Bitmap tracking covered edges
        total_bits: Total number of bits set
        new_bits: Newly discovered bits

    """

    size: int = MAP_SIZE
    virgin_bits: bytearray = field(default_factory=lambda: bytearray(MAP_SIZE))
    total_bits: int = 0
    new_bits: int = 0

    def update(self, trace_bits: bytes) -> bool:
        """Update coverage map with new trace.

        Returns:
            True if new coverage was found.

        """
        has_new = False

        for i, (virgin, trace) in enumerate(
            zip(self.virgin_bits, trace_bits, strict=False)
        ):
            if trace and not virgin:
                self.virgin_bits[i] = trace
                self.new_bits += 1
                has_new = True
            elif trace and virgin:
                if trace > virgin:
                    self.virgin_bits[i] = trace
                    has_new = True

        self.total_bits = sum(1 for b in self.virgin_bits if b > 0)
        return has_new

    def get_coverage_percent(self) -> float:
        """Get coverage as percentage of map."""
        return (self.total_bits / self.size) * 100

    def compute_hash(self) -> str:
        """Compute hash of coverage state."""
        return hashlib.sha256(bytes(self.virgin_bits)).hexdigest()[:16]


# =============================================================================
# State Transition Types
# =============================================================================


@dataclass
class GUIStateTransition:
    """State transition for GUI application monitoring.

    AFLNet-style state tracking for GUI applications.
    Uses string states for flexibility with any application.
    Consolidates StateTransition from state_coverage.py.

    Attributes:
        from_state: Origin state name
        to_state: Destination state name
        trigger: What caused the transition (e.g., "file_load")
        timestamp: When the transition occurred
        test_file: File that triggered this transition

    """

    from_state: str
    to_state: str
    trigger: str = ""
    timestamp: float = 0.0
    test_file: Path | None = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()

    def __hash__(self) -> int:
        return hash((self.from_state, self.to_state, self.trigger))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GUIStateTransition):
            return False
        return (
            self.from_state == other.from_state
            and self.to_state == other.to_state
            and self.trigger == other.trigger
        )


# Backward compatibility alias
StateTransition = GUIStateTransition


@dataclass
class ProtocolStateTransition:
    """State transition for DICOM protocol fuzzing.

    Uses DICOMState enum for type-safe protocol state tracking.
    Consolidates StateTransition from state_aware_fuzzer.py.

    Attributes:
        from_state: Origin DICOM protocol state
        to_state: Destination DICOM protocol state
        trigger_message: Message bytes that triggered transition
        transition_type: Type of transition (valid, invalid, etc.)
        response: Response bytes from target
        duration_ms: Transition duration in milliseconds
        timestamp: When the transition occurred
        coverage_increase: New edges discovered

    """

    from_state: Any  # DICOMState - using Any to avoid circular import at runtime
    to_state: Any  # DICOMState
    trigger_message: bytes = b""
    transition_type: Any = None  # StateTransitionType
    response: bytes = b""
    duration_ms: float = 0.0
    timestamp: float = 0.0
    coverage_increase: int = 0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class StateFingerprint:
    """Fingerprint of a protocol state using LSH.

    Based on StateAFL's approach of using locality-sensitive hashing
    to identify unique application states from memory snapshots.

    Attributes:
        hash_value: Unique hash for this fingerprint
        state: DICOM protocol state
        timestamp: When fingerprint was taken
        coverage_bitmap: Edge coverage bitmap at this state
        response_pattern: Pattern of responses observed
        memory_regions: Memory region snapshots
        message_sequence_hash: Hash of message sequence

    """

    hash_value: str
    state: Any  # DICOMState
    timestamp: float = 0.0
    coverage_bitmap: bytes = b""
    response_pattern: str = ""
    memory_regions: list[tuple[int, int, bytes]] = field(default_factory=list)
    message_sequence_hash: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()

    def similarity(self, other: StateFingerprint) -> float:
        """Calculate Jaccard similarity with another fingerprint."""
        if not self.coverage_bitmap or not other.coverage_bitmap:
            return 0.0

        self_edges = {i for i, b in enumerate(self.coverage_bitmap) if b > 0}
        other_edges = {i for i, b in enumerate(other.coverage_bitmap) if b > 0}

        if not self_edges and not other_edges:
            return 1.0
        if not self_edges or not other_edges:
            return 0.0

        intersection = len(self_edges & other_edges)
        union = len(self_edges | other_edges)
        return intersection / union if union > 0 else 0.0


@dataclass
class StateCoverage:
    """Tracks coverage of protocol states.

    Consolidates from state_aware_fuzzer.py.

    Attributes:
        visited_states: Set of visited DICOM states
        state_transitions: Dict mapping (from, to) to count
        unique_fingerprints: Dict of unique state fingerprints
        state_depths: Minimum depth to reach each state
        total_transitions: Total transition count
        new_states_found: Count of newly discovered states
        new_transitions_found: Count of newly discovered transitions

    """

    visited_states: set[Any] = field(default_factory=set)  # set[DICOMState]
    state_transitions: dict[tuple[Any, Any], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    unique_fingerprints: dict[str, StateFingerprint] = field(default_factory=dict)
    state_depths: dict[Any, int] = field(default_factory=dict)  # dict[DICOMState, int]
    total_transitions: int = 0
    new_states_found: int = 0
    new_transitions_found: int = 0

    def add_state(self, state: Any, depth: int = 0) -> bool:
        """Add a visited state. Returns True if new."""
        is_new = state not in self.visited_states
        self.visited_states.add(state)
        if state not in self.state_depths or self.state_depths[state] > depth:
            self.state_depths[state] = depth
        if is_new:
            self.new_states_found += 1
        return is_new

    def add_transition(self, from_state: Any, to_state: Any) -> bool:
        """Add a state transition. Returns True if new."""
        key = (from_state, to_state)
        is_new = self.state_transitions[key] == 0
        self.state_transitions[key] += 1
        self.total_transitions += 1
        if is_new:
            self.new_transitions_found += 1
        return is_new

    def add_fingerprint(self, fingerprint: StateFingerprint) -> bool:
        """Add a state fingerprint. Returns True if new/interesting."""
        for existing in self.unique_fingerprints.values():
            if fingerprint.similarity(existing) > 0.95:
                return False

        self.unique_fingerprints[fingerprint.hash_value] = fingerprint
        return True

    def get_coverage_score(self, total_states: int = 17) -> float:
        """Calculate state coverage score.

        Args:
            total_states: Total number of possible states (default: len(DICOMState))

        """
        visited_ratio = len(self.visited_states) / total_states
        max_transitions = total_states * total_states
        transition_ratio = len(self.state_transitions) / max_transitions
        return (visited_ratio * 0.6 + transition_ratio * 0.4) * 100

    def get_uncovered_states(self, all_states: set[Any]) -> set[Any]:
        """Get states not yet visited."""
        return all_states - self.visited_states


# =============================================================================
# Analysis Types
# =============================================================================


@dataclass
class CoverageInsight:
    """Coverage insights for crash correlation analysis.

    Used to identify code paths that correlate with crashes.
    Consolidates from utils/coverage_correlation.py.

    Attributes:
        identifier: Function/file:line/block identifier
        total_hits: Total times this path was hit
        crash_hits: Times this path led to crash
        safe_hits: Times this path was hit safely
        crash_rate: Ratio of crash_hits to total_hits
        unique_crashes: Set of unique crash identifiers

    """

    identifier: str
    total_hits: int = 0
    crash_hits: int = 0
    safe_hits: int = 0
    crash_rate: float = 0.0
    unique_crashes: set[str] = field(default_factory=set)

    def update_crash_rate(self) -> None:
        """Recalculate crash rate."""
        if self.total_hits > 0:
            self.crash_rate = self.crash_hits / self.total_hits


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Execution coverage
    "ExecutionCoverageInfo",
    "CoverageInfo",  # Alias
    "SeedCoverageInfo",
    "CoverageSnapshot",
    "CoverageMap",
    # State transitions
    "GUIStateTransition",
    "StateTransition",  # Alias
    "ProtocolStateTransition",
    "StateFingerprint",
    "StateCoverage",
    # Analysis
    "CoverageInsight",
]

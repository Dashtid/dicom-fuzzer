"""State and Coverage Types for DICOM Fuzzer.

This module provides types for:
- Corpus seed coverage metadata (SeedCoverageInfo)
- GUI state transitions (GUIStateTransition)
- DICOM protocol state tracking (ProtocolStateTransition, StateCoverage)

"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from dicom_fuzzer.core.constants import DICOMState, StateTransitionType

# =============================================================================
# Corpus Coverage Types
# =============================================================================


@dataclass
class SeedCoverageInfo:
    """Coverage metadata for a corpus seed.

    Used for corpus minimization and seed management.

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


# =============================================================================
# State Transition Types
# =============================================================================


@dataclass
class GUIStateTransition:
    """State transition for GUI application monitoring.

    AFLNet-style state tracking for GUI applications.
    Uses string states for flexibility with any application.

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

    from_state: DICOMState
    to_state: DICOMState
    trigger_message: bytes = b""
    transition_type: StateTransitionType | None = None
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
    state: DICOMState
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

    Attributes:
        visited_states: Set of visited DICOM states
        state_transitions: Dict mapping (from, to) to count
        unique_fingerprints: Dict of unique state fingerprints
        state_depths: Minimum depth to reach each state
        total_transitions: Total transition count
        new_states_found: Count of newly discovered states
        new_transitions_found: Count of newly discovered transitions

    """

    visited_states: set[DICOMState] = field(default_factory=set)
    state_transitions: dict[tuple[DICOMState, DICOMState], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    unique_fingerprints: dict[str, StateFingerprint] = field(default_factory=dict)
    state_depths: dict[DICOMState, int] = field(default_factory=dict)
    total_transitions: int = 0
    new_states_found: int = 0
    new_transitions_found: int = 0

    def add_state(self, state: DICOMState, depth: int = 0) -> bool:
        """Add a visited state. Returns True if new."""
        is_new = state not in self.visited_states
        self.visited_states.add(state)
        if state not in self.state_depths or self.state_depths[state] > depth:
            self.state_depths[state] = depth
        if is_new:
            self.new_states_found += 1
        return is_new

    def add_transition(self, from_state: DICOMState, to_state: DICOMState) -> bool:
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

    def get_uncovered_states(self, all_states: set[DICOMState]) -> set[DICOMState]:
        """Get states not yet visited."""
        return all_states - self.visited_states


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Corpus coverage
    "SeedCoverageInfo",
    # State transitions
    "GUIStateTransition",
    "StateTransition",  # Alias
    "ProtocolStateTransition",
    "StateFingerprint",
    "StateCoverage",
]

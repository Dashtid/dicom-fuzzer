"""Tests for state and coverage types."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from dicom_fuzzer.core.constants import CoverageType
from dicom_fuzzer.core.corpus.coverage_types import (
    CoverageSnapshot,
    GUIStateTransition,
    ProtocolStateTransition,
    SeedCoverageInfo,
    StateCoverage,
    StateFingerprint,
    StateTransition,
)


class TestCoverageType:
    """Tests for CoverageType enum."""

    def test_inherits_from_str(self) -> None:
        """Test CoverageType inherits from str for serialization."""
        assert isinstance(CoverageType.EDGE, str)
        assert CoverageType.EDGE.value == "edge"
        assert CoverageType.EDGE == "edge"

    def test_all_values_exist(self) -> None:
        """Test all coverage type values are defined."""
        assert CoverageType.EDGE.value == "edge"
        assert CoverageType.BRANCH.value == "branch"
        assert CoverageType.PATH.value == "path"
        assert CoverageType.FUNCTION.value == "function"
        assert CoverageType.LINE.value == "line"
        assert CoverageType.STATE.value == "state"

    def test_enum_iteration(self) -> None:
        """Test all coverage types can be iterated."""
        all_types = list(CoverageType)
        assert len(all_types) == 6
        assert CoverageType.EDGE in all_types
        assert CoverageType.STATE in all_types


class TestSeedCoverageInfo:
    """Tests for SeedCoverageInfo dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        info = SeedCoverageInfo(seed_path=Path("test.dcm"))
        assert info.seed_path == Path("test.dcm")
        assert info.coverage_hash == ""
        assert info.edges_hit == 0
        assert info.branches_hit == 0
        assert info.bitmap == b""
        assert info.exec_time_us == 0.0
        assert info.file_size == 0

    def test_auto_hash_from_bitmap(self) -> None:
        """Test coverage_hash is auto-computed from bitmap."""
        bitmap = b"\x01\x02\x03\x04"
        info = SeedCoverageInfo(seed_path=Path("test.dcm"), bitmap=bitmap)

        assert len(info.coverage_hash) == 16
        assert info.bitmap == bitmap

    def test_initialization_with_all_fields(self) -> None:
        """Test initialization with all fields."""
        info = SeedCoverageInfo(
            seed_path=Path("test.dcm"),
            coverage_hash="abc123def456ghi7",
            edges_hit=100,
            branches_hit=50,
            bitmap=b"\x00" * 100,
            exec_time_us=1500.5,
            file_size=2048,
        )

        assert info.edges_hit == 100
        assert info.branches_hit == 50
        assert info.exec_time_us == 1500.5
        assert info.file_size == 2048
        # Pre-set hash should be preserved
        assert info.coverage_hash == "abc123def456ghi7"

    def test_no_hash_no_bitmap(self) -> None:
        """Test SeedCoverageInfo with no hash and no bitmap (branch: hash stays empty)."""
        info = SeedCoverageInfo(seed_path=Path("nonexistent.dcm"))
        assert info.coverage_hash == ""  # No bitmap means no auto-hash

    def test_with_hash_and_bitmap(self) -> None:
        """Test SeedCoverageInfo with pre-set hash and bitmap (hash preserved)."""
        info = SeedCoverageInfo(
            seed_path=Path("test.dcm"),
            coverage_hash="preexisting",
            bitmap=b"\x01\x02\x03",
        )
        # Pre-set hash should be preserved, not overwritten
        assert info.coverage_hash == "preexisting"

    def test_existing_file_size(self, tmp_path: Path) -> None:
        """Test SeedCoverageInfo auto-calculates file size for existing file."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"x" * 100)

        info = SeedCoverageInfo(seed_path=test_file)
        assert info.file_size == 100

    def test_nonexistent_file_size(self) -> None:
        """Test SeedCoverageInfo with nonexistent file (no size calculation)."""
        info = SeedCoverageInfo(seed_path=Path("/nonexistent/path.dcm"))
        assert info.file_size == 0


class TestCoverageSnapshot:
    """Tests for CoverageSnapshot dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        snapshot = CoverageSnapshot()
        assert snapshot.lines_covered == set()
        assert snapshot.branches_covered == set()
        assert snapshot.test_case_id == ""
        assert snapshot.total_lines == 0
        assert snapshot.total_branches == 0
        assert isinstance(snapshot.timestamp, datetime)

    def test_post_init_calculates_totals(self) -> None:
        """Test __post_init__ calculates totals."""
        lines = {("a.py", 1), ("a.py", 2), ("b.py", 3)}
        branches = {("a.py", 1, 0), ("a.py", 1, 1)}

        snapshot = CoverageSnapshot(lines_covered=lines, branches_covered=branches)

        assert snapshot.total_lines == 3
        assert snapshot.total_branches == 2

    def test_coverage_hash(self) -> None:
        """Test coverage hash generation."""
        snapshot = CoverageSnapshot(
            lines_covered={("file.py", 10), ("file.py", 20)},
            branches_covered={("file.py", 15, 0)},
        )

        hash_val = snapshot.coverage_hash()
        assert isinstance(hash_val, str)
        assert len(hash_val) > 0

        # Same coverage should give same hash
        snapshot2 = CoverageSnapshot(
            lines_covered={("file.py", 10), ("file.py", 20)},
            branches_covered={("file.py", 15, 0)},
        )
        assert snapshot.coverage_hash() == snapshot2.coverage_hash()

    def test_new_coverage_vs(self) -> None:
        """Test finding new coverage between snapshots."""
        snapshot1 = CoverageSnapshot(
            lines_covered={("a.py", 1), ("a.py", 2), ("b.py", 3)}
        )
        snapshot2 = CoverageSnapshot(lines_covered={("a.py", 1)})

        new_lines = snapshot1.new_coverage_vs(snapshot2)
        assert new_lines == {("a.py", 2), ("b.py", 3)}

    def test_coverage_percentage(self) -> None:
        """Test coverage percentage calculation."""
        snapshot = CoverageSnapshot(
            lines_covered={("a.py", 1), ("a.py", 2)},  # 2 lines
        )

        # 2 out of 10 = 20%
        assert snapshot.coverage_percentage(10) == 20.0
        # Handle zero case
        assert snapshot.coverage_percentage(0) == 0.0


class TestGUIStateTransition:
    """Tests for GUIStateTransition dataclass."""

    def test_basic_initialization(self) -> None:
        """Test basic initialization."""
        transition = GUIStateTransition(from_state="idle", to_state="loading")
        assert transition.from_state == "idle"
        assert transition.to_state == "loading"
        assert transition.trigger == ""
        assert transition.timestamp > 0
        assert transition.test_file is None

    def test_full_initialization(self) -> None:
        """Test initialization with all fields."""
        test_path = Path("test.dcm")
        transition = GUIStateTransition(
            from_state="idle",
            to_state="loading",
            trigger="file_load",
            timestamp=12345.0,
            test_file=test_path,
        )

        assert transition.from_state == "idle"
        assert transition.to_state == "loading"
        assert transition.trigger == "file_load"
        assert transition.timestamp == 12345.0
        assert transition.test_file == test_path

    def test_auto_timestamp(self) -> None:
        """Test timestamp is auto-set if not provided."""
        before = time.time()
        transition = GUIStateTransition(from_state="a", to_state="b")
        after = time.time()

        assert before <= transition.timestamp <= after

    def test_hash_and_equality(self) -> None:
        """Test hash and equality based on states and trigger."""
        t1 = GUIStateTransition(from_state="a", to_state="b", trigger="x")
        t2 = GUIStateTransition(from_state="a", to_state="b", trigger="x")
        t3 = GUIStateTransition(from_state="a", to_state="c", trigger="x")

        assert t1 == t2
        assert hash(t1) == hash(t2)
        assert t1 != t3

        # Can be used in sets
        transitions = {t1, t2, t3}
        assert len(transitions) == 2

    def test_state_transition_alias(self) -> None:
        """Test StateTransition is alias for GUIStateTransition."""
        assert StateTransition is GUIStateTransition
        t = StateTransition(from_state="a", to_state="b")
        assert isinstance(t, GUIStateTransition)

    def test_inequality_with_non_transition(self) -> None:
        """Test GUIStateTransition inequality with non-transition object."""
        transition = GUIStateTransition(from_state="a", to_state="b")

        assert transition != "not a transition"
        assert transition != 123
        assert transition is not None
        assert transition != {"from_state": "a", "to_state": "b"}

    def test_explicit_timestamp(self) -> None:
        """Test GUIStateTransition with explicit timestamp (not auto-set)."""
        transition = GUIStateTransition(
            from_state="a", to_state="b", timestamp=12345.67
        )
        assert transition.timestamp == 12345.67


class TestProtocolStateTransition:
    """Tests for ProtocolStateTransition dataclass."""

    def test_basic_initialization(self) -> None:
        """Test basic initialization with mock states."""
        transition = ProtocolStateTransition(
            from_state="IDLE",  # Using str for testing
            to_state="ASSOCIATED",
        )
        assert transition.from_state == "IDLE"
        assert transition.to_state == "ASSOCIATED"
        assert transition.trigger_message == b""
        assert transition.response == b""
        assert transition.duration_ms == 0.0
        assert transition.coverage_increase == 0
        assert transition.timestamp > 0

    def test_full_initialization(self) -> None:
        """Test initialization with all fields."""
        transition = ProtocolStateTransition(
            from_state="IDLE",
            to_state="ASSOCIATED",
            trigger_message=b"\x01\x00\x00\x00",
            transition_type="VALID",
            response=b"\x02\x00\x00\x00",
            duration_ms=15.5,
            timestamp=12345.0,
            coverage_increase=10,
        )

        assert transition.trigger_message == b"\x01\x00\x00\x00"
        assert transition.response == b"\x02\x00\x00\x00"
        assert transition.duration_ms == 15.5
        assert transition.coverage_increase == 10

    def test_explicit_timestamp(self) -> None:
        """Test ProtocolStateTransition with explicit timestamp."""
        transition = ProtocolStateTransition(
            from_state="IDLE",
            to_state="ASSOCIATED",
            timestamp=98765.43,
        )
        assert transition.timestamp == 98765.43


class TestStateFingerprint:
    """Tests for StateFingerprint dataclass."""

    def test_basic_initialization(self) -> None:
        """Test basic initialization."""
        fp = StateFingerprint(hash_value="abc123", state="IDLE")
        assert fp.hash_value == "abc123"
        assert fp.state == "IDLE"
        assert fp.coverage_bitmap == b""
        assert fp.response_pattern == ""
        assert fp.memory_regions == []
        assert fp.timestamp > 0

    def test_similarity_empty_bitmaps(self) -> None:
        """Test similarity with empty bitmaps."""
        fp1 = StateFingerprint(hash_value="a", state="IDLE")
        fp2 = StateFingerprint(hash_value="b", state="IDLE")

        assert fp1.similarity(fp2) == 0.0

    def test_similarity_identical_bitmaps(self) -> None:
        """Test similarity with identical bitmaps."""
        bitmap = bytes([1, 0, 1, 0, 1])
        fp1 = StateFingerprint(hash_value="a", state="IDLE", coverage_bitmap=bitmap)
        fp2 = StateFingerprint(hash_value="b", state="IDLE", coverage_bitmap=bitmap)

        assert fp1.similarity(fp2) == 1.0

    def test_similarity_partial_overlap(self) -> None:
        """Test similarity with partial overlap."""
        # Bitmap 1: edges at positions 0, 2
        # Bitmap 2: edges at positions 0, 3
        # Intersection: {0}, Union: {0, 2, 3}
        # Jaccard = 1/3 ≈ 0.333
        bitmap1 = bytes([1, 0, 1, 0])
        bitmap2 = bytes([1, 0, 0, 1])

        fp1 = StateFingerprint(hash_value="a", state="IDLE", coverage_bitmap=bitmap1)
        fp2 = StateFingerprint(hash_value="b", state="IDLE", coverage_bitmap=bitmap2)

        similarity = fp1.similarity(fp2)
        assert 0.3 < similarity < 0.4

    def test_explicit_timestamp(self) -> None:
        """Test StateFingerprint with explicit timestamp."""
        fp = StateFingerprint(
            hash_value="abc",
            state="IDLE",
            timestamp=11111.22,
        )
        assert fp.timestamp == 11111.22

    def test_similarity_one_empty_bitmap(self) -> None:
        """Test StateFingerprint similarity when only one bitmap is empty."""
        fp1 = StateFingerprint(
            hash_value="a",
            state="IDLE",
            coverage_bitmap=bytes([1, 0, 1, 0]),
        )
        fp2 = StateFingerprint(hash_value="b", state="IDLE", coverage_bitmap=b"")

        assert fp1.similarity(fp2) == 0.0
        assert fp2.similarity(fp1) == 0.0

    def test_similarity_both_empty_edges(self) -> None:
        """Test StateFingerprint similarity when both have no edges (all zeros)."""
        fp1 = StateFingerprint(
            hash_value="a",
            state="IDLE",
            coverage_bitmap=bytes([0, 0, 0, 0]),
        )
        fp2 = StateFingerprint(
            hash_value="b",
            state="IDLE",
            coverage_bitmap=bytes([0, 0, 0, 0]),
        )

        # Both empty edge sets should return 1.0 similarity
        assert fp1.similarity(fp2) == 1.0

    def test_similarity_one_empty_edges(self) -> None:
        """Test StateFingerprint similarity when one has no edges."""
        fp1 = StateFingerprint(
            hash_value="a",
            state="IDLE",
            coverage_bitmap=bytes([1, 0, 1, 0]),
        )
        fp2 = StateFingerprint(
            hash_value="b",
            state="IDLE",
            coverage_bitmap=bytes([0, 0, 0, 0]),  # No edges
        )

        assert fp1.similarity(fp2) == 0.0


class TestStateCoverage:
    """Tests for StateCoverage dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        cov = StateCoverage()
        assert cov.visited_states == set()
        assert len(cov.state_transitions) == 0
        assert cov.unique_fingerprints == {}
        assert cov.state_depths == {}
        assert cov.total_transitions == 0
        assert cov.new_states_found == 0
        assert cov.new_transitions_found == 0

    def test_add_state(self) -> None:
        """Test adding states."""
        cov = StateCoverage()

        # First add is new
        is_new = cov.add_state("IDLE", depth=0)
        assert is_new is True
        assert "IDLE" in cov.visited_states
        assert cov.new_states_found == 1
        assert cov.state_depths["IDLE"] == 0

        # Second add is not new
        is_new = cov.add_state("IDLE", depth=1)
        assert is_new is False
        assert cov.new_states_found == 1
        # Depth should not update if higher
        assert cov.state_depths["IDLE"] == 0

    def test_add_state_updates_min_depth(self) -> None:
        """Test add_state updates to minimum depth."""
        cov = StateCoverage()

        cov.add_state("STATE", depth=5)
        assert cov.state_depths["STATE"] == 5

        # Lower depth should update
        cov.add_state("STATE", depth=2)
        assert cov.state_depths["STATE"] == 2

    def test_add_transition(self) -> None:
        """Test adding transitions."""
        cov = StateCoverage()

        # First transition is new
        is_new = cov.add_transition("IDLE", "ASSOCIATED")
        assert is_new is True
        assert cov.state_transitions[("IDLE", "ASSOCIATED")] == 1
        assert cov.total_transitions == 1
        assert cov.new_transitions_found == 1

        # Same transition again
        is_new = cov.add_transition("IDLE", "ASSOCIATED")
        assert is_new is False
        assert cov.state_transitions[("IDLE", "ASSOCIATED")] == 2
        assert cov.total_transitions == 2
        assert cov.new_transitions_found == 1

    def test_add_fingerprint(self) -> None:
        """Test adding fingerprints."""
        cov = StateCoverage()

        # Different coverage = different fingerprints
        fp1 = StateFingerprint(
            hash_value="fp1",
            state="IDLE",
            coverage_bitmap=bytes([1, 0, 0, 0]),
        )
        fp2 = StateFingerprint(
            hash_value="fp2",
            state="IDLE",
            coverage_bitmap=bytes([0, 1, 0, 0]),
        )

        is_new = cov.add_fingerprint(fp1)
        assert is_new is True
        assert "fp1" in cov.unique_fingerprints

        is_new = cov.add_fingerprint(fp2)
        assert is_new is True
        assert "fp2" in cov.unique_fingerprints

    def test_add_fingerprint_similar_rejected(self) -> None:
        """Test similar fingerprints are rejected."""
        cov = StateCoverage()

        # Identical coverage = similar fingerprints (rejected)
        bitmap = bytes([1, 1, 1, 1])
        fp1 = StateFingerprint(hash_value="fp1", state="IDLE", coverage_bitmap=bitmap)
        fp2 = StateFingerprint(hash_value="fp2", state="IDLE", coverage_bitmap=bitmap)

        cov.add_fingerprint(fp1)
        is_new = cov.add_fingerprint(fp2)
        assert is_new is False
        assert len(cov.unique_fingerprints) == 1

    def test_get_coverage_score(self) -> None:
        """Test coverage score calculation."""
        cov = StateCoverage()

        cov.add_state("IDLE")
        cov.add_state("ASSOCIATED")
        cov.add_transition("IDLE", "ASSOCIATED")

        # With 17 total states (default):
        # visited_ratio = 2/17
        # max_transitions = 17*17 = 289
        # transition_ratio = 1/289
        # score = (visited_ratio * 0.6 + transition_ratio * 0.4) * 100
        score = cov.get_coverage_score()
        assert score > 0
        assert score < 100

    def test_get_uncovered_states(self) -> None:
        """Test finding uncovered states."""
        cov = StateCoverage()
        cov.add_state("IDLE")
        cov.add_state("ASSOCIATED")

        all_states = {"IDLE", "ASSOCIATED", "DATA_TRANSFER", "CLOSED"}
        uncovered = cov.get_uncovered_states(all_states)

        assert uncovered == {"DATA_TRANSFER", "CLOSED"}

    def test_add_state_new_depth_tracking(self) -> None:
        """Test StateCoverage add_state depth tracking for new state."""
        cov = StateCoverage()

        # Add state first time with depth 3
        cov.add_state("STATE_A", depth=3)
        assert cov.state_depths["STATE_A"] == 3

        # Add again with higher depth - should not update
        cov.add_state("STATE_A", depth=5)
        assert cov.state_depths["STATE_A"] == 3

        # Add again with lower depth - should update
        cov.add_state("STATE_A", depth=1)
        assert cov.state_depths["STATE_A"] == 1


class TestCoverageTypesBackwardCompatibility:
    """Test backward compatibility for coverage type imports."""

    def test_import_from_core(self) -> None:
        """Test key types can be imported from core."""
        from dicom_fuzzer.core import (
            GUIStateTransition as GUIStateTransitionCore,
        )
        from dicom_fuzzer.core import (
            ProtocolStateTransition as ProtocolStateTransitionCore,
        )
        from dicom_fuzzer.core import (
            StateCoverage as StateCoverageCore,
        )
        from dicom_fuzzer.core import (
            StateFingerprint as StateFingerprintCore,
        )
        from dicom_fuzzer.core import (
            StateTransition as StateTransitionCore,
        )

        assert GUIStateTransitionCore is GUIStateTransition
        assert ProtocolStateTransitionCore is ProtocolStateTransition
        assert StateCoverageCore is StateCoverage
        assert StateFingerprintCore is StateFingerprint
        assert StateTransitionCore is GUIStateTransition

    def test_import_from_corpus_minimizer(self) -> None:
        """Test imports from corpus_minimizer."""
        from dicom_fuzzer.core.corpus.corpus_minimizer import (
            CoverageInfo as CoverageInfoMinimizer,
        )

        # corpus_minimizer has backward compatibility alias
        assert CoverageInfoMinimizer is SeedCoverageInfo

"""Tests for State Coverage module."""

from __future__ import annotations

from pathlib import Path

from dicom_fuzzer.core.state_coverage import (
    StateCoverageTracker,
    StateTransition,
)


class TestStateTransition:
    """Tests for StateTransition dataclass."""

    def test_creation(self) -> None:
        """Test creating StateTransition."""
        transition = StateTransition(
            from_state="initial",
            to_state="loading",
            trigger="file_open",
        )
        assert transition.from_state == "initial"
        assert transition.to_state == "loading"
        assert transition.trigger == "file_open"
        assert transition.timestamp == 0.0
        assert transition.test_file is None

    def test_full_initialization(self) -> None:
        """Test StateTransition with all fields."""
        test_file = Path("/test/file.dcm")
        transition = StateTransition(
            from_state="loading",
            to_state="error",
            trigger="parse_error",
            timestamp=1234.5,
            test_file=test_file,
        )
        assert transition.timestamp == 1234.5
        assert transition.test_file == test_file

    def test_hash(self) -> None:
        """Test StateTransition hashing."""
        t1 = StateTransition(from_state="a", to_state="b", trigger="x")
        t2 = StateTransition(from_state="a", to_state="b", trigger="x")
        t3 = StateTransition(from_state="a", to_state="c", trigger="x")

        assert hash(t1) == hash(t2)
        assert hash(t1) != hash(t3)

    def test_equality(self) -> None:
        """Test StateTransition equality."""
        t1 = StateTransition(from_state="a", to_state="b", trigger="x")
        t2 = StateTransition(from_state="a", to_state="b", trigger="x")
        t3 = StateTransition(from_state="a", to_state="c", trigger="x")

        assert t1 == t2
        assert t1 != t3
        assert t1 != "not a transition"

    def test_set_membership(self) -> None:
        """Test StateTransition in sets."""
        t1 = StateTransition(from_state="a", to_state="b", trigger="x")
        t2 = StateTransition(from_state="a", to_state="b", trigger="x")
        t3 = StateTransition(from_state="a", to_state="c", trigger="y")

        s = {t1, t2, t3}
        assert len(s) == 2  # t1 and t2 are equal


class TestStateCoverageTracker:
    """Tests for StateCoverageTracker class."""

    def test_initialization(self) -> None:
        """Test tracker initialization."""
        tracker = StateCoverageTracker()
        coverage = tracker.get_state_coverage()

        assert coverage["unique_states"] == 0
        assert coverage["unique_transitions"] == 0
        assert coverage["total_executions"] == 0

    def test_class_constants(self) -> None:
        """Verify class-level constants."""
        assert StateCoverageTracker.STATE_INITIAL == "initial"
        assert StateCoverageTracker.STATE_LOADING == "loading"
        assert StateCoverageTracker.STATE_NORMAL == "normal"
        assert StateCoverageTracker.STATE_CRASH == "crash"

    def test_start_execution(self) -> None:
        """Test starting an execution."""
        tracker = StateCoverageTracker()
        tracker.start_execution()

        coverage = tracker.get_state_coverage()
        assert "initial" in coverage["states_visited"]

    def test_record_state_new(self) -> None:
        """Test recording a new state."""
        tracker = StateCoverageTracker()
        tracker.start_execution()

        is_new = tracker.record_state("loading", trigger="file_open")
        assert is_new is True

        is_new_again = tracker.record_state("loading", trigger="another")
        assert is_new_again is False

    def test_record_state_creates_transition(self) -> None:
        """Test that recording states creates transitions."""
        tracker = StateCoverageTracker()
        tracker.start_execution()
        tracker.record_state("loading", trigger="file_open")
        tracker.record_state("normal", trigger="parse_complete")

        coverage = tracker.get_state_coverage()
        assert coverage["unique_transitions"] >= 2

    def test_end_execution(self) -> None:
        """Test ending an execution."""
        tracker = StateCoverageTracker()
        tracker.start_execution()
        tracker.record_state("loading")
        tracker.record_state("normal")

        sequence = tracker.end_execution()

        assert sequence == ["initial", "loading", "normal"]
        assert tracker.get_state_coverage()["total_executions"] == 1

    def test_multiple_executions(self) -> None:
        """Test multiple execution tracking."""
        tracker = StateCoverageTracker()

        # First execution
        tracker.start_execution()
        tracker.record_state("loading")
        tracker.end_execution()

        # Second execution
        tracker.start_execution()
        tracker.record_state("loading")
        tracker.record_state("error")
        tracker.end_execution()

        coverage = tracker.get_state_coverage()
        assert coverage["total_executions"] == 2
        assert "error" in coverage["states_visited"]

    def test_interesting_inputs(self) -> None:
        """Test tracking interesting inputs."""
        tracker = StateCoverageTracker()
        test_file = Path("/test/file.dcm")

        tracker.start_execution()
        tracker.record_state("loading", trigger="file_open", test_file=test_file)
        tracker.record_state("error", trigger="parse_error", test_file=test_file)
        tracker.end_execution()

        inputs = tracker.get_interesting_inputs()
        assert test_file in inputs

    def test_is_interesting_true(self) -> None:
        """Test is_interesting returns True for new states."""
        tracker = StateCoverageTracker()
        file1 = Path("/test/file1.dcm")
        file2 = Path("/test/file2.dcm")

        # File 1 reaches new states
        tracker.start_execution()
        tracker.record_state("loading", test_file=file1)
        tracker.record_state("unique_state", test_file=file1)
        tracker.end_execution()

        # File 2 reaches same states
        tracker.start_execution()
        tracker.record_state("loading", test_file=file2)
        tracker.end_execution()

        assert tracker.is_interesting(file1) is True

    def test_is_interesting_unknown_file(self) -> None:
        """Test is_interesting returns False for unknown file."""
        tracker = StateCoverageTracker()
        unknown_file = Path("/unknown/file.dcm")

        assert tracker.is_interesting(unknown_file) is False

    def test_get_state_coverage_details(self) -> None:
        """Test get_state_coverage returns detailed info."""
        tracker = StateCoverageTracker()
        tracker.start_execution()
        tracker.record_state("loading", trigger="file_open")
        tracker.end_execution()

        coverage = tracker.get_state_coverage()

        assert "unique_states" in coverage
        assert "states_visited" in coverage
        assert "unique_transitions" in coverage
        assert "total_executions" in coverage
        assert "transition_details" in coverage

        # Verify transition details structure
        assert len(coverage["transition_details"]) > 0
        detail = coverage["transition_details"][0]
        assert "from" in detail
        assert "to" in detail
        assert "trigger" in detail


class TestBackwardCompatibility:
    """Test backward compatibility with gui_monitor module."""

    def test_imports_from_gui_monitor(self) -> None:
        """Verify types can be imported from gui_monitor."""
        from dicom_fuzzer.core.gui_monitor import (
            StateCoverageTracker as SCTracker,
        )
        from dicom_fuzzer.core.gui_monitor import (
            StateTransition as STrans,
        )

        assert SCTracker is StateCoverageTracker
        assert STrans is StateTransition

    def test_imports_from_core(self) -> None:
        """Verify types can be imported from core __init__."""
        from dicom_fuzzer.core import (
            StateCoverageTracker as SCTracker,
        )
        from dicom_fuzzer.core import (
            StateTransition as STrans,
        )

        assert SCTracker is StateCoverageTracker
        assert STrans is StateTransition

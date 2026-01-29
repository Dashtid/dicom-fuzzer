"""Tests for State Coverage module."""

from __future__ import annotations

from pathlib import Path

from dicom_fuzzer.strategies.robustness.network.stateful.coverage import (
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
        # __post_init__ auto-sets timestamp to time.time() when 0
        assert transition.timestamp > 0
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


class TestStateCoverageTrackerBranchCoverage:
    """Additional tests for branch coverage in StateCoverageTracker."""

    def test_record_state_without_current_sequence(self) -> None:
        """Test recording state when no execution started (empty sequence)."""
        tracker = StateCoverageTracker()
        # Don't call start_execution - _current_sequence is empty

        # This should still work but won't create a transition
        is_new = tracker.record_state("loading", trigger="test")
        assert is_new is True

        coverage = tracker.get_state_coverage()
        assert "loading" in coverage["states_visited"]
        # No transition since there was no from_state
        assert coverage["unique_transitions"] == 0

    def test_record_state_without_test_file(self) -> None:
        """Test recording state without test_file (None)."""
        tracker = StateCoverageTracker()
        tracker.start_execution()

        # Record without test_file
        tracker.record_state("loading", trigger="test", test_file=None)

        # Should not be in interesting_inputs
        inputs = tracker.get_interesting_inputs()
        assert len(inputs) == 0

    def test_end_execution_empty_sequence(self) -> None:
        """Test ending execution with empty sequence."""
        tracker = StateCoverageTracker()
        # Don't call start_execution

        # End execution with no sequence
        sequence = tracker.end_execution()

        assert sequence == []
        assert tracker.get_state_coverage()["total_executions"] == 0

    def test_is_interesting_all_states_common(self) -> None:
        """Test is_interesting when all states are common across files."""
        tracker = StateCoverageTracker()
        file1 = Path("/test/file1.dcm")
        file2 = Path("/test/file2.dcm")

        # File 1 reaches some states
        tracker.start_execution()
        tracker.record_state("loading", test_file=file1)
        tracker.record_state("normal", test_file=file1)
        tracker.end_execution()

        # File 2 reaches the same states
        tracker.start_execution()
        tracker.record_state("loading", test_file=file2)
        tracker.record_state("normal", test_file=file2)
        tracker.end_execution()

        # Both files reached the same states, so neither is uniquely interesting
        # (initial was reached by start_execution, not by files)
        # file2's states are all also in file1, so file2 is not interesting
        result = tracker.is_interesting(file2)
        assert result is False

    def test_is_interesting_with_unique_state(self) -> None:
        """Test is_interesting when file has a unique state not in others."""
        tracker = StateCoverageTracker()
        file1 = Path("/test/file1.dcm")
        file2 = Path("/test/file2.dcm")

        # File 1 reaches common states only
        tracker.start_execution()
        tracker.record_state("loading", test_file=file1)
        tracker.end_execution()

        # File 2 reaches a unique state
        tracker.start_execution()
        tracker.record_state("loading", test_file=file2)
        tracker.record_state("unique_crash", test_file=file2)
        tracker.end_execution()

        # File 2 has a unique state
        assert tracker.is_interesting(file2) is True

    def test_interesting_inputs_ranking(self) -> None:
        """Test that interesting inputs are ranked by states reached."""
        tracker = StateCoverageTracker()
        file1 = Path("/test/file1.dcm")
        file2 = Path("/test/file2.dcm")
        file3 = Path("/test/file3.dcm")

        # File 1 reaches 1 state
        tracker.start_execution()
        tracker.record_state("state1", test_file=file1)
        tracker.end_execution()

        # File 2 reaches 3 states
        tracker.start_execution()
        tracker.record_state("state2", test_file=file2)
        tracker.record_state("state3", test_file=file2)
        tracker.record_state("state4", test_file=file2)
        tracker.end_execution()

        # File 3 reaches 2 states
        tracker.start_execution()
        tracker.record_state("state5", test_file=file3)
        tracker.record_state("state6", test_file=file3)
        tracker.end_execution()

        inputs = tracker.get_interesting_inputs()
        # Should be ranked by number of states: file2 (3), file3 (2), file1 (1)
        assert inputs[0] == file2
        assert inputs[1] == file3
        assert inputs[2] == file1


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

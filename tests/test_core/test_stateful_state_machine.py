"""Tests for DICOM State Machine.

Tests the state machine implementation in
dicom_fuzzer.core.stateful.state_machine module.
"""

import pytest

from dicom_fuzzer.strategies.network.stateful.enums import (
    AssociationState,
    ProtocolEvent,
    TransitionType,
)
from dicom_fuzzer.strategies.network.stateful.state_machine import DICOMStateMachine


class TestDICOMStateMachineInit:
    """Tests for DICOMStateMachine initialization."""

    def test_init_creates_valid_transitions(self) -> None:
        """Test initialization builds valid transitions."""
        sm = DICOMStateMachine()
        assert sm.valid_transitions is not None
        assert len(sm.valid_transitions) > 0

    def test_init_creates_invalid_transitions(self) -> None:
        """Test initialization builds invalid transitions."""
        sm = DICOMStateMachine()
        assert sm.invalid_transitions is not None
        assert len(sm.invalid_transitions) > 0


class TestValidTransitions:
    """Tests for valid state transitions."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_sta1_to_sta4_via_associate_rq(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test transition from STA1 to STA4 via A-ASSOCIATE-RQ."""
        key = (AssociationState.STA1, ProtocolEvent.A_ASSOCIATE_RQ)
        assert key in state_machine.valid_transitions
        trans = state_machine.valid_transitions[key]
        assert trans.to_state == AssociationState.STA4
        assert trans.transition_type == TransitionType.VALID

    def test_sta1_to_sta2_via_transport_connect(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test transition from STA1 to STA2 via TRANSPORT_CONNECT."""
        key = (AssociationState.STA1, ProtocolEvent.TRANSPORT_CONNECT)
        assert key in state_machine.valid_transitions
        trans = state_machine.valid_transitions[key]
        assert trans.to_state == AssociationState.STA2

    def test_sta6_data_transfer_stays_in_sta6(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test P-DATA-TF in STA6 stays in STA6."""
        key = (AssociationState.STA6, ProtocolEvent.P_DATA_TF)
        assert key in state_machine.valid_transitions
        trans = state_machine.valid_transitions[key]
        assert trans.to_state == AssociationState.STA6

    def test_sta6_to_sta7_via_release_rq(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test transition from STA6 to STA7 via A-RELEASE-RQ."""
        key = (AssociationState.STA6, ProtocolEvent.A_RELEASE_RQ)
        assert key in state_machine.valid_transitions
        trans = state_machine.valid_transitions[key]
        assert trans.to_state == AssociationState.STA7

    def test_sta6_to_sta13_via_abort(self, state_machine: DICOMStateMachine) -> None:
        """Test transition from STA6 to STA13 via A-ABORT."""
        key = (AssociationState.STA6, ProtocolEvent.A_ABORT)
        assert key in state_machine.valid_transitions
        trans = state_machine.valid_transitions[key]
        assert trans.to_state == AssociationState.STA13


class TestInvalidTransitions:
    """Tests for invalid state transitions."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_invalid_transition_in_sta1(self, state_machine: DICOMStateMachine) -> None:
        """Test invalid transitions are generated for STA1."""
        # P-DATA-TF in STA1 is invalid
        key = (AssociationState.STA1, ProtocolEvent.P_DATA_TF)
        assert key in state_machine.invalid_transitions
        trans = state_machine.invalid_transitions[key]
        assert trans.transition_type == TransitionType.INVALID

    def test_invalid_transition_stays_in_same_state(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test invalid transitions don't change state."""
        key = (AssociationState.STA1, ProtocolEvent.P_DATA_TF)
        trans = state_machine.invalid_transitions[key]
        assert trans.from_state == trans.to_state

    def test_all_invalid_combinations_generated(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test all state/event combinations are covered."""
        all_states = list(AssociationState)
        all_events = list(ProtocolEvent)

        # Total combinations
        total_combinations = len(all_states) * len(all_events)

        # Valid + Invalid should cover all
        valid_count = len(state_machine.valid_transitions)
        invalid_count = len(state_machine.invalid_transitions)

        assert valid_count + invalid_count == total_combinations


class TestGetValidEvents:
    """Tests for get_valid_events method."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_get_valid_events_sta1(self, state_machine: DICOMStateMachine) -> None:
        """Test getting valid events for STA1 (Idle)."""
        events = state_machine.get_valid_events(AssociationState.STA1)

        assert ProtocolEvent.A_ASSOCIATE_RQ in events
        assert ProtocolEvent.TRANSPORT_CONNECT in events
        assert len(events) == 2

    def test_get_valid_events_sta6(self, state_machine: DICOMStateMachine) -> None:
        """Test getting valid events for STA6 (Association established)."""
        events = state_machine.get_valid_events(AssociationState.STA6)

        assert ProtocolEvent.P_DATA_TF in events
        assert ProtocolEvent.A_RELEASE_RQ in events
        assert ProtocolEvent.A_ABORT in events
        assert len(events) == 3

    def test_get_valid_events_sta13(self, state_machine: DICOMStateMachine) -> None:
        """Test getting valid events for STA13 (Awaiting transport close)."""
        events = state_machine.get_valid_events(AssociationState.STA13)

        assert ProtocolEvent.TRANSPORT_CLOSE in events
        assert len(events) == 1


class TestGetInvalidEvents:
    """Tests for get_invalid_events method."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_get_invalid_events_sta1(self, state_machine: DICOMStateMachine) -> None:
        """Test getting invalid events for STA1 (Idle)."""
        invalid_events = state_machine.get_invalid_events(AssociationState.STA1)
        valid_events = state_machine.get_valid_events(AssociationState.STA1)

        # Invalid events should be complement of valid events
        all_events = list(ProtocolEvent)
        assert len(invalid_events) == len(all_events) - len(valid_events)

        # P-DATA-TF should be invalid in STA1
        assert ProtocolEvent.P_DATA_TF in invalid_events

    def test_get_invalid_events_sta6(self, state_machine: DICOMStateMachine) -> None:
        """Test getting invalid events for STA6."""
        invalid_events = state_machine.get_invalid_events(AssociationState.STA6)

        # A-ASSOCIATE-RQ should be invalid in STA6 (already associated)
        assert ProtocolEvent.A_ASSOCIATE_RQ in invalid_events


class TestGetTransition:
    """Tests for get_transition method."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_get_valid_transition(self, state_machine: DICOMStateMachine) -> None:
        """Test getting a valid transition."""
        trans = state_machine.get_transition(
            AssociationState.STA6, ProtocolEvent.P_DATA_TF
        )
        assert trans is not None
        assert trans.transition_type == TransitionType.VALID
        assert trans.to_state == AssociationState.STA6

    def test_get_invalid_transition(self, state_machine: DICOMStateMachine) -> None:
        """Test getting an invalid transition."""
        trans = state_machine.get_transition(
            AssociationState.STA1, ProtocolEvent.P_DATA_TF
        )
        assert trans is not None
        assert trans.transition_type == TransitionType.INVALID

    def test_all_combinations_return_transition(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test all state/event combinations return a transition."""
        for state in AssociationState:
            for event in ProtocolEvent:
                trans = state_machine.get_transition(state, event)
                assert trans is not None


class TestGetAllTransitions:
    """Tests for get_all_transitions method."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_get_all_transitions_count(self, state_machine: DICOMStateMachine) -> None:
        """Test get_all_transitions returns all transitions."""
        all_trans = state_machine.get_all_transitions()

        expected_count = len(AssociationState) * len(ProtocolEvent)
        assert len(all_trans) == expected_count

    def test_get_all_transitions_contains_valid(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test get_all_transitions includes valid transitions."""
        all_trans = state_machine.get_all_transitions()
        valid_trans = [
            t for t in all_trans if t.transition_type == TransitionType.VALID
        ]

        assert len(valid_trans) == len(state_machine.valid_transitions)

    def test_get_all_transitions_contains_invalid(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test get_all_transitions includes invalid transitions."""
        all_trans = state_machine.get_all_transitions()
        invalid_trans = [
            t for t in all_trans if t.transition_type == TransitionType.INVALID
        ]

        assert len(invalid_trans) == len(state_machine.invalid_transitions)


class TestTransitionDescriptions:
    """Tests for transition descriptions."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create a state machine instance."""
        return DICOMStateMachine()

    def test_valid_transitions_have_descriptions(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test valid transitions have meaningful descriptions."""
        for trans in state_machine.valid_transitions.values():
            assert trans.description is not None
            assert len(trans.description) > 0

    def test_invalid_transitions_have_descriptions(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test invalid transitions have descriptions."""
        for trans in state_machine.invalid_transitions.values():
            assert trans.description is not None
            assert "Invalid" in trans.description

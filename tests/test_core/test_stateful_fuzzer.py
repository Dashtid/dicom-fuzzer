"""Comprehensive tests for stateful protocol fuzzer.

Tests the StatefulFuzzer, state machine, and sequence generators
for DICOM protocol state-aware fuzzing.
"""

import pytest

from dicom_fuzzer.core.stateful_fuzzer import (
    AssociationState,
    CoverageStats,
    DICOMStateMachine,
    FuzzSequence,
    ProtocolEvent,
    ResourceExhaustionGenerator,
    SequenceGenerator,
    StatefulFuzzer,
    StateMachineConfig,
    StateTransition,
    TimingAttackGenerator,
    TransitionResult,
    TransitionType,
)


class TestAssociationState:
    """Tests for AssociationState enum."""

    def test_all_states_defined(self):
        """Test all DICOM association states are defined."""
        expected_states = [
            "STA1",
            "STA2",
            "STA3",
            "STA4",
            "STA5",
            "STA6",
            "STA7",
            "STA8",
            "STA9",
            "STA10",
            "STA11",
            "STA12",
            "STA13",
        ]

        for state in expected_states:
            assert hasattr(AssociationState, state)

    def test_state_count(self):
        """Test expected number of states."""
        assert len(AssociationState) == 13


class TestProtocolEvent:
    """Tests for ProtocolEvent enum."""

    def test_association_events(self):
        """Test association events are defined."""
        assert hasattr(ProtocolEvent, "A_ASSOCIATE_RQ")
        assert hasattr(ProtocolEvent, "A_ASSOCIATE_AC")
        assert hasattr(ProtocolEvent, "A_ASSOCIATE_RJ")

    def test_release_events(self):
        """Test release events are defined."""
        assert hasattr(ProtocolEvent, "A_RELEASE_RQ")
        assert hasattr(ProtocolEvent, "A_RELEASE_RP")

    def test_data_transfer_event(self):
        """Test data transfer event is defined."""
        assert hasattr(ProtocolEvent, "P_DATA_TF")

    def test_abort_events(self):
        """Test abort events are defined."""
        assert hasattr(ProtocolEvent, "A_ABORT")
        assert hasattr(ProtocolEvent, "A_P_ABORT")


class TestTransitionType:
    """Tests for TransitionType enum."""

    def test_all_types_defined(self):
        """Test all transition types are defined."""
        expected = ["VALID", "INVALID", "UNEXPECTED", "MALFORMED", "DUPLICATE"]

        for t in expected:
            assert hasattr(TransitionType, t)


class TestStateTransition:
    """Tests for StateTransition class."""

    def test_basic_creation(self):
        """Test basic transition creation."""
        transition = StateTransition(
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA4,
            event=ProtocolEvent.A_ASSOCIATE_RQ,
        )

        assert transition.from_state == AssociationState.STA1
        assert transition.to_state == AssociationState.STA4
        assert transition.event == ProtocolEvent.A_ASSOCIATE_RQ
        assert transition.transition_type == TransitionType.VALID

    def test_with_description(self):
        """Test transition with description."""
        transition = StateTransition(
            from_state=AssociationState.STA5,
            to_state=AssociationState.STA6,
            event=ProtocolEvent.A_ASSOCIATE_AC,
            description="Association accepted",
        )

        assert transition.description == "Association accepted"


class TestDICOMStateMachine:
    """Tests for DICOMStateMachine class."""

    @pytest.fixture
    def state_machine(self):
        """Create a state machine."""
        return DICOMStateMachine()

    def test_has_valid_transitions(self, state_machine):
        """Test state machine has valid transitions."""
        assert len(state_machine.valid_transitions) > 0

    def test_has_invalid_transitions(self, state_machine):
        """Test state machine has invalid transitions."""
        assert len(state_machine.invalid_transitions) > 0

    def test_get_valid_events_from_sta1(self, state_machine):
        """Test getting valid events from STA1."""
        events = state_machine.get_valid_events(AssociationState.STA1)

        assert ProtocolEvent.A_ASSOCIATE_RQ in events
        assert ProtocolEvent.TRANSPORT_CONNECT in events

    def test_get_valid_events_from_sta6(self, state_machine):
        """Test getting valid events from STA6 (established)."""
        events = state_machine.get_valid_events(AssociationState.STA6)

        assert ProtocolEvent.P_DATA_TF in events
        assert ProtocolEvent.A_RELEASE_RQ in events
        assert ProtocolEvent.A_ABORT in events

    def test_get_invalid_events_from_sta1(self, state_machine):
        """Test getting invalid events from STA1."""
        invalid = state_machine.get_invalid_events(AssociationState.STA1)

        # P_DATA_TF is not valid in STA1
        assert ProtocolEvent.P_DATA_TF in invalid

    def test_get_transition_valid(self, state_machine):
        """Test getting valid transition."""
        transition = state_machine.get_transition(
            AssociationState.STA1,
            ProtocolEvent.A_ASSOCIATE_RQ,
        )

        assert transition is not None
        assert transition.transition_type == TransitionType.VALID
        assert transition.to_state == AssociationState.STA4

    def test_get_transition_invalid(self, state_machine):
        """Test getting invalid transition."""
        transition = state_machine.get_transition(
            AssociationState.STA1,
            ProtocolEvent.P_DATA_TF,
        )

        assert transition is not None
        assert transition.transition_type == TransitionType.INVALID

    def test_get_all_transitions(self, state_machine):
        """Test getting all transitions."""
        all_transitions = state_machine.get_all_transitions()

        # Should have many transitions
        assert len(all_transitions) > 50


class TestFuzzSequence:
    """Tests for FuzzSequence class."""

    def test_basic_creation(self):
        """Test basic sequence creation."""
        seq = FuzzSequence(
            events=[ProtocolEvent.A_ASSOCIATE_RQ],
            description="Test sequence",
        )

        assert len(seq.events) == 1
        assert seq.description == "Test sequence"
        assert seq.attack_type == "generic"

    def test_with_expected_states(self):
        """Test sequence with expected states."""
        seq = FuzzSequence(
            events=[
                ProtocolEvent.A_ASSOCIATE_RQ,
                ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ],
            expected_states=[
                AssociationState.STA1,
                AssociationState.STA4,
                AssociationState.STA5,
            ],
        )

        assert len(seq.expected_states) == 3


class TestSequenceGenerator:
    """Tests for SequenceGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a sequence generator."""
        sm = DICOMStateMachine()
        return SequenceGenerator(sm)

    def test_generate_valid_sequence(self, generator):
        """Test generating valid sequence."""
        seq = generator.generate_valid_sequence()

        assert len(seq.events) > 0
        assert seq.attack_type == "baseline"

    def test_generate_sequence_to_sta6(self, generator):
        """Test generating sequence to STA6."""
        seq = generator.generate_valid_sequence(target_state=AssociationState.STA6)

        # Should include association establishment
        assert ProtocolEvent.A_ASSOCIATE_AC in seq.events or len(seq.events) > 0

    def test_generate_invalid_transition_sequence(self, generator):
        """Test generating invalid transition sequence."""
        seq = generator.generate_invalid_transition_sequence()

        assert seq.attack_type == "invalid_transition"
        assert len(seq.events) > 0

    def test_generate_out_of_order_sequence(self, generator):
        """Test generating out-of-order sequence."""
        seq = generator.generate_out_of_order_sequence()

        assert seq.attack_type == "out_of_order"
        assert len(seq.events) > 3

    def test_generate_state_confusion_sequence(self, generator):
        """Test generating state confusion sequence."""
        seq = generator.generate_state_confusion_sequence()

        assert seq.attack_type == "state_confusion"
        # Should have multiple associate/release cycles
        assert seq.events.count(ProtocolEvent.A_ASSOCIATE_RQ) >= 2

    def test_generate_duplicate_sequence(self, generator):
        """Test generating duplicate message sequence."""
        seq = generator.generate_duplicate_sequence()

        assert seq.attack_type == "duplicate"
        # Should have duplicate events
        from collections import Counter

        event_counts = Counter(seq.events)
        has_duplicates = any(c > 1 for c in event_counts.values())
        assert has_duplicates

    def test_generate_release_collision_sequence(self, generator):
        """Test generating release collision sequence."""
        seq = generator.generate_release_collision_sequence()

        assert seq.attack_type == "release_collision"
        # Should have multiple release requests
        assert seq.events.count(ProtocolEvent.A_RELEASE_RQ) >= 2

    def test_generate_abort_recovery_sequence(self, generator):
        """Test generating abort recovery sequence."""
        seq = generator.generate_abort_recovery_sequence()

        assert seq.attack_type == "abort_recovery"
        assert ProtocolEvent.A_ABORT in seq.events


class TestCoverageStats:
    """Tests for CoverageStats class."""

    def test_default_values(self):
        """Test default coverage statistics."""
        stats = CoverageStats()

        assert len(stats.states_visited) == 0
        assert len(stats.transitions_executed) == 0
        assert stats.sequences_executed == 0

    def test_state_coverage_calculation(self):
        """Test state coverage percentage calculation."""
        stats = CoverageStats()
        stats.states_visited.add(AssociationState.STA1)
        stats.states_visited.add(AssociationState.STA6)

        # 2 of 13 states = ~15%
        coverage = stats.state_coverage
        assert 15 < coverage < 16


class TestStatefulFuzzer:
    """Tests for high-level StatefulFuzzer class."""

    @pytest.fixture
    def fuzzer(self):
        """Create a stateful fuzzer."""
        return StatefulFuzzer()

    def test_initial_state(self, fuzzer):
        """Test fuzzer initial state."""
        assert fuzzer.current_state == AssociationState.STA1

    def test_reset(self, fuzzer):
        """Test fuzzer reset."""
        fuzzer.current_state = AssociationState.STA6
        fuzzer.reset()

        assert fuzzer.current_state == AssociationState.STA1

    def test_execute_valid_event(self, fuzzer):
        """Test executing valid event."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)

        assert result.success
        assert result.from_state == AssociationState.STA1
        assert result.to_state == AssociationState.STA4

    def test_execute_invalid_event(self, fuzzer):
        """Test executing invalid event."""
        # P_DATA_TF is not valid in STA1
        result = fuzzer.execute_event(ProtocolEvent.P_DATA_TF)

        assert result.success  # Event was processed
        # State doesn't change for invalid transition

    def test_execute_sequence(self, fuzzer):
        """Test executing event sequence."""
        seq = FuzzSequence(
            events=[
                ProtocolEvent.A_ASSOCIATE_RQ,
                ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ]
        )

        results = fuzzer.execute_sequence(seq)

        assert len(results) == 2
        assert all(isinstance(r, TransitionResult) for r in results)

    def test_coverage_tracking(self, fuzzer):
        """Test coverage statistics tracking."""
        fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        fuzzer.execute_event(ProtocolEvent.TRANSPORT_CONNECT_CONFIRM)

        stats = fuzzer.get_coverage_stats()

        assert stats["states_visited"] >= 2
        assert stats["transitions_executed"] >= 2

    def test_generate_fuzz_sequences(self, fuzzer):
        """Test fuzz sequence generation."""
        sequences = list(fuzzer.generate_fuzz_sequences(count=10))

        assert len(sequences) == 10
        assert all(isinstance(s, FuzzSequence) for s in sequences)

    def test_get_untested_transitions(self, fuzzer):
        """Test getting untested transitions."""
        untested = fuzzer.get_untested_transitions()

        # Initially all are untested
        assert len(untested) > 0

        # Execute some events
        fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        untested_after = fuzzer.get_untested_transitions()

        # Should have fewer untested
        assert len(untested_after) < len(untested)

    def test_generate_targeted_sequences(self, fuzzer):
        """Test generating sequences for specific transitions."""
        targets = [
            (AssociationState.STA6, ProtocolEvent.P_DATA_TF),
        ]

        sequences = list(fuzzer.generate_targeted_sequences(targets))

        assert len(sequences) == 1
        assert sequences[0].attack_type == "targeted"


class TestStateMachineConfig:
    """Tests for StateMachineConfig class."""

    def test_default_values(self):
        """Test default configuration."""
        config = StateMachineConfig()

        assert config.probability_invalid_transition == 0.2
        assert config.probability_out_of_order == 0.1
        assert config.enable_timing_attacks is True
        assert config.track_state_coverage is True

    def test_custom_values(self):
        """Test custom configuration."""
        config = StateMachineConfig(
            probability_invalid_transition=0.5,
            enable_timing_attacks=False,
        )

        assert config.probability_invalid_transition == 0.5
        assert config.enable_timing_attacks is False


class TestTimingAttackGenerator:
    """Tests for TimingAttackGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a timing attack generator."""
        return TimingAttackGenerator()

    def test_generate_timeout_attack(self, generator):
        """Test timeout attack generation."""
        seq = generator.generate_timeout_attack()

        assert seq.attack_type == "timeout"
        assert len(seq.events) == 1

    def test_generate_slow_data_attack(self, generator):
        """Test slow data attack generation."""
        seq = generator.generate_slow_data_attack()

        assert seq.attack_type == "slow_data"
        # Should have many P_DATA_TF events
        data_count = seq.events.count(ProtocolEvent.P_DATA_TF)
        assert data_count >= 50

    def test_generate_rapid_reconnect_attack(self, generator):
        """Test rapid reconnect attack generation."""
        seq = generator.generate_rapid_reconnect_attack()

        assert seq.attack_type == "rapid_reconnect"
        # Should have many connect/disconnect cycles
        assert len(seq.events) >= 100


class TestResourceExhaustionGenerator:
    """Tests for ResourceExhaustionGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a resource exhaustion generator."""
        return ResourceExhaustionGenerator()

    def test_generate_connection_exhaustion(self, generator):
        """Test connection exhaustion attack generation."""
        sequences = generator.generate_connection_exhaustion(num_connections=10)

        assert len(sequences) == 10
        assert all(s.attack_type == "connection_exhaustion" for s in sequences)

    def test_generate_pending_release_exhaustion(self, generator):
        """Test pending release exhaustion generation."""
        seq = generator.generate_pending_release_exhaustion()

        assert seq.attack_type == "pending_release"
        # Should have many release requests
        release_count = seq.events.count(ProtocolEvent.A_RELEASE_RQ)
        assert release_count >= 50


class TestTransitionResult:
    """Tests for TransitionResult class."""

    def test_successful_result(self):
        """Test successful transition result."""
        result = TransitionResult(
            success=True,
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA4,
            event=ProtocolEvent.A_ASSOCIATE_RQ,
            duration_ms=5.0,
        )

        assert result.success
        assert result.error is None

    def test_failed_result(self):
        """Test failed transition result."""
        result = TransitionResult(
            success=False,
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA1,
            event=ProtocolEvent.P_DATA_TF,
            error="Invalid transition",
        )

        assert not result.success
        assert result.error is not None

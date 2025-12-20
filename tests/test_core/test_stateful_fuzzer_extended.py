"""Extended tests for Stateful Protocol Fuzzer.

Tests for state machine-based DICOM protocol fuzzing including:
- AssociationState and ProtocolEvent enums
- DICOMStateMachine transitions
- SequenceGenerator attack patterns
- StatefulFuzzer execution
- Coverage tracking
- Timing and resource attacks
"""

from __future__ import annotations

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

    def test_initial_state(self) -> None:
        """Test STA1 is the initial idle state."""
        assert AssociationState.STA1.name == "STA1"
        assert AssociationState.STA1.value is not None

    def test_all_states_defined(self) -> None:
        """Test all 13 association states are defined."""
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
        actual_states = [s.name for s in AssociationState]
        assert sorted(actual_states) == sorted(expected_states)

    def test_state_uniqueness(self) -> None:
        """Test all states have unique values."""
        values = [s.value for s in AssociationState]
        assert len(values) == len(set(values))


class TestProtocolEvent:
    """Tests for ProtocolEvent enum."""

    def test_association_events(self) -> None:
        """Test association events are defined."""
        assert ProtocolEvent.A_ASSOCIATE_RQ.name == "A_ASSOCIATE_RQ"
        assert ProtocolEvent.A_ASSOCIATE_AC.name == "A_ASSOCIATE_AC"
        assert ProtocolEvent.A_ASSOCIATE_RJ.name == "A_ASSOCIATE_RJ"

    def test_release_events(self) -> None:
        """Test release events are defined."""
        assert ProtocolEvent.A_RELEASE_RQ.name == "A_RELEASE_RQ"
        assert ProtocolEvent.A_RELEASE_RP.name == "A_RELEASE_RP"

    def test_abort_events(self) -> None:
        """Test abort events are defined."""
        assert ProtocolEvent.A_ABORT.name == "A_ABORT"
        assert ProtocolEvent.A_P_ABORT.name == "A_P_ABORT"

    def test_data_transfer_events(self) -> None:
        """Test data transfer events are defined."""
        assert ProtocolEvent.P_DATA_TF.name == "P_DATA_TF"

    def test_transport_events(self) -> None:
        """Test transport events are defined."""
        assert ProtocolEvent.TRANSPORT_CONNECT.name == "TRANSPORT_CONNECT"
        assert (
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM.name == "TRANSPORT_CONNECT_CONFIRM"
        )
        assert ProtocolEvent.TRANSPORT_CLOSE.name == "TRANSPORT_CLOSE"

    def test_timer_events(self) -> None:
        """Test timer events are defined."""
        assert ProtocolEvent.ARTIM_TIMEOUT.name == "ARTIM_TIMEOUT"


class TestTransitionType:
    """Tests for TransitionType enum."""

    def test_all_types(self) -> None:
        """Test all transition types are defined."""
        expected_types = ["VALID", "INVALID", "UNEXPECTED", "MALFORMED", "DUPLICATE"]
        actual_types = [t.name for t in TransitionType]
        assert sorted(actual_types) == sorted(expected_types)


class TestStateTransition:
    """Tests for StateTransition dataclass."""

    def test_basic_transition(self) -> None:
        """Test creating a basic state transition."""
        transition = StateTransition(
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA4,
            event=ProtocolEvent.A_ASSOCIATE_RQ,
        )

        assert transition.from_state == AssociationState.STA1
        assert transition.to_state == AssociationState.STA4
        assert transition.event == ProtocolEvent.A_ASSOCIATE_RQ
        assert transition.transition_type == TransitionType.VALID

    def test_transition_with_description(self) -> None:
        """Test transition with description."""
        transition = StateTransition(
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA4,
            event=ProtocolEvent.A_ASSOCIATE_RQ,
            description="AE-1: Issue transport connect",
        )

        assert transition.description == "AE-1: Issue transport connect"

    def test_invalid_transition_type(self) -> None:
        """Test creating invalid transition."""
        transition = StateTransition(
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA1,
            event=ProtocolEvent.P_DATA_TF,
            transition_type=TransitionType.INVALID,
        )

        assert transition.transition_type == TransitionType.INVALID


class TestStateMachineConfig:
    """Tests for StateMachineConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = StateMachineConfig()

        assert config.probability_invalid_transition == 0.2
        assert config.probability_out_of_order == 0.1
        assert config.probability_duplicate == 0.05
        assert config.enable_timing_attacks is True
        assert config.min_delay_ms == 0
        assert config.max_delay_ms == 5000
        assert config.enable_state_confusion is True
        assert config.confusion_depth == 3
        assert config.track_state_coverage is True
        assert config.track_transition_coverage is True

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = StateMachineConfig(
            probability_invalid_transition=0.5,
            probability_out_of_order=0.3,
            enable_timing_attacks=False,
            confusion_depth=5,
        )

        assert config.probability_invalid_transition == 0.5
        assert config.probability_out_of_order == 0.3
        assert config.enable_timing_attacks is False
        assert config.confusion_depth == 5


class TestDICOMStateMachine:
    """Tests for DICOMStateMachine class."""

    @pytest.fixture
    def state_machine(self) -> DICOMStateMachine:
        """Create state machine instance."""
        return DICOMStateMachine()

    def test_init(self, state_machine: DICOMStateMachine) -> None:
        """Test state machine initialization."""
        assert state_machine.valid_transitions is not None
        assert state_machine.invalid_transitions is not None
        assert len(state_machine.valid_transitions) > 0
        assert len(state_machine.invalid_transitions) > 0

    def test_valid_transitions_from_sta1(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test valid transitions from idle state."""
        valid_events = state_machine.get_valid_events(AssociationState.STA1)

        assert ProtocolEvent.A_ASSOCIATE_RQ in valid_events
        assert ProtocolEvent.TRANSPORT_CONNECT in valid_events

    def test_valid_transitions_from_sta6(
        self, state_machine: DICOMStateMachine
    ) -> None:
        """Test valid transitions from established state."""
        valid_events = state_machine.get_valid_events(AssociationState.STA6)

        assert ProtocolEvent.P_DATA_TF in valid_events
        assert ProtocolEvent.A_RELEASE_RQ in valid_events
        assert ProtocolEvent.A_ABORT in valid_events

    def test_invalid_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test invalid transitions are identified."""
        # P_DATA_TF should be invalid in STA1
        invalid_events = state_machine.get_invalid_events(AssociationState.STA1)

        assert ProtocolEvent.P_DATA_TF in invalid_events

    def test_get_transition_valid(self, state_machine: DICOMStateMachine) -> None:
        """Test getting valid transition."""
        transition = state_machine.get_transition(
            AssociationState.STA1, ProtocolEvent.A_ASSOCIATE_RQ
        )

        assert transition is not None
        assert transition.transition_type == TransitionType.VALID
        assert transition.to_state == AssociationState.STA4

    def test_get_transition_invalid(self, state_machine: DICOMStateMachine) -> None:
        """Test getting invalid transition."""
        transition = state_machine.get_transition(
            AssociationState.STA1, ProtocolEvent.P_DATA_TF
        )

        assert transition is not None
        assert transition.transition_type == TransitionType.INVALID

    def test_get_all_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test getting all transitions."""
        all_transitions = state_machine.get_all_transitions()

        # Should have both valid and invalid
        valid_count = sum(
            1 for t in all_transitions if t.transition_type == TransitionType.VALID
        )
        invalid_count = sum(
            1 for t in all_transitions if t.transition_type == TransitionType.INVALID
        )

        assert valid_count > 0
        assert invalid_count > 0

    def test_sta2_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA2."""
        valid = state_machine.get_valid_events(AssociationState.STA2)
        assert ProtocolEvent.A_ASSOCIATE_RQ in valid

    def test_sta3_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA3."""
        valid = state_machine.get_valid_events(AssociationState.STA3)
        assert ProtocolEvent.A_ASSOCIATE_AC in valid
        assert ProtocolEvent.A_ASSOCIATE_RJ in valid

    def test_sta4_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA4."""
        valid = state_machine.get_valid_events(AssociationState.STA4)
        assert ProtocolEvent.TRANSPORT_CONNECT_CONFIRM in valid

    def test_sta5_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA5."""
        valid = state_machine.get_valid_events(AssociationState.STA5)
        assert ProtocolEvent.A_ASSOCIATE_AC in valid
        assert ProtocolEvent.A_ASSOCIATE_RJ in valid

    def test_sta7_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA7."""
        valid = state_machine.get_valid_events(AssociationState.STA7)
        assert ProtocolEvent.A_RELEASE_RP in valid
        assert ProtocolEvent.A_RELEASE_RQ in valid  # Release collision

    def test_sta9_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA9."""
        valid = state_machine.get_valid_events(AssociationState.STA9)
        assert ProtocolEvent.A_RELEASE_RP in valid

    def test_sta13_transitions(self, state_machine: DICOMStateMachine) -> None:
        """Test transitions from STA13."""
        valid = state_machine.get_valid_events(AssociationState.STA13)
        assert ProtocolEvent.TRANSPORT_CLOSE in valid


class TestFuzzSequence:
    """Tests for FuzzSequence dataclass."""

    def test_basic_sequence(self) -> None:
        """Test creating basic sequence."""
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        seq = FuzzSequence(events=events)

        assert len(seq.events) == 3
        assert seq.attack_type == "generic"

    def test_sequence_with_states(self) -> None:
        """Test sequence with expected states."""
        events = [ProtocolEvent.A_ASSOCIATE_RQ]
        states = [AssociationState.STA1, AssociationState.STA4]

        seq = FuzzSequence(
            events=events,
            expected_states=states,
            description="Test sequence",
            attack_type="test",
        )

        assert seq.expected_states == states
        assert seq.description == "Test sequence"
        assert seq.attack_type == "test"


class TestSequenceGenerator:
    """Tests for SequenceGenerator class."""

    @pytest.fixture
    def generator(self) -> SequenceGenerator:
        """Create sequence generator."""
        sm = DICOMStateMachine()
        return SequenceGenerator(sm)

    def test_generate_valid_sequence(self, generator: SequenceGenerator) -> None:
        """Test generating valid sequence."""
        seq = generator.generate_valid_sequence()

        assert isinstance(seq, FuzzSequence)
        assert len(seq.events) > 0
        assert seq.attack_type == "baseline"

    def test_generate_valid_sequence_with_target(
        self, generator: SequenceGenerator
    ) -> None:
        """Test generating sequence to target state."""
        seq = generator.generate_valid_sequence(
            target_state=AssociationState.STA6,
            max_length=10,
        )

        assert isinstance(seq, FuzzSequence)
        # Should reach STA6 or stop trying
        assert len(seq.events) <= 10

    def test_generate_invalid_transition_sequence(
        self, generator: SequenceGenerator
    ) -> None:
        """Test generating invalid transition sequence."""
        seq = generator.generate_invalid_transition_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "invalid_transition"

    def test_generate_out_of_order_sequence(self, generator: SequenceGenerator) -> None:
        """Test generating out-of-order sequence."""
        seq = generator.generate_out_of_order_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "out_of_order"
        assert len(seq.events) > 0

    def test_generate_state_confusion_sequence(
        self, generator: SequenceGenerator
    ) -> None:
        """Test generating state confusion sequence."""
        seq = generator.generate_state_confusion_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "state_confusion"
        # Should have rapid state changes
        assert len(seq.events) > 5

    def test_generate_duplicate_sequence(self, generator: SequenceGenerator) -> None:
        """Test generating duplicate message sequence."""
        seq = generator.generate_duplicate_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "duplicate"
        # Should have repeated events
        events = seq.events
        assert len(events) > len(set(events))  # Has duplicates

    def test_generate_release_collision_sequence(
        self, generator: SequenceGenerator
    ) -> None:
        """Test generating release collision sequence."""
        seq = generator.generate_release_collision_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "release_collision"
        # Should have release events
        assert ProtocolEvent.A_RELEASE_RQ in seq.events

    def test_generate_abort_recovery_sequence(
        self, generator: SequenceGenerator
    ) -> None:
        """Test generating abort recovery sequence."""
        seq = generator.generate_abort_recovery_sequence()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "abort_recovery"
        assert ProtocolEvent.A_ABORT in seq.events


class TestCoverageStats:
    """Tests for CoverageStats dataclass."""

    def test_default_values(self) -> None:
        """Test default coverage stats."""
        stats = CoverageStats()

        assert len(stats.states_visited) == 0
        assert len(stats.transitions_executed) == 0
        assert len(stats.invalid_transitions_tested) == 0
        assert stats.sequences_executed == 0

    def test_state_coverage_calculation(self) -> None:
        """Test state coverage percentage calculation."""
        stats = CoverageStats()
        stats.states_visited.add(AssociationState.STA1)
        stats.states_visited.add(AssociationState.STA4)
        stats.states_visited.add(AssociationState.STA5)
        stats.states_visited.add(AssociationState.STA6)

        # 4 out of 13 states = ~30.77%
        coverage = stats.state_coverage
        assert 30 < coverage < 32

    def test_transition_coverage_calculation(self) -> None:
        """Test transition coverage percentage calculation."""
        stats = CoverageStats()
        stats.transitions_executed.add(
            (AssociationState.STA1, ProtocolEvent.A_ASSOCIATE_RQ)
        )

        coverage = stats.transition_coverage
        assert coverage > 0


class TestTransitionResult:
    """Tests for TransitionResult dataclass."""

    def test_successful_result(self) -> None:
        """Test successful transition result."""
        result = TransitionResult(
            success=True,
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA4,
            event=ProtocolEvent.A_ASSOCIATE_RQ,
        )

        assert result.success is True
        assert result.error is None
        assert result.duration_ms == 0.0

    def test_failed_result(self) -> None:
        """Test failed transition result."""
        result = TransitionResult(
            success=False,
            from_state=AssociationState.STA1,
            to_state=AssociationState.STA1,
            event=ProtocolEvent.P_DATA_TF,
            error="Invalid transition",
        )

        assert result.success is False
        assert result.error == "Invalid transition"


class TestStatefulFuzzer:
    """Tests for StatefulFuzzer class."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        """Create stateful fuzzer."""
        return StatefulFuzzer()

    def test_init(self, fuzzer: StatefulFuzzer) -> None:
        """Test fuzzer initialization."""
        assert fuzzer.current_state == AssociationState.STA1
        assert fuzzer.state_machine is not None
        assert fuzzer.sequence_gen is not None
        assert fuzzer.coverage is not None

    def test_reset(self, fuzzer: StatefulFuzzer) -> None:
        """Test fuzzer reset."""
        fuzzer.current_state = AssociationState.STA6
        fuzzer.reset()

        assert fuzzer.current_state == AssociationState.STA1

    def test_execute_event_valid(self, fuzzer: StatefulFuzzer) -> None:
        """Test executing valid event."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)

        assert result.success is True
        assert result.from_state == AssociationState.STA1
        assert result.to_state == AssociationState.STA4
        assert fuzzer.current_state == AssociationState.STA4

    def test_execute_event_invalid(self, fuzzer: StatefulFuzzer) -> None:
        """Test executing invalid event."""
        result = fuzzer.execute_event(ProtocolEvent.P_DATA_TF)

        # Should succeed (we record the event) but not change state
        assert result.success is True
        assert fuzzer.current_state == AssociationState.STA1

    def test_execute_sequence(self, fuzzer: StatefulFuzzer) -> None:
        """Test executing sequence."""
        seq = FuzzSequence(
            events=[
                ProtocolEvent.A_ASSOCIATE_RQ,
                ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ]
        )

        results = fuzzer.execute_sequence(seq)

        assert len(results) == 2
        assert fuzzer.coverage.sequences_executed == 1

    def test_generate_fuzz_sequences(self, fuzzer: StatefulFuzzer) -> None:
        """Test generating fuzz sequences."""
        sequences = list(fuzzer.generate_fuzz_sequences(count=10))

        assert len(sequences) == 10
        for seq in sequences:
            assert isinstance(seq, FuzzSequence)

    def test_get_coverage_stats(self, fuzzer: StatefulFuzzer) -> None:
        """Test getting coverage statistics."""
        # Execute some events
        fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)

        stats = fuzzer.get_coverage_stats()

        assert "states_visited" in stats
        assert "total_states" in stats
        assert "state_coverage_pct" in stats
        assert "transitions_executed" in stats

    def test_get_untested_transitions(self, fuzzer: StatefulFuzzer) -> None:
        """Test getting untested transitions."""
        untested = fuzzer.get_untested_transitions()

        # Initially all valid transitions are untested
        assert len(untested) > 0

    def test_generate_targeted_sequences(self, fuzzer: StatefulFuzzer) -> None:
        """Test generating targeted sequences."""
        targets = [
            (AssociationState.STA6, ProtocolEvent.P_DATA_TF),
        ]

        sequences = list(fuzzer.generate_targeted_sequences(targets))

        assert len(sequences) == 1
        assert sequences[0].attack_type == "targeted"

    def test_coverage_tracking(self, fuzzer: StatefulFuzzer) -> None:
        """Test coverage is tracked during execution."""
        fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)

        assert AssociationState.STA1 in fuzzer.coverage.states_visited
        assert AssociationState.STA4 in fuzzer.coverage.states_visited
        assert (
            AssociationState.STA1,
            ProtocolEvent.A_ASSOCIATE_RQ,
        ) in fuzzer.coverage.transitions_executed


class TestTimingAttackGenerator:
    """Tests for TimingAttackGenerator class."""

    @pytest.fixture
    def generator(self) -> TimingAttackGenerator:
        """Create timing attack generator."""
        return TimingAttackGenerator()

    def test_generate_timeout_attack(self, generator: TimingAttackGenerator) -> None:
        """Test generating timeout attack."""
        seq = generator.generate_timeout_attack()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "timeout"
        assert ProtocolEvent.A_ASSOCIATE_RQ in seq.events

    def test_generate_slow_data_attack(self, generator: TimingAttackGenerator) -> None:
        """Test generating slow data attack."""
        seq = generator.generate_slow_data_attack()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "slow_data"
        # Should have many data transfers
        data_count = seq.events.count(ProtocolEvent.P_DATA_TF)
        assert data_count >= 100

    def test_generate_rapid_reconnect_attack(
        self, generator: TimingAttackGenerator
    ) -> None:
        """Test generating rapid reconnect attack."""
        seq = generator.generate_rapid_reconnect_attack()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "rapid_reconnect"
        # Should have many connect/abort cycles
        assert seq.events.count(ProtocolEvent.A_ABORT) >= 50


class TestResourceExhaustionGenerator:
    """Tests for ResourceExhaustionGenerator class."""

    @pytest.fixture
    def generator(self) -> ResourceExhaustionGenerator:
        """Create resource exhaustion generator."""
        return ResourceExhaustionGenerator()

    def test_generate_connection_exhaustion(
        self, generator: ResourceExhaustionGenerator
    ) -> None:
        """Test generating connection exhaustion attack."""
        sequences = generator.generate_connection_exhaustion(num_connections=10)

        assert len(sequences) == 10
        for seq in sequences:
            assert seq.attack_type == "connection_exhaustion"
            assert ProtocolEvent.A_ASSOCIATE_AC in seq.events

    def test_generate_pending_release_exhaustion(
        self, generator: ResourceExhaustionGenerator
    ) -> None:
        """Test generating pending release exhaustion."""
        seq = generator.generate_pending_release_exhaustion()

        assert isinstance(seq, FuzzSequence)
        assert seq.attack_type == "pending_release"
        # Should have many release requests
        assert seq.events.count(ProtocolEvent.A_RELEASE_RQ) >= 100


class TestCustomConfig:
    """Tests with custom configuration."""

    def test_fuzzer_with_custom_config(self) -> None:
        """Test fuzzer with custom configuration."""
        config = StateMachineConfig(
            probability_invalid_transition=0.5,
            confusion_depth=10,
        )

        fuzzer = StatefulFuzzer(config)

        assert fuzzer.config.probability_invalid_transition == 0.5
        assert fuzzer.config.confusion_depth == 10

    def test_sequence_generator_with_custom_config(self) -> None:
        """Test sequence generator with custom config."""
        config = StateMachineConfig(confusion_depth=5)
        sm = DICOMStateMachine()
        gen = SequenceGenerator(sm, config)

        seq = gen.generate_state_confusion_sequence()

        # Should have 5 cycles + abort
        assert len(seq.events) > 20


class TestEdgeCases:
    """Tests for edge cases."""

    def test_execute_event_with_message_generator(self) -> None:
        """Test execute event with message generator."""
        fuzzer = StatefulFuzzer()

        def mock_generator(event: ProtocolEvent) -> bytes:
            return b"mock message"

        result = fuzzer.execute_event(
            ProtocolEvent.A_ASSOCIATE_RQ,
            message_generator=mock_generator,
        )

        assert result.success is True

    def test_execute_sequence_with_delay(self) -> None:
        """Test sequence execution with delay."""
        fuzzer = StatefulFuzzer()
        seq = FuzzSequence(events=[ProtocolEvent.A_ASSOCIATE_RQ])

        results = fuzzer.execute_sequence(seq, delay_between_events_ms=10)

        assert len(results) == 1

    def test_valid_sequence_no_valid_events(self) -> None:
        """Test generating sequence when no valid events available."""
        sm = DICOMStateMachine()
        gen = SequenceGenerator(sm)

        # Generate with max_length 0
        seq = gen.generate_valid_sequence(max_length=0)

        assert len(seq.events) == 0

    def test_invalid_transition_sequence_target_state(self) -> None:
        """Test invalid transition with different target states."""
        sm = DICOMStateMachine()
        gen = SequenceGenerator(sm)

        # Try with different target states
        for state in [AssociationState.STA1, AssociationState.STA5]:
            seq = gen.generate_invalid_transition_sequence(target_state=state)
            assert isinstance(seq, FuzzSequence)

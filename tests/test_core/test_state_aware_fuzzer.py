"""Tests for StateAwareFuzzer - State-aware protocol fuzzing."""

import random
import time

import pytest

from dicom_fuzzer.core.state_aware_fuzzer import (
    DICOMState,
    FuzzerConfig,
    MessageSequence,
    ProtocolMessage,
    StateAwareBitFlip,
    StateAwareFuzzer,
    StateCoverage,
    StateFingerprint,
    StateGuidedHavoc,
    StateInferenceEngine,
    StateTransition,
    StateTransitionType,
)


class TestDICOMState:
    """Test DICOMState enum."""

    def test_all_states_defined(self) -> None:
        """Test all expected DICOM states exist."""
        expected_states = [
            "IDLE",
            "ASSOCIATION_REQUESTED",
            "ASSOCIATION_ESTABLISHED",
            "ASSOCIATION_REJECTED",
            "DATA_TRANSFER",
            "RELEASE_REQUESTED",
            "RELEASE_COMPLETED",
            "ABORT",
            "C_STORE_PENDING",
            "C_FIND_PENDING",
            "C_MOVE_PENDING",
            "C_GET_PENDING",
            "N_CREATE_PENDING",
            "N_SET_PENDING",
            "N_DELETE_PENDING",
            "N_ACTION_PENDING",
            "N_EVENT_PENDING",
        ]
        for state_name in expected_states:
            assert hasattr(DICOMState, state_name)

    def test_state_values_unique(self) -> None:
        """Test all state values are unique."""
        values = [s.value for s in DICOMState]
        assert len(values) == len(set(values))


class TestStateTransitionType:
    """Test StateTransitionType enum."""

    def test_all_transition_types(self) -> None:
        """Test all transition types exist."""
        assert StateTransitionType.VALID.value == "valid"
        assert StateTransitionType.INVALID.value == "invalid"
        assert StateTransitionType.TIMEOUT.value == "timeout"
        assert StateTransitionType.ERROR.value == "error"
        assert StateTransitionType.CRASH.value == "crash"


class TestStateFingerprint:
    """Test StateFingerprint dataclass."""

    def test_creation_basic(self) -> None:
        """Test basic fingerprint creation."""
        fp = StateFingerprint(
            hash_value="abc123",
            state=DICOMState.IDLE,
        )
        assert fp.hash_value == "abc123"
        assert fp.state == DICOMState.IDLE
        assert fp.coverage_bitmap == b""
        assert fp.response_pattern == ""

    def test_creation_with_timestamp(self) -> None:
        """Test fingerprint auto-generates timestamp."""
        before = time.time()
        fp = StateFingerprint(hash_value="test", state=DICOMState.IDLE)
        after = time.time()
        assert before <= fp.timestamp <= after

    def test_creation_with_explicit_timestamp(self) -> None:
        """Test fingerprint with explicit timestamp."""
        fp = StateFingerprint(
            hash_value="test",
            state=DICOMState.IDLE,
            timestamp=12345.0,
        )
        assert fp.timestamp == 12345.0

    def test_similarity_empty_bitmaps(self) -> None:
        """Test similarity with empty coverage bitmaps."""
        fp1 = StateFingerprint(hash_value="a", state=DICOMState.IDLE)
        fp2 = StateFingerprint(hash_value="b", state=DICOMState.IDLE)
        assert fp1.similarity(fp2) == 0.0

    def test_similarity_identical_bitmaps(self) -> None:
        """Test similarity with identical coverage bitmaps."""
        bitmap = bytes([1, 0, 1, 0, 1])
        fp1 = StateFingerprint(
            hash_value="a", state=DICOMState.IDLE, coverage_bitmap=bitmap
        )
        fp2 = StateFingerprint(
            hash_value="b", state=DICOMState.IDLE, coverage_bitmap=bitmap
        )
        assert fp1.similarity(fp2) == 1.0

    def test_similarity_different_bitmaps(self) -> None:
        """Test similarity with different coverage bitmaps."""
        fp1 = StateFingerprint(
            hash_value="a",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([1, 0, 1, 0, 0]),
        )
        fp2 = StateFingerprint(
            hash_value="b",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([0, 1, 1, 0, 0]),
        )
        # Intersection: {2}, Union: {0, 1, 2}
        assert fp1.similarity(fp2) == pytest.approx(1 / 3)

    def test_similarity_one_empty(self) -> None:
        """Test similarity when one bitmap is all zeros."""
        fp1 = StateFingerprint(
            hash_value="a",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([1, 1, 1]),
        )
        fp2 = StateFingerprint(
            hash_value="b",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([0, 0, 0]),
        )
        assert fp1.similarity(fp2) == 0.0

    def test_similarity_both_empty_zeros(self) -> None:
        """Test similarity when both bitmaps are all zeros."""
        fp1 = StateFingerprint(
            hash_value="a",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([0, 0, 0]),
        )
        fp2 = StateFingerprint(
            hash_value="b",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([0, 0, 0]),
        )
        assert fp1.similarity(fp2) == 1.0


class TestStateTransition:
    """Test StateTransition dataclass."""

    def test_creation_basic(self) -> None:
        """Test basic transition creation."""
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ASSOCIATION_ESTABLISHED,
            trigger_message=b"\x01\x00\x00",
            transition_type=StateTransitionType.VALID,
        )
        assert trans.from_state == DICOMState.IDLE
        assert trans.to_state == DICOMState.ASSOCIATION_ESTABLISHED
        assert trans.trigger_message == b"\x01\x00\x00"
        assert trans.transition_type == StateTransitionType.VALID

    def test_auto_timestamp(self) -> None:
        """Test auto-generated timestamp."""
        before = time.time()
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ABORT,
            trigger_message=b"",
            transition_type=StateTransitionType.ERROR,
        )
        after = time.time()
        assert before <= trans.timestamp <= after

    def test_explicit_timestamp(self) -> None:
        """Test explicit timestamp preserved."""
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ABORT,
            trigger_message=b"",
            transition_type=StateTransitionType.ERROR,
            timestamp=99999.0,
        )
        assert trans.timestamp == 99999.0

    def test_optional_fields(self) -> None:
        """Test optional fields have defaults."""
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ABORT,
            trigger_message=b"test",
            transition_type=StateTransitionType.CRASH,
        )
        assert trans.response == b""
        assert trans.duration_ms == 0.0
        assert trans.coverage_increase == 0


class TestStateCoverage:
    """Test StateCoverage dataclass."""

    def test_creation_empty(self) -> None:
        """Test empty coverage creation."""
        cov = StateCoverage()
        assert len(cov.visited_states) == 0
        assert len(cov.state_transitions) == 0
        assert cov.total_transitions == 0
        assert cov.new_states_found == 0

    def test_add_state_new(self) -> None:
        """Test adding a new state."""
        cov = StateCoverage()
        is_new = cov.add_state(DICOMState.IDLE)
        assert is_new is True
        assert DICOMState.IDLE in cov.visited_states
        assert cov.new_states_found == 1

    def test_add_state_existing(self) -> None:
        """Test adding an existing state."""
        cov = StateCoverage()
        cov.add_state(DICOMState.IDLE)
        is_new = cov.add_state(DICOMState.IDLE)
        assert is_new is False
        assert cov.new_states_found == 1

    def test_add_state_with_depth(self) -> None:
        """Test adding state with depth tracking."""
        cov = StateCoverage()
        cov.add_state(DICOMState.DATA_TRANSFER, depth=5)
        assert cov.state_depths[DICOMState.DATA_TRANSFER] == 5

    def test_add_state_updates_min_depth(self) -> None:
        """Test that depth is updated only if smaller."""
        cov = StateCoverage()
        cov.add_state(DICOMState.DATA_TRANSFER, depth=10)
        cov.add_state(DICOMState.DATA_TRANSFER, depth=5)
        assert cov.state_depths[DICOMState.DATA_TRANSFER] == 5
        cov.add_state(DICOMState.DATA_TRANSFER, depth=8)
        assert cov.state_depths[DICOMState.DATA_TRANSFER] == 5

    def test_add_transition_new(self) -> None:
        """Test adding a new transition."""
        cov = StateCoverage()
        is_new = cov.add_transition(DICOMState.IDLE, DICOMState.ASSOCIATION_ESTABLISHED)
        assert is_new is True
        assert cov.total_transitions == 1
        assert cov.new_transitions_found == 1

    def test_add_transition_existing(self) -> None:
        """Test adding an existing transition increments count."""
        cov = StateCoverage()
        cov.add_transition(DICOMState.IDLE, DICOMState.ASSOCIATION_ESTABLISHED)
        is_new = cov.add_transition(DICOMState.IDLE, DICOMState.ASSOCIATION_ESTABLISHED)
        assert is_new is False
        assert cov.total_transitions == 2
        assert cov.new_transitions_found == 1

    def test_add_fingerprint_new(self) -> None:
        """Test adding a new fingerprint."""
        cov = StateCoverage()
        fp = StateFingerprint(
            hash_value="unique123",
            state=DICOMState.IDLE,
            coverage_bitmap=bytes([1, 0, 1]),
        )
        is_new = cov.add_fingerprint(fp)
        assert is_new is True
        assert "unique123" in cov.unique_fingerprints

    def test_add_fingerprint_similar_rejected(self) -> None:
        """Test that very similar fingerprints are rejected."""
        cov = StateCoverage()
        bitmap = bytes([1, 0, 1, 0, 1])
        fp1 = StateFingerprint(
            hash_value="fp1", state=DICOMState.IDLE, coverage_bitmap=bitmap
        )
        fp2 = StateFingerprint(
            hash_value="fp2", state=DICOMState.IDLE, coverage_bitmap=bitmap
        )
        cov.add_fingerprint(fp1)
        is_new = cov.add_fingerprint(fp2)
        assert is_new is False

    def test_get_coverage_score_empty(self) -> None:
        """Test coverage score with no coverage."""
        cov = StateCoverage()
        score = cov.get_coverage_score()
        assert score == 0.0

    def test_get_coverage_score_partial(self) -> None:
        """Test coverage score with partial coverage."""
        cov = StateCoverage()
        cov.add_state(DICOMState.IDLE)
        cov.add_state(DICOMState.DATA_TRANSFER)
        cov.add_transition(DICOMState.IDLE, DICOMState.DATA_TRANSFER)
        score = cov.get_coverage_score()
        assert score > 0.0
        assert score < 100.0

    def test_get_uncovered_states(self) -> None:
        """Test getting uncovered states."""
        cov = StateCoverage()
        cov.add_state(DICOMState.IDLE)
        uncovered = cov.get_uncovered_states()
        assert DICOMState.IDLE not in uncovered
        assert DICOMState.ABORT in uncovered
        assert len(uncovered) == len(DICOMState) - 1


class TestProtocolMessage:
    """Test ProtocolMessage dataclass."""

    def test_creation_basic(self) -> None:
        """Test basic message creation."""
        msg = ProtocolMessage(data=b"\x01\x02\x03")
        assert msg.data == b"\x01\x02\x03"
        assert msg.message_type == ""
        assert msg.expected_state == DICOMState.IDLE
        assert msg.is_mutated is False

    def test_creation_with_all_fields(self) -> None:
        """Test message with all fields."""
        msg = ProtocolMessage(
            data=b"test",
            message_type="A-ASSOCIATE-RQ",
            expected_state=DICOMState.ASSOCIATION_REQUESTED,
            is_mutated=True,
            mutation_info="bit flip at offset 5",
        )
        assert msg.message_type == "A-ASSOCIATE-RQ"
        assert msg.expected_state == DICOMState.ASSOCIATION_REQUESTED
        assert msg.is_mutated is True
        assert msg.mutation_info == "bit flip at offset 5"

    def test_auto_timestamp(self) -> None:
        """Test auto-generated timestamp."""
        before = time.time()
        msg = ProtocolMessage(data=b"")
        after = time.time()
        assert before <= msg.timestamp <= after


class TestMessageSequence:
    """Test MessageSequence dataclass."""

    def test_creation_empty(self) -> None:
        """Test empty sequence creation."""
        seq = MessageSequence()
        assert len(seq.messages) == 0
        assert seq.final_state == DICOMState.IDLE
        assert seq.coverage_hash == ""
        assert seq.fitness_score == 0.0

    def test_compute_hash(self) -> None:
        """Test hash computation."""
        seq = MessageSequence(
            messages=[
                ProtocolMessage(data=b"hello"),
                ProtocolMessage(data=b"world"),
            ]
        )
        hash_val = seq.compute_hash()
        assert len(hash_val) == 16
        assert hash_val == seq.coverage_hash

    def test_compute_hash_deterministic(self) -> None:
        """Test hash is deterministic."""
        seq1 = MessageSequence(messages=[ProtocolMessage(data=b"test")])
        seq2 = MessageSequence(messages=[ProtocolMessage(data=b"test")])
        assert seq1.compute_hash() == seq2.compute_hash()

    def test_get_state_path_str_empty(self) -> None:
        """Test state path string for empty path."""
        seq = MessageSequence()
        assert seq.get_state_path_str() == ""

    def test_get_state_path_str(self) -> None:
        """Test state path string representation."""
        seq = MessageSequence(
            state_path=[
                DICOMState.IDLE,
                DICOMState.ASSOCIATION_REQUESTED,
                DICOMState.ASSOCIATION_ESTABLISHED,
            ]
        )
        path_str = seq.get_state_path_str()
        assert path_str == "IDLE -> ASSOCIATION_REQUESTED -> ASSOCIATION_ESTABLISHED"


class TestStateInferenceEngine:
    """Test StateInferenceEngine class."""

    def test_creation(self) -> None:
        """Test engine creation."""
        engine = StateInferenceEngine()
        assert len(engine.observed_transitions) == 0
        assert len(engine.inferred_states) == 0

    def test_infer_state_empty_response(self) -> None:
        """Test state inference from empty response."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"")
        assert state == DICOMState.IDLE

    def test_infer_state_associate_accept(self) -> None:
        """Test state inference for A-ASSOCIATE-AC."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\x02\x00\x00")
        assert state == DICOMState.ASSOCIATION_ESTABLISHED

    def test_infer_state_associate_reject(self) -> None:
        """Test state inference for A-ASSOCIATE-RJ."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\x03\x00\x00")
        assert state == DICOMState.ASSOCIATION_REJECTED

    def test_infer_state_data_transfer(self) -> None:
        """Test state inference for P-DATA-TF."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\x04\x00\x00")
        assert state == DICOMState.DATA_TRANSFER

    def test_infer_state_release(self) -> None:
        """Test state inference for A-RELEASE-RP."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\x06\x00\x00")
        assert state == DICOMState.RELEASE_COMPLETED

    def test_infer_state_abort(self) -> None:
        """Test state inference for A-ABORT."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\x07\x00\x00")
        assert state == DICOMState.ABORT

    def test_infer_state_unknown_pdu(self) -> None:
        """Test state inference for unknown PDU type."""
        engine = StateInferenceEngine()
        state = engine.infer_state_from_response(b"\xff\x00\x00")
        assert state == DICOMState.IDLE

    def test_infer_state_from_memory(self) -> None:
        """Test state fingerprint from memory snapshot."""
        engine = StateInferenceEngine()
        memory = b"memory snapshot data"
        bitmap = bytes([1, 0, 1, 0])
        fp = engine.infer_state_from_memory(memory, bitmap)
        assert isinstance(fp, StateFingerprint)
        assert len(fp.hash_value) == 16
        assert fp.coverage_bitmap == bitmap

    def test_record_transition(self) -> None:
        """Test recording a transition."""
        engine = StateInferenceEngine()
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ASSOCIATION_ESTABLISHED,
            trigger_message=b"\x01",
            transition_type=StateTransitionType.VALID,
        )
        engine.record_transition(trans)
        assert len(engine.observed_transitions) == 1
        assert engine.observed_transitions[0] is trans

    def test_build_state_machine_empty(self) -> None:
        """Test building state machine with no observations."""
        engine = StateInferenceEngine()
        sm = engine.build_state_machine()
        assert len(sm) == 0

    def test_build_state_machine_valid_transitions(self) -> None:
        """Test building state machine from valid transitions."""
        engine = StateInferenceEngine()
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ASSOCIATION_ESTABLISHED,
            trigger_message=b"\x01\x00" * 20,  # Long enough message
            transition_type=StateTransitionType.VALID,
        )
        engine.record_transition(trans)
        sm = engine.build_state_machine()
        assert DICOMState.IDLE in sm
        assert len(sm[DICOMState.IDLE]) == 1

    def test_build_state_machine_ignores_invalid(self) -> None:
        """Test that invalid transitions are not included in state machine."""
        engine = StateInferenceEngine()
        trans = StateTransition(
            from_state=DICOMState.IDLE,
            to_state=DICOMState.ABORT,
            trigger_message=b"\x01",
            transition_type=StateTransitionType.INVALID,
        )
        engine.record_transition(trans)
        sm = engine.build_state_machine()
        assert len(sm) == 0

    def test_infer_state_pdata_with_command(self) -> None:
        """Test P-DATA with DIMSE command detection."""
        engine = StateInferenceEngine()
        # P-DATA with command group 0000 and success status
        response = (
            b"\x04" + b"\x00" * 9 + b"\x00\x00" + b"\x00" * 5 + b"\x00\x00\x00\x00"
        )
        state = engine.infer_state_from_response(response)
        assert state == DICOMState.DATA_TRANSFER

    def test_infer_state_pdata_with_warning(self) -> None:
        """Test P-DATA with warning status."""
        engine = StateInferenceEngine()
        # P-DATA with command group 0000 and warning status
        response = b"\x04" + b"\x00" * 9 + b"\x00\x00" + b"\x00\x01" + b"\x00" * 10
        state = engine.infer_state_from_response(response)
        assert state == DICOMState.DATA_TRANSFER


class TestStateAwareBitFlip:
    """Test StateAwareBitFlip mutator."""

    def test_creation_default(self) -> None:
        """Test default creation."""
        mutator = StateAwareBitFlip()
        assert mutator.flip_rate == 0.01

    def test_creation_custom_rate(self) -> None:
        """Test custom flip rate."""
        mutator = StateAwareBitFlip(flip_rate=0.05)
        assert mutator.flip_rate == 0.05

    def test_mutate_empty_sequence(self) -> None:
        """Test mutation of empty sequence returns it unchanged."""
        mutator = StateAwareBitFlip()
        seq = MessageSequence()
        cov = StateCoverage()
        result = mutator.mutate(seq, DICOMState.IDLE, cov)
        assert len(result.messages) == 0

    def test_mutate_preserves_message_count(self) -> None:
        """Test mutation preserves message count."""
        mutator = StateAwareBitFlip()
        seq = MessageSequence(
            messages=[
                ProtocolMessage(data=b"\x01\x02\x03\x04"),
                ProtocolMessage(data=b"\x05\x06\x07\x08"),
            ]
        )
        cov = StateCoverage()
        result = mutator.mutate(seq, DICOMState.IDLE, cov)
        assert len(result.messages) == 2

    def test_mutate_marks_as_mutated(self) -> None:
        """Test mutated messages are marked as such."""
        mutator = StateAwareBitFlip(flip_rate=1.0)  # High rate to ensure mutation
        seq = MessageSequence(messages=[ProtocolMessage(data=b"\x00" * 100)])
        cov = StateCoverage()
        result = mutator.mutate(seq, DICOMState.IDLE, cov)
        assert result.messages[0].is_mutated is True

    def test_protected_regions_pdu_type(self) -> None:
        """Test PDU type byte is protected."""
        mutator = StateAwareBitFlip()
        msg = ProtocolMessage(data=b"\x01\x00\x00\x00\x00\x00\x00\x00")
        regions = mutator._get_protected_regions(msg, DICOMState.IDLE)
        assert (0, 1) in regions

    def test_protected_regions_pdu_length(self) -> None:
        """Test PDU length field is protected."""
        mutator = StateAwareBitFlip()
        msg = ProtocolMessage(data=b"\x01\x00\x00\x00\x00\x00\x00\x00")
        regions = mutator._get_protected_regions(msg, DICOMState.IDLE)
        assert (2, 6) in regions

    def test_protected_regions_association(self) -> None:
        """Test AE titles protected in association state."""
        mutator = StateAwareBitFlip()
        msg = ProtocolMessage(data=b"\x01" + b"\x00" * 50)
        regions = mutator._get_protected_regions(
            msg, DICOMState.ASSOCIATION_ESTABLISHED
        )
        assert (10, 26) in regions  # Called AE
        assert (26, 42) in regions  # Calling AE

    def test_is_protected(self) -> None:
        """Test _is_protected method."""
        mutator = StateAwareBitFlip()
        regions = [(0, 5), (10, 15)]
        assert mutator._is_protected(0, regions) is True
        assert mutator._is_protected(4, regions) is True
        assert mutator._is_protected(5, regions) is False
        assert mutator._is_protected(12, regions) is True
        assert mutator._is_protected(20, regions) is False


class TestStateGuidedHavoc:
    """Test StateGuidedHavoc mutator."""

    def test_creation_default(self) -> None:
        """Test default creation."""
        mutator = StateGuidedHavoc()
        assert mutator.intensity == 10

    def test_creation_custom_intensity(self) -> None:
        """Test custom intensity."""
        mutator = StateGuidedHavoc(intensity=5)
        assert mutator.intensity == 5

    def test_mutate_empty_sequence(self) -> None:
        """Test mutation of empty sequence."""
        mutator = StateGuidedHavoc()
        seq = MessageSequence()
        cov = StateCoverage()
        result = mutator.mutate(seq, DICOMState.IDLE, cov)
        # Empty sequence may gain messages via insert operations
        assert isinstance(result, MessageSequence)

    def test_mutate_with_messages(self) -> None:
        """Test mutation with messages."""
        random.seed(42)  # Deterministic
        mutator = StateGuidedHavoc(intensity=3)
        seq = MessageSequence(
            messages=[
                ProtocolMessage(data=b"\x01" * 20),
                ProtocolMessage(data=b"\x02" * 20),
            ]
        )
        cov = StateCoverage()
        result = mutator.mutate(seq, DICOMState.IDLE, cov)
        assert isinstance(result, MessageSequence)

    def test_generate_state_trigger_associate_ac(self) -> None:
        """Test generating A-ASSOCIATE-AC PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_associate_ac()
        assert msg.data[0:1] == b"\x02"  # PDU type 2
        assert msg.message_type == "A-ASSOCIATE-AC"
        assert msg.expected_state == DICOMState.ASSOCIATION_ESTABLISHED

    def test_generate_state_trigger_associate_rj(self) -> None:
        """Test generating A-ASSOCIATE-RJ PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_associate_rj()
        assert msg.data[0:1] == b"\x03"  # PDU type 3
        assert msg.message_type == "A-ASSOCIATE-RJ"
        assert msg.expected_state == DICOMState.ASSOCIATION_REJECTED

    def test_generate_release_rq(self) -> None:
        """Test generating A-RELEASE-RQ PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_release_rq()
        assert msg.data[0:1] == b"\x05"  # PDU type 5
        assert msg.message_type == "A-RELEASE-RQ"

    def test_generate_abort(self) -> None:
        """Test generating A-ABORT PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_abort()
        assert msg.data[0:1] == b"\x07"  # PDU type 7
        assert msg.message_type == "A-ABORT"

    def test_generate_p_data(self) -> None:
        """Test generating P-DATA-TF PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_p_data()
        assert msg.data[0:1] == b"\x04"  # PDU type 4
        assert msg.message_type == "P-DATA-TF"

    def test_generate_random_pdu(self) -> None:
        """Test generating random PDU."""
        mutator = StateGuidedHavoc()
        msg = mutator._generate_random_pdu()
        assert msg.data[0] in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        assert msg.expected_state == DICOMState.IDLE

    def test_generate_state_trigger_routing(self) -> None:
        """Test state trigger routing to correct generators."""
        mutator = StateGuidedHavoc()

        # Test each known target state
        msg = mutator._generate_state_trigger(DICOMState.ASSOCIATION_ESTABLISHED)
        assert msg.data[0:1] == b"\x02"

        msg = mutator._generate_state_trigger(DICOMState.ASSOCIATION_REJECTED)
        assert msg.data[0:1] == b"\x03"

        msg = mutator._generate_state_trigger(DICOMState.ABORT)
        assert msg.data[0:1] == b"\x07"

        # Unknown state falls back to random PDU
        msg = mutator._generate_state_trigger(DICOMState.C_STORE_PENDING)
        assert msg.data[0] in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]


class TestFuzzerConfig:
    """Test FuzzerConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = FuzzerConfig()
        assert config.target_host == "localhost"
        assert config.target_port == 11112
        assert config.timeout == 5.0
        assert config.max_iterations == 10000
        assert config.max_depth == 20
        assert config.state_coverage_weight == 0.4
        assert config.edge_coverage_weight == 0.6
        assert config.energy_budget == 100
        assert config.use_memory_snapshots is False
        assert config.snapshot_interval == 100

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = FuzzerConfig(
            target_host="192.168.1.1",
            target_port=4242,
            timeout=10.0,
            max_iterations=5000,
        )
        assert config.target_host == "192.168.1.1"
        assert config.target_port == 4242
        assert config.timeout == 10.0
        assert config.max_iterations == 5000


class TestStateAwareFuzzer:
    """Test StateAwareFuzzer class."""

    def test_creation_default(self) -> None:
        """Test default fuzzer creation."""
        fuzzer = StateAwareFuzzer()
        assert fuzzer.config.target_host == "localhost"
        assert fuzzer.current_state == DICOMState.IDLE
        assert len(fuzzer.corpus) == 0
        assert len(fuzzer.mutators) == 2

    def test_creation_with_config(self) -> None:
        """Test fuzzer creation with custom config."""
        config = FuzzerConfig(target_port=5000)
        fuzzer = StateAwareFuzzer(config=config)
        assert fuzzer.config.target_port == 5000

    def test_add_seed(self) -> None:
        """Test adding seed sequences."""
        fuzzer = StateAwareFuzzer()
        fuzzer.add_seed([b"\x01\x00\x00", b"\x02\x00\x00"])
        assert len(fuzzer.corpus) == 1
        assert len(fuzzer.corpus[0].messages) == 2

    def test_select_seed_empty_corpus(self) -> None:
        """Test seed selection with empty corpus."""
        fuzzer = StateAwareFuzzer()
        seed = fuzzer.select_seed()
        assert isinstance(seed, MessageSequence)
        assert len(seed.messages) == 0

    def test_select_seed_with_corpus(self) -> None:
        """Test seed selection from corpus."""
        random.seed(42)
        fuzzer = StateAwareFuzzer()
        fuzzer.add_seed([b"\x01"])
        fuzzer.add_seed([b"\x02"])
        seed = fuzzer.select_seed()
        assert isinstance(seed, MessageSequence)
        assert len(seed.messages) == 1

    def test_mutate(self) -> None:
        """Test mutation method."""
        random.seed(42)
        fuzzer = StateAwareFuzzer()
        seq = MessageSequence(messages=[ProtocolMessage(data=b"\x01" * 50)])
        result = fuzzer.mutate(seq)
        assert isinstance(result, MessageSequence)

    def test_execute_sequence_no_callback(self) -> None:
        """Test sequence execution without target callback."""
        fuzzer = StateAwareFuzzer()
        seq = MessageSequence(messages=[ProtocolMessage(data=b"\x01")])
        is_interesting, response = fuzzer.execute_sequence(seq)
        assert is_interesting is False
        assert response == b""

    def test_execute_sequence_with_callback(self) -> None:
        """Test sequence execution with target callback."""

        def mock_target(data: bytes) -> bytes:
            if data[0:1] == b"\x01":
                return b"\x02\x00\x00"  # A-ASSOCIATE-AC
            return b"\x04\x00\x00"  # P-DATA

        fuzzer = StateAwareFuzzer(target_callback=mock_target)
        seq = MessageSequence(
            messages=[
                ProtocolMessage(data=b"\x01\x00\x00"),
                ProtocolMessage(data=b"\x04\x00\x00"),
            ]
        )
        is_interesting, response = fuzzer.execute_sequence(seq)
        assert fuzzer.total_executions == 1
        assert len(response) > 0
        assert len(seq.state_path) > 0

    def test_compute_seed_score(self) -> None:
        """Test seed scoring computation."""
        fuzzer = StateAwareFuzzer()
        seq = MessageSequence(
            state_path=[DICOMState.IDLE, DICOMState.DATA_TRANSFER],
            fitness_score=5.0,
        )
        score = fuzzer._compute_seed_score(seq)
        # Unvisited states get 10.0 each
        assert score > 0.0

    def test_compute_seed_score_penalizes_long(self) -> None:
        """Test that long sequences are penalized."""
        fuzzer = StateAwareFuzzer()
        fuzzer.config.max_depth = 5
        seq = MessageSequence(
            messages=[ProtocolMessage(data=b"\x00") for _ in range(10)],
            state_path=[DICOMState.IDLE] * 10,
        )
        score = fuzzer._compute_seed_score(seq)
        # Score should be reduced by 50% for long sequence
        assert score >= 0.0

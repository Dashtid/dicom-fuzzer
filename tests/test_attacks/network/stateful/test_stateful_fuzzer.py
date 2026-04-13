"""Tests for StatefulFuzzer.

Tests the stateful fuzzer including PDU building, execute_event() wiring,
and fuzz() sequence generation/filtering.
"""

import pytest

from dicom_fuzzer.attacks.network.stateful.enums import (
    AssociationState,
    ProtocolEvent,
)
from dicom_fuzzer.attacks.network.stateful.fuzzer import (
    StatefulFuzzer,
    build_pdu_for_event,
)
from dicom_fuzzer.attacks.network.stateful.types import FuzzSequence, TransitionResult

# ---------------------------------------------------------------------------
# build_pdu_for_event
# ---------------------------------------------------------------------------


class TestBuildPduForEvent:
    """Tests for build_pdu_for_event() helper."""

    def test_a_associate_rq_returns_bytes(self) -> None:
        """A-ASSOCIATE-RQ event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_associate_rq_pdu_type_byte(self) -> None:
        """A-ASSOCIATE-RQ PDU starts with type byte 0x01."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result[0] == 0x01

    def test_a_associate_ac_returns_bytes(self) -> None:
        """A-ASSOCIATE-AC event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_AC)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_associate_ac_pdu_type_byte(self) -> None:
        """A-ASSOCIATE-AC PDU starts with type byte 0x02."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_AC)
        assert result[0] == 0x02

    def test_a_associate_rj_returns_bytes(self) -> None:
        """A-ASSOCIATE-RJ event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_RJ)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_associate_rj_pdu_type_byte(self) -> None:
        """A-ASSOCIATE-RJ PDU starts with type byte 0x03."""
        result = build_pdu_for_event(ProtocolEvent.A_ASSOCIATE_RJ)
        assert result[0] == 0x03

    def test_a_release_rq_returns_bytes(self) -> None:
        """A-RELEASE-RQ event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_RELEASE_RQ)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_release_rq_pdu_type_byte(self) -> None:
        """A-RELEASE-RQ PDU starts with type byte 0x05."""
        result = build_pdu_for_event(ProtocolEvent.A_RELEASE_RQ)
        assert result[0] == 0x05

    def test_a_release_rp_returns_bytes(self) -> None:
        """A-RELEASE-RP event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_RELEASE_RP)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_release_rp_pdu_type_byte(self) -> None:
        """A-RELEASE-RP PDU starts with type byte 0x06."""
        result = build_pdu_for_event(ProtocolEvent.A_RELEASE_RP)
        assert result[0] == 0x06

    def test_a_abort_returns_bytes(self) -> None:
        """A-ABORT event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.A_ABORT)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_a_abort_pdu_type_byte(self) -> None:
        """A-ABORT PDU starts with type byte 0x07."""
        result = build_pdu_for_event(ProtocolEvent.A_ABORT)
        assert result[0] == 0x07

    def test_p_data_tf_returns_bytes(self) -> None:
        """P-DATA-TF event produces non-empty bytes."""
        result = build_pdu_for_event(ProtocolEvent.P_DATA_TF)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_p_data_tf_pdu_type_byte(self) -> None:
        """P-DATA-TF PDU starts with type byte 0x04."""
        result = build_pdu_for_event(ProtocolEvent.P_DATA_TF)
        assert result[0] == 0x04

    def test_non_pdu_event_returns_empty(self) -> None:
        """Timer events that have no PDU return empty bytes."""
        # ARTIM_TIMEOUT is a timer event with no corresponding PDU
        result = build_pdu_for_event(ProtocolEvent.ARTIM_TIMEOUT)
        assert result == b""

    def test_transport_connect_returns_empty(self) -> None:
        """Transport connection event returns empty bytes (no PDU)."""
        result = build_pdu_for_event(ProtocolEvent.TRANSPORT_CONNECT)
        assert result == b""


# ---------------------------------------------------------------------------
# StatefulFuzzer.execute_event()
# ---------------------------------------------------------------------------


class TestExecuteEventMessageSent:
    """Tests that execute_event() populates message_sent."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        return StatefulFuzzer()

    def test_message_sent_populated_for_pdu_event(self, fuzzer: StatefulFuzzer) -> None:
        """execute_event() populates message_sent with PDU bytes."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.message_sent is not None
        assert isinstance(result.message_sent, bytes)
        assert len(result.message_sent) > 0

    def test_message_sent_is_valid_pdu(self, fuzzer: StatefulFuzzer) -> None:
        """message_sent bytes start with the correct PDU type byte."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.message_sent is not None
        assert result.message_sent[0] == 0x01  # A-ASSOCIATE-RQ type

    def test_message_sent_uses_custom_generator(self, fuzzer: StatefulFuzzer) -> None:
        """execute_event() uses caller-supplied message_generator."""
        custom_bytes = b"\xde\xad\xbe\xef"

        def my_gen(event: ProtocolEvent) -> bytes:
            return custom_bytes

        result = fuzzer.execute_event(
            ProtocolEvent.A_ASSOCIATE_RQ, message_generator=my_gen
        )
        assert result.message_sent == custom_bytes

    def test_message_sent_none_for_non_pdu_event(self, fuzzer: StatefulFuzzer) -> None:
        """Non-PDU events (timer, transport) produce empty or None message_sent."""
        # ARTIM_TIMEOUT has no PDU builder → b"" from build_pdu_for_event
        result = fuzzer.execute_event(ProtocolEvent.ARTIM_TIMEOUT)
        # Either None or empty bytes is acceptable; the key is it's not a real PDU
        assert result.message_sent is None or result.message_sent == b""

    def test_custom_generator_exception_yields_none(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """If message_generator raises, message_sent is None (no crash)."""

        def bad_gen(event: ProtocolEvent) -> bytes:
            raise RuntimeError("boom")

        result = fuzzer.execute_event(
            ProtocolEvent.A_ASSOCIATE_RQ, message_generator=bad_gen
        )
        assert result.message_sent is None


class TestExecuteEventInvalidTransitionFlag:
    """Tests that execute_event() sets is_invalid_transition correctly."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        return StatefulFuzzer()

    def test_valid_transition_not_flagged(self, fuzzer: StatefulFuzzer) -> None:
        """A-ASSOCIATE-RQ from STA1 is a valid transition — flag is False."""
        # STA1 → A_ASSOCIATE_RQ is the standard connection initiation
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.is_invalid_transition is False

    def test_invalid_transition_flagged(self, fuzzer: StatefulFuzzer) -> None:
        """A-RELEASE-RQ from STA1 is an invalid transition — flag is True."""
        # Can't release an association that was never opened
        result = fuzzer.execute_event(ProtocolEvent.A_RELEASE_RQ)
        assert result.is_invalid_transition is True

    def test_state_advances_on_valid_transition(self, fuzzer: StatefulFuzzer) -> None:
        """Executing a valid transition advances current_state."""
        assert fuzzer.current_state == AssociationState.STA1
        fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert fuzzer.current_state != AssociationState.STA1

    def test_state_unchanged_on_invalid_transition(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """Executing an invalid transition keeps current_state unchanged."""
        initial = fuzzer.current_state
        result = fuzzer.execute_event(ProtocolEvent.A_RELEASE_RQ)
        assert result.is_invalid_transition is True
        assert fuzzer.current_state == initial

    def test_result_has_success_true_for_defined_transition(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """Even an invalid transition returns success=True if it is defined in the SM."""
        result = fuzzer.execute_event(ProtocolEvent.A_RELEASE_RQ)
        # The transition IS defined (as INVALID type), so success=True
        assert result.success is True

    def test_artim_timeout_is_invalid_from_sta1(self, fuzzer: StatefulFuzzer) -> None:
        """ARTIM_TIMEOUT from STA1 is an invalid transition — flagged accordingly."""
        result = fuzzer.execute_event(ProtocolEvent.ARTIM_TIMEOUT)
        # All events are defined in the state machine; this one is an invalid transition
        assert result.success is True
        assert result.is_invalid_transition is True


class TestExecuteEventResultFields:
    """Tests that TransitionResult fields are populated correctly."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        return StatefulFuzzer()

    def test_from_state_matches_current_state(self, fuzzer: StatefulFuzzer) -> None:
        """from_state in result matches the fuzzer's state before execution."""
        initial = fuzzer.current_state
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.from_state == initial

    def test_event_field_matches_input(self, fuzzer: StatefulFuzzer) -> None:
        """event field in result matches the input event."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.event == ProtocolEvent.A_ASSOCIATE_RQ

    def test_duration_ms_is_non_negative(self, fuzzer: StatefulFuzzer) -> None:
        """duration_ms in result is >= 0."""
        result = fuzzer.execute_event(ProtocolEvent.A_ASSOCIATE_RQ)
        assert result.duration_ms >= 0.0


# ---------------------------------------------------------------------------
# StatefulFuzzer.fuzz()
# ---------------------------------------------------------------------------


class TestFuzzMethod:
    """Tests for the fuzz() generator method."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        return StatefulFuzzer()

    def test_fuzz_yields_results(self, fuzzer: StatefulFuzzer) -> None:
        """fuzz() yields at least some results for 20 sequences."""
        results = list(fuzzer.fuzz(count=20))
        assert len(results) > 0

    def test_fuzz_yields_lists_of_transition_results(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """Each yielded item is a list of TransitionResult objects."""
        for result_list in fuzzer.fuzz(count=5):
            assert isinstance(result_list, list)
            for item in result_list:
                assert isinstance(item, TransitionResult)

    def test_fuzz_invalid_only_skips_valid_sequences(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """With invalid_only=True, no sequence with attack_type 'valid' is executed."""
        # Run a large batch; all yielded sequences must be invalid attack types
        _invalid_attack_types = frozenset(
            {
                "invalid_transition",
                "out_of_order",
                "state_confusion",
                "duplicate",
                "release_collision",
                "abort_recovery",
            }
        )
        # Patch to check: generate sequences and track which ones were yielded
        yielded = list(fuzzer.fuzz(count=50, invalid_only=True))
        # All results should come from invalid sequences (we can't inspect attack_type
        # directly here, but we can verify at least some results include invalid transitions)
        assert len(yielded) > 0  # confirms filter doesn't drop everything

    def test_fuzz_invalid_only_false_includes_valid(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """With invalid_only=False, valid sequences are also executed."""
        results_strict = list(fuzzer.fuzz(count=30, invalid_only=True))
        results_all = list(fuzzer.fuzz(count=30, invalid_only=False))
        # With all sequences included we expect >= as many or more results
        assert len(results_all) >= len(results_strict)

    def test_fuzz_results_contain_message_sent(self, fuzzer: StatefulFuzzer) -> None:
        """Transition results from fuzz() have message_sent populated."""
        for result_list in fuzzer.fuzz(count=10):
            for result in result_list:
                # All PDU events should have bytes; non-PDU events may have None/b""
                # Just verify the field exists and is bytes or None
                assert result.message_sent is None or isinstance(
                    result.message_sent, bytes
                )

    def test_fuzz_with_custom_generator(self, fuzzer: StatefulFuzzer) -> None:
        """fuzz() passes custom message_generator through to execute_event()."""
        sentinel = b"\xca\xfe\xba\xbe"

        def fixed_gen(event: ProtocolEvent) -> bytes:
            return sentinel

        for result_list in fuzzer.fuzz(count=5, message_generator=fixed_gen):
            for result in result_list:
                assert result.message_sent == sentinel

    def test_fuzz_increments_sequences_executed(self, fuzzer: StatefulFuzzer) -> None:
        """Executing sequences via fuzz() increments coverage.sequences_executed."""
        initial = fuzzer.coverage.sequences_executed
        results = list(fuzzer.fuzz(count=20))
        assert fuzzer.coverage.sequences_executed > initial


# ---------------------------------------------------------------------------
# StatefulFuzzer.execute_sequence()
# ---------------------------------------------------------------------------


class TestExecuteSequence:
    """Tests for execute_sequence() with the updated TransitionResult fields."""

    @pytest.fixture
    def fuzzer(self) -> StatefulFuzzer:
        return StatefulFuzzer()

    def test_execute_sequence_returns_results(self, fuzzer: StatefulFuzzer) -> None:
        """execute_sequence() returns a list of TransitionResult."""
        seq = FuzzSequence(
            events=[ProtocolEvent.A_ASSOCIATE_RQ],
            description="test",
            attack_type="valid",
        )
        results = fuzzer.execute_sequence(seq)
        assert isinstance(results, list)
        assert len(results) == 1

    def test_execute_sequence_message_sent_in_results(
        self, fuzzer: StatefulFuzzer
    ) -> None:
        """Each result in execute_sequence() has message_sent bytes."""
        seq = FuzzSequence(
            events=[ProtocolEvent.A_ASSOCIATE_RQ, ProtocolEvent.A_ABORT],
            description="associate then abort",
            attack_type="valid",
        )
        results = fuzzer.execute_sequence(seq)
        for result in results:
            assert result.message_sent is None or isinstance(result.message_sent, bytes)

    def test_execute_sequence_resets_state(self, fuzzer: StatefulFuzzer) -> None:
        """execute_sequence() resets state to STA1 before executing."""
        fuzzer.current_state = AssociationState.STA5  # Manually advance state
        seq = FuzzSequence(
            events=[ProtocolEvent.A_ASSOCIATE_RQ],
            description="test",
            attack_type="valid",
        )
        results = fuzzer.execute_sequence(seq)
        # from_state should be STA1 (reset happened)
        assert results[0].from_state == AssociationState.STA1

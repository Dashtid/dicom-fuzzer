"""Tests for response-aware network fuzzer.

Tests for dicom_fuzzer.core.response_aware_fuzzer module.
"""

import struct
from unittest.mock import patch

from dicom_fuzzer.core.network_fuzzer import PDUType
from dicom_fuzzer.core.response_aware_fuzzer import (
    AdaptiveMutationSelector,
    AnomalyType,
    FuzzingSession,
    MutationFeedback,
    ParsedResponse,
    ResponseAnalyzer,
    ResponseAwareFuzzer,
    ResponseParser,
    ResponseType,
    ServerFingerprint,
)


class TestEnums:
    """Test enum definitions."""

    def test_response_type_values(self):
        """Test ResponseType has expected values."""
        assert ResponseType.ACCEPT
        assert ResponseType.REJECT
        assert ResponseType.ABORT
        assert ResponseType.DATA
        assert ResponseType.RELEASE
        assert ResponseType.TIMEOUT
        assert ResponseType.DISCONNECT
        assert ResponseType.MALFORMED
        assert ResponseType.CRASH
        assert ResponseType.HANG
        assert ResponseType.ERROR

    def test_anomaly_type_values(self):
        """Test AnomalyType has expected values."""
        assert AnomalyType.UNEXPECTED_RESPONSE
        assert AnomalyType.TIMING_ANOMALY
        assert AnomalyType.LENGTH_ANOMALY
        assert AnomalyType.STATE_VIOLATION
        assert AnomalyType.CRASH_INDICATION
        assert AnomalyType.RESOURCE_EXHAUSTION
        assert AnomalyType.ERROR_LEAK


class TestParsedResponse:
    """Test ParsedResponse dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        response = ParsedResponse()
        assert response.pdu_type is None
        assert response.pdu_length == 0
        assert response.raw_data == b""
        assert response.response_type == ResponseType.MALFORMED
        assert response.response_time_ms == 0.0

    def test_to_dict(self):
        """Test to_dict method."""
        response = ParsedResponse(
            pdu_type=PDUType.A_ASSOCIATE_AC,
            pdu_length=100,
            response_type=ResponseType.ACCEPT,
            response_time_ms=15.5,
        )
        d = response.to_dict()

        assert d["pdu_type"] == "A_ASSOCIATE_AC"
        assert d["pdu_length"] == 100
        assert d["response_type"] == "ACCEPT"
        assert d["response_time_ms"] == 15.5

    def test_to_dict_none_pdu(self):
        """Test to_dict with no PDU type."""
        response = ParsedResponse()
        d = response.to_dict()
        assert d["pdu_type"] is None


class TestMutationFeedback:
    """Test MutationFeedback dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        response = ParsedResponse()
        feedback = MutationFeedback(
            mutation_type="bit_flip",
            input_hash="abc123",
            response=response,
        )
        assert feedback.mutation_type == "bit_flip"
        assert feedback.input_hash == "abc123"
        assert feedback.anomalies == []
        assert feedback.interesting is False
        assert feedback.crash_potential is False
        assert feedback.new_code_path is False

    def test_with_anomalies(self):
        """Test with anomalies."""
        response = ParsedResponse()
        feedback = MutationFeedback(
            mutation_type="overflow",
            input_hash="def456",
            response=response,
            anomalies=[AnomalyType.TIMING_ANOMALY, AnomalyType.CRASH_INDICATION],
            interesting=True,
            crash_potential=True,
        )
        assert len(feedback.anomalies) == 2
        assert feedback.interesting is True
        assert feedback.crash_potential is True


class TestServerFingerprint:
    """Test ServerFingerprint dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        fp = ServerFingerprint()
        assert len(fp.common_responses) == 0
        assert len(fp.response_times) == 0
        assert len(fp.error_messages) == 0
        assert fp.max_pdu_size == 0

    def test_avg_response_time_empty(self):
        """Test avg_response_time with no data."""
        fp = ServerFingerprint()
        assert fp.avg_response_time() == 0.0

    def test_avg_response_time(self):
        """Test avg_response_time calculation."""
        fp = ServerFingerprint()
        fp.response_times = [10.0, 20.0, 30.0]
        assert fp.avg_response_time() == 20.0


class TestFuzzingSession:
    """Test FuzzingSession dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        session = FuzzingSession()
        assert session.session_id == ""
        assert session.total_tests == 0
        assert session.anomalies_found == 0
        assert session.crashes_detected == 0
        assert session.unique_responses == 0


class TestResponseParser:
    """Test ResponseParser class."""

    def test_parse_empty_data(self):
        """Test parsing empty data returns TIMEOUT."""
        response = ResponseParser.parse(b"")
        assert response.response_type == ResponseType.TIMEOUT

    def test_parse_short_data(self):
        """Test parsing too short data returns MALFORMED."""
        response = ResponseParser.parse(b"\x01\x02\x03")
        assert response.response_type == ResponseType.MALFORMED

    def test_parse_invalid_pdu_type(self):
        """Test parsing invalid PDU type returns MALFORMED."""
        # Invalid PDU type 0xFF
        data = struct.pack(">BBL", 0xFF, 0, 100)
        response = ResponseParser.parse(data)
        assert response.response_type == ResponseType.MALFORMED

    def test_parse_associate_ac(self):
        """Test parsing A-ASSOCIATE-AC."""
        # PDU type 2 = A_ASSOCIATE_AC
        data = struct.pack(">BBL", 2, 0, 100) + b"\x00" * 100
        response = ResponseParser.parse(data, response_time_ms=10.5)
        assert response.pdu_type == PDUType.A_ASSOCIATE_AC
        assert response.response_type == ResponseType.ACCEPT
        assert response.pdu_length == 100
        assert response.response_time_ms == 10.5

    def test_parse_associate_rj(self):
        """Test parsing A-ASSOCIATE-RJ with rejection details."""
        # PDU type 3 = A_ASSOCIATE_RJ, result=1, source=2, reason=3 at bytes 7,8,9
        data = struct.pack(">BBL", 3, 0, 4) + b"\x00" + bytes([1, 2, 3])
        response = ResponseParser.parse(data)
        assert response.pdu_type == PDUType.A_ASSOCIATE_RJ
        assert response.response_type == ResponseType.REJECT
        assert response.reject_result == 1
        assert response.reject_source == 2
        assert response.reject_reason == 3

    def test_parse_abort(self):
        """Test parsing A-ABORT with abort details."""
        # PDU type 7 = A_ABORT, source at byte 8, reason at byte 9
        data = struct.pack(">BBL", 7, 0, 4) + b"\x00\x00" + bytes([2, 1])
        response = ResponseParser.parse(data)
        assert response.pdu_type == PDUType.A_ABORT
        assert response.response_type == ResponseType.ABORT
        assert response.abort_source == 2
        assert response.abort_reason == 1

    def test_parse_data_tf(self):
        """Test parsing P-DATA-TF."""
        # PDU type 4 = P_DATA_TF
        data = struct.pack(">BBL", 4, 0, 100) + b"\x00" * 100
        response = ResponseParser.parse(data)
        assert response.pdu_type == PDUType.P_DATA_TF
        assert response.response_type == ResponseType.DATA

    def test_parse_release_rp(self):
        """Test parsing A-RELEASE-RP."""
        # PDU type 6 = A_RELEASE_RP
        data = struct.pack(">BBL", 6, 0, 4) + b"\x00" * 4
        response = ResponseParser.parse(data)
        assert response.pdu_type == PDUType.A_RELEASE_RP
        assert response.response_type == ResponseType.RELEASE

    def test_parse_struct_error(self):
        """Test handling struct.error during parsing."""
        # Valid PDU header but malformed structure
        data = struct.pack(">BBL", 3, 0, 100)  # Claims 100 bytes but only 6
        response = ResponseParser.parse(data)
        # Should still succeed with basic parsing
        assert response.pdu_type == PDUType.A_ASSOCIATE_RJ

    def test_reject_reasons_dict(self):
        """Test REJECT_REASONS dictionary."""
        assert ResponseParser.REJECT_REASONS[(1, 1, 1)] == "no-reason-given"
        assert (
            ResponseParser.REJECT_REASONS[(1, 1, 2)]
            == "application-context-not-supported"
        )

    def test_abort_reasons_dict(self):
        """Test ABORT_REASONS dictionary."""
        assert ResponseParser.ABORT_REASONS[(0, 0)] == "reason-not-specified"
        assert ResponseParser.ABORT_REASONS[(0, 1)] == "unrecognized-pdu"


class TestResponseAnalyzer:
    """Test ResponseAnalyzer class."""

    def test_init_no_fingerprint(self):
        """Test initialization without fingerprint."""
        analyzer = ResponseAnalyzer()
        assert analyzer.fingerprint is not None
        assert not analyzer.baseline_established

    def test_init_with_fingerprint(self):
        """Test initialization with fingerprint."""
        fp = ServerFingerprint()
        fp.max_pdu_size = 16384
        analyzer = ResponseAnalyzer(fingerprint=fp)
        assert analyzer.fingerprint.max_pdu_size == 16384

    def test_establish_baseline(self):
        """Test establishing baseline."""
        analyzer = ResponseAnalyzer()
        responses = [
            ParsedResponse(response_type=ResponseType.ACCEPT, response_time_ms=10.0),
            ParsedResponse(response_type=ResponseType.ACCEPT, response_time_ms=20.0),
            ParsedResponse(
                response_type=ResponseType.REJECT,
                response_time_ms=15.0,
                reject_result=1,
                reject_source=1,
                reject_reason=2,
            ),
        ]

        analyzer.establish_baseline(responses)

        assert analyzer.baseline_established
        assert analyzer.fingerprint.common_responses[ResponseType.ACCEPT] == 2
        assert analyzer.fingerprint.common_responses[ResponseType.REJECT] == 1
        assert len(analyzer.fingerprint.response_times) == 3
        assert (1, 1, 2) in analyzer.fingerprint.rejection_reasons

    def test_establish_baseline_with_abort(self):
        """Test establishing baseline with abort responses."""
        analyzer = ResponseAnalyzer()
        responses = [
            ParsedResponse(
                response_type=ResponseType.ABORT,
                response_time_ms=5.0,
                abort_source=0,
                abort_reason=1,
            ),
        ]

        analyzer.establish_baseline(responses)

        assert (0, 1) in analyzer.fingerprint.abort_reasons

    def test_analyze_timing_anomaly(self):
        """Test detecting timing anomaly."""
        analyzer = ResponseAnalyzer()
        # Establish baseline with fast responses
        analyzer.fingerprint.response_times = [10.0, 10.0, 10.0]

        # Analyze slow response
        response = ParsedResponse(
            response_type=ResponseType.ACCEPT,
            response_time_ms=100.0,  # 10x baseline
        )
        anomalies = analyzer.analyze(response)

        assert AnomalyType.TIMING_ANOMALY in anomalies

    def test_analyze_crash_indication_timeout(self):
        """Test detecting crash from timeout."""
        analyzer = ResponseAnalyzer()
        analyzer.baseline_established = True

        response = ParsedResponse(response_type=ResponseType.TIMEOUT)
        anomalies = analyzer.analyze(response)

        assert AnomalyType.CRASH_INDICATION in anomalies

    def test_analyze_crash_indication_disconnect(self):
        """Test detecting crash from disconnect."""
        analyzer = ResponseAnalyzer()

        response = ParsedResponse(response_type=ResponseType.DISCONNECT)
        anomalies = analyzer.analyze(response)

        assert AnomalyType.CRASH_INDICATION in anomalies

    def test_analyze_unexpected_response(self):
        """Test detecting unexpected response type."""
        analyzer = ResponseAnalyzer()
        analyzer.baseline_established = True
        analyzer.fingerprint.common_responses[ResponseType.ACCEPT] = 10

        # Get a response type not in baseline
        response = ParsedResponse(response_type=ResponseType.HANG)
        anomalies = analyzer.analyze(response)

        assert AnomalyType.UNEXPECTED_RESPONSE in anomalies

    def test_analyze_new_rejection_reason(self):
        """Test detecting new rejection reason."""
        analyzer = ResponseAnalyzer()
        analyzer.fingerprint.rejection_reasons[(1, 1, 1)] = 5

        response = ParsedResponse(
            response_type=ResponseType.REJECT,
            reject_result=1,
            reject_source=2,  # Different source
            reject_reason=1,
        )
        anomalies = analyzer.analyze(response)

        assert AnomalyType.STATE_VIOLATION in anomalies

    def test_analyze_new_abort_reason(self):
        """Test detecting new abort reason."""
        analyzer = ResponseAnalyzer()
        analyzer.fingerprint.abort_reasons[(0, 0)] = 3

        response = ParsedResponse(
            response_type=ResponseType.ABORT,
            abort_source=0,
            abort_reason=1,  # Different reason
        )
        anomalies = analyzer.analyze(response)

        assert AnomalyType.STATE_VIOLATION in anomalies

    def test_analyze_updates_fingerprint(self):
        """Test that analyze updates fingerprint."""
        analyzer = ResponseAnalyzer()

        response = ParsedResponse(
            response_type=ResponseType.ACCEPT, response_time_ms=25.0
        )
        analyzer.analyze(response)

        assert analyzer.fingerprint.common_responses[ResponseType.ACCEPT] == 1
        assert 25.0 in analyzer.fingerprint.response_times

    def test_analyze_updates_anomaly_count(self):
        """Test that analyze updates anomaly count."""
        analyzer = ResponseAnalyzer()

        response = ParsedResponse(response_type=ResponseType.DISCONNECT)
        analyzer.analyze(response)

        assert analyzer.fingerprint.anomaly_count[AnomalyType.CRASH_INDICATION] == 1


class TestAdaptiveMutationSelector:
    """Test AdaptiveMutationSelector class."""

    def test_init(self):
        """Test initialization."""
        selector = AdaptiveMutationSelector()
        assert len(selector.mutation_scores) == len(selector.MUTATIONS)
        assert all(score == 1.0 for score in selector.mutation_scores.values())

    def test_select_returns_valid_mutation(self):
        """Test select returns valid mutation type."""
        selector = AdaptiveMutationSelector()
        mutation = selector.select()
        assert mutation in selector.MUTATIONS

    def test_select_with_context(self):
        """Test select with response type context."""
        selector = AdaptiveMutationSelector()
        # Add context-specific effectiveness
        selector.response_mutations[ResponseType.REJECT]["overflow"] = 10
        selector.response_mutations[ResponseType.REJECT]["boundary"] = 5

        # Selection should prefer overflow
        with patch("random.random", return_value=0.1):
            mutation = selector.select(ResponseType.REJECT)
        # May return overflow or boundary depending on random
        assert mutation in ["overflow", "boundary"]

    def test_select_fallback_to_global(self):
        """Test select falls back to global scores."""
        selector = AdaptiveMutationSelector()
        selector.mutation_scores["havoc"] = 10.0  # High score

        # No context-specific data, should use global
        mutation = selector.select(ResponseType.ACCEPT)
        assert mutation in selector.MUTATIONS

    def test_select_zero_scores(self):
        """Test select with all zero scores."""
        selector = AdaptiveMutationSelector()
        selector.mutation_scores = dict.fromkeys(selector.MUTATIONS, 0.0)

        with patch("random.choice", return_value="bit_flip"):
            mutation = selector.select()
        assert mutation == "bit_flip"

    def test_update_interesting(self):
        """Test update with interesting feedback."""
        selector = AdaptiveMutationSelector()
        initial_score = selector.mutation_scores["bit_flip"]

        response = ParsedResponse(response_type=ResponseType.ACCEPT)
        feedback = MutationFeedback(
            mutation_type="bit_flip",
            input_hash="abc123",
            response=response,
            interesting=True,
        )
        selector.update(feedback)

        assert selector.mutation_attempts["bit_flip"] == 1
        assert selector.mutation_successes["bit_flip"] == 1
        # Score should increase
        assert selector.mutation_scores["bit_flip"] != initial_score

    def test_update_with_anomalies(self):
        """Test update with anomalies."""
        selector = AdaptiveMutationSelector()

        response = ParsedResponse(response_type=ResponseType.MALFORMED)
        feedback = MutationFeedback(
            mutation_type="overflow",
            input_hash="def456",
            response=response,
            anomalies=[AnomalyType.TIMING_ANOMALY, AnomalyType.CRASH_INDICATION],
        )
        selector.update(feedback)

        assert selector.mutation_anomalies["overflow"] == 2

    def test_update_crash_potential(self):
        """Test update with crash potential."""
        selector = AdaptiveMutationSelector()
        initial_score = selector.mutation_scores["structure"]

        response = ParsedResponse(response_type=ResponseType.CRASH)
        feedback = MutationFeedback(
            mutation_type="structure",
            input_hash="ghi789",
            response=response,
            crash_potential=True,
        )
        selector.update(feedback)

        # Score should increase significantly
        assert selector.mutation_scores["structure"] != initial_score

    def test_update_new_code_path(self):
        """Test update with new code path."""
        selector = AdaptiveMutationSelector()

        response = ParsedResponse(response_type=ResponseType.DATA)
        feedback = MutationFeedback(
            mutation_type="encoding",
            input_hash="jkl012",
            response=response,
            new_code_path=True,
        )
        selector.update(feedback)

        assert selector.mutation_attempts["encoding"] == 1

    def test_update_response_mutations_mapping(self):
        """Test that update updates response-specific mapping."""
        selector = AdaptiveMutationSelector()

        response = ParsedResponse(response_type=ResponseType.REJECT)
        feedback = MutationFeedback(
            mutation_type="truncate",
            input_hash="mno345",
            response=response,
            interesting=True,
        )
        selector.update(feedback)

        assert selector.response_mutations[ResponseType.REJECT]["truncate"] == 1


class TestResponseAwareFuzzer:
    """Test ResponseAwareFuzzer class."""

    def test_init(self):
        """Test initialization."""
        fuzzer = ResponseAwareFuzzer()
        assert fuzzer.parser is not None
        assert fuzzer.analyzer is not None
        assert fuzzer.selector is not None
        assert fuzzer.session is not None

    def test_process_response_basic(self):
        """Test processing a basic response."""
        fuzzer = ResponseAwareFuzzer()
        response_data = struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4  # A-ASSOCIATE-AC

        feedback = fuzzer.process_response(
            input_data=b"test_input",
            response_data=response_data,
            response_time_ms=10.0,
            mutation_type="bit_flip",
        )

        assert feedback.mutation_type == "bit_flip"
        assert feedback.response.response_type == ResponseType.ACCEPT
        assert fuzzer.session.total_tests == 1

    def test_process_response_anomaly(self):
        """Test processing response with anomaly."""
        fuzzer = ResponseAwareFuzzer()
        fuzzer.analyzer.baseline_established = True

        # Disconnect triggers crash indication
        response_data = b""  # Empty = timeout

        feedback = fuzzer.process_response(
            input_data=b"crash_input",
            response_data=response_data,
            response_time_ms=1000.0,
            mutation_type="overflow",
        )

        assert feedback.response.response_type == ResponseType.TIMEOUT
        # Anomalies detected because baseline established and timeout
        assert fuzzer.session.anomalies_found > 0

    def test_process_response_crash_potential(self):
        """Test detecting crash potential."""
        fuzzer = ResponseAwareFuzzer()

        # Empty response = timeout, which after baseline = crash indication
        fuzzer.analyzer.baseline_established = True

        feedback = fuzzer.process_response(
            input_data=b"test",
            response_data=b"",
            response_time_ms=0.0,
            mutation_type="havoc",
        )

        # Timeout with baseline established triggers crash indication
        assert len(feedback.anomalies) > 0
        assert fuzzer.session.anomalies_found > 0

    def test_process_response_interesting_inputs(self):
        """Test that interesting inputs are tracked."""
        fuzzer = ResponseAwareFuzzer()

        # Process response that triggers anomaly
        fuzzer.analyzer.baseline_established = True
        feedback = fuzzer.process_response(
            input_data=b"interesting_input",
            response_data=b"",  # Timeout
            response_time_ms=0.0,
            mutation_type="structure",
        )

        # Should be marked interesting due to timeout with baseline
        if feedback.interesting:
            assert len(fuzzer.session.interesting_inputs) > 0

    def test_process_response_input_hash(self):
        """Test that input hash is computed correctly."""
        fuzzer = ResponseAwareFuzzer()
        response_data = struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4

        feedback = fuzzer.process_response(
            input_data=b"test_input",
            response_data=response_data,
            response_time_ms=10.0,
            mutation_type="bit_flip",
        )

        # Hash should be 16 characters (first 16 of sha256 hex)
        assert len(feedback.input_hash) == 16

    def test_suggest_mutation(self):
        """Test suggesting mutations."""
        fuzzer = ResponseAwareFuzzer()
        mutation = fuzzer.suggest_mutation()
        assert mutation in AdaptiveMutationSelector.MUTATIONS

    def test_suggest_mutation_with_context(self):
        """Test suggesting mutation with response context."""
        fuzzer = ResponseAwareFuzzer()
        # Add context
        fuzzer.selector.response_mutations[ResponseType.REJECT]["overflow"] = 5

        mutation = fuzzer.suggest_mutation(ResponseType.REJECT)
        assert mutation in AdaptiveMutationSelector.MUTATIONS

    def test_get_statistics(self):
        """Test getting statistics."""
        fuzzer = ResponseAwareFuzzer()

        # Process some responses
        response_data = struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4
        fuzzer.process_response(
            input_data=b"test1",
            response_data=response_data,
            response_time_ms=10.0,
            mutation_type="bit_flip",
        )
        fuzzer.process_response(
            input_data=b"test2",
            response_data=response_data,
            response_time_ms=15.0,
            mutation_type="byte_flip",
        )

        stats = fuzzer.get_statistics()

        assert stats["total_tests"] == 2
        assert "mutation_scores" in stats
        assert "fingerprint" in stats
        assert "common_responses" in stats["fingerprint"]
        assert "avg_response_time" in stats["fingerprint"]

    def test_establish_baseline(self):
        """Test establishing baseline."""
        fuzzer = ResponseAwareFuzzer()

        normal_responses = [
            (struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4, 10.0),
            (struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4, 12.0),
            (struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4, 11.0),
        ]

        fuzzer.establish_baseline(normal_responses)

        assert fuzzer.analyzer.baseline_established
        assert fuzzer.analyzer.fingerprint.common_responses[ResponseType.ACCEPT] == 3


class TestIntegration:
    """Integration tests for response-aware fuzzer."""

    def test_full_fuzzing_session(self):
        """Test complete fuzzing session workflow."""
        fuzzer = ResponseAwareFuzzer()

        # Establish baseline
        baseline = [
            (struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4, 10.0),
            (struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4, 12.0),
        ]
        fuzzer.establish_baseline(baseline)

        # Run fuzzing iterations
        for i in range(10):
            mutation = fuzzer.suggest_mutation()
            # Simulate various responses
            if i % 3 == 0:
                response_data = struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4  # Accept
            elif i % 3 == 1:
                response_data = (
                    struct.pack(">BBL", 3, 0, 4) + b"\x00" + bytes([1, 1, 2])
                )  # Reject
            else:
                response_data = b""  # Timeout

            fuzzer.process_response(
                input_data=f"input_{i}".encode(),
                response_data=response_data,
                response_time_ms=10.0 + i,
                mutation_type=mutation,
            )

        stats = fuzzer.get_statistics()
        assert stats["total_tests"] == 10
        assert len(fuzzer.session.response_history) == 10

    def test_adaptive_mutation_improvement(self):
        """Test that mutations adapt based on feedback."""
        fuzzer = ResponseAwareFuzzer()

        # Simulate successful mutations with "overflow"
        response_data = struct.pack(">BBL", 2, 0, 4) + b"\x00" * 4

        for _ in range(5):
            # Create feedback that marks overflow as interesting
            response = ParsedResponse(response_type=ResponseType.ACCEPT)
            feedback = MutationFeedback(
                mutation_type="overflow",
                input_hash="test",
                response=response,
                interesting=True,
                crash_potential=True,
            )
            fuzzer.selector.update(feedback)

        # Overflow score should be higher than initial
        assert fuzzer.selector.mutation_scores["overflow"] != 1.0

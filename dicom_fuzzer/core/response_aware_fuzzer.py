"""Response-Aware Network Fuzzer for DICOM Protocol.

Implements adaptive fuzzing that learns from server responses to improve
test case generation. Based on research from:
- NetworkFuzzer (ARES 2025) - Response-aware network fuzzing
- DICOM-Fuzzer (SpringerLink) - Vulnerability mining framework

Key Features:
- Response parsing and classification
- Adaptive mutation strategy selection
- Server behavior fingerprinting
- Anomaly detection based on response patterns
- Feedback-driven test case prioritization

References:
- https://link.springer.com/chapter/10.1007/978-3-032-00644-8_13
- https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38

"""

from __future__ import annotations

import logging
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any

from dicom_fuzzer.core.network_fuzzer import PDUType

logger = logging.getLogger(__name__)


class ResponseType(Enum):
    """Classification of server responses."""

    ACCEPT = auto()  # Normal acceptance (A-ASSOCIATE-AC)
    REJECT = auto()  # Normal rejection (A-ASSOCIATE-RJ)
    ABORT = auto()  # Protocol abort (A-ABORT)
    DATA = auto()  # Data response (P-DATA-TF)
    RELEASE = auto()  # Release response (A-RELEASE-RP)
    TIMEOUT = auto()  # No response (timeout)
    DISCONNECT = auto()  # Connection closed
    MALFORMED = auto()  # Unparseable response
    CRASH = auto()  # Server crash detected
    HANG = auto()  # Server hang detected
    ERROR = auto()  # Error response in data


class AnomalyType(Enum):
    """Types of anomalous server behavior."""

    UNEXPECTED_RESPONSE = auto()  # Response doesn't match expected
    TIMING_ANOMALY = auto()  # Unusual response time
    LENGTH_ANOMALY = auto()  # Unusual response length
    STATE_VIOLATION = auto()  # Protocol state machine violation
    CRASH_INDICATION = auto()  # Crash-like behavior
    RESOURCE_EXHAUSTION = auto()  # Signs of resource exhaustion
    ERROR_LEAK = auto()  # Error message leaking info


@dataclass
class ParsedResponse:
    """Parsed DICOM protocol response."""

    pdu_type: PDUType | None = None
    pdu_length: int = 0
    raw_data: bytes = b""
    response_type: ResponseType = ResponseType.MALFORMED

    # For A-ASSOCIATE-AC/RJ
    reject_result: int = 0
    reject_source: int = 0
    reject_reason: int = 0

    # For A-ABORT
    abort_source: int = 0
    abort_reason: int = 0

    # For P-DATA-TF
    dimse_command: int = 0
    dimse_status: int = 0

    # Timing
    response_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pdu_type": self.pdu_type.name if self.pdu_type else None,
            "pdu_length": self.pdu_length,
            "response_type": self.response_type.name,
            "reject_result": self.reject_result,
            "reject_source": self.reject_source,
            "reject_reason": self.reject_reason,
            "abort_source": self.abort_source,
            "abort_reason": self.abort_reason,
            "dimse_command": self.dimse_command,
            "dimse_status": self.dimse_status,
            "response_time_ms": self.response_time_ms,
        }


@dataclass
class MutationFeedback:
    """Feedback from a mutation's effect on server."""

    mutation_type: str
    input_hash: str
    response: ParsedResponse
    anomalies: list[AnomalyType] = field(default_factory=list)
    interesting: bool = False
    crash_potential: bool = False
    new_code_path: bool = False


@dataclass
class ServerFingerprint:
    """Fingerprint of server behavior patterns."""

    # Response patterns
    common_responses: Counter[ResponseType] = field(default_factory=Counter)
    response_times: list[float] = field(default_factory=list)

    # Error handling
    error_messages: set[str] = field(default_factory=set)
    rejection_reasons: Counter[tuple[int, int, int]] = field(default_factory=Counter)
    abort_reasons: Counter[tuple[int, int]] = field(default_factory=Counter)

    # Protocol behavior
    max_pdu_size: int = 0
    supported_sop_classes: set[str] = field(default_factory=set)
    supported_transfer_syntaxes: set[str] = field(default_factory=set)

    # Anomalies detected
    anomaly_count: Counter = field(default_factory=Counter)

    def avg_response_time(self) -> float:
        """Calculate average response time."""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)


class ResponseParser:
    """Parse DICOM protocol responses."""

    # DICOM rejection reasons (PS3.8)
    REJECT_REASONS = {
        (1, 1, 1): "no-reason-given",
        (1, 1, 2): "application-context-not-supported",
        (1, 1, 3): "calling-ae-not-recognized",
        (1, 1, 7): "called-ae-not-recognized",
        (1, 2, 1): "no-reason-given (acse)",
        (1, 2, 2): "protocol-version-not-supported",
        (2, 1, 1): "temporary-congestion",
        (2, 1, 2): "local-limit-exceeded",
    }

    # DICOM abort reasons (PS3.8)
    ABORT_REASONS = {
        (0, 0): "reason-not-specified",
        (0, 1): "unrecognized-pdu",
        (0, 2): "unexpected-pdu",
        (0, 4): "unrecognized-pdu-parameter",
        (0, 5): "unexpected-pdu-parameter",
        (0, 6): "invalid-pdu-parameter-value",
    }

    @classmethod
    def parse(cls, data: bytes, response_time_ms: float = 0.0) -> ParsedResponse:
        """Parse a DICOM protocol response.

        Args:
            data: Raw response bytes
            response_time_ms: Response time in milliseconds

        Returns:
            ParsedResponse with extracted information

        """
        response = ParsedResponse(
            raw_data=data,
            response_time_ms=response_time_ms,
        )

        if not data:
            response.response_type = ResponseType.TIMEOUT
            return response

        if len(data) < 6:
            response.response_type = ResponseType.MALFORMED
            return response

        try:
            pdu_type_byte, _, pdu_length = struct.unpack(">BBL", data[:6])

            try:
                response.pdu_type = PDUType(pdu_type_byte)
            except ValueError:
                response.response_type = ResponseType.MALFORMED
                return response

            response.pdu_length = pdu_length

            # Parse based on PDU type
            if response.pdu_type == PDUType.A_ASSOCIATE_AC:
                response.response_type = ResponseType.ACCEPT
                cls._parse_associate_ac(response, data)

            elif response.pdu_type == PDUType.A_ASSOCIATE_RJ:
                response.response_type = ResponseType.REJECT
                cls._parse_associate_rj(response, data)

            elif response.pdu_type == PDUType.A_ABORT:
                response.response_type = ResponseType.ABORT
                cls._parse_abort(response, data)

            elif response.pdu_type == PDUType.P_DATA_TF:
                response.response_type = ResponseType.DATA
                cls._parse_data_tf(response, data)

            elif response.pdu_type == PDUType.A_RELEASE_RP:
                response.response_type = ResponseType.RELEASE

        except (struct.error, IndexError):
            response.response_type = ResponseType.MALFORMED

        return response

    @classmethod
    def _parse_associate_ac(cls, response: ParsedResponse, data: bytes) -> None:
        """Parse A-ASSOCIATE-AC details."""
        # Extract user info items for max PDU size, etc.
        # For now, basic parsing
        pass

    @classmethod
    def _parse_associate_rj(cls, response: ParsedResponse, data: bytes) -> None:
        """Parse A-ASSOCIATE-RJ details."""
        if len(data) >= 10:
            # Result, Source, Reason/Diag are at bytes 7, 8, 9
            response.reject_result = data[7]
            response.reject_source = data[8]
            response.reject_reason = data[9]

    @classmethod
    def _parse_abort(cls, response: ParsedResponse, data: bytes) -> None:
        """Parse A-ABORT details."""
        if len(data) >= 10:
            # Reserved, Reserved, Source, Reason at bytes 6, 7, 8, 9
            response.abort_source = data[8]
            response.abort_reason = data[9]

    @classmethod
    def _parse_data_tf(cls, response: ParsedResponse, data: bytes) -> None:
        """Parse P-DATA-TF and extract DIMSE info."""
        # Basic parsing to extract command field if present
        if len(data) > 12:
            try:
                # Skip PDU header (6), PDV header (6)
                # Look for command field (0000,0100) in data
                # This is simplified; real parsing would be more complex
                pass
            except (struct.error, IndexError):
                pass


class ResponseAnalyzer:
    """Analyze responses for anomalies and interesting behavior."""

    def __init__(self, fingerprint: ServerFingerprint | None = None) -> None:
        """Initialize analyzer with optional baseline fingerprint."""
        self.fingerprint = fingerprint or ServerFingerprint()
        self.baseline_established = False
        self.baseline_responses: list[ParsedResponse] = []

    def establish_baseline(self, responses: list[ParsedResponse]) -> None:
        """Establish baseline behavior from normal responses."""
        self.baseline_responses = responses

        for resp in responses:
            self.fingerprint.common_responses[resp.response_type] += 1
            if resp.response_time_ms > 0:
                self.fingerprint.response_times.append(resp.response_time_ms)

            if resp.response_type == ResponseType.REJECT:
                reject_key = (
                    resp.reject_result,
                    resp.reject_source,
                    resp.reject_reason,
                )
                self.fingerprint.rejection_reasons[reject_key] += 1

            if resp.response_type == ResponseType.ABORT:
                abort_key = (resp.abort_source, resp.abort_reason)
                self.fingerprint.abort_reasons[abort_key] += 1

        self.baseline_established = True

    def analyze(self, response: ParsedResponse) -> list[AnomalyType]:
        """Analyze response for anomalies.

        Args:
            response: Parsed response to analyze

        Returns:
            List of detected anomalies

        """
        anomalies: list[AnomalyType] = []

        # Check timing anomalies
        avg_time = self.fingerprint.avg_response_time()
        if avg_time > 0 and response.response_time_ms > avg_time * 3:
            anomalies.append(AnomalyType.TIMING_ANOMALY)

        # Check for crash indicators
        if response.response_type == ResponseType.TIMEOUT:
            if self.baseline_established:
                anomalies.append(AnomalyType.CRASH_INDICATION)

        if response.response_type == ResponseType.DISCONNECT:
            anomalies.append(AnomalyType.CRASH_INDICATION)

        # Check for unexpected responses
        if self.baseline_established:
            if response.response_type not in self.fingerprint.common_responses:
                anomalies.append(AnomalyType.UNEXPECTED_RESPONSE)

        # Check for new rejection/abort reasons
        if response.response_type == ResponseType.REJECT:
            reject_key = (
                response.reject_result,
                response.reject_source,
                response.reject_reason,
            )
            if reject_key not in self.fingerprint.rejection_reasons:
                anomalies.append(AnomalyType.STATE_VIOLATION)

        if response.response_type == ResponseType.ABORT:
            abort_key = (response.abort_source, response.abort_reason)
            if abort_key not in self.fingerprint.abort_reasons:
                anomalies.append(AnomalyType.STATE_VIOLATION)

        # Update fingerprint
        self.fingerprint.common_responses[response.response_type] += 1
        if response.response_time_ms > 0:
            self.fingerprint.response_times.append(response.response_time_ms)

        for anomaly in anomalies:
            self.fingerprint.anomaly_count[anomaly] += 1

        return anomalies


class AdaptiveMutationSelector:
    """Select mutations based on response feedback."""

    # Mutation types
    MUTATIONS = [
        "bit_flip",
        "byte_flip",
        "arithmetic",
        "insert",
        "delete",
        "havoc",
        "boundary",
        "format_string",
        "overflow",
        "truncate",
        "null_inject",
        "encoding",
        "structure",
    ]

    def __init__(self) -> None:
        """Initialize mutation selector."""
        # Track mutation effectiveness
        self.mutation_scores: dict[str, float] = dict.fromkeys(self.MUTATIONS, 1.0)
        self.mutation_attempts: Counter[str] = Counter()
        self.mutation_successes: Counter[str] = Counter()
        self.mutation_anomalies: Counter[str] = Counter()

        # Track response type -> effective mutations
        self.response_mutations: dict[ResponseType, Counter[str]] = defaultdict(Counter)

    def select(self, context: ResponseType | None = None) -> str:
        """Select next mutation based on feedback.

        Args:
            context: Response type context for selection

        Returns:
            Selected mutation type

        """
        # Use context-specific selection if available
        if context and context in self.response_mutations:
            effective = self.response_mutations[context]
            if effective:
                # Weighted selection based on effectiveness
                items = list(effective.items())
                mutations = [item[0] for item in items]
                weights = [item[1] for item in items]
                total = sum(weights)
                if total > 0:
                    import random

                    r = random.random() * total
                    cumsum = 0.0
                    for m, w in zip(mutations, weights, strict=True):
                        cumsum += w
                        if r <= cumsum:
                            return m

        # Fallback to global scores
        total_score = sum(self.mutation_scores.values())
        if total_score <= 0:
            import random

            return random.choice(self.MUTATIONS)

        import random

        r = random.random() * total_score
        cumsum = 0.0
        for mutation, score in self.mutation_scores.items():
            cumsum += score
            if r <= cumsum:
                return mutation

        return self.MUTATIONS[0]

    def update(self, feedback: MutationFeedback) -> None:
        """Update mutation scores based on feedback.

        Args:
            feedback: Feedback from mutation execution

        """
        mutation = feedback.mutation_type
        self.mutation_attempts[mutation] += 1

        # Reward interesting results
        reward = 0.0
        if feedback.interesting:
            reward += 1.0
            self.mutation_successes[mutation] += 1

        if feedback.anomalies:
            reward += 0.5 * len(feedback.anomalies)
            self.mutation_anomalies[mutation] += len(feedback.anomalies)

        if feedback.crash_potential:
            reward += 2.0

        if feedback.new_code_path:
            reward += 1.5

        # Update score with decay
        current = self.mutation_scores.get(mutation, 1.0)
        self.mutation_scores[mutation] = current * 0.95 + reward * 0.1

        # Update response-specific mapping
        resp_type = feedback.response.response_type
        if feedback.interesting or feedback.anomalies:
            self.response_mutations[resp_type][mutation] += 1


@dataclass
class FuzzingSession:
    """Track a response-aware fuzzing session."""

    session_id: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None

    # Statistics
    total_tests: int = 0
    anomalies_found: int = 0
    crashes_detected: int = 0
    unique_responses: int = 0

    # Fingerprint
    fingerprint: ServerFingerprint = field(default_factory=ServerFingerprint)

    # Response history
    response_history: list[ParsedResponse] = field(default_factory=list)

    # Interesting inputs
    interesting_inputs: list[tuple[bytes, ParsedResponse]] = field(default_factory=list)


class ResponseAwareFuzzer:
    """Response-aware network fuzzer for DICOM protocol.

    Adapts fuzzing strategy based on server responses to maximize
    vulnerability discovery.
    """

    def __init__(self) -> None:
        """Initialize the response-aware fuzzer."""
        self.parser = ResponseParser()
        self.analyzer = ResponseAnalyzer()
        self.selector = AdaptiveMutationSelector()
        self.session = FuzzingSession()

    def process_response(
        self,
        input_data: bytes,
        response_data: bytes,
        response_time_ms: float,
        mutation_type: str,
    ) -> MutationFeedback:
        """Process a fuzzing response and update adaptive state.

        Args:
            input_data: Input that was sent
            response_data: Response received
            response_time_ms: Response time
            mutation_type: Type of mutation used

        Returns:
            Feedback for the mutation

        """
        # Parse response
        response = ResponseParser.parse(response_data, response_time_ms)

        # Analyze for anomalies
        anomalies = self.analyzer.analyze(response)

        # Determine if interesting
        interesting = bool(anomalies) or response.response_type in (
            ResponseType.CRASH,
            ResponseType.HANG,
            ResponseType.MALFORMED,
        )

        crash_potential = response.response_type in (
            ResponseType.CRASH,
            ResponseType.HANG,
            ResponseType.DISCONNECT,
        )

        # Create feedback
        feedback = MutationFeedback(
            mutation_type=mutation_type,
            input_hash=hash(input_data).__str__(),
            response=response,
            anomalies=anomalies,
            interesting=interesting,
            crash_potential=crash_potential,
        )

        # Update selector
        self.selector.update(feedback)

        # Update session
        self.session.total_tests += 1
        if anomalies:
            self.session.anomalies_found += len(anomalies)
        if crash_potential:
            self.session.crashes_detected += 1
        if interesting:
            self.session.interesting_inputs.append((input_data, response))

        self.session.response_history.append(response)

        return feedback

    def suggest_mutation(self, prev_response: ResponseType | None = None) -> str:
        """Suggest next mutation based on response feedback.

        Args:
            prev_response: Previous response type for context

        Returns:
            Suggested mutation type

        """
        return self.selector.select(prev_response)

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzing statistics.

        Returns:
            Dictionary of statistics

        """
        return {
            "session_id": self.session.session_id,
            "total_tests": self.session.total_tests,
            "anomalies_found": self.session.anomalies_found,
            "crashes_detected": self.session.crashes_detected,
            "interesting_count": len(self.session.interesting_inputs),
            "mutation_scores": dict(self.selector.mutation_scores),
            "fingerprint": {
                "common_responses": dict(self.analyzer.fingerprint.common_responses),
                "avg_response_time": self.analyzer.fingerprint.avg_response_time(),
                "anomaly_count": dict(self.analyzer.fingerprint.anomaly_count),
            },
        }

    def establish_baseline(self, normal_responses: list[tuple[bytes, float]]) -> None:
        """Establish baseline from normal server responses.

        Args:
            normal_responses: List of (response_data, response_time_ms) tuples

        """
        parsed = [ResponseParser.parse(data, time) for data, time in normal_responses]
        self.analyzer.establish_baseline(parsed)

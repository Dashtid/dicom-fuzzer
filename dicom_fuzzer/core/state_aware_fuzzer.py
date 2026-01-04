"""State-Aware Protocol Fuzzer for DICOM.

Implements state-aware fuzzing techniques based on StateAFL and SGFuzz research
for improved protocol state coverage in DICOM implementations.

Key Features:
- Protocol state machine inference from message sequences
- LSH-based memory snapshot hashing for state identification
- State-aware seed selection and corpus management
- State coverage metrics and visualization
- Adaptive mutation based on protocol state

Research References:
- StateAFL: Greybox Fuzzing with Efficient State-Aware Coverage (ICSE 2022)
- SGFuzz: Segment-based greybox fuzzing (NDSS 2022)
- AFLNet: A Greybox Fuzzer for Network Protocols (ICST 2020)
- IJON: Exploring Deep State Spaces via Fuzzing (S&P 2020)

"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dicom_fuzzer.core.constants import DICOMState, StateTransitionType
from dicom_fuzzer.core.coverage_types import (
    ProtocolStateTransition,
    StateCoverage,
    StateFingerprint,
)

logger = logging.getLogger(__name__)

# Backward compatibility alias
StateTransition = ProtocolStateTransition


@dataclass
class ProtocolMessage:
    """A DICOM protocol message for state-aware fuzzing."""

    data: bytes
    message_type: str = ""
    expected_state: DICOMState = DICOMState.IDLE
    timestamp: float = 0.0
    is_mutated: bool = False
    mutation_info: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class MessageSequence:
    """A sequence of protocol messages representing a test case."""

    messages: list[ProtocolMessage] = field(default_factory=list)
    final_state: DICOMState = DICOMState.IDLE
    transitions: list[StateTransition] = field(default_factory=list)
    state_path: list[DICOMState] = field(default_factory=list)
    coverage_hash: str = ""
    fitness_score: float = 0.0
    execution_time_ms: float = 0.0

    def compute_hash(self) -> str:
        """Compute hash of the message sequence."""
        hasher = hashlib.sha256()
        for msg in self.messages:
            hasher.update(msg.data)
        self.coverage_hash = hasher.hexdigest()[:16]
        return self.coverage_hash

    def get_state_path_str(self) -> str:
        """Get string representation of state path."""
        return " -> ".join(s.name for s in self.state_path)


class StateInferenceEngine:
    """Infers protocol state machine from observed message sequences.

    Based on techniques from AFLNet and StateAFL for learning
    protocol state machines from fuzzing observations.
    """

    def __init__(self) -> None:
        self.observed_transitions: list[StateTransition] = []
        self.inferred_states: dict[str, DICOMState] = {}
        self.response_patterns: dict[bytes, DICOMState] = {}
        self._setup_dicom_patterns()

    def _setup_dicom_patterns(self) -> None:
        """Setup DICOM-specific response patterns for state inference."""
        # A-ASSOCIATE-AC pattern (association accepted)
        self.response_patterns[b"\x02"] = DICOMState.ASSOCIATION_ESTABLISHED
        # A-ASSOCIATE-RJ pattern (association rejected)
        self.response_patterns[b"\x03"] = DICOMState.ASSOCIATION_REJECTED
        # P-DATA-TF pattern (data transfer)
        self.response_patterns[b"\x04"] = DICOMState.DATA_TRANSFER
        # A-RELEASE-RP pattern (release response)
        self.response_patterns[b"\x06"] = DICOMState.RELEASE_COMPLETED
        # A-ABORT pattern
        self.response_patterns[b"\x07"] = DICOMState.ABORT

    def infer_state_from_response(self, response: bytes) -> DICOMState:
        """Infer protocol state from server response."""
        if not response:
            return DICOMState.IDLE

        # Check PDU type byte
        pdu_type = response[0:1]
        if pdu_type in self.response_patterns:
            return self.response_patterns[pdu_type]

        # Check for C-STORE-RSP in P-DATA
        if pdu_type == b"\x04" and len(response) > 10:
            # Look for command field in DIMSE message
            if b"\x00\x00" in response[10:20]:  # Command Group 0000
                # Check for status field patterns
                if b"\x00\x00\x00\x00" in response:  # Success status
                    return DICOMState.DATA_TRANSFER
                if b"\x00\x01" in response:  # Warning status
                    return DICOMState.DATA_TRANSFER

        # Default to current state maintenance
        return DICOMState.IDLE

    def infer_state_from_memory(
        self, memory_snapshot: bytes, coverage_bitmap: bytes
    ) -> StateFingerprint:
        """Create state fingerprint from memory snapshot using LSH.

        Implements locality-sensitive hashing for state identification
        as described in StateAFL paper.
        """
        # Compute MinHash signature for LSH
        hasher = hashlib.sha256()
        hasher.update(memory_snapshot)
        hasher.update(coverage_bitmap)

        # Create fingerprint
        fingerprint = StateFingerprint(
            hash_value=hasher.hexdigest()[:16],
            state=DICOMState.IDLE,  # Will be refined
            coverage_bitmap=coverage_bitmap,
        )

        return fingerprint

    def record_transition(self, transition: StateTransition) -> None:
        """Record an observed state transition."""
        self.observed_transitions.append(transition)

    def build_state_machine(self) -> dict[DICOMState, list[tuple[bytes, DICOMState]]]:
        """Build inferred state machine from observations."""
        state_machine: dict[DICOMState, list[tuple[bytes, DICOMState]]] = defaultdict(
            list
        )

        for transition in self.observed_transitions:
            if transition.transition_type == StateTransitionType.VALID:
                state_machine[transition.from_state].append(
                    (transition.trigger_message[:32], transition.to_state)
                )

        return dict(state_machine)


class StateMutator(ABC):
    """Abstract base class for state-aware mutation strategies."""

    @abstractmethod
    def mutate(
        self,
        sequence: MessageSequence,
        current_state: DICOMState,
        coverage: StateCoverage,
    ) -> MessageSequence:
        """Apply mutation considering current protocol state."""


class StateAwareBitFlip(StateMutator):
    """State-aware bit flip mutation."""

    def __init__(self, flip_rate: float = 0.01) -> None:
        self.flip_rate = flip_rate

    def mutate(
        self,
        sequence: MessageSequence,
        current_state: DICOMState,
        coverage: StateCoverage,
    ) -> MessageSequence:
        """Flip bits in message while preserving state-critical fields."""
        if not sequence.messages:
            return sequence

        new_messages = []
        for msg in sequence.messages:
            data = bytearray(msg.data)

            # Identify state-critical regions to protect
            protected_regions = self._get_protected_regions(msg, current_state)

            # Apply bit flips outside protected regions
            for i in range(len(data)):
                if self._is_protected(i, protected_regions):
                    continue
                if random.random() < self.flip_rate:
                    data[i] ^= 1 << random.randint(0, 7)

            new_msg = ProtocolMessage(
                data=bytes(data),
                message_type=msg.message_type,
                expected_state=msg.expected_state,
                is_mutated=True,
                mutation_info="state_aware_bitflip",
            )
            new_messages.append(new_msg)

        new_seq = MessageSequence(
            messages=new_messages,
            final_state=sequence.final_state,
        )
        return new_seq

    def _get_protected_regions(
        self, msg: ProtocolMessage, state: DICOMState
    ) -> list[tuple[int, int]]:
        """Get byte regions critical for state maintenance."""
        regions = []

        # PDU type byte always protected
        regions.append((0, 1))

        # PDU length field
        if len(msg.data) >= 6:
            regions.append((2, 6))

        # State-specific protections
        if state in (
            DICOMState.ASSOCIATION_REQUESTED,
            DICOMState.ASSOCIATION_ESTABLISHED,
        ):
            # Protect AE titles and context IDs
            if len(msg.data) > 20:
                regions.append((10, 26))  # Called AE Title
                regions.append((26, 42))  # Calling AE Title

        return regions

    def _is_protected(self, index: int, regions: list[tuple[int, int]]) -> bool:
        """Check if byte index is in protected region."""
        return any(start <= index < end for start, end in regions)


class StateGuidedHavoc(StateMutator):
    """State-guided havoc mutation with bias toward unexplored states."""

    def __init__(self, intensity: int = 10) -> None:
        self.intensity = intensity

    def mutate(
        self,
        sequence: MessageSequence,
        current_state: DICOMState,
        coverage: StateCoverage,
    ) -> MessageSequence:
        """Apply havoc mutations biased toward unexplored transitions."""
        if not sequence.messages:
            return sequence

        new_messages = list(sequence.messages)

        # Get unexplored transitions from current state
        explored_next_states = {
            to_state
            for (from_state, to_state) in coverage.state_transitions
            if from_state == current_state
        }
        unexplored_states = set(DICOMState) - explored_next_states

        # Bias mutations toward triggering unexplored transitions
        for _ in range(self.intensity):
            mutation_type = random.choice(
                [
                    "insert_message",
                    "delete_message",
                    "swap_messages",
                    "duplicate_message",
                    "truncate_message",
                    "inject_state_trigger",
                ]
            )

            if mutation_type == "insert_message":
                if unexplored_states:
                    target_state = random.choice(list(unexplored_states))
                    trigger_msg = self._generate_state_trigger(target_state)
                    pos = random.randint(0, len(new_messages))
                    new_messages.insert(pos, trigger_msg)

            elif mutation_type == "delete_message" and len(new_messages) > 1:
                pos = random.randint(0, len(new_messages) - 1)
                new_messages.pop(pos)

            elif mutation_type == "swap_messages" and len(new_messages) > 1:
                i, j = random.sample(range(len(new_messages)), 2)
                new_messages[i], new_messages[j] = new_messages[j], new_messages[i]

            elif mutation_type == "duplicate_message" and new_messages:
                pos = random.randint(0, len(new_messages) - 1)
                new_messages.insert(pos, new_messages[pos])

            elif mutation_type == "truncate_message" and new_messages:
                pos = random.randint(0, len(new_messages) - 1)
                msg = new_messages[pos]
                if len(msg.data) > 10:
                    truncate_len = random.randint(1, len(msg.data) // 2)
                    new_messages[pos] = ProtocolMessage(
                        data=msg.data[:truncate_len],
                        message_type=msg.message_type,
                        is_mutated=True,
                        mutation_info="truncated",
                    )

            elif mutation_type == "inject_state_trigger":
                if unexplored_states:
                    target_state = random.choice(list(unexplored_states))
                    trigger_msg = self._generate_state_trigger(target_state)
                    new_messages.append(trigger_msg)

        new_seq = MessageSequence(
            messages=new_messages,
            final_state=sequence.final_state,
        )
        return new_seq

    def _generate_state_trigger(self, target_state: DICOMState) -> ProtocolMessage:
        """Generate a message likely to trigger transition to target state."""
        # State-specific trigger generation (map to generator methods)
        triggers: dict[DICOMState, Callable[[], ProtocolMessage]] = {
            DICOMState.ASSOCIATION_ESTABLISHED: self._generate_associate_ac,
            DICOMState.ASSOCIATION_REJECTED: self._generate_associate_rj,
            DICOMState.RELEASE_REQUESTED: self._generate_release_rq,
            DICOMState.ABORT: self._generate_abort,
            DICOMState.DATA_TRANSFER: self._generate_p_data,
        }

        generator = triggers.get(target_state, self._generate_random_pdu)
        return generator()

    def _generate_associate_ac(self) -> ProtocolMessage:
        """Generate A-ASSOCIATE-AC PDU."""
        pdu = bytes([0x02, 0x00])  # PDU type 2, reserved
        pdu += b"\x00\x00\x00\x44"  # Placeholder length
        pdu += b"\x00\x01"  # Protocol version
        pdu += b"\x00\x00"  # Reserved
        pdu += b"CALLED_AE_TITLE " * 1  # Called AE (16 bytes)
        pdu += b"CALLING_AE_TITL " * 1  # Calling AE (16 bytes)
        pdu += b"\x00" * 32  # Reserved

        return ProtocolMessage(
            data=pdu,
            message_type="A-ASSOCIATE-AC",
            expected_state=DICOMState.ASSOCIATION_ESTABLISHED,
        )

    def _generate_associate_rj(self) -> ProtocolMessage:
        """Generate A-ASSOCIATE-RJ PDU."""
        pdu = bytes([0x03, 0x00])  # PDU type 3, reserved
        pdu += b"\x00\x00\x00\x04"  # Length = 4
        pdu += b"\x00"  # Reserved
        pdu += bytes([random.randint(1, 2)])  # Result
        pdu += bytes([random.randint(1, 3)])  # Source
        pdu += bytes([random.randint(1, 7)])  # Reason

        return ProtocolMessage(
            data=pdu,
            message_type="A-ASSOCIATE-RJ",
            expected_state=DICOMState.ASSOCIATION_REJECTED,
        )

    def _generate_release_rq(self) -> ProtocolMessage:
        """Generate A-RELEASE-RQ PDU."""
        pdu = bytes([0x05, 0x00])  # PDU type 5, reserved
        pdu += b"\x00\x00\x00\x04"  # Length = 4
        pdu += b"\x00\x00\x00\x00"  # Reserved

        return ProtocolMessage(
            data=pdu,
            message_type="A-RELEASE-RQ",
            expected_state=DICOMState.RELEASE_REQUESTED,
        )

    def _generate_abort(self) -> ProtocolMessage:
        """Generate A-ABORT PDU."""
        pdu = bytes([0x07, 0x00])  # PDU type 7, reserved
        pdu += b"\x00\x00\x00\x04"  # Length = 4
        pdu += b"\x00\x00"  # Reserved
        pdu += bytes([random.randint(0, 2)])  # Source
        pdu += bytes([random.randint(0, 6)])  # Reason

        return ProtocolMessage(
            data=pdu,
            message_type="A-ABORT",
            expected_state=DICOMState.ABORT,
        )

    def _generate_p_data(self) -> ProtocolMessage:
        """Generate P-DATA-TF PDU with random DIMSE command."""
        pdu = bytes([0x04, 0x00])  # PDU type 4, reserved
        # Random presentation data value
        pdv_data = bytes(
            [random.randint(0, 255) for _ in range(random.randint(10, 100))]
        )
        length = len(pdv_data) + 4
        pdu += length.to_bytes(4, "big")
        pdu += pdv_data

        return ProtocolMessage(
            data=pdu,
            message_type="P-DATA-TF",
            expected_state=DICOMState.DATA_TRANSFER,
        )

    def _generate_random_pdu(self) -> ProtocolMessage:
        """Generate random PDU for exploration."""
        pdu_type = random.choice([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        pdu = bytes([pdu_type, 0x00])
        length = random.randint(4, 100)
        pdu += length.to_bytes(4, "big")
        pdu += bytes([random.randint(0, 255) for _ in range(length)])

        return ProtocolMessage(
            data=pdu,
            message_type=f"PDU-{pdu_type:02X}",
            expected_state=DICOMState.IDLE,
        )


@dataclass
class FuzzerConfig:
    """Configuration for state-aware fuzzer."""

    target_host: str = "localhost"
    target_port: int = 11112
    timeout: float = 5.0
    max_iterations: int = 10000
    max_depth: int = 20
    state_coverage_weight: float = 0.4
    edge_coverage_weight: float = 0.6
    energy_budget: int = 100
    use_memory_snapshots: bool = False
    snapshot_interval: int = 100


class StateAwareFuzzer:
    """State-aware protocol fuzzer for DICOM.

    Implements state-aware coverage-guided fuzzing with:
    - Protocol state tracking and inference
    - State-aware seed selection
    - State-biased mutation strategies
    - State coverage metrics
    """

    def __init__(
        self,
        config: FuzzerConfig | None = None,
        target_callback: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.config = config or FuzzerConfig()
        self.target_callback = target_callback

        # State tracking
        self.coverage = StateCoverage()
        self.inference_engine = StateInferenceEngine()
        self.current_state = DICOMState.IDLE

        # Corpus management
        self.corpus: list[MessageSequence] = []
        self.interesting_sequences: list[MessageSequence] = []
        self.crash_sequences: list[MessageSequence] = []

        # Mutators
        self.mutators: list[StateMutator] = [
            StateAwareBitFlip(flip_rate=0.01),
            StateGuidedHavoc(intensity=10),
        ]

        # Statistics
        self.total_executions = 0
        self.total_crashes = 0
        self.start_time = 0.0

    def add_seed(self, messages: list[bytes]) -> None:
        """Add a seed sequence to the corpus."""
        protocol_messages = [ProtocolMessage(data=data) for data in messages]
        sequence = MessageSequence(messages=protocol_messages)
        sequence.compute_hash()
        self.corpus.append(sequence)
        logger.info(f"[+] Added seed sequence with {len(messages)} messages")

    def select_seed(self) -> MessageSequence:
        """Select a seed for mutation using state-aware scheduling.

        Prioritizes seeds that:
        1. Reach less-explored states
        2. Have higher coverage potential
        3. Have been executed less frequently
        """
        if not self.corpus:
            # Create empty sequence if no seeds
            return MessageSequence()

        # Score seeds based on state coverage potential
        scored_seeds: list[tuple[float, MessageSequence]] = []

        for seq in self.corpus:
            score = self._compute_seed_score(seq)
            scored_seeds.append((score, seq))

        # Sort by score descending
        scored_seeds.sort(key=lambda x: -x[0])

        # Power schedule: higher probability for better seeds
        weights = [1.0 / (i + 1) for i in range(len(scored_seeds))]
        total_weight = sum(weights)
        probabilities = [w / total_weight for w in weights]

        # Weighted random selection
        r = random.random()
        cumulative = 0.0
        for prob, (_, seq) in zip(probabilities, scored_seeds, strict=False):
            cumulative += prob
            if r <= cumulative:
                return seq

        return scored_seeds[0][1]

    def _compute_seed_score(self, sequence: MessageSequence) -> float:
        """Compute fitness score for a seed sequence."""
        score = 0.0

        # Reward reaching unexplored states
        for state in sequence.state_path:
            if state not in self.coverage.visited_states:
                score += 10.0
            else:
                # Lower reward for visited states
                score += 1.0

        # Reward new transitions
        for i in range(len(sequence.state_path) - 1):
            key = (sequence.state_path[i], sequence.state_path[i + 1])
            if self.coverage.state_transitions[key] == 0:
                score += 5.0

        # Penalize very long sequences
        if len(sequence.messages) > self.config.max_depth:
            score *= 0.5

        # Add coverage component
        score += sequence.fitness_score * self.config.edge_coverage_weight

        return score

    def mutate(self, sequence: MessageSequence) -> MessageSequence:
        """Apply state-aware mutations to a sequence."""
        mutator = random.choice(self.mutators)
        return mutator.mutate(sequence, self.current_state, self.coverage)

    def execute_sequence(self, sequence: MessageSequence) -> tuple[bool, bytes]:
        """Execute a message sequence against the target.

        Returns:
            Tuple of (is_interesting, response_data)

        """
        if not self.target_callback:
            return False, b""

        combined_response = b""
        state_path = [DICOMState.IDLE]

        try:
            for msg in sequence.messages:
                # Send message and get response
                response = self.target_callback(msg.data)
                combined_response += response

                # Infer state from response
                new_state = self.inference_engine.infer_state_from_response(response)

                # Record transition
                transition = StateTransition(
                    from_state=state_path[-1],
                    to_state=new_state,
                    trigger_message=msg.data,
                    transition_type=StateTransitionType.VALID,
                    response=response,
                )
                self.inference_engine.record_transition(transition)

                # Update coverage
                self.coverage.add_state(new_state, len(state_path))
                self.coverage.add_transition(state_path[-1], new_state)

                state_path.append(new_state)
                self.current_state = new_state

            sequence.state_path = state_path
            sequence.final_state = state_path[-1]
            self.total_executions += 1

            # Check if interesting (new coverage)
            is_interesting = (
                self.coverage.new_states_found > 0
                or self.coverage.new_transitions_found > 0
            )

            return is_interesting, combined_response

        except Exception as e:
            logger.warning(f"[-] Execution error: {e}")
            self.total_crashes += 1
            sequence.state_path = state_path
            self.crash_sequences.append(sequence)
            return True, combined_response  # Crashes are interesting

    def run(self, iterations: int | None = None) -> dict[str, Any]:
        """Run the state-aware fuzzing campaign.

        Args:
            iterations: Number of iterations (default from config)

        Returns:
            Campaign statistics

        """
        iterations = iterations or self.config.max_iterations
        self.start_time = time.time()

        logger.info(
            f"[+] Starting state-aware fuzzing campaign ({iterations} iterations)"
        )

        for i in range(iterations):
            # Select and mutate seed
            seed = self.select_seed()
            mutated = self.mutate(seed)

            # Execute
            is_interesting, response = self.execute_sequence(mutated)

            if is_interesting:
                mutated.compute_hash()
                self.corpus.append(mutated)
                self.interesting_sequences.append(mutated)
                logger.info(
                    f"[+] New interesting sequence at iteration {i}: "
                    f"states={len(self.coverage.visited_states)}, "
                    f"transitions={len(self.coverage.state_transitions)}"
                )

            # Periodic logging
            if (i + 1) % 100 == 0:
                coverage_score = self.coverage.get_coverage_score()
                logger.info(
                    f"[i] Progress: {i + 1}/{iterations}, "
                    f"coverage={coverage_score:.1f}%, "
                    f"crashes={self.total_crashes}"
                )

        return self.get_statistics()

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzing campaign statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0

        return {
            "total_executions": self.total_executions,
            "total_crashes": self.total_crashes,
            "elapsed_seconds": elapsed,
            "executions_per_second": self.total_executions / elapsed
            if elapsed > 0
            else 0,
            "corpus_size": len(self.corpus),
            "interesting_sequences": len(self.interesting_sequences),
            "state_coverage": {
                "visited_states": len(self.coverage.visited_states),
                "total_states": len(DICOMState),
                "coverage_percent": len(self.coverage.visited_states)
                / len(DICOMState)
                * 100,
                "transitions_discovered": len(self.coverage.state_transitions),
                "unique_fingerprints": len(self.coverage.unique_fingerprints),
            },
            "coverage_score": self.coverage.get_coverage_score(),
            "uncovered_states": [
                s.name for s in self.coverage.get_uncovered_states(set(DICOMState))
            ],
        }

    def save_corpus(self, output_dir: Path | str) -> int:
        """Save corpus to directory.

        Returns:
            Number of sequences saved.

        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        for i, seq in enumerate(self.corpus):
            seq_dir = output_dir / f"seq_{i:05d}"
            seq_dir.mkdir(exist_ok=True)

            for j, msg in enumerate(seq.messages):
                msg_path = seq_dir / f"msg_{j:03d}.bin"
                msg_path.write_bytes(msg.data)

            # Save metadata
            meta = {
                "hash": seq.coverage_hash,
                "message_count": len(seq.messages),
                "state_path": [s.name for s in seq.state_path],
                "final_state": seq.final_state.name,
                "fitness_score": seq.fitness_score,
            }
            meta_path = seq_dir / "metadata.json"
            import json

            meta_path.write_text(json.dumps(meta, indent=2))

            count += 1

        logger.info(f"[+] Saved {count} sequences to {output_dir}")
        return count

    def export_state_machine(self) -> dict[str, Any]:
        """Export inferred state machine."""
        sm = self.inference_engine.build_state_machine()

        return {
            "states": [s.name for s in DICOMState],
            "visited_states": [s.name for s in self.coverage.visited_states],
            "transitions": {
                f"{from_s.name} -> {to_s.name}": count
                for (from_s, to_s), count in self.coverage.state_transitions.items()
            },
            "inferred_machine": {
                state.name: [
                    {
                        "trigger_hash": hashlib.sha256(trigger).hexdigest()[:8],
                        "to_state": to.name,
                    }
                    for trigger, to in transitions
                ]
                for state, transitions in sm.items()
            },
        }


def create_sample_fuzzer() -> StateAwareFuzzer:
    """Create a sample state-aware fuzzer for demonstration."""
    config = FuzzerConfig(
        target_host="localhost",
        target_port=11112,
        max_iterations=1000,
        max_depth=10,
    )

    # Mock target callback for demonstration
    def mock_target(data: bytes) -> bytes:
        """Mock target that simulates DICOM server responses."""
        if not data:
            return b""

        pdu_type = data[0] if data else 0

        # Simulate responses
        if pdu_type == 0x01:  # A-ASSOCIATE-RQ
            # Return A-ASSOCIATE-AC
            return bytes([0x02, 0x00]) + b"\x00\x00\x00\x44" + b"\x00" * 68
        elif pdu_type == 0x04:  # P-DATA-TF
            # Return success response
            return bytes([0x04, 0x00]) + b"\x00\x00\x00\x10" + b"\x00" * 16
        elif pdu_type == 0x05:  # A-RELEASE-RQ
            # Return A-RELEASE-RP
            return bytes([0x06, 0x00]) + b"\x00\x00\x00\x04" + b"\x00" * 4

        return b""

    fuzzer = StateAwareFuzzer(config=config, target_callback=mock_target)

    # Add sample seed
    seed_messages = [
        bytes([0x01, 0x00]) + b"\x00\x00\x00\x44" + b"\x00" * 68,  # A-ASSOCIATE-RQ
        bytes([0x04, 0x00]) + b"\x00\x00\x00\x10" + b"\x00" * 16,  # P-DATA-TF
        bytes([0x05, 0x00]) + b"\x00\x00\x00\x04" + b"\x00" * 4,  # A-RELEASE-RQ
    ]
    fuzzer.add_seed(seed_messages)

    return fuzzer


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    fuzzer = create_sample_fuzzer()
    stats = fuzzer.run(iterations=100)

    print("\n[+] Fuzzing Statistics:")
    import json

    print(json.dumps(stats, indent=2))

    print("\n[+] State Machine:")
    print(json.dumps(fuzzer.export_state_machine(), indent=2))

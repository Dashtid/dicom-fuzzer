#!/usr/bin/env python3
"""DICOM Network Protocol Fuzzing Harness.

AFLNet-style state-aware fuzzing for DICOM network protocols including
C-STORE, C-FIND, C-GET, and C-MOVE operations.

This harness enables fuzzing of DICOM servers (e.g., Orthanc, DCM4CHEE)
by sending mutated DICOM messages over the network.

References:
- AFLNet: A Greybox Fuzzer for Network Protocols (ICST 2020)
- DICOM Part 7: Message Exchange
- DICOM Part 8: Network Communication Support

Usage:
    # Start target server (e.g., Orthanc)
    docker run -p 4242:4242 orthancteam/orthanc

    # Run fuzzer
    python dicom_network_harness.py --host localhost --port 4242 --corpus ./seeds

"""

from __future__ import annotations

import argparse
import hashlib
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PDUType(IntEnum):
    """DICOM Protocol Data Unit types."""

    A_ASSOCIATE_RQ = 0x01
    A_ASSOCIATE_AC = 0x02
    A_ASSOCIATE_RJ = 0x03
    P_DATA_TF = 0x04
    A_RELEASE_RQ = 0x05
    A_RELEASE_RP = 0x06
    A_ABORT = 0x07


class CommandField(IntEnum):
    """DICOM DIMSE Command fields."""

    C_STORE_RQ = 0x0001
    C_STORE_RSP = 0x8001
    C_GET_RQ = 0x0010
    C_GET_RSP = 0x8010
    C_FIND_RQ = 0x0020
    C_FIND_RSP = 0x8020
    C_MOVE_RQ = 0x0021
    C_MOVE_RSP = 0x8021
    C_ECHO_RQ = 0x0030
    C_ECHO_RSP = 0x8030
    N_EVENT_REPORT_RQ = 0x0100
    N_GET_RQ = 0x0110
    N_SET_RQ = 0x0120
    N_ACTION_RQ = 0x0130
    N_CREATE_RQ = 0x0140
    N_DELETE_RQ = 0x0150


class ProtocolState(IntEnum):
    """DICOM association state machine states."""

    IDLE = 0
    AWAITING_ASSOCIATE_AC = 1
    ASSOCIATED = 2
    AWAITING_RELEASE_RP = 3
    AWAITING_DATA = 4
    ERROR = 5


@dataclass
class DicomMessage:
    """Represents a DICOM network message."""

    pdu_type: PDUType
    data: bytes
    timestamp: float = 0.0

    def to_bytes(self) -> bytes:
        """Serialize message to bytes."""
        # PDU format: type (1) + reserved (1) + length (4) + data
        length = len(self.data)
        return struct.pack(">BBL", self.pdu_type, 0, length) + self.data


@dataclass
class StateTransition:
    """Records a state transition in the protocol."""

    from_state: ProtocolState
    to_state: ProtocolState
    trigger: str
    message_hash: str = ""


@dataclass
class FuzzingSession:
    """Tracks a fuzzing session."""

    start_time: float = 0.0
    messages_sent: int = 0
    states_visited: set[ProtocolState] = field(default_factory=set)
    transitions: list[StateTransition] = field(default_factory=list)
    crashes: list[dict[str, Any]] = field(default_factory=list)
    timeouts: int = 0
    errors: list[str] = field(default_factory=list)


class DicomProtocolStateMachine:
    """DICOM association state machine for protocol fuzzing.

    Implements the DICOM Upper Layer State Machine per DICOM Part 8.
    """

    def __init__(self) -> None:
        self.state = ProtocolState.IDLE
        self.transitions: list[StateTransition] = []

    def transition(self, new_state: ProtocolState, trigger: str) -> None:
        """Record a state transition."""
        transition = StateTransition(
            from_state=self.state,
            to_state=new_state,
            trigger=trigger,
        )
        self.transitions.append(transition)
        self.state = new_state

    def reset(self) -> None:
        """Reset to initial state."""
        self.state = ProtocolState.IDLE

    def get_valid_transitions(self) -> list[str]:
        """Get valid transitions from current state."""
        transitions_map = {
            ProtocolState.IDLE: ["A-ASSOCIATE-RQ"],
            ProtocolState.AWAITING_ASSOCIATE_AC: [
                "A-ASSOCIATE-AC",
                "A-ASSOCIATE-RJ",
                "A-ABORT",
            ],
            ProtocolState.ASSOCIATED: [
                "P-DATA-TF",
                "A-RELEASE-RQ",
                "A-ABORT",
                "C-STORE-RQ",
                "C-FIND-RQ",
                "C-GET-RQ",
                "C-MOVE-RQ",
                "C-ECHO-RQ",
            ],
            ProtocolState.AWAITING_RELEASE_RP: ["A-RELEASE-RP", "A-ABORT"],
            ProtocolState.AWAITING_DATA: ["P-DATA-TF", "A-ABORT"],
        }
        return transitions_map.get(self.state, [])


class DicomNetworkFuzzer:
    """AFLNet-style network fuzzer for DICOM protocol."""

    # Standard DICOM UIDs
    VERIFICATION_SOP_CLASS = "1.2.840.10008.1.1"
    CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"
    MR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.4"
    PATIENT_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
    STUDY_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.2.1"
    IMPLICIT_VR_LE = "1.2.840.10008.1.2"
    EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 4242,
        calling_ae: str = "FUZZER",
        called_ae: str = "ORTHANC",
        timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.calling_ae = calling_ae.ljust(16)[:16]
        self.called_ae = called_ae.ljust(16)[:16]
        self.timeout = timeout

        self.state_machine = DicomProtocolStateMachine()
        self.session = FuzzingSession()
        self.socket: socket.socket | None = None

        # State coverage tracking
        self.unique_states: set[ProtocolState] = set()
        self.unique_transitions: set[tuple[ProtocolState, ProtocolState, str]] = set()
        self.interesting_inputs: list[bytes] = []

    def connect(self) -> bool:
        """Establish TCP connection to DICOM server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            self.state_machine.reset()
            return True
        except (TimeoutError, OSError) as e:
            logger.error(f"Connection failed: {e}")
            self.session.errors.append(f"Connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close TCP connection."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        self.state_machine.reset()

    def send_pdu(self, pdu_type: PDUType, data: bytes) -> bool:
        """Send a PDU to the server."""
        if not self.socket:
            return False

        try:
            pdu = struct.pack(">BBL", pdu_type, 0, len(data)) + data
            self.socket.sendall(pdu)
            self.session.messages_sent += 1
            return True
        except OSError as e:
            logger.error(f"Send failed: {e}")
            self.session.errors.append(f"Send failed: {e}")
            return False

    def receive_pdu(self) -> tuple[PDUType | None, bytes]:
        """Receive a PDU from the server."""
        if not self.socket:
            return None, b""

        try:
            header = self._recv_exact(6)
            if len(header) < 6:
                return None, b""

            pdu_type, _, length = struct.unpack(">BBL", header)
            data = self._recv_exact(length) if length > 0 else b""
            return PDUType(pdu_type), data
        except (TimeoutError, OSError) as e:
            logger.debug(f"Receive timeout/error: {e}")
            return None, b""
        except ValueError:
            return None, b""

    def _recv_exact(self, length: int) -> bytes:
        """Receive exact number of bytes."""
        if not self.socket:
            return b""

        data = b""
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def build_associate_rq(
        self,
        abstract_syntax: str = VERIFICATION_SOP_CLASS,
        transfer_syntaxes: list[str] | None = None,
    ) -> bytes:
        """Build A-ASSOCIATE-RQ PDU data."""
        if transfer_syntaxes is None:
            transfer_syntaxes = [self.IMPLICIT_VR_LE, self.EXPLICIT_VR_LE]

        # Protocol version
        data = struct.pack(">H", 1)  # Protocol version 1
        data += b"\x00\x00"  # Reserved

        # Called/Calling AE titles (16 bytes each)
        data += self.called_ae.encode("ascii")
        data += self.calling_ae.encode("ascii")

        # Reserved (32 bytes)
        data += b"\x00" * 32

        # Application Context Item
        app_context = "1.2.840.10008.3.1.1.1"  # DICOM Application Context
        data += self._build_item(0x10, app_context.encode("ascii"))

        # Presentation Context Item
        pc_data = struct.pack(">BBH", 1, 0, 0)  # PC-ID=1, reserved
        pc_data += self._build_item(0x30, abstract_syntax.encode("ascii"))
        for ts in transfer_syntaxes:
            pc_data += self._build_item(0x40, ts.encode("ascii"))
        data += self._build_item(0x20, pc_data)

        # User Information Item
        user_info = b""
        # Maximum Length Sub-item
        user_info += self._build_item(0x51, struct.pack(">L", 16384))
        # Implementation Class UID
        impl_class = "1.2.3.4.5.6.7.8.9"
        user_info += self._build_item(0x52, impl_class.encode("ascii"))
        # Implementation Version Name
        impl_version = "DICOM_FUZZER"
        user_info += self._build_item(0x55, impl_version.encode("ascii"))
        data += self._build_item(0x50, user_info)

        return data

    def _build_item(self, item_type: int, data: bytes) -> bytes:
        """Build a variable item."""
        return struct.pack(">BBH", item_type, 0, len(data)) + data

    def build_c_echo_rq(self, message_id: int = 1) -> bytes:
        """Build C-ECHO-RQ command."""
        # Command Set
        command = b""
        # (0000,0000) CommandGroupLength - calculated later
        # (0000,0002) AffectedSOPClassUID
        command += self._build_element(
            0x0000, 0x0002, "UI", self.VERIFICATION_SOP_CLASS
        )
        # (0000,0100) CommandField = C-ECHO-RQ (0x0030)
        command += self._build_element(0x0000, 0x0100, "US", struct.pack("<H", 0x0030))
        # (0000,0110) MessageID
        command += self._build_element(
            0x0000, 0x0110, "US", struct.pack("<H", message_id)
        )
        # (0000,0800) CommandDataSetType = 0x0101 (no dataset)
        command += self._build_element(0x0000, 0x0800, "US", struct.pack("<H", 0x0101))

        # Add CommandGroupLength at start
        length_element = self._build_element(
            0x0000, 0x0000, "UL", struct.pack("<L", len(command))
        )
        command = length_element + command

        # Wrap in P-DATA-TF PDV
        pdv = self._build_pdv(1, command, is_command=True, is_last=True)
        return pdv

    def _build_element(
        self, group: int, element: int, vr: str, value: bytes | str
    ) -> bytes:
        """Build a DICOM data element (Implicit VR Little Endian)."""
        if isinstance(value, str):
            value = value.encode("ascii")
            if len(value) % 2:
                value += b"\x00"  # Pad to even length

        # Implicit VR: Group (2) + Element (2) + Length (4) + Value
        return struct.pack("<HHL", group, element, len(value)) + value

    def _build_pdv(
        self,
        context_id: int,
        data: bytes,
        is_command: bool = True,
        is_last: bool = True,
    ) -> bytes:
        """Build a Presentation Data Value item."""
        # Message Control Header
        mch = 0x00
        if is_command:
            mch |= 0x01
        if is_last:
            mch |= 0x02

        # PDV: Length (4) + Context ID (1) + MCH (1) + Data
        pdv_length = 2 + len(data)
        return struct.pack(">LBB", pdv_length, context_id, mch) + data

    def mutate_pdu(self, data: bytes, mutation_rate: float = 0.1) -> bytes:
        """Apply mutations to PDU data."""
        if not data or random.random() > mutation_rate:
            return data

        data = bytearray(data)
        mutation_type = random.choice(
            [
                "bit_flip",
                "byte_flip",
                "insert",
                "delete",
                "havoc",
                "length_corrupt",
            ]
        )

        if mutation_type == "bit_flip" and data:
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= 1 << bit

        elif mutation_type == "byte_flip" and data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)

        elif mutation_type == "insert":
            pos = random.randint(0, len(data))
            insert_data = bytes(
                [random.randint(0, 255) for _ in range(random.randint(1, 16))]
            )
            data = data[:pos] + insert_data + data[pos:]

        elif mutation_type == "delete" and len(data) > 1:
            pos = random.randint(0, len(data) - 1)
            del_len = random.randint(1, min(16, len(data) - pos))
            data = data[:pos] + data[pos + del_len :]

        elif mutation_type == "havoc" and data:
            for _ in range(random.randint(1, 8)):
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)

        elif mutation_type == "length_corrupt" and len(data) >= 4:
            # Corrupt length fields (common vulnerability trigger)
            pos = random.randint(0, len(data) - 4)
            corrupt_values = [0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 1, 2]
            value = random.choice(corrupt_values)
            data[pos : pos + 4] = struct.pack("<L", value & 0xFFFFFFFF)

        return bytes(data)

    def fuzz_association(self) -> dict[str, Any]:
        """Fuzz the association establishment phase."""
        result: dict[str, Any] = {
            "success": False,
            "state_reached": None,
            "crash": False,
        }

        if not self.connect():
            return result

        try:
            # Build and optionally mutate A-ASSOCIATE-RQ
            associate_data = self.build_associate_rq()
            if random.random() < 0.3:  # 30% mutation rate for association
                associate_data = self.mutate_pdu(associate_data, 0.2)

            self.send_pdu(PDUType.A_ASSOCIATE_RQ, associate_data)
            self.state_machine.transition(
                ProtocolState.AWAITING_ASSOCIATE_AC, "A-ASSOCIATE-RQ"
            )

            # Wait for response
            pdu_type, response_data = self.receive_pdu()

            if pdu_type == PDUType.A_ASSOCIATE_AC:
                self.state_machine.transition(
                    ProtocolState.ASSOCIATED, "A-ASSOCIATE-AC"
                )
                result["success"] = True
                result["state_reached"] = ProtocolState.ASSOCIATED
            elif pdu_type == PDUType.A_ASSOCIATE_RJ:
                self.state_machine.transition(ProtocolState.IDLE, "A-ASSOCIATE-RJ")
                result["state_reached"] = ProtocolState.IDLE
            elif pdu_type == PDUType.A_ABORT:
                self.state_machine.transition(ProtocolState.IDLE, "A-ABORT")
                result["state_reached"] = ProtocolState.IDLE
            elif pdu_type is None:
                self.session.timeouts += 1
                result["crash"] = True  # Potential crash - no response

            # Track state coverage
            self._track_state_coverage()

        except Exception as e:
            logger.error(f"Fuzzing error: {e}")
            result["crash"] = True
            self.session.crashes.append(
                {
                    "phase": "association",
                    "error": str(e),
                    "timestamp": time.time(),
                }
            )
        finally:
            self.disconnect()

        return result

    def fuzz_c_echo(self) -> dict[str, Any]:
        """Fuzz C-ECHO operation."""
        result: dict[str, Any] = {
            "success": False,
            "state_reached": None,
            "crash": False,
        }

        # First establish association
        if not self.connect():
            return result

        try:
            # Normal association
            associate_data = self.build_associate_rq()
            self.send_pdu(PDUType.A_ASSOCIATE_RQ, associate_data)
            self.state_machine.transition(
                ProtocolState.AWAITING_ASSOCIATE_AC, "A-ASSOCIATE-RQ"
            )

            pdu_type, _ = self.receive_pdu()
            if pdu_type != PDUType.A_ASSOCIATE_AC:
                return result

            self.state_machine.transition(ProtocolState.ASSOCIATED, "A-ASSOCIATE-AC")

            # Build and mutate C-ECHO
            echo_data = self.build_c_echo_rq()
            if random.random() < 0.5:  # Higher mutation rate for DIMSE
                echo_data = self.mutate_pdu(echo_data, 0.3)

            self.send_pdu(PDUType.P_DATA_TF, echo_data)
            self.state_machine.transition(ProtocolState.AWAITING_DATA, "C-ECHO-RQ")

            # Wait for response
            pdu_type, response_data = self.receive_pdu()

            if pdu_type == PDUType.P_DATA_TF:
                result["success"] = True
                result["state_reached"] = ProtocolState.ASSOCIATED
                self.state_machine.transition(ProtocolState.ASSOCIATED, "C-ECHO-RSP")
            elif pdu_type is None:
                self.session.timeouts += 1
                result["crash"] = True

            self._track_state_coverage()

        except Exception as e:
            logger.error(f"C-ECHO fuzzing error: {e}")
            result["crash"] = True
            self.session.crashes.append(
                {
                    "phase": "c_echo",
                    "error": str(e),
                    "timestamp": time.time(),
                }
            )
        finally:
            self.disconnect()

        return result

    def fuzz_with_seed(self, seed_data: bytes) -> dict[str, Any]:
        """Fuzz using a seed file (recorded network message)."""
        result = {"success": False, "new_coverage": False, "crash": False}

        if not self.connect():
            return result

        try:
            # Mutate the seed
            mutated = self.mutate_pdu(seed_data, 0.5)

            # Determine PDU type from first byte
            if mutated:
                pdu_type = (
                    PDUType(mutated[0])
                    if mutated[0] in [e.value for e in PDUType]
                    else PDUType.P_DATA_TF
                )
            else:
                pdu_type = PDUType.P_DATA_TF

            # Send mutated message
            self.send_pdu(pdu_type, mutated[6:] if len(mutated) > 6 else mutated)

            # Check for response
            resp_type, resp_data = self.receive_pdu()

            if resp_type is None:
                result["crash"] = True
                self.session.timeouts += 1
            else:
                result["success"] = True

            # Check for new coverage
            old_coverage = len(self.unique_transitions)
            self._track_state_coverage()
            if len(self.unique_transitions) > old_coverage:
                result["new_coverage"] = True
                self.interesting_inputs.append(mutated)

        except Exception as e:
            result["crash"] = True
            self.session.crashes.append(
                {
                    "phase": "seed_fuzzing",
                    "error": str(e),
                    "seed_hash": hashlib.sha256(seed_data).hexdigest()[:16],
                    "timestamp": time.time(),
                }
            )
        finally:
            self.disconnect()

        return result

    def _track_state_coverage(self) -> None:
        """Track state coverage metrics."""
        self.unique_states.add(self.state_machine.state)
        self.session.states_visited.add(self.state_machine.state)

        for transition in self.state_machine.transitions:
            key = (transition.from_state, transition.to_state, transition.trigger)
            self.unique_transitions.add(key)

    def run_campaign(
        self,
        iterations: int = 1000,
        seed_corpus: Path | None = None,
    ) -> dict[str, Any]:
        """Run a fuzzing campaign."""
        self.session = FuzzingSession(start_time=time.time())
        seeds: list[bytes] = []

        # Load seed corpus if provided
        if seed_corpus and seed_corpus.exists():
            for seed_file in seed_corpus.glob("*"):
                if seed_file.is_file():
                    seeds.append(seed_file.read_bytes())
            logger.info(f"Loaded {len(seeds)} seeds from corpus")

        for i in range(iterations):
            if i % 100 == 0:
                logger.info(
                    f"Iteration {i}/{iterations} - "
                    f"States: {len(self.unique_states)}, "
                    f"Transitions: {len(self.unique_transitions)}, "
                    f"Crashes: {len(self.session.crashes)}"
                )

            # Choose fuzzing strategy
            if seeds and random.random() < 0.7:
                # Use seed-based fuzzing 70% of the time
                seed = random.choice(seeds)
                self.fuzz_with_seed(seed)
            else:
                # Protocol-aware fuzzing
                strategy = random.choice(["association", "c_echo"])
                if strategy == "association":
                    self.fuzz_association()
                else:
                    self.fuzz_c_echo()

        # Compile results
        duration = time.time() - self.session.start_time
        return {
            "iterations": iterations,
            "duration_seconds": duration,
            "executions_per_second": iterations / duration if duration > 0 else 0,
            "messages_sent": self.session.messages_sent,
            "unique_states": len(self.unique_states),
            "states": [s.name for s in self.unique_states],
            "unique_transitions": len(self.unique_transitions),
            "crashes": self.session.crashes,
            "crash_count": len(self.session.crashes),
            "timeouts": self.session.timeouts,
            "interesting_inputs": len(self.interesting_inputs),
            "errors": self.session.errors,
        }

    def save_interesting_inputs(self, output_dir: Path) -> int:
        """Save inputs that discovered new coverage."""
        output_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        for i, data in enumerate(self.interesting_inputs):
            filename = f"interesting_{i:06d}_{hashlib.sha256(data).hexdigest()[:8]}.bin"
            (output_dir / filename).write_bytes(data)
            count += 1

        return count


def main() -> None:
    """Main entry point for network fuzzing harness."""
    parser = argparse.ArgumentParser(description="DICOM Network Protocol Fuzzer")
    parser.add_argument("--host", default="localhost", help="Target host")
    parser.add_argument("--port", type=int, default=4242, help="Target port")
    parser.add_argument("--calling-ae", default="FUZZER", help="Calling AE title")
    parser.add_argument("--called-ae", default="ORTHANC", help="Called AE title")
    parser.add_argument(
        "--iterations", type=int, default=1000, help="Number of iterations"
    )
    parser.add_argument("--corpus", type=Path, help="Seed corpus directory")
    parser.add_argument(
        "--output", type=Path, default=Path("./findings"), help="Output directory"
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout")

    args = parser.parse_args()

    fuzzer = DicomNetworkFuzzer(
        host=args.host,
        port=args.port,
        calling_ae=args.calling_ae,
        called_ae=args.called_ae,
        timeout=args.timeout,
    )

    logger.info(f"Starting DICOM network fuzzing against {args.host}:{args.port}")
    results = fuzzer.run_campaign(iterations=args.iterations, seed_corpus=args.corpus)

    # Print results
    print("\n" + "=" * 60)
    print("DICOM Network Fuzzing Results")
    print("=" * 60)
    print(f"Iterations:           {results['iterations']}")
    print(f"Duration:             {results['duration_seconds']:.2f}s")
    print(f"Exec/sec:             {results['executions_per_second']:.2f}")
    print(f"Messages sent:        {results['messages_sent']}")
    print(f"Unique states:        {results['unique_states']}")
    print(f"Unique transitions:   {results['unique_transitions']}")
    print(f"Crashes/Timeouts:     {results['crash_count']}/{results['timeouts']}")
    print(f"Interesting inputs:   {results['interesting_inputs']}")
    print("=" * 60)

    # Save findings
    if results["crashes"]:
        args.output.mkdir(parents=True, exist_ok=True)
        import json

        with open(args.output / "crashes.json", "w") as f:
            json.dump(results["crashes"], f, indent=2, default=str)
        print(f"\n[!] Crash details saved to {args.output / 'crashes.json'}")

    saved = fuzzer.save_interesting_inputs(args.output / "interesting")
    if saved:
        print(f"[+] Saved {saved} interesting inputs to {args.output / 'interesting'}")


if __name__ == "__main__":
    main()

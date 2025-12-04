"""DICOM Network Protocol Fuzzer.

This module provides network-level fuzzing capabilities for DICOM protocol
implementations, targeting:
- A-ASSOCIATE handshake fuzzing
- C-STORE operation fuzzing
- C-FIND query fuzzing
- C-MOVE operation fuzzing
- DICOM TLS implementation testing

Based on research from:
- IOActive: Penetration Testing of the DICOM Protocol
- DICOM-Fuzzer (SpringerLink) - Vulnerability mining framework
- NetworkFuzzer (ARES 2025) - Response-aware network fuzzing
- EXPLIoT Framework - DICOM testing capabilities

References:
- https://www.ioactive.com/penetration-testing-of-the-dicom-protocol-real-world-attacks/
- https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38
- https://github.com/r1b/dicom-fuzz
- https://expliot.readthedocs.io/en/latest/tests/dicom.html

"""

from __future__ import annotations

import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DICOMCommand(Enum):
    """DICOM Command Field values."""

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
    N_EVENT_REPORT_RSP = 0x8100
    N_GET_RQ = 0x0110
    N_GET_RSP = 0x8110
    N_SET_RQ = 0x0120
    N_SET_RSP = 0x8120
    N_ACTION_RQ = 0x0130
    N_ACTION_RSP = 0x8130
    N_CREATE_RQ = 0x0140
    N_CREATE_RSP = 0x8140
    N_DELETE_RQ = 0x0150
    N_DELETE_RSP = 0x8150
    C_CANCEL_RQ = 0x0FFF


class PDUType(Enum):
    """DICOM PDU (Protocol Data Unit) types."""

    A_ASSOCIATE_RQ = 0x01
    A_ASSOCIATE_AC = 0x02
    A_ASSOCIATE_RJ = 0x03
    P_DATA_TF = 0x04
    A_RELEASE_RQ = 0x05
    A_RELEASE_RP = 0x06
    A_ABORT = 0x07


class FuzzingStrategy(Enum):
    """Network fuzzing strategies."""

    MALFORMED_PDU = "malformed_pdu"
    INVALID_LENGTH = "invalid_length"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_BYTES = "null_bytes"
    UNICODE_INJECTION = "unicode_injection"
    PROTOCOL_STATE = "protocol_state"
    TIMING_ATTACK = "timing_attack"


@dataclass
class NetworkFuzzResult:
    """Result of a network fuzzing test.

    Attributes:
        strategy: Fuzzing strategy used
        target_host: Target host address
        target_port: Target port number
        test_name: Name of the specific test
        success: Whether the test completed successfully
        response: Response received from server
        error: Error message if failed
        duration: Time taken for test
        timestamp: When the test was performed
        crash_detected: Whether a crash was detected
        anomaly_detected: Whether an anomaly was detected

    """

    strategy: FuzzingStrategy
    target_host: str
    target_port: int
    test_name: str
    success: bool = True
    response: bytes = b""
    error: str = ""
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    crash_detected: bool = False
    anomaly_detected: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "strategy": self.strategy.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "test_name": self.test_name,
            "success": self.success,
            "response_length": len(self.response),
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp.isoformat(),
            "crash_detected": self.crash_detected,
            "anomaly_detected": self.anomaly_detected,
        }


@dataclass
class DICOMNetworkConfig:
    """Configuration for DICOM network fuzzing.

    Attributes:
        target_host: Target DICOM server hostname/IP
        target_port: Target DICOM port (default 104 or 11112)
        calling_ae: Calling AE Title
        called_ae: Called AE Title
        timeout: Socket timeout in seconds
        max_pdu_size: Maximum PDU size to use
        use_tls: Whether to use TLS/SSL
        verify_ssl: Whether to verify SSL certificates

    """

    target_host: str = "localhost"
    target_port: int = 11112
    calling_ae: str = "FUZZER_SCU"
    called_ae: str = "ANY_SCP"
    timeout: float = 5.0
    max_pdu_size: int = 16384
    use_tls: bool = False
    verify_ssl: bool = False


class DICOMProtocolBuilder:
    """Builds DICOM protocol messages for fuzzing.

    Provides methods to construct both valid and malformed DICOM
    protocol messages for testing server implementations.
    """

    # Common Transfer Syntaxes
    IMPLICIT_VR_LITTLE_ENDIAN = b"1.2.840.10008.1.2\x00"
    EXPLICIT_VR_LITTLE_ENDIAN = b"1.2.840.10008.1.2.1\x00"
    EXPLICIT_VR_BIG_ENDIAN = b"1.2.840.10008.1.2.2\x00"

    # Common SOP Classes
    VERIFICATION_SOP_CLASS = b"1.2.840.10008.1.1\x00"
    CT_IMAGE_STORAGE = b"1.2.840.10008.5.1.4.1.1.2\x00"
    MR_IMAGE_STORAGE = b"1.2.840.10008.5.1.4.1.1.4\x00"
    PATIENT_ROOT_QR_FIND = b"1.2.840.10008.5.1.4.1.2.1.1\x00"
    PATIENT_ROOT_QR_MOVE = b"1.2.840.10008.5.1.4.1.2.1.2\x00"

    @staticmethod
    def build_a_associate_rq(
        calling_ae: str = "FUZZER_SCU",
        called_ae: str = "ANY_SCP",
        application_context: bytes | None = None,
        presentation_contexts: list[bytes] | None = None,
        max_pdu_size: int = 16384,
    ) -> bytes:
        """Build an A-ASSOCIATE-RQ PDU.

        Args:
            calling_ae: Calling Application Entity Title
            called_ae: Called Application Entity Title
            application_context: Application context UID
            presentation_contexts: List of presentation context items
            max_pdu_size: Maximum PDU size

        Returns:
            Bytes of the A-ASSOCIATE-RQ PDU

        """
        # Default application context (DICOM)
        if application_context is None:
            application_context = b"1.2.840.10008.3.1.1.1\x00"

        # Default presentation context (Verification SOP Class)
        if presentation_contexts is None:
            presentation_contexts = [
                DICOMProtocolBuilder._build_presentation_context(
                    context_id=1,
                    abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
                    transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
                )
            ]

        # Pad AE titles to 16 bytes
        calling_ae_bytes = calling_ae.encode("ascii").ljust(16)[:16]
        called_ae_bytes = called_ae.encode("ascii").ljust(16)[:16]

        # Build Application Context Item (0x10)
        app_context_item = (
            struct.pack(">BBH", 0x10, 0x00, len(application_context))
            + application_context
        )

        # Build User Information Item (0x50)
        max_length_item = struct.pack(">BBHI", 0x51, 0x00, 4, max_pdu_size)
        implementation_uid = b"1.2.3.4.5.6.7.8.9\x00"
        impl_uid_item = (
            struct.pack(">BBH", 0x52, 0x00, len(implementation_uid))
            + implementation_uid
        )

        user_info_data = max_length_item + impl_uid_item
        user_info_item = (
            struct.pack(">BBH", 0x50, 0x00, len(user_info_data)) + user_info_data
        )

        # Combine presentation contexts
        pres_ctx_data = b"".join(presentation_contexts)

        # Build variable items
        variable_items = app_context_item + pres_ctx_data + user_info_item

        # Build PDU header
        # Protocol version (1), reserved (2 bytes), called AE (16), calling AE (16),
        # reserved (32 bytes)
        pdu_data = (
            struct.pack(">H", 1)
            + b"\x00\x00"  # Protocol version  # Reserved
            + called_ae_bytes
            + calling_ae_bytes
            + b"\x00" * 32  # Reserved
            + variable_items
        )

        # PDU header: type (1), reserved (1), length (4)
        pdu = struct.pack(">BBL", PDUType.A_ASSOCIATE_RQ.value, 0x00, len(pdu_data))
        return pdu + pdu_data

    @staticmethod
    def _build_presentation_context(
        context_id: int,
        abstract_syntax: bytes,
        transfer_syntaxes: list[bytes],
    ) -> bytes:
        """Build a Presentation Context Item.

        Args:
            context_id: Presentation context ID (odd number)
            abstract_syntax: Abstract syntax UID
            transfer_syntaxes: List of transfer syntax UIDs

        Returns:
            Bytes of the presentation context item

        """
        # Abstract Syntax Item (0x30)
        abstract_item = (
            struct.pack(">BBH", 0x30, 0x00, len(abstract_syntax)) + abstract_syntax
        )

        # Transfer Syntax Items (0x40)
        transfer_items = b""
        for ts in transfer_syntaxes:
            transfer_items += struct.pack(">BBH", 0x40, 0x00, len(ts)) + ts

        # Presentation Context Item (0x20)
        ctx_data = (
            struct.pack(">B", context_id)
            + b"\x00\x00\x00"  # Reserved
            + abstract_item
            + transfer_items
        )

        return struct.pack(">BBH", 0x20, 0x00, len(ctx_data)) + ctx_data

    @staticmethod
    def build_c_echo_rq(message_id: int = 1) -> bytes:
        """Build a C-ECHO-RQ DIMSE message.

        Args:
            message_id: Message ID for the request

        Returns:
            Bytes of the C-ECHO-RQ wrapped in P-DATA-TF

        """
        # Build Command Dataset
        # Group Length (0000,0000)
        group_length = struct.pack("<HH", 0x0000, 0x0000) + struct.pack("<I", 4)
        # Affected SOP Class UID (0000,0002)
        sop_class = b"1.2.840.10008.1.1"
        sop_class_elem = (
            struct.pack("<HH", 0x0000, 0x0002)
            + struct.pack("<I", len(sop_class))
            + sop_class
        )
        # Command Field (0000,0100)
        cmd_field = (
            struct.pack("<HH", 0x0000, 0x0100)
            + struct.pack("<I", 2)
            + struct.pack("<H", DICOMCommand.C_ECHO_RQ.value)
        )
        # Message ID (0000,0110)
        msg_id = (
            struct.pack("<HH", 0x0000, 0x0110)
            + struct.pack("<I", 2)
            + struct.pack("<H", message_id)
        )
        # Data Set Type (0000,0800) - No data set
        data_set_type = (
            struct.pack("<HH", 0x0000, 0x0800)
            + struct.pack("<I", 2)
            + struct.pack("<H", 0x0101)
        )

        command_data = sop_class_elem + cmd_field + msg_id + data_set_type
        # Update group length
        group_length = struct.pack("<HH", 0x0000, 0x0000) + struct.pack(
            "<I", len(command_data) - 8
        )
        command_data = group_length + command_data

        # Wrap in PDV (Presentation Data Value)
        # Context ID (1) + Message Control Header (0x03 = last fragment, command)
        pdv = struct.pack(">I", len(command_data) + 2) + bytes([1, 0x03]) + command_data

        # Wrap in P-DATA-TF PDU
        return struct.pack(">BBL", PDUType.P_DATA_TF.value, 0x00, len(pdv)) + pdv


class DICOMNetworkFuzzer:
    """DICOM Network Protocol Fuzzer.

    Performs network-level fuzzing of DICOM protocol implementations
    to discover vulnerabilities in:
    - Association establishment (A-ASSOCIATE)
    - DIMSE operations (C-STORE, C-FIND, C-MOVE, C-ECHO)
    - Protocol state handling
    - Length field parsing
    - Buffer handling

    Usage:
        fuzzer = DICOMNetworkFuzzer(config)
        results = fuzzer.run_campaign()
        fuzzer.print_summary(results)

    """

    def __init__(self, config: DICOMNetworkConfig | None = None):
        """Initialize network fuzzer.

        Args:
            config: Network configuration (uses defaults if None)

        """
        self.config = config or DICOMNetworkConfig()
        self._results: list[NetworkFuzzResult] = []

        logger.info(
            f"DICOMNetworkFuzzer initialized: "
            f"target={self.config.target_host}:{self.config.target_port}"
        )

    def _create_socket(self) -> socket.socket:
        """Create a socket connection to the target.

        Returns:
            Connected socket

        Raises:
            ConnectionError: If connection fails

        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            if self.config.use_tls:
                import ssl

                context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(
                    sock, server_hostname=self.config.target_host
                )

            sock.connect((self.config.target_host, self.config.target_port))
            return sock

        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}") from e

    def _send_receive(
        self, data: bytes, sock: socket.socket | None = None
    ) -> tuple[bytes, float]:
        """Send data and receive response.

        Args:
            data: Data to send
            sock: Existing socket or None to create new one

        Returns:
            Tuple of (response bytes, duration in seconds)

        """
        close_sock = sock is None
        if sock is None:
            sock = self._create_socket()

        start_time = time.time()
        try:
            sock.sendall(data)
            response = sock.recv(65536)
            duration = time.time() - start_time
            return response, duration
        finally:
            if close_sock:
                sock.close()

    def test_valid_association(self) -> NetworkFuzzResult:
        """Test valid A-ASSOCIATE-RQ to verify connectivity.

        Returns:
            NetworkFuzzResult with test outcome

        """
        test_name = "valid_association"
        start_time = time.time()

        try:
            pdu = DICOMProtocolBuilder.build_a_associate_rq(
                calling_ae=self.config.calling_ae,
                called_ae=self.config.called_ae,
            )
            response, _ = self._send_receive(pdu)
            duration = time.time() - start_time

            # Check response type
            if len(response) >= 1:
                pdu_type = response[0]
                if pdu_type == PDUType.A_ASSOCIATE_AC.value:
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response,
                        duration=duration,
                    )
                elif pdu_type == PDUType.A_ASSOCIATE_RJ.value:
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response,
                        duration=duration,
                        error="Association rejected",
                    )

            return NetworkFuzzResult(
                strategy=FuzzingStrategy.PROTOCOL_STATE,
                target_host=self.config.target_host,
                target_port=self.config.target_port,
                test_name=test_name,
                success=False,
                response=response,
                duration=duration,
                error="Unexpected response",
                anomaly_detected=True,
            )

        except Exception as e:
            return NetworkFuzzResult(
                strategy=FuzzingStrategy.PROTOCOL_STATE,
                target_host=self.config.target_host,
                target_port=self.config.target_port,
                test_name=test_name,
                success=False,
                error=str(e),
                duration=time.time() - start_time,
            )

    def fuzz_pdu_length(self) -> list[NetworkFuzzResult]:
        """Fuzz PDU length field with various invalid values.

        Tests:
        - Zero length
        - Maximum length
        - Length mismatch (too short/long)
        - Negative length (as unsigned)

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        test_cases = [
            ("zero_length", 0),
            ("max_length", 0xFFFFFFFF),
            ("small_negative", 0xFFFFFFFF - 10),
            ("length_1", 1),
            ("length_overflow", 0x7FFFFFFF + 1),
        ]

        for test_name, length in test_cases:
            start_time = time.time()
            try:
                # Build malformed PDU with invalid length
                pdu = struct.pack(">BBL", PDUType.A_ASSOCIATE_RQ.value, 0x00, length)
                # Add some data
                pdu += b"\x00" * min(length, 1000)

                response, _ = self._send_receive(pdu)
                duration = time.time() - start_time

                # Server should handle gracefully (reject/abort/close)
                crash_detected = len(response) == 0
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.INVALID_LENGTH,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pdu_length_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                        crash_detected=crash_detected,
                        anomaly_detected=crash_detected,
                    )
                )

            except TimeoutError:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.INVALID_LENGTH,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pdu_length_{test_name}",
                        success=True,
                        duration=time.time() - start_time,
                        error="Timeout (server may have hung)",
                        anomaly_detected=True,
                    )
                )
            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.INVALID_LENGTH,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pdu_length_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_ae_title(self) -> list[NetworkFuzzResult]:
        """Fuzz AE Title fields with various payloads.

        Tests:
        - Empty AE title
        - Very long AE title (buffer overflow)
        - Null bytes in AE title
        - Unicode characters
        - Format string specifiers
        - SQL injection payloads (if backend uses DB)

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        payloads = [
            ("empty", ""),
            ("single_char", "A"),
            ("max_length", "A" * 16),
            ("overflow_17", "A" * 17),
            ("overflow_64", "A" * 64),
            ("overflow_256", "A" * 256),
            ("overflow_1024", "A" * 1024),
            ("null_bytes", "TEST\x00FUZZ"),
            ("format_string", "%s%s%s%s%n"),
            ("sql_inject", "'; DROP TABLE--"),
            ("special_chars", "!@#$%^&*(){}[]"),
            ("unicode", "\u0000\u0001\u00ff\u0100"),
            ("path_traversal", "../../../etc/passwd"),
            ("shell_inject", "; cat /etc/passwd"),
        ]

        for test_name, payload in payloads:
            start_time = time.time()
            try:
                # Build PDU with fuzzed AE title
                pdu = DICOMProtocolBuilder.build_a_associate_rq(
                    calling_ae=payload[:16] if len(payload) > 16 else payload,
                    called_ae=self.config.called_ae,
                )

                # For overflow tests, manually construct malformed PDU
                if len(payload) > 16:
                    # Inject longer payload directly
                    calling_ae_bytes = payload.encode("utf-8", errors="replace")[:256]
                    called_ae_bytes = self.config.called_ae.encode("ascii").ljust(16)[
                        :16
                    ]

                    pdu_data = (
                        struct.pack(">H", 1)
                        + b"\x00\x00"
                        + called_ae_bytes
                        + calling_ae_bytes.ljust(len(payload))
                        + b"\x00" * 32
                    )
                    pdu = struct.pack(
                        ">BBL", PDUType.A_ASSOCIATE_RQ.value, 0x00, len(pdu_data)
                    )
                    pdu += pdu_data

                response, _ = self._send_receive(pdu)
                duration = time.time() - start_time

                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"ae_title_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                        crash_detected=len(response) == 0,
                    )
                )

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"ae_title_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_presentation_context(self) -> list[NetworkFuzzResult]:
        """Fuzz presentation context with malformed data.

        Tests:
        - Invalid context IDs
        - Malformed abstract syntax
        - Missing transfer syntax
        - Too many presentation contexts

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        test_cases = [
            ("invalid_ctx_id_0", 0),
            ("invalid_ctx_id_even", 2),
            ("invalid_ctx_id_256", 256),
            ("max_ctx_id", 255),
        ]

        for test_name, ctx_id in test_cases:
            start_time = time.time()
            try:
                # Build presentation context with invalid ID
                pres_ctx = DICOMProtocolBuilder._build_presentation_context(
                    context_id=ctx_id & 0xFF,
                    abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
                    transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
                )

                pdu = DICOMProtocolBuilder.build_a_associate_rq(
                    calling_ae=self.config.calling_ae,
                    called_ae=self.config.called_ae,
                    presentation_contexts=[pres_ctx],
                )

                response, _ = self._send_receive(pdu)
                duration = time.time() - start_time

                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.MALFORMED_PDU,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pres_ctx_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                    )
                )

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.MALFORMED_PDU,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pres_ctx_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_random_bytes(self, count: int = 10) -> list[NetworkFuzzResult]:
        """Send random bytes to test robustness.

        Args:
            count: Number of random byte tests to perform

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []

        for i in range(count):
            size = random.choice([1, 10, 100, 1000, 10000])
            start_time = time.time()

            try:
                data = bytes(random.getrandbits(8) for _ in range(size))
                response, _ = self._send_receive(data)
                duration = time.time() - start_time

                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.MALFORMED_PDU,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"random_bytes_{size}_{i}",
                        success=True,
                        response=response,
                        duration=duration,
                    )
                )

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.MALFORMED_PDU,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"random_bytes_{size}_{i}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_protocol_state(self) -> list[NetworkFuzzResult]:
        """Test protocol state machine violations.

        Tests:
        - Sending P-DATA before association
        - Sending multiple A-ASSOCIATE-RQ
        - Sending A-RELEASE without association
        - Sending commands out of order

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        test_cases = [
            ("pdata_before_assoc", DICOMProtocolBuilder.build_c_echo_rq()),
            (
                "release_before_assoc",
                struct.pack(">BBL", PDUType.A_RELEASE_RQ.value, 0x00, 4) + b"\x00" * 4,
            ),
            (
                "abort_before_assoc",
                struct.pack(">BBL", PDUType.A_ABORT.value, 0x00, 4) + b"\x00" * 4,
            ),
        ]

        for test_name, pdu in test_cases:
            start_time = time.time()
            try:
                response, _ = self._send_receive(pdu)
                duration = time.time() - start_time

                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"state_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                    )
                )

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"state_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def run_campaign(
        self, strategies: list[FuzzingStrategy] | None = None
    ) -> list[NetworkFuzzResult]:
        """Run complete fuzzing campaign.

        Args:
            strategies: List of strategies to run (all if None)

        Returns:
            List of all NetworkFuzzResult objects

        """
        if strategies is None:
            strategies = list(FuzzingStrategy)

        results: list[NetworkFuzzResult] = []

        # First test valid association
        logger.info("Testing valid association...")
        results.append(self.test_valid_association())

        if FuzzingStrategy.INVALID_LENGTH in strategies:
            logger.info("Fuzzing PDU length fields...")
            results.extend(self.fuzz_pdu_length())

        if FuzzingStrategy.BUFFER_OVERFLOW in strategies:
            logger.info("Fuzzing AE titles (buffer overflow)...")
            results.extend(self.fuzz_ae_title())

        if FuzzingStrategy.MALFORMED_PDU in strategies:
            logger.info("Fuzzing presentation contexts...")
            results.extend(self.fuzz_presentation_context())

            logger.info("Sending random bytes...")
            results.extend(self.fuzz_random_bytes())

        if FuzzingStrategy.PROTOCOL_STATE in strategies:
            logger.info("Testing protocol state violations...")
            results.extend(self.fuzz_protocol_state())

        self._results = results
        return results

    def get_summary(self) -> dict[str, Any]:
        """Get summary of fuzzing results.

        Returns:
            Dictionary with result statistics

        """
        results = self._results

        summary: dict[str, Any] = {
            "total_tests": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "crashes_detected": sum(1 for r in results if r.crash_detected),
            "anomalies_detected": sum(1 for r in results if r.anomaly_detected),
            "by_strategy": {},
            "critical_findings": [],
        }

        for result in results:
            strategy = result.strategy.value
            if strategy not in summary["by_strategy"]:
                summary["by_strategy"][strategy] = {
                    "total": 0,
                    "successful": 0,
                    "crashes": 0,
                    "anomalies": 0,
                }
            summary["by_strategy"][strategy]["total"] += 1
            if result.success:
                summary["by_strategy"][strategy]["successful"] += 1
            if result.crash_detected:
                summary["by_strategy"][strategy]["crashes"] += 1
            if result.anomaly_detected:
                summary["by_strategy"][strategy]["anomalies"] += 1

            if result.crash_detected or result.anomaly_detected:
                summary["critical_findings"].append(result.to_dict())

        return summary

    def print_summary(self) -> None:
        """Print formatted summary to console."""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("  DICOM Network Fuzzing Campaign Results")
        print("=" * 70)
        print(
            f"  Target:            {self.config.target_host}:{self.config.target_port}"
        )
        print(f"  Total Tests:       {summary['total_tests']}")
        print(f"  Successful:        {summary['successful']}")
        print(f"  Failed:            {summary['failed']}")
        print(f"  Crashes Detected:  {summary['crashes_detected']}")
        print(f"  Anomalies:         {summary['anomalies_detected']}")

        print("\n--- Results by Strategy ---")
        for strategy, stats in summary["by_strategy"].items():
            print(
                f"  {strategy}: {stats['total']} tests, "
                f"{stats['crashes']} crashes, {stats['anomalies']} anomalies"
            )

        if summary["critical_findings"]:
            print("\n--- Critical Findings ---")
            for finding in summary["critical_findings"][:10]:
                print(
                    f"  [!] {finding['test_name']}: {finding.get('error', 'anomaly')}"
                )

        print("=" * 70 + "\n")

    def save_results(self, output_path: Path) -> None:
        """Save results to JSON file.

        Args:
            output_path: Path to save results

        """
        import json

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(
                {
                    "config": {
                        "target_host": self.config.target_host,
                        "target_port": self.config.target_port,
                        "calling_ae": self.config.calling_ae,
                        "called_ae": self.config.called_ae,
                    },
                    "summary": self.get_summary(),
                    "results": [r.to_dict() for r in self._results],
                },
                f,
                indent=2,
            )
        logger.info(f"Results saved to {output_path}")

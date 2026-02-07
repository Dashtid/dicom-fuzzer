"""DICOM PDU Fuzzing Mixin.

Provides fuzzing methods for DICOM PDU structure, AE titles,
and presentation contexts.
"""

from __future__ import annotations

import random
import struct
import time
from typing import TYPE_CHECKING

from .base import (
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUType,
)
from .builder import DICOMProtocolBuilder

if TYPE_CHECKING:
    from .base import DICOMNetworkConfig


class PDUFuzzingMixin:
    """Mixin providing PDU structure fuzzing methods.

    Requires:
        self.config: DICOMNetworkConfig
        self._send_receive(data: bytes) -> tuple[bytes, float]
    """

    config: DICOMNetworkConfig

    def _send_receive(self, data: bytes) -> tuple[bytes, float]:
        """Send data and receive response. Must be implemented by main class."""
        raise NotImplementedError

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

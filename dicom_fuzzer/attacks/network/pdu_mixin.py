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

    def fuzz_transfer_syntax_list(self) -> list[NetworkFuzzResult]:
        """Fuzz the Transfer Syntax list within a single Presentation Context.

        Gap #8 from the 2026-06-06 Phase 1 audit. The existing
        ``fuzz_presentation_context`` only varies ``context_id`` with a
        hardcoded ``[IMPLICIT_VR_LE]`` TS list, leaving the list-shape
        attack surface entirely uncovered. PS3.8 9.3.2.2 allows multiple
        TS sub-items in an A-ASSOCIATE-RQ Presentation Context but
        exactly one in the matching A-ASSOCIATE-AC -- a divergence that
        often confuses SCP parsers.

        Tests:

        - ``ts_empty_list``: zero Transfer Syntax sub-items (PS3.8 says
          at least one is required)
        - ``ts_duplicate``: ``[IMPLICIT, IMPLICIT]`` -- same UID twice
        - ``ts_app_context_uid_as_ts``: misuses
          ``1.2.840.10008.3.1.1.1`` (the DICOM Application Context UID)
          as a Transfer Syntax
        - ``ts_mixed_uncompressed_and_compressed``: ``[IMPLICIT,
          EXPLICIT, JPEG_2000_LOSSLESS, RLE]``

        Returns:
            List of NetworkFuzzResult objects

        """
        # JPEG 2000 Lossless + RLE TS UIDs (NUL-terminated per builder convention)
        jpeg_2000_lossless = b"1.2.840.10008.1.2.4.90\x00\x00"
        rle_lossless = b"1.2.840.10008.1.2.5\x00"
        application_context_uid_as_ts = b"1.2.840.10008.3.1.1.1\x00"
        test_cases = [
            ("ts_empty_list", []),
            (
                "ts_duplicate",
                [
                    DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                    DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                ],
            ),
            ("ts_app_context_uid_as_ts", [application_context_uid_as_ts]),
            (
                "ts_mixed_uncompressed_and_compressed",
                [
                    DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                    DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN,
                    jpeg_2000_lossless,
                    rle_lossless,
                ],
            ),
        ]
        return self._run_pres_ctx_test_cases(test_cases, "ts_list")

    def fuzz_presentation_context_list_shape(self) -> list[NetworkFuzzResult]:
        """Fuzz the shape of the Presentation Context list itself.

        Gap #9 from the 2026-06-06 Phase 1 audit. Sibling of
        ``fuzz_transfer_syntax_list`` -- where that method varies the TS
        list inside one PC, this one varies the list of PCs as a whole.
        PS3.8 mandates odd context IDs in the range 1..255; many SCP
        implementations allocate fixed-size arrays indexed by raw
        context_id and trust the ID to be unique within an RQ.

        Tests:

        - ``pcs_empty_list``: zero Presentation Context items (PS3.8
          implies >= 1)
        - ``pcs_256_items``: 256 PC items with sequential odd IDs --
          probes SCP array-bound logic
        - ``pcs_duplicate_ctx_id``: two PCs sharing the same context_id
        - ``pcs_even_ids``: PCs with ctx_id 0, 2, 254 (even IDs are
          illegal per PS3.8 7.1.1.13)

        Returns:
            List of NetworkFuzzResult objects

        """

        # Helper to build a PC with a single sane TS so we isolate the
        # shape of the PC list as the attack variable.
        def _pc(ctx_id: int) -> bytes:
            return DICOMProtocolBuilder._build_presentation_context(
                context_id=ctx_id & 0xFF,
                abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
                transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
            )

        test_cases: list[tuple[str, list[bytes]]] = [
            ("pcs_empty_list", []),
            # 256 odd ctx_ids; the byte field is 1 byte (0..255) so this
            # forces the SCP to handle near-maximum count.
            ("pcs_256_items", [_pc(i) for i in range(1, 512, 2)]),
            ("pcs_duplicate_ctx_id", [_pc(1), _pc(1)]),
            ("pcs_even_ids", [_pc(0), _pc(2), _pc(254)]),
        ]
        results = []
        for test_name, pc_list in test_cases:
            start_time = time.time()
            try:
                pdu = DICOMProtocolBuilder.build_a_associate_rq(
                    calling_ae=self.config.calling_ae,
                    called_ae=self.config.called_ae,
                    presentation_contexts=pc_list,
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
                        crash_detected=len(response) == 0,
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

    def _run_pres_ctx_test_cases(
        self,
        test_cases: list[tuple[str, list[bytes]]],
        label: str,
    ) -> list[NetworkFuzzResult]:
        """Build one A-ASSOCIATE-RQ per (test_name, ts_list) case and send it.

        Shared driver used by ``fuzz_transfer_syntax_list``. Each
        ``test_name`` is prefixed with ``label`` so the resulting
        result objects are uniquely attributable.
        """
        results = []
        for test_name, ts_list in test_cases:
            start_time = time.time()
            try:
                pres_ctx = DICOMProtocolBuilder._build_presentation_context(
                    context_id=1,
                    abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
                    transfer_syntaxes=ts_list,
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
                        test_name=f"pres_ctx_{label}_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                        crash_detected=len(response) == 0,
                    )
                )
            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.MALFORMED_PDU,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"pres_ctx_{label}_{test_name}",
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

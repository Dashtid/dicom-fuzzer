"""DICOM Authentication Testing.

Test DICOM authentication security including AE title enumeration
and anonymous association attempts. Extracted from dicom_tls_fuzzer.py
to enable better modularity.
"""

from __future__ import annotations

import socket
import ssl
import struct
import time

from dicom_fuzzer.core.tls_types import (
    COMMON_AE_TITLES,
    DICOMTLSFuzzerConfig,
    TLSFuzzResult,
)
from dicom_fuzzer.core.types import PDUType


class DICOMAuthTester:
    """Test DICOM authentication security."""

    def __init__(self, config: DICOMTLSFuzzerConfig) -> None:
        """Initialize the DICOM authentication tester.

        Args:
            config: DICOM TLS fuzzer configuration.

        """
        self.config = config
        self.results: list[TLSFuzzResult] = []

    def test_ae_title_enumeration(self) -> list[TLSFuzzResult]:
        """Enumerate valid AE Titles through association attempts.

        Returns:
            List of test results for each AE title tested.

        """
        results = []

        for ae_title in COMMON_AE_TITLES:
            result = self._test_ae_title(ae_title)
            results.append(result)

        return results

    def _test_ae_title(self, ae_title: str) -> TLSFuzzResult:
        """Test if an AE Title is valid/accepted.

        Args:
            ae_title: Application Entity title to test.

        Returns:
            Test result for the specified AE title.

        """
        start_time = time.time()

        try:
            # Build A-ASSOCIATE-RQ PDU
            pdu = self._build_associate_request(
                calling_ae=self.config.calling_ae,
                called_ae=ae_title,
            )

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                if self.config.use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)

                sock.send(pdu)
                response = sock.recv(4096)

                if response and len(response) > 0:
                    pdu_type = response[0]

                    if pdu_type == PDUType.A_ASSOCIATE_AC.value:
                        return TLSFuzzResult(
                            test_type="ae_title_enum",
                            target=f"{self.config.target_host}:{self.config.target_port}",
                            success=True,
                            vulnerability_found=True,
                            vulnerability_type="ae_title_accepted",
                            details=f"AE Title '{ae_title}' accepted",
                            raw_response=response,
                            duration_ms=(time.time() - start_time) * 1000,
                            severity="medium",
                        )
                    elif pdu_type == PDUType.A_ASSOCIATE_RJ.value:
                        reject_reason = response[7] if len(response) > 7 else 0
                        return TLSFuzzResult(
                            test_type="ae_title_enum",
                            target=f"{self.config.target_host}:{self.config.target_port}",
                            success=True,
                            vulnerability_found=False,
                            details=f"AE Title '{ae_title}' rejected (reason: {reject_reason})",
                            raw_response=response,
                            duration_ms=(time.time() - start_time) * 1000,
                            severity="info",
                        )

                return TLSFuzzResult(
                    test_type="ae_title_enum",
                    target=f"{self.config.target_host}:{self.config.target_port}",
                    success=True,
                    details=f"Unknown response for AE Title '{ae_title}'",
                    raw_response=response,
                    duration_ms=(time.time() - start_time) * 1000,
                    severity="info",
                )

        except Exception as e:
            return TLSFuzzResult(
                test_type="ae_title_enum",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error testing AE Title '{ae_title}': {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

    def _build_associate_request(
        self,
        calling_ae: str,
        called_ae: str,
        abstract_syntax: str = "1.2.840.10008.1.1",  # Verification SOP Class
    ) -> bytes:
        """Build DICOM A-ASSOCIATE-RQ PDU.

        Args:
            calling_ae: Calling Application Entity title.
            called_ae: Called Application Entity title.
            abstract_syntax: Abstract syntax UID for the presentation context.

        Returns:
            Encoded A-ASSOCIATE-RQ PDU bytes.

        """
        # Pad AE Titles to 16 bytes
        calling_ae_bytes = calling_ae.encode("ascii").ljust(16)[:16]
        called_ae_bytes = called_ae.encode("ascii").ljust(16)[:16]

        # Application Context Item
        app_context_name = b"1.2.840.10008.3.1.1.1"  # DICOM Application Context
        app_context_item = (
            struct.pack(">BxH", 0x10, len(app_context_name)) + app_context_name
        )

        # Presentation Context Item (simplified)
        abstract_syntax_bytes = abstract_syntax.encode("ascii")
        abstract_syntax_item = (
            struct.pack(">BxH", 0x30, len(abstract_syntax_bytes))
            + abstract_syntax_bytes
        )

        transfer_syntax = b"1.2.840.10008.1.2"  # Implicit VR Little Endian
        transfer_syntax_item = (
            struct.pack(">BxH", 0x40, len(transfer_syntax)) + transfer_syntax
        )

        presentation_context = (
            struct.pack(
                ">BxHBxxxH",
                0x20,
                len(abstract_syntax_item) + len(transfer_syntax_item) + 4,
                1,  # Presentation Context ID
                len(abstract_syntax_item) + len(transfer_syntax_item),
            )
            + abstract_syntax_item
            + transfer_syntax_item
        )

        # Build variable items
        variable_items = app_context_item + presentation_context

        # Build PDU
        pdu_length = 68 + len(variable_items)  # Fixed fields + variable

        pdu = struct.pack(
            ">BxI",  # PDU Type, Reserved, PDU Length
            PDUType.A_ASSOCIATE_RQ.value,
            pdu_length,
        )

        pdu += struct.pack(">HH", 1, 0)  # Protocol Version, Reserved
        pdu += called_ae_bytes  # Called AE Title (16 bytes)
        pdu += calling_ae_bytes  # Calling AE Title (16 bytes)
        pdu += b"\x00" * 32  # Reserved (32 bytes)
        pdu += variable_items

        return pdu

    def test_anonymous_association(self) -> TLSFuzzResult:
        """Test if anonymous associations are accepted.

        Returns:
            Test result for anonymous association attempt.

        """
        start_time = time.time()

        try:
            # Try empty/blank AE titles
            pdu = self._build_associate_request(
                calling_ae="",
                called_ae="",
            )

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                if self.config.use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)

                sock.send(pdu)
                response = sock.recv(4096)

                if (
                    response
                    and len(response) > 0
                    and response[0] == PDUType.A_ASSOCIATE_AC.value
                ):
                    return TLSFuzzResult(
                        test_type="anonymous_assoc",
                        target=f"{self.config.target_host}:{self.config.target_port}",
                        success=True,
                        vulnerability_found=True,
                        vulnerability_type="anonymous_access",
                        details="Server accepts anonymous associations!",
                        raw_response=response,
                        duration_ms=(time.time() - start_time) * 1000,
                        severity="critical",
                    )

                return TLSFuzzResult(
                    test_type="anonymous_assoc",
                    target=f"{self.config.target_host}:{self.config.target_port}",
                    success=True,
                    vulnerability_found=False,
                    details="Anonymous associations rejected",
                    raw_response=response if response else b"",
                    duration_ms=(time.time() - start_time) * 1000,
                    severity="info",
                )

        except Exception as e:
            return TLSFuzzResult(
                test_type="anonymous_assoc",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

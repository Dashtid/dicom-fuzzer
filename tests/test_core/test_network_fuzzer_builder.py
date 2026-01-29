"""Tests for DICOM Protocol Message Builder.

Tests the PDU building functionality in
dicom_fuzzer.core.network_fuzzer_builder module.
"""

import struct

from dicom_fuzzer.strategies.network.builder import DICOMProtocolBuilder
from dicom_fuzzer.core.types import PDUType


class TestBuildAAssociateRQ:
    """Tests for build_a_associate_rq method."""

    def test_build_with_defaults(self) -> None:
        """Test building A-ASSOCIATE-RQ with default values."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq()

        # Verify it's bytes
        assert isinstance(pdu, bytes)
        assert len(pdu) > 0

        # Verify PDU type (first byte)
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

    def test_build_has_correct_pdu_type(self) -> None:
        """Test PDU type is A-ASSOCIATE-RQ (0x01)."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq()
        assert pdu[0] == 0x01

    def test_build_with_custom_ae_titles(self) -> None:
        """Test building with custom AE titles."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            calling_ae="MY_SCU",
            called_ae="MY_SCP",
        )

        # PDU should contain the AE titles (padded to 16 bytes)
        # After PDU header (6 bytes), protocol version (2), reserved (2)
        # called AE is at offset 10, calling AE is at offset 26
        called_ae_start = 10
        calling_ae_start = 26

        called_ae_bytes = pdu[called_ae_start : called_ae_start + 16]
        calling_ae_bytes = pdu[calling_ae_start : calling_ae_start + 16]

        assert b"MY_SCP" in called_ae_bytes
        assert b"MY_SCU" in calling_ae_bytes

    def test_build_with_long_ae_title_truncated(self) -> None:
        """Test that AE titles longer than 16 chars are truncated."""
        long_title = "THIS_IS_A_VERY_LONG_AE_TITLE"
        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            calling_ae=long_title,
            called_ae=long_title,
        )

        # Verify PDU is still valid (doesn't fail)
        assert isinstance(pdu, bytes)
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

    def test_build_with_custom_max_pdu_size(self) -> None:
        """Test building with custom max PDU size."""
        max_pdu = 32768
        pdu = DICOMProtocolBuilder.build_a_associate_rq(max_pdu_size=max_pdu)

        # PDU should contain the max PDU size in user info
        # It's encoded as big-endian 32-bit int somewhere in the PDU
        assert isinstance(pdu, bytes)

        # The max PDU size (32768 = 0x8000) should be in the PDU
        # Encoded as big-endian 4 bytes: 0x00 0x00 0x80 0x00
        assert b"\x00\x00\x80\x00" in pdu

    def test_build_with_custom_presentation_contexts(self) -> None:
        """Test building with custom presentation contexts."""
        # Build a custom presentation context
        custom_ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=3,
            abstract_syntax=DICOMProtocolBuilder.CT_IMAGE_STORAGE,
            transfer_syntaxes=[
                DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN,
            ],
        )

        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            presentation_contexts=[custom_ctx]
        )

        # Verify PDU is valid
        assert isinstance(pdu, bytes)
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

        # Verify CT Image Storage UID is in the PDU
        assert b"1.2.840.10008.5.1.4.1.1.2" in pdu

    def test_build_with_custom_application_context(self) -> None:
        """Test building with custom application context."""
        custom_app_ctx = b"1.2.3.4.5.6.7.8.9\x00"
        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            application_context=custom_app_ctx
        )

        # Verify custom app context is in PDU
        assert b"1.2.3.4.5.6.7.8.9" in pdu

    def test_pdu_length_field(self) -> None:
        """Test PDU length field is correct."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq()

        # PDU format: type (1), reserved (1), length (4, big-endian), data
        length_bytes = pdu[2:6]
        length = struct.unpack(">L", length_bytes)[0]

        # Total PDU length should be 6 (header) + length
        assert len(pdu) == 6 + length


class TestBuildPresentationContext:
    """Tests for _build_presentation_context method."""

    def test_build_single_transfer_syntax(self) -> None:
        """Test building presentation context with single transfer syntax."""
        ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=1,
            abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
            transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
        )

        # Verify it's bytes
        assert isinstance(ctx, bytes)

        # Verify presentation context item type (0x20)
        assert ctx[0] == 0x20

        # Verify abstract syntax is included
        assert b"1.2.840.10008.1.1" in ctx

        # Verify transfer syntax is included
        assert b"1.2.840.10008.1.2" in ctx

    def test_build_multiple_transfer_syntaxes(self) -> None:
        """Test building presentation context with multiple transfer syntaxes."""
        ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=1,
            abstract_syntax=DICOMProtocolBuilder.CT_IMAGE_STORAGE,
            transfer_syntaxes=[
                DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN,
                DICOMProtocolBuilder.EXPLICIT_VR_BIG_ENDIAN,
            ],
        )

        # Verify all transfer syntaxes are included
        assert b"1.2.840.10008.1.2\x00" in ctx  # Implicit VR LE
        assert b"1.2.840.10008.1.2.1\x00" in ctx  # Explicit VR LE
        assert b"1.2.840.10008.1.2.2\x00" in ctx  # Explicit VR BE

    def test_context_id_in_output(self) -> None:
        """Test context ID is encoded in output."""
        ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=5,
            abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
            transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
        )

        # Context ID should be in the item data after item header
        # Item format: type (1), reserved (1), length (2), context_id (1), reserved (3), data
        # Context ID is at offset 4
        assert ctx[4] == 5


class TestBuildCEchoRQ:
    """Tests for build_c_echo_rq method."""

    def test_build_default_message_id(self) -> None:
        """Test building C-ECHO-RQ with default message ID."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq()

        # Verify it's bytes
        assert isinstance(pdu, bytes)
        assert len(pdu) > 0

        # Verify PDU type is P-DATA-TF (0x04)
        assert pdu[0] == PDUType.P_DATA_TF.value

    def test_build_custom_message_id(self) -> None:
        """Test building C-ECHO-RQ with custom message ID."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq(message_id=42)

        # Verify PDU is valid
        assert isinstance(pdu, bytes)
        assert pdu[0] == PDUType.P_DATA_TF.value

        # Message ID 42 = 0x002A should be somewhere in the PDU (little-endian)
        assert b"\x2a\x00" in pdu

    def test_contains_verification_sop_class(self) -> None:
        """Test C-ECHO contains Verification SOP Class UID."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq()

        # Verification SOP Class UID
        assert b"1.2.840.10008.1.1" in pdu

    def test_contains_c_echo_command_field(self) -> None:
        """Test C-ECHO contains C-ECHO command field value."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq()

        # C-ECHO-RQ command field is 0x0030 (little-endian: 0x30 0x00)
        assert b"\x30\x00" in pdu

    def test_pdu_length_field(self) -> None:
        """Test P-DATA-TF PDU length field is correct."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq()

        # PDU format: type (1), reserved (1), length (4, big-endian), data
        length_bytes = pdu[2:6]
        length = struct.unpack(">L", length_bytes)[0]

        # Total PDU length should be 6 (header) + length
        assert len(pdu) == 6 + length


class TestClassConstants:
    """Tests for class constants."""

    def test_transfer_syntaxes_defined(self) -> None:
        """Test transfer syntax constants are defined."""
        assert (
            DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN == b"1.2.840.10008.1.2\x00"
        )
        assert (
            DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN == b"1.2.840.10008.1.2.1\x00"
        )
        assert DICOMProtocolBuilder.EXPLICIT_VR_BIG_ENDIAN == b"1.2.840.10008.1.2.2\x00"

    def test_sop_classes_defined(self) -> None:
        """Test SOP class constants are defined."""
        assert DICOMProtocolBuilder.VERIFICATION_SOP_CLASS == b"1.2.840.10008.1.1\x00"
        assert DICOMProtocolBuilder.CT_IMAGE_STORAGE == b"1.2.840.10008.5.1.4.1.1.2\x00"
        assert DICOMProtocolBuilder.MR_IMAGE_STORAGE == b"1.2.840.10008.5.1.4.1.1.4\x00"
        assert (
            DICOMProtocolBuilder.PATIENT_ROOT_QR_FIND
            == b"1.2.840.10008.5.1.4.1.2.1.1\x00"
        )
        assert (
            DICOMProtocolBuilder.PATIENT_ROOT_QR_MOVE
            == b"1.2.840.10008.5.1.4.1.2.1.2\x00"
        )

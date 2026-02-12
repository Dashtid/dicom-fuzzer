"""
Comprehensive test suite for types.py

Tests shared type definitions including:
- DICOMCommand enum
- PDUType enum
- Backward compatibility aliases
"""

from dicom_fuzzer.core.types import (
    DICOMCommand,
    DIMSECommand,
    PDUType,
)


class TestDICOMCommand:
    """Test DICOMCommand enum for DICOM protocol commands."""

    def test_composite_commands_exist(self):
        """Test that C-DIMSE commands are defined."""
        assert hasattr(DICOMCommand, "C_STORE_RQ")
        assert hasattr(DICOMCommand, "C_STORE_RSP")
        assert hasattr(DICOMCommand, "C_GET_RQ")
        assert hasattr(DICOMCommand, "C_GET_RSP")
        assert hasattr(DICOMCommand, "C_FIND_RQ")
        assert hasattr(DICOMCommand, "C_FIND_RSP")
        assert hasattr(DICOMCommand, "C_MOVE_RQ")
        assert hasattr(DICOMCommand, "C_MOVE_RSP")
        assert hasattr(DICOMCommand, "C_ECHO_RQ")
        assert hasattr(DICOMCommand, "C_ECHO_RSP")
        assert hasattr(DICOMCommand, "C_CANCEL_RQ")

    def test_normalized_commands_exist(self):
        """Test that N-DIMSE commands are defined."""
        assert hasattr(DICOMCommand, "N_EVENT_REPORT_RQ")
        assert hasattr(DICOMCommand, "N_EVENT_REPORT_RSP")
        assert hasattr(DICOMCommand, "N_GET_RQ")
        assert hasattr(DICOMCommand, "N_GET_RSP")
        assert hasattr(DICOMCommand, "N_SET_RQ")
        assert hasattr(DICOMCommand, "N_SET_RSP")
        assert hasattr(DICOMCommand, "N_ACTION_RQ")
        assert hasattr(DICOMCommand, "N_ACTION_RSP")
        assert hasattr(DICOMCommand, "N_CREATE_RQ")
        assert hasattr(DICOMCommand, "N_CREATE_RSP")
        assert hasattr(DICOMCommand, "N_DELETE_RQ")
        assert hasattr(DICOMCommand, "N_DELETE_RSP")

    def test_command_values_are_hex(self):
        """Test that command values are correct hex values."""
        assert DICOMCommand.C_STORE_RQ.value == 0x0001
        assert DICOMCommand.C_STORE_RSP.value == 0x8001
        assert DICOMCommand.C_ECHO_RQ.value == 0x0030
        assert DICOMCommand.C_ECHO_RSP.value == 0x8030
        assert DICOMCommand.C_CANCEL_RQ.value == 0x0FFF

    def test_response_values_have_high_bit_set(self):
        """Test that response commands have high bit set (0x8000)."""
        assert DICOMCommand.C_STORE_RSP.value & 0x8000 == 0x8000
        assert DICOMCommand.C_GET_RSP.value & 0x8000 == 0x8000
        assert DICOMCommand.C_FIND_RSP.value & 0x8000 == 0x8000
        assert DICOMCommand.C_MOVE_RSP.value & 0x8000 == 0x8000
        assert DICOMCommand.C_ECHO_RSP.value & 0x8000 == 0x8000

    def test_request_values_no_high_bit(self):
        """Test that request commands don't have high bit set."""
        assert DICOMCommand.C_STORE_RQ.value & 0x8000 == 0
        assert DICOMCommand.C_GET_RQ.value & 0x8000 == 0
        assert DICOMCommand.C_FIND_RQ.value & 0x8000 == 0
        assert DICOMCommand.C_MOVE_RQ.value & 0x8000 == 0
        assert DICOMCommand.C_ECHO_RQ.value & 0x8000 == 0

    def test_enum_member_count(self):
        """Test that enum has expected number of members (C-DIMSE + N-DIMSE)."""
        # 11 C-DIMSE (5 pairs + C_CANCEL_RQ) + 12 N-DIMSE (6 pairs) = 23
        assert len(DICOMCommand) == 23


class TestDIMSECommandAlias:
    """Test DIMSECommand backward compatibility alias."""

    def test_alias_is_same_enum(self):
        """Test that DIMSECommand is an alias for DICOMCommand."""
        assert DIMSECommand is DICOMCommand

    def test_alias_members_accessible(self):
        """Test that members are accessible through alias."""
        assert DIMSECommand.C_ECHO_RQ == DICOMCommand.C_ECHO_RQ
        assert DIMSECommand.C_STORE_RQ == DICOMCommand.C_STORE_RQ

    def test_alias_comparison(self):
        """Test comparing values from alias and original."""
        assert DIMSECommand.C_ECHO_RQ.value == DICOMCommand.C_ECHO_RQ.value


class TestPDUType:
    """Test PDUType enum for DICOM PDU types."""

    def test_all_pdu_types_exist(self):
        """Test that all PDU types are defined."""
        assert hasattr(PDUType, "A_ASSOCIATE_RQ")
        assert hasattr(PDUType, "A_ASSOCIATE_AC")
        assert hasattr(PDUType, "A_ASSOCIATE_RJ")
        assert hasattr(PDUType, "P_DATA_TF")
        assert hasattr(PDUType, "A_RELEASE_RQ")
        assert hasattr(PDUType, "A_RELEASE_RP")
        assert hasattr(PDUType, "A_ABORT")

    def test_pdu_type_values(self):
        """Test that PDU type values are correct."""
        assert PDUType.A_ASSOCIATE_RQ.value == 0x01
        assert PDUType.A_ASSOCIATE_AC.value == 0x02
        assert PDUType.A_ASSOCIATE_RJ.value == 0x03
        assert PDUType.P_DATA_TF.value == 0x04
        assert PDUType.A_RELEASE_RQ.value == 0x05
        assert PDUType.A_RELEASE_RP.value == 0x06
        assert PDUType.A_ABORT.value == 0x07

    def test_enum_member_count(self):
        """Test that enum has exactly 7 members."""
        assert len(PDUType) == 7

    def test_pdu_types_sequential(self):
        """Test that PDU type values are sequential 1-7."""
        values = sorted([pdu.value for pdu in PDUType])
        assert values == [1, 2, 3, 4, 5, 6, 7]

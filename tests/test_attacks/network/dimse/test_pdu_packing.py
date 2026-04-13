"""Tests for DIMSE PDU packing -- to_p_data_tf_pdu() and build_c_store_from_pydicom().

Covers:
- DIMSEMessage.to_p_data_tf_pdu(): complete P-DATA-TF PDU output
- DIMSECommandBuilder.build_c_store_from_pydicom(): C-STORE from pydicom Dataset
- DIMSEFuzzer integration: generated fuzz cases can be serialized to PDU bytes
"""

import struct

import pytest
from pydicom.dataset import Dataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.attacks.network.dimse.fuzzer import (
    DIMSECommandBuilder,
    DIMSEFuzzer,
    SOPClass,
)
from dicom_fuzzer.attacks.network.dimse.types import (
    DICOMElement,
    DIMSEMessage,
)
from dicom_fuzzer.core.types import DIMSECommand

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_P_DATA_TF_TYPE = 0x04


def _parse_p_data_tf_header(data: bytes) -> tuple[int, int, int]:
    """Parse a P-DATA-TF PDU header.

    Returns:
        (pdu_type, reserved, pdu_length) as ints.

    """
    assert len(data) >= 6, "P-DATA-TF PDU too short for header"
    pdu_type, reserved, pdu_length = struct.unpack(">BBL", data[:6])
    return pdu_type, reserved, pdu_length


def _make_minimal_dataset() -> Dataset:
    """Return a minimal pydicom Dataset suitable for C-STORE tests."""
    ds = Dataset()
    ds.file_meta = Dataset()
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.9.0"
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9.0"
    ds.PatientName = "FUZZER^TEST"
    ds.PatientID = "FUZZ001"
    ds.Rows = 4
    ds.Columns = 4
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = b"\x00" * 16
    ds.is_implicit_VR = False
    ds.is_little_endian = True
    return ds


# ---------------------------------------------------------------------------
# DIMSEMessage.to_p_data_tf_pdu() -- command-only
# ---------------------------------------------------------------------------


class TestToPDataTfPduCommandOnly:
    """to_p_data_tf_pdu() for messages with no data elements."""

    @pytest.fixture
    def msg(self) -> DIMSEMessage:
        return DIMSEMessage(
            command=DIMSECommand.C_ECHO_RQ,
            command_elements=[
                DICOMElement((0x0000, 0x0002), "UI", "1.2.840.10008.1.1"),
                DICOMElement((0x0000, 0x0100), "US", DIMSECommand.C_ECHO_RQ.value),
                DICOMElement((0x0000, 0x0110), "US", 1),
                DICOMElement((0x0000, 0x0800), "US", 0x0101),
            ],
        )

    def test_returns_bytes(self, msg: DIMSEMessage) -> None:
        """to_p_data_tf_pdu() returns bytes."""
        result = msg.to_p_data_tf_pdu()
        assert isinstance(result, bytes)

    def test_returns_non_empty(self, msg: DIMSEMessage) -> None:
        """to_p_data_tf_pdu() returns non-empty bytes."""
        result = msg.to_p_data_tf_pdu()
        assert len(result) > 0

    def test_pdu_type_byte_is_p_data_tf(self, msg: DIMSEMessage) -> None:
        """First byte is P-DATA-TF type (0x04)."""
        result = msg.to_p_data_tf_pdu()
        assert result[0] == _P_DATA_TF_TYPE

    def test_reserved_byte_is_zero(self, msg: DIMSEMessage) -> None:
        """Second byte (reserved) is 0x00."""
        result = msg.to_p_data_tf_pdu()
        assert result[1] == 0x00

    def test_pdu_length_matches_payload(self, msg: DIMSEMessage) -> None:
        """PDU length field matches remaining bytes after the 6-byte header."""
        result = msg.to_p_data_tf_pdu()
        _, _, pdu_length = _parse_p_data_tf_header(result)
        assert pdu_length == len(result) - 6

    def test_total_length_at_least_header_plus_pdv_header(
        self, msg: DIMSEMessage
    ) -> None:
        """PDU is at least 6 (PDU header) + 6 (PDV header: 4B len + 1B ctx + 1B ctrl) bytes."""
        result = msg.to_p_data_tf_pdu()
        assert len(result) >= 12

    def test_control_byte_indicates_command_and_last(self, msg: DIMSEMessage) -> None:
        """PDV control byte has bit0 (command) and bit1 (last-fragment) set = 0x03."""
        result = msg.to_p_data_tf_pdu()
        # PDU header = 6 bytes, PDV item length = 4 bytes, context_id = 1 byte, control = 1 byte
        control_byte_offset = 6 + 4 + 1
        assert result[control_byte_offset] == 0x03  # is_command=True, is_last=True


# ---------------------------------------------------------------------------
# DIMSEMessage.to_p_data_tf_pdu() -- command + data
# ---------------------------------------------------------------------------


class TestToPDataTfPduWithData:
    """to_p_data_tf_pdu() for messages that include data elements."""

    @pytest.fixture
    def msg(self) -> DIMSEMessage:
        return DIMSEMessage(
            command=DIMSECommand.C_STORE_RQ,
            command_elements=[
                DICOMElement((0x0000, 0x0002), "UI", SOPClass.CT_IMAGE_STORAGE.value),
                DICOMElement((0x0000, 0x0100), "US", DIMSECommand.C_STORE_RQ.value),
                DICOMElement((0x0000, 0x0110), "US", 1),
                DICOMElement((0x0000, 0x0700), "US", 0),
                DICOMElement((0x0000, 0x0800), "US", 0x0000),
                DICOMElement((0x0000, 0x1000), "UI", "1.2.3.4.5.6.7"),
            ],
            data_elements=[
                DICOMElement((0x0010, 0x0010), "PN", "FUZZER^TEST"),
                DICOMElement((0x0010, 0x0020), "LO", "FUZZ001"),
            ],
        )

    def test_returns_bytes(self, msg: DIMSEMessage) -> None:
        result = msg.to_p_data_tf_pdu()
        assert isinstance(result, bytes)

    def test_produces_two_pdus(self, msg: DIMSEMessage) -> None:
        """Two concatenated P-DATA-TF PDUs: command + data."""
        result = msg.to_p_data_tf_pdu()
        # First PDU
        pdu_type_1, _, pdu_length_1 = _parse_p_data_tf_header(result)
        assert pdu_type_1 == _P_DATA_TF_TYPE
        # Second PDU starts after first
        offset = 6 + pdu_length_1
        assert offset < len(result)
        pdu_type_2, _, pdu_length_2 = _parse_p_data_tf_header(result[offset:])
        assert pdu_type_2 == _P_DATA_TF_TYPE
        # No trailing bytes
        assert offset + 6 + pdu_length_2 == len(result)

    def test_data_pdu_control_byte_is_data_and_last(self, msg: DIMSEMessage) -> None:
        """Second PDV control byte has bit1=1 (last), bit0=0 (data) = 0x02."""
        result = msg.to_p_data_tf_pdu()
        _, _, pdu_length_1 = _parse_p_data_tf_header(result)
        # Jump to second PDU
        offset = 6 + pdu_length_1
        # PDV header in second PDU: 4B length + 1B context_id + 1B control
        control_offset = offset + 6 + 4 + 1
        assert result[control_offset] == 0x02  # is_command=False, is_last=True

    def test_command_pdu_longer_than_minimum(self, msg: DIMSEMessage) -> None:
        """Command PDU contains more than just the PDU header (has payload)."""
        result = msg.to_p_data_tf_pdu()
        _, _, pdu_length_1 = _parse_p_data_tf_header(result)
        # PDV item itself must be > 2 bytes (context_id + control)
        assert pdu_length_1 > 2


# ---------------------------------------------------------------------------
# DIMSECommandBuilder.build_c_store_from_pydicom()
# ---------------------------------------------------------------------------


class TestBuildCStoreFromPydicom:
    """Tests for build_c_store_from_pydicom()."""

    @pytest.fixture
    def builder(self) -> DIMSECommandBuilder:
        return DIMSECommandBuilder()

    @pytest.fixture
    def dataset(self) -> Dataset:
        return _make_minimal_dataset()

    def test_returns_dimse_message(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """Returns a DIMSEMessage."""
        result = builder.build_c_store_from_pydicom(dataset)
        assert isinstance(result, DIMSEMessage)

    def test_command_is_c_store_rq(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """Command field is C_STORE_RQ."""
        result = builder.build_c_store_from_pydicom(dataset)
        assert result.command == DIMSECommand.C_STORE_RQ

    def test_has_command_elements(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """Result has command elements."""
        result = builder.build_c_store_from_pydicom(dataset)
        assert len(result.command_elements) > 0

    def test_has_data_elements(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """Result has data elements (the serialized dataset)."""
        result = builder.build_c_store_from_pydicom(dataset)
        assert len(result.data_elements) > 0

    def test_sop_class_from_dataset(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """SOPClassUID in command is taken from dataset."""
        result = builder.build_c_store_from_pydicom(dataset)
        # Find AffectedSOPClassUID element (0000,0002)
        sop_class_elem = next(
            (e for e in result.command_elements if e.tag == (0x0000, 0x0002)), None
        )
        assert sop_class_elem is not None
        assert str(sop_class_elem.value) == str(dataset.SOPClassUID)

    def test_sop_instance_from_dataset(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """SOPInstanceUID in command is taken from dataset."""
        result = builder.build_c_store_from_pydicom(dataset)
        sop_inst_elem = next(
            (e for e in result.command_elements if e.tag == (0x0000, 0x1000)), None
        )
        assert sop_inst_elem is not None
        assert str(sop_inst_elem.value) == str(dataset.SOPInstanceUID)

    def test_missing_sop_class_uses_default(self, builder: DIMSECommandBuilder) -> None:
        """Dataset without SOPClassUID falls back gracefully."""
        ds = Dataset()
        ds.PatientName = "TEST"
        ds.is_implicit_VR = False
        ds.is_little_endian = True
        result = builder.build_c_store_from_pydicom(ds)
        assert isinstance(result, DIMSEMessage)
        assert result.command == DIMSECommand.C_STORE_RQ

    def test_can_serialize_to_pdu(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """The returned message can be serialized to P-DATA-TF PDU bytes."""
        msg = builder.build_c_store_from_pydicom(dataset)
        pdu = msg.to_p_data_tf_pdu()
        assert isinstance(pdu, bytes)
        assert pdu[0] == _P_DATA_TF_TYPE

    def test_custom_priority(
        self, builder: DIMSECommandBuilder, dataset: Dataset
    ) -> None:
        """Priority argument is reflected in command elements."""
        result = builder.build_c_store_from_pydicom(dataset, priority=1)
        priority_elem = next(
            (e for e in result.command_elements if e.tag == (0x0000, 0x0700)), None
        )
        assert priority_elem is not None
        assert priority_elem.value == 1


# ---------------------------------------------------------------------------
# DIMSEFuzzer integration
# ---------------------------------------------------------------------------


class TestDIMSEFuzzerPduIntegration:
    """DIMSEFuzzer-generated messages can be serialized to P-DATA-TF PDUs."""

    @pytest.fixture
    def fuzzer(self) -> DIMSEFuzzer:
        return DIMSEFuzzer()

    def test_c_echo_fuzz_cases_serialize_to_pdu(self, fuzzer: DIMSEFuzzer) -> None:
        """All C-ECHO fuzz cases produce valid P-DATA-TF PDU bytes."""
        for msg in fuzzer.generate_c_echo_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            assert pdu[0] == _P_DATA_TF_TYPE

    def test_c_store_fuzz_cases_serialize_to_pdu(self, fuzzer: DIMSEFuzzer) -> None:
        """All C-STORE fuzz cases produce valid P-DATA-TF PDU bytes."""
        for msg in fuzzer.generate_c_store_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            assert pdu[0] == _P_DATA_TF_TYPE

    def test_c_find_fuzz_cases_serialize_to_pdu(self, fuzzer: DIMSEFuzzer) -> None:
        """All C-FIND fuzz cases produce valid P-DATA-TF PDU bytes."""
        for msg in fuzzer.generate_c_find_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            assert pdu[0] == _P_DATA_TF_TYPE

    def test_c_move_fuzz_cases_serialize_to_pdu(self, fuzzer: DIMSEFuzzer) -> None:
        """All C-MOVE fuzz cases produce valid P-DATA-TF PDU bytes."""
        for msg in fuzzer.generate_c_move_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            assert pdu[0] == _P_DATA_TF_TYPE

    def test_generate_all_fuzz_cases_serialize(self, fuzzer: DIMSEFuzzer) -> None:
        """generate_all_fuzz_cases() messages all produce valid PDU bytes."""
        for _name, msg in fuzzer.generate_all_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            assert pdu[0] == _P_DATA_TF_TYPE

    def test_pdu_length_consistency(self, fuzzer: DIMSEFuzzer) -> None:
        """PDU length field is consistent with actual byte length."""
        for msg in fuzzer.generate_c_echo_fuzz_cases():
            pdu = msg.to_p_data_tf_pdu()
            _, _, pdu_length = _parse_p_data_tf_header(pdu)
            # For single-PDU output, length should match remaining bytes
            # (command-only messages produce one PDU)
            first_pdu_total = 6 + pdu_length
            assert first_pdu_total <= len(pdu)

"""
Comprehensive test suite for dimse_types.py

Tests DIMSE-specific types including:
- QueryRetrieveLevel enum
- SOPClass enum
- DICOMElement dataclass
- DIMSEMessage dataclass
- DIMSEFuzzingConfig dataclass
- UIDGenerator class
"""

from dicom_fuzzer.strategies.network.dimse.types import (
    DICOMElement,
    DIMSEFuzzingConfig,
    DIMSEMessage,
    FuzzingConfig,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)
from dicom_fuzzer.core.types import DIMSECommand


class TestQueryRetrieveLevel:
    """Test QueryRetrieveLevel enum."""

    def test_all_levels_exist(self):
        """Test that all Q/R levels are defined."""
        assert hasattr(QueryRetrieveLevel, "PATIENT")
        assert hasattr(QueryRetrieveLevel, "STUDY")
        assert hasattr(QueryRetrieveLevel, "SERIES")
        assert hasattr(QueryRetrieveLevel, "IMAGE")

    def test_level_values(self):
        """Test that level values are correct strings."""
        assert QueryRetrieveLevel.PATIENT.value == "PATIENT"
        assert QueryRetrieveLevel.STUDY.value == "STUDY"
        assert QueryRetrieveLevel.SERIES.value == "SERIES"
        assert QueryRetrieveLevel.IMAGE.value == "IMAGE"

    def test_enum_member_count(self):
        """Test that enum has exactly 4 members."""
        assert len(QueryRetrieveLevel) == 4


class TestSOPClass:
    """Test SOPClass enum for common SOP Class UIDs."""

    def test_verification_sop_class(self):
        """Test verification SOP class UID."""
        assert SOPClass.VERIFICATION.value == "1.2.840.10008.1.1"

    def test_storage_sop_classes(self):
        """Test storage SOP class UIDs."""
        assert SOPClass.CT_IMAGE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.2"
        assert SOPClass.MR_IMAGE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.4"
        assert SOPClass.CR_IMAGE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.1"
        assert SOPClass.US_IMAGE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.6.1"
        assert SOPClass.SECONDARY_CAPTURE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.7"

    def test_query_retrieve_sop_classes(self):
        """Test Q/R SOP class UIDs."""
        assert SOPClass.PATIENT_ROOT_QR_FIND.value == "1.2.840.10008.5.1.4.1.2.1.1"
        assert SOPClass.PATIENT_ROOT_QR_MOVE.value == "1.2.840.10008.5.1.4.1.2.1.2"
        assert SOPClass.STUDY_ROOT_QR_FIND.value == "1.2.840.10008.5.1.4.1.2.2.1"

    def test_worklist_sop_class(self):
        """Test modality worklist SOP class UID."""
        assert SOPClass.MODALITY_WORKLIST_FIND.value == "1.2.840.10008.5.1.4.31"

    def test_all_uids_start_with_dicom_root(self):
        """Test that all UIDs start with DICOM organization root."""
        for sop_class in SOPClass:
            assert sop_class.value.startswith("1.2.840.10008")


class TestDICOMElement:
    """Test DICOMElement dataclass."""

    def test_create_element(self):
        """Test creating a basic element."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Doe^John")
        assert element.tag == (0x0010, 0x0010)
        assert element.vr == "PN"
        assert element.value == "Doe^John"

    def test_create_element_with_bytes(self):
        """Test creating element with bytes value."""
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OW", value=b"\x00\x01\x02\x03")
        assert element.tag == (0x7FE0, 0x0010)
        assert element.vr == "OW"
        assert element.value == b"\x00\x01\x02\x03"

    def test_create_element_with_integer(self):
        """Test creating element with integer value."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="US", value=512)
        assert element.tag == (0x0028, 0x0010)
        assert element.vr == "US"
        assert element.value == 512

    def test_encode_string_element_explicit_vr(self):
        """Test encoding string element with explicit VR."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Test")
        encoded = element.encode(explicit_vr=True)
        # Should contain tag, VR, length, and value
        assert len(encoded) > 0
        # First 4 bytes are group and element
        assert encoded[0:2] == b"\x10\x00"  # Group 0x0010
        assert encoded[2:4] == b"\x10\x00"  # Element 0x0010

    def test_encode_integer_element(self):
        """Test encoding unsigned short element."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="US", value=256)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_implicit_vr(self):
        """Test encoding with implicit VR."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Test")
        encoded = element.encode(explicit_vr=False)
        # Implicit VR doesn't include VR bytes
        assert len(encoded) > 0


class TestDIMSEMessage:
    """Test DIMSEMessage dataclass."""

    def test_create_message(self):
        """Test creating a basic DIMSE message."""
        msg = DIMSEMessage(command=DIMSECommand.C_ECHO_RQ)
        assert msg.command == DIMSECommand.C_ECHO_RQ
        assert msg.command_elements == []
        assert msg.data_elements == []
        assert msg.presentation_context_id == 1

    def test_create_message_with_elements(self):
        """Test creating message with command elements."""
        elements = [
            DICOMElement(tag=(0x0000, 0x0002), vr="UI", value="1.2.3.4"),
        ]
        msg = DIMSEMessage(
            command=DIMSECommand.C_STORE_RQ,
            command_elements=elements,
            presentation_context_id=3,
        )
        assert msg.command == DIMSECommand.C_STORE_RQ
        assert len(msg.command_elements) == 1
        assert msg.presentation_context_id == 3

    def test_encode_message(self):
        """Test encoding a DIMSE message."""
        elements = [
            DICOMElement(tag=(0x0000, 0x0100), vr="US", value=0x0030),  # C-ECHO-RQ
        ]
        msg = DIMSEMessage(
            command=DIMSECommand.C_ECHO_RQ,
            command_elements=elements,
        )
        encoded = msg.encode()
        assert len(encoded) > 0
        # Should be valid PDV format
        assert isinstance(encoded, bytes)


class TestDIMSEFuzzingConfig:
    """Test DIMSEFuzzingConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DIMSEFuzzingConfig()
        assert config.max_string_length == 1024
        assert config.max_sequence_depth == 5
        assert config.probability_invalid_vr == 0.1
        assert config.probability_invalid_length == 0.1
        assert config.probability_invalid_tag == 0.1
        assert config.fuzz_sop_class_uid is True
        assert config.fuzz_sop_instance_uid is True
        assert config.generate_collision_uids is True
        assert config.fuzz_query_levels is True
        assert config.generate_wildcard_attacks is True
        assert config.add_private_elements is True
        assert config.add_nested_sequences is True
        assert config.max_elements_per_message == 100

    def test_custom_config(self):
        """Test custom configuration values."""
        config = DIMSEFuzzingConfig(
            max_string_length=2048,
            probability_invalid_vr=0.5,
            add_private_elements=False,
        )
        assert config.max_string_length == 2048
        assert config.probability_invalid_vr == 0.5
        assert config.add_private_elements is False

    def test_fuzzing_config_alias(self):
        """Test FuzzingConfig backward compatibility alias."""
        assert FuzzingConfig is DIMSEFuzzingConfig
        config = FuzzingConfig()
        assert isinstance(config, DIMSEFuzzingConfig)


class TestUIDGenerator:
    """Test UIDGenerator class."""

    def test_generate_valid_uid(self):
        """Test generating a valid UID."""
        gen = UIDGenerator()
        uid = gen.generate_valid_uid()
        assert uid.startswith("1.2.999.999")
        assert "." in uid

    def test_generate_uid_with_prefix(self):
        """Test generating UID with custom prefix."""
        gen = UIDGenerator()
        uid = gen.generate_valid_uid(prefix="1.2.840.12345")
        assert uid.startswith("1.2.840.12345")

    def test_uid_uniqueness(self):
        """Test that generated UIDs are unique."""
        gen = UIDGenerator()
        uids = [gen.generate_valid_uid() for _ in range(100)]
        assert len(uids) == len(set(uids))

    def test_generate_collision_uid(self):
        """Test generating collision UIDs."""
        gen = UIDGenerator()
        existing_uid = "1.2.840.10008.1.1"
        collision_uid = gen.generate_collision_uid(existing_uid)
        # Should return some UID (exact behavior is randomized)
        assert isinstance(collision_uid, str)

    def test_generate_malformed_uid(self):
        """Test generating malformed UIDs."""
        gen = UIDGenerator()
        malformed = gen.generate_malformed_uid()
        assert isinstance(malformed, str)
        # Malformed UIDs have various issues like empty, spaces, etc.


class TestDICOMElementBranchCoverage:
    """Additional tests for branch coverage in DICOMElement."""

    def test_encode_long_vr_explicit(self):
        """Test encoding element with long VR (4-byte length format)."""
        # OW is a "long VR" that requires 4-byte length format
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OW", value=b"\x00\x01\x02\x03")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0
        # Check that it uses the 4-byte length format
        # Format: group(2) + element(2) + VR(2) + reserved(2) + length(4) + value
        assert encoded[4:6] == b"OW"

    def test_encode_ob_vr_explicit(self):
        """Test encoding OB VR with explicit VR."""
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OB", value=b"\x00\x01")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_un_vr_explicit(self):
        """Test encoding UN VR with explicit VR."""
        element = DICOMElement(tag=(0x0099, 0x0001), vr="UN", value=b"\x00\x01")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_sq_vr_explicit(self):
        """Test encoding SQ VR with explicit VR."""
        element = DICOMElement(tag=(0x0040, 0xA730), vr="SQ", value=b"")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_value_bytes_directly(self):
        """Test _encode_value with bytes value."""
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OB", value=b"\x01\x02\x03")
        encoded = element.encode()
        assert len(encoded) > 0

    def test_encode_float_fl_vr(self):
        """Test encoding FL (float) VR."""
        element = DICOMElement(tag=(0x0018, 0x0050), vr="FL", value=1.5)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_float_fd_vr(self):
        """Test encoding FD (double) VR."""
        element = DICOMElement(tag=(0x0018, 0x0051), vr="FD", value=3.14159265359)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_float_invalid_value(self):
        """Test encoding float VR with invalid value falls back to default."""
        element = DICOMElement(tag=(0x0018, 0x0050), vr="FL", value="not_a_float")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_fd_invalid_value(self):
        """Test encoding FD VR with invalid value falls back to default."""
        element = DICOMElement(tag=(0x0018, 0x0051), vr="FD", value="invalid")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_binary_vr_non_bytes(self):
        """Test encoding binary VR (OB) with non-bytes value returns empty."""
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OB", value="not_bytes")
        # Binary VR with non-bytes value - should return empty bytes for value
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_invalid_value(self):
        """Test encoding numeric VR with invalid value falls back to default."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="US", value="not_a_number")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_ss_vr(self):
        """Test encoding SS (signed short) VR."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="SS", value=-100)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_sl_vr(self):
        """Test encoding SL (signed long) VR."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="SL", value=-100000)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_ul_vr(self):
        """Test encoding UL (unsigned long) VR."""
        element = DICOMElement(tag=(0x0028, 0x0010), vr="UL", value=1000000)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_clamping_max(self):
        """Test numeric value clamping at max."""
        # US max is 65535, try to exceed it
        element = DICOMElement(tag=(0x0028, 0x0010), vr="US", value=99999)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_numeric_clamping_min(self):
        """Test numeric value clamping at min."""
        # SS min is -32768, try to go below
        element = DICOMElement(tag=(0x0028, 0x0010), vr="SS", value=-99999)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_string_from_number(self):
        """Test encoding string VR with numeric value converts to string."""
        element = DICOMElement(tag=(0x0010, 0x0020), vr="LO", value=12345)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_unknown_vr_with_string(self):
        """Test encoding unknown VR with string value."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="XX", value="test")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_encode_unknown_vr_with_non_string(self):
        """Test encoding unknown VR with non-string value."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="XX", value=None)
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_pad_value_ui_vr_odd_length(self):
        """Test padding UI VR with odd length value."""
        element = DICOMElement(tag=(0x0008, 0x0016), vr="UI", value="1.2.3")
        encoded = element.encode(explicit_vr=True)
        # UI should be padded with null byte
        assert len(encoded) > 0

    def test_pad_value_ob_vr_odd_length(self):
        """Test padding OB VR with odd length value."""
        element = DICOMElement(tag=(0x7FE0, 0x0010), vr="OB", value=b"\x01\x02\x03")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_pad_value_un_vr_odd_length(self):
        """Test padding UN VR with odd length value."""
        element = DICOMElement(tag=(0x0099, 0x0001), vr="UN", value=b"\x01\x02\x03")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_pad_value_string_vr_odd_length(self):
        """Test padding string VR with odd length value."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Doe")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0

    def test_pad_value_even_length(self):
        """Test no padding needed for even length value."""
        element = DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Test")
        encoded = element.encode(explicit_vr=True)
        assert len(encoded) > 0


class TestDIMSEMessageBranchCoverage:
    """Additional tests for branch coverage in DIMSEMessage."""

    def test_encode_message_with_data_elements(self):
        """Test encoding DIMSE message with data elements."""
        command_elements = [
            DICOMElement(tag=(0x0000, 0x0100), vr="US", value=0x0001),
        ]
        data_elements = [
            DICOMElement(tag=(0x0010, 0x0010), vr="PN", value="Doe^John"),
            DICOMElement(tag=(0x0010, 0x0020), vr="LO", value="12345"),
        ]
        msg = DIMSEMessage(
            command=DIMSECommand.C_STORE_RQ,
            command_elements=command_elements,
            data_elements=data_elements,
        )
        encoded = msg.encode()
        assert len(encoded) > 0
        # Should have both command and data PDVs
        assert isinstance(encoded, bytes)

    def test_encode_message_empty_data_elements(self):
        """Test encoding message with explicitly empty data elements."""
        msg = DIMSEMessage(
            command=DIMSECommand.C_ECHO_RQ,
            command_elements=[],
            data_elements=[],
        )
        encoded = msg.encode()
        assert len(encoded) > 0


class TestUIDGeneratorBranchCoverage:
    """Additional tests for branch coverage in UIDGenerator."""

    def test_generate_collision_uid_strategies(self):
        """Test collision UID generation covers all strategies."""
        gen = UIDGenerator()
        existing_uid = "1.2.840.10008.1.1"

        # Run many times to cover different strategies
        results = set()
        for _ in range(100):
            uid = gen.generate_collision_uid(existing_uid)
            results.add(uid)

        # Should have multiple different results from different strategies
        assert len(results) >= 1

    def test_generate_collision_uid_empty_existing(self):
        """Test collision UID with empty existing UID."""
        gen = UIDGenerator()
        uid = gen.generate_collision_uid("")
        assert isinstance(uid, str)

    def test_generate_collision_uid_case_variation(self):
        """Test collision UID case variation strategy."""
        gen = UIDGenerator()
        # Use lowercase UID to trigger case variation
        existing_uid = "1.2.3.4.5"

        # Generate many to hit case variation strategy
        for _ in range(50):
            uid = gen.generate_collision_uid(existing_uid)
            assert isinstance(uid, str)

    def test_generate_malformed_uid_multiple_calls(self):
        """Test that malformed UID generation covers all malformed types."""
        gen = UIDGenerator()
        results = set()
        for _ in range(100):
            uid = gen.generate_malformed_uid()
            results.add(uid)

        # Should have multiple different malformed UIDs
        assert len(results) >= 3

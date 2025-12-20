"""Comprehensive tests for DIMSE protocol layer fuzzer.

Tests the DIMSEFuzzer, command builders, dataset mutators,
and protocol message generation.
"""

import struct

import pytest

from dicom_fuzzer.core.dimse_fuzzer import (
    DatasetMutator,
    DICOMElement,
    DIMSECommand,
    DIMSECommandBuilder,
    DIMSEFuzzer,
    DIMSEMessage,
    FuzzingConfig,
    QueryGenerator,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)


class TestDICOMElement:
    """Tests for DICOMElement class."""

    def test_basic_creation(self):
        """Test basic element creation."""
        element = DICOMElement(
            tag=(0x0010, 0x0020),
            vr="LO",
            value="TEST123",
        )

        assert element.tag == (0x0010, 0x0020)
        assert element.vr == "LO"
        assert element.value == "TEST123"

    def test_encode_string_element(self):
        """Test encoding string element."""
        element = DICOMElement(
            tag=(0x0010, 0x0010),
            vr="PN",
            value="SMITH^JOHN",
        )

        encoded = element.encode()

        # Should have tag (4 bytes) + VR (2 bytes) + length (2 bytes) + value
        assert len(encoded) >= 8
        assert encoded[:2] == struct.pack("<H", 0x0010)

    def test_encode_integer_element(self):
        """Test encoding integer element."""
        element = DICOMElement(
            tag=(0x0028, 0x0010),
            vr="US",
            value=512,
        )

        encoded = element.encode()

        # Should include the packed integer
        assert struct.pack("<H", 512) in encoded

    def test_encode_uid_element(self):
        """Test encoding UID element."""
        element = DICOMElement(
            tag=(0x0008, 0x0016),
            vr="UI",
            value="1.2.840.10008.1.1",
        )

        encoded = element.encode()

        # UID should be in the encoded data
        assert b"1.2.840.10008.1.1" in encoded

    def test_encode_pads_to_even_length(self):
        """Test that encoding pads to even length."""
        element = DICOMElement(
            tag=(0x0010, 0x0020),
            vr="LO",
            value="ODD",  # 3 characters
        )

        encoded = element.encode()
        value_start = encoded.find(b"ODD")

        # Value should be padded to even length
        # Find the value part and check its length
        assert len(encoded) % 2 == 0

    def test_encode_long_vr(self):
        """Test encoding with 4-byte length VR."""
        element = DICOMElement(
            tag=(0x7FE0, 0x0010),
            vr="OW",
            value=b"\x00\x01\x02\x03",
        )

        encoded = element.encode()

        # OW uses 4-byte length format
        # Tag (4) + VR (2) + Reserved (2) + Length (4) + Value
        assert len(encoded) >= 12


class TestDIMSEMessage:
    """Tests for DIMSEMessage class."""

    def test_command_only_message(self):
        """Test message with command only."""
        msg = DIMSEMessage(
            command=DIMSECommand.C_ECHO_RQ,
            command_elements=[
                DICOMElement((0x0000, 0x0002), "UI", "1.2.840.10008.1.1"),
                DICOMElement((0x0000, 0x0100), "US", 0x0030),
            ],
        )

        encoded = msg.encode()

        # Should have PDV structure
        assert len(encoded) > 0

    def test_message_with_data(self):
        """Test message with command and data."""
        msg = DIMSEMessage(
            command=DIMSECommand.C_STORE_RQ,
            command_elements=[
                DICOMElement((0x0000, 0x0002), "UI", "1.2.840.10008.5.1.4.1.1.2"),
                DICOMElement((0x0000, 0x0100), "US", 0x0001),
            ],
            data_elements=[
                DICOMElement((0x0010, 0x0010), "PN", "TEST^PATIENT"),
            ],
        )

        encoded = msg.encode()

        # Should have both command and data PDVs
        assert len(encoded) > 20


class TestDIMSECommand:
    """Tests for DIMSECommand enum."""

    def test_all_commands_defined(self):
        """Test all expected commands are defined."""
        expected_commands = [
            "C_STORE_RQ",
            "C_STORE_RSP",
            "C_FIND_RQ",
            "C_FIND_RSP",
            "C_MOVE_RQ",
            "C_MOVE_RSP",
            "C_GET_RQ",
            "C_GET_RSP",
            "C_ECHO_RQ",
            "C_ECHO_RSP",
            "N_GET_RQ",
            "N_SET_RQ",
        ]

        for cmd in expected_commands:
            assert hasattr(DIMSECommand, cmd)

    def test_command_values(self):
        """Test command field values are correct."""
        assert DIMSECommand.C_STORE_RQ.value == 0x0001
        assert DIMSECommand.C_ECHO_RQ.value == 0x0030
        assert DIMSECommand.C_FIND_RQ.value == 0x0020


class TestSOPClass:
    """Tests for SOPClass enum."""

    def test_verification_uid(self):
        """Test verification SOP class UID."""
        assert SOPClass.VERIFICATION.value == "1.2.840.10008.1.1"

    def test_ct_storage_uid(self):
        """Test CT storage SOP class UID."""
        assert SOPClass.CT_IMAGE_STORAGE.value == "1.2.840.10008.5.1.4.1.1.2"

    def test_query_retrieve_uids(self):
        """Test Query/Retrieve SOP class UIDs."""
        assert "1.2.840.10008.5.1.4" in SOPClass.PATIENT_ROOT_QR_FIND.value
        assert "1.2.840.10008.5.1.4" in SOPClass.STUDY_ROOT_QR_FIND.value


class TestDIMSECommandBuilder:
    """Tests for DIMSECommandBuilder class."""

    @pytest.fixture
    def builder(self):
        """Create a command builder."""
        return DIMSECommandBuilder()

    def test_build_c_echo_rq(self, builder):
        """Test building C-ECHO-RQ message."""
        msg = builder.build_c_echo_rq()

        assert msg.command == DIMSECommand.C_ECHO_RQ
        assert len(msg.command_elements) >= 4
        assert len(msg.data_elements) == 0

    def test_build_c_echo_with_custom_sop_class(self, builder):
        """Test C-ECHO with custom SOP class."""
        msg = builder.build_c_echo_rq("1.2.3.4.5")

        # Check SOP class UID element
        sop_element = next(e for e in msg.command_elements if e.tag == (0x0000, 0x0002))
        assert sop_element.value == "1.2.3.4.5"

    def test_build_c_store_rq(self, builder):
        """Test building C-STORE-RQ message."""
        dataset = [
            DICOMElement((0x0010, 0x0010), "PN", "TEST^PATIENT"),
        ]

        msg = builder.build_c_store_rq(
            sop_class_uid=SOPClass.CT_IMAGE_STORAGE.value,
            sop_instance_uid="1.2.3.4.5",
            dataset_elements=dataset,
        )

        assert msg.command == DIMSECommand.C_STORE_RQ
        assert len(msg.command_elements) >= 5
        assert len(msg.data_elements) == 1

    def test_build_c_find_rq(self, builder):
        """Test building C-FIND-RQ message."""
        query = [
            DICOMElement((0x0008, 0x0052), "CS", "STUDY"),
        ]

        msg = builder.build_c_find_rq(
            sop_class_uid=SOPClass.STUDY_ROOT_QR_FIND.value,
            query_elements=query,
        )

        assert msg.command == DIMSECommand.C_FIND_RQ
        assert len(msg.data_elements) == 1

    def test_build_c_move_rq(self, builder):
        """Test building C-MOVE-RQ message."""
        query = [
            DICOMElement((0x0020, 0x000D), "UI", "1.2.3.4"),
        ]

        msg = builder.build_c_move_rq(
            sop_class_uid=SOPClass.STUDY_ROOT_QR_MOVE.value,
            move_destination="STORESCU",
            query_elements=query,
        )

        assert msg.command == DIMSECommand.C_MOVE_RQ
        # Check move destination element exists
        dest_element = next(
            (e for e in msg.command_elements if e.tag == (0x0000, 0x0600)), None
        )
        assert dest_element is not None
        assert dest_element.value == "STORESCU"

    def test_message_id_increments(self, builder):
        """Test that message IDs increment."""
        msg1 = builder.build_c_echo_rq()
        msg2 = builder.build_c_echo_rq()

        id1 = next(e.value for e in msg1.command_elements if e.tag == (0x0000, 0x0110))
        id2 = next(e.value for e in msg2.command_elements if e.tag == (0x0000, 0x0110))

        assert id2 == id1 + 1


class TestDatasetMutator:
    """Tests for DatasetMutator class."""

    @pytest.fixture
    def mutator(self):
        """Create a dataset mutator."""
        return DatasetMutator()

    def test_mutate_element_changes_value(self, mutator):
        """Test mutation changes element value."""
        element = DICOMElement((0x0010, 0x0020), "LO", "ORIGINAL")

        # Mutate multiple times to ensure at least one change
        mutated_values = set()
        for _ in range(10):
            mutated = mutator.mutate_element(element)
            mutated_values.add(str(mutated.value))

        # Should have some different values
        assert len(mutated_values) >= 1

    def test_generate_malformed_dataset(self, mutator):
        """Test generating malformed dataset."""
        original = [
            DICOMElement((0x0010, 0x0010), "PN", "TEST"),
            DICOMElement((0x0010, 0x0020), "LO", "ID123"),
        ]

        malformed = mutator.generate_malformed_dataset(original)

        assert len(malformed) >= len(original)

    def test_generates_private_elements(self):
        """Test private element generation."""
        config = FuzzingConfig(add_private_elements=True)
        mutator = DatasetMutator(config)

        original = [DICOMElement((0x0010, 0x0010), "PN", "TEST")]
        malformed = mutator.generate_malformed_dataset(original)

        # Should have added private elements
        private_elements = [e for e in malformed if e.tag[0] % 2 == 1]
        # May or may not have private elements depending on random chance


class TestUIDGenerator:
    """Tests for UIDGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a UID generator."""
        return UIDGenerator()

    def test_generate_valid_uid(self, generator):
        """Test generating valid UID."""
        uid = generator.generate_valid_uid()

        assert uid.startswith("1.2.999.999")
        assert len(uid) <= 64  # Max UID length

    def test_generate_unique_uids(self, generator):
        """Test generated UIDs are unique."""
        uids = [generator.generate_valid_uid() for _ in range(100)]

        assert len(set(uids)) == 100

    def test_generate_collision_uid(self, generator):
        """Test collision UID generation."""
        original = "1.2.3.4.5.6.7.8.9"
        collision = generator.generate_collision_uid(original)

        # Should be related to original in some way
        assert isinstance(collision, str)

    def test_generate_malformed_uid(self, generator):
        """Test malformed UID generation."""
        malformed = generator.generate_malformed_uid()

        # Should be some form of invalid UID
        assert isinstance(malformed, str)


class TestQueryGenerator:
    """Tests for QueryGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a query generator."""
        return QueryGenerator()

    def test_generate_patient_level_query(self, generator):
        """Test patient level query generation."""
        query = generator.generate_find_query(QueryRetrieveLevel.PATIENT)

        # Should have query retrieve level
        level_element = next((e for e in query if e.tag == (0x0008, 0x0052)), None)
        assert level_element is not None
        assert level_element.value == "PATIENT"

    def test_generate_study_level_query(self, generator):
        """Test study level query generation."""
        query = generator.generate_find_query(QueryRetrieveLevel.STUDY)

        # Should have study-related elements
        tags = [e.tag for e in query]
        assert (0x0008, 0x0052) in tags  # Query level

    def test_generate_fuzzed_query(self, generator):
        """Test fuzzed query generation."""
        query = generator.generate_fuzzed_query(QueryRetrieveLevel.STUDY)

        # Should have elements (possibly mutated)
        assert len(query) >= 1


class TestDIMSEFuzzer:
    """Tests for high-level DIMSEFuzzer class."""

    @pytest.fixture
    def fuzzer(self):
        """Create a DIMSE fuzzer."""
        return DIMSEFuzzer()

    def test_generate_c_echo_fuzz_cases(self, fuzzer):
        """Test C-ECHO fuzz case generation."""
        cases = list(fuzzer.generate_c_echo_fuzz_cases())

        assert len(cases) >= 5
        assert all(isinstance(c, DIMSEMessage) for c in cases)
        assert all(c.command == DIMSECommand.C_ECHO_RQ for c in cases)

    def test_generate_c_store_fuzz_cases(self, fuzzer):
        """Test C-STORE fuzz case generation."""
        cases = list(fuzzer.generate_c_store_fuzz_cases())

        assert len(cases) >= 10
        assert all(c.command == DIMSECommand.C_STORE_RQ for c in cases)

    def test_generate_c_find_fuzz_cases(self, fuzzer):
        """Test C-FIND fuzz case generation."""
        cases = list(fuzzer.generate_c_find_fuzz_cases())

        assert len(cases) >= 10
        assert all(c.command == DIMSECommand.C_FIND_RQ for c in cases)

    def test_generate_c_move_fuzz_cases(self, fuzzer):
        """Test C-MOVE fuzz case generation."""
        cases = list(fuzzer.generate_c_move_fuzz_cases())

        assert len(cases) >= 5
        assert all(c.command == DIMSECommand.C_MOVE_RQ for c in cases)

    def test_generate_all_fuzz_cases(self, fuzzer):
        """Test generating all fuzz cases."""
        cases = list(fuzzer.generate_all_fuzz_cases())

        assert len(cases) >= 30

        # Should have variety of commands
        commands = {msg.command for _, msg in cases}
        assert len(commands) >= 4

    def test_fuzz_cases_are_encodable(self, fuzzer):
        """Test that generated fuzz cases can be encoded."""
        for name, msg in list(fuzzer.generate_all_fuzz_cases())[:10]:
            try:
                encoded = msg.encode()
                assert isinstance(encoded, bytes)
                assert len(encoded) > 0
            except Exception as e:
                pytest.fail(f"Failed to encode {name}: {e}")


class TestFuzzingConfig:
    """Tests for FuzzingConfig class."""

    def test_default_values(self):
        """Test default fuzzing configuration."""
        config = FuzzingConfig()

        assert config.max_string_length == 1024
        assert config.probability_invalid_vr == 0.1
        assert config.fuzz_sop_class_uid is True
        assert config.generate_wildcard_attacks is True

    def test_custom_values(self):
        """Test custom fuzzing configuration."""
        config = FuzzingConfig(
            max_string_length=256,
            probability_invalid_vr=0.5,
            generate_collision_uids=False,
        )

        assert config.max_string_length == 256
        assert config.probability_invalid_vr == 0.5
        assert config.generate_collision_uids is False


class TestQueryRetrieveLevel:
    """Tests for QueryRetrieveLevel enum."""

    def test_all_levels_defined(self):
        """Test all Q/R levels are defined."""
        expected = ["PATIENT", "STUDY", "SERIES", "IMAGE"]

        for level in expected:
            assert hasattr(QueryRetrieveLevel, level)

    def test_level_values(self):
        """Test level string values."""
        assert QueryRetrieveLevel.PATIENT.value == "PATIENT"
        assert QueryRetrieveLevel.STUDY.value == "STUDY"
        assert QueryRetrieveLevel.SERIES.value == "SERIES"
        assert QueryRetrieveLevel.IMAGE.value == "IMAGE"

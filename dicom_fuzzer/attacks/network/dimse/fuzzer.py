"""DIMSE Protocol Layer Fuzzer for DICOM Network Services.

This module implements DIMSE (DICOM Message Service Element) layer fuzzing,
operating at a higher protocol level than the existing PDU-level fuzzer.

DIMSE commands include:
- C-STORE: Store composite instance
- C-FIND: Query for matching instances
- C-MOVE: Retrieve instances
- C-GET: Get instances
- C-ECHO: Verification service
- N-EVENT-REPORT, N-GET, N-SET, N-ACTION, N-CREATE, N-DELETE

Key fuzzing targets:
- Command datasets with invalid fields
- Data datasets with malformed elements
- UID manipulation and collision attacks
- Query level attacks for C-FIND/C-MOVE
- Attribute tampering
"""

from __future__ import annotations

import logging
from collections.abc import Generator

from dicom_fuzzer.core.types import DIMSECommand

from .dataset_mutator import DatasetMutator
from .types import (
    DICOMElement,
    DIMSEFuzzingConfig,
    DIMSEMessage,
    QueryRetrieveLevel,
    SOPClass,
    UIDGenerator,
)

# Backward compatibility aliases
FuzzingConfig = DIMSEFuzzingConfig

logger = logging.getLogger(__name__)


class DIMSECommandBuilder:
    """Builder for DIMSE command datasets."""

    # Standard command field tags
    AFFECTED_SOP_CLASS_UID = (0x0000, 0x0002)
    COMMAND_FIELD = (0x0000, 0x0100)
    MESSAGE_ID = (0x0000, 0x0110)
    MESSAGE_ID_RESPONDED_TO = (0x0000, 0x0120)
    DATA_SET_TYPE = (0x0000, 0x0800)
    STATUS = (0x0000, 0x0900)
    AFFECTED_SOP_INSTANCE_UID = (0x0000, 0x1000)
    MOVE_DESTINATION = (0x0000, 0x0600)
    PRIORITY = (0x0000, 0x0700)

    # Data set type values
    DATA_SET_PRESENT = 0x0000
    NO_DATA_SET = 0x0101

    def __init__(self, config: DIMSEFuzzingConfig | None = None):
        """Initialize the command builder.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or DIMSEFuzzingConfig()
        self._message_id = 1

    def _next_message_id(self) -> int:
        """Get next message ID."""
        msg_id = self._message_id
        self._message_id = (self._message_id + 1) % 65536
        return msg_id

    def build_c_echo_rq(
        self,
        affected_sop_class: str = SOPClass.VERIFICATION.value,
    ) -> DIMSEMessage:
        """Build a C-ECHO-RQ message.

        Args:
            affected_sop_class: SOP Class UID for echo.

        Returns:
            DIMSE message.

        """
        elements = [
            DICOMElement(self.AFFECTED_SOP_CLASS_UID, "UI", affected_sop_class),
            DICOMElement(self.COMMAND_FIELD, "US", DIMSECommand.C_ECHO_RQ.value),
            DICOMElement(self.MESSAGE_ID, "US", self._next_message_id()),
            DICOMElement(self.DATA_SET_TYPE, "US", self.NO_DATA_SET),
        ]

        return DIMSEMessage(
            command=DIMSECommand.C_ECHO_RQ,
            command_elements=elements,
        )

    def build_c_store_rq(
        self,
        sop_class_uid: str,
        sop_instance_uid: str,
        dataset_elements: list[DICOMElement],
        priority: int = 0,  # MEDIUM
    ) -> DIMSEMessage:
        """Build a C-STORE-RQ message.

        Args:
            sop_class_uid: SOP Class UID.
            sop_instance_uid: SOP Instance UID.
            dataset_elements: Data elements to store.
            priority: Request priority (0=MEDIUM, 1=HIGH, 2=LOW).

        Returns:
            DIMSE message.

        """
        command_elements = [
            DICOMElement(self.AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid),
            DICOMElement(self.COMMAND_FIELD, "US", DIMSECommand.C_STORE_RQ.value),
            DICOMElement(self.MESSAGE_ID, "US", self._next_message_id()),
            DICOMElement(self.PRIORITY, "US", priority),
            DICOMElement(self.DATA_SET_TYPE, "US", self.DATA_SET_PRESENT),
            DICOMElement(self.AFFECTED_SOP_INSTANCE_UID, "UI", sop_instance_uid),
        ]

        return DIMSEMessage(
            command=DIMSECommand.C_STORE_RQ,
            command_elements=command_elements,
            data_elements=dataset_elements,
        )

    def build_c_find_rq(
        self,
        sop_class_uid: str,
        query_elements: list[DICOMElement],
        priority: int = 0,
    ) -> DIMSEMessage:
        """Build a C-FIND-RQ message.

        Args:
            sop_class_uid: SOP Class UID (Patient/Study Root).
            query_elements: Query dataset elements.
            priority: Request priority.

        Returns:
            DIMSE message.

        """
        command_elements = [
            DICOMElement(self.AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid),
            DICOMElement(self.COMMAND_FIELD, "US", DIMSECommand.C_FIND_RQ.value),
            DICOMElement(self.MESSAGE_ID, "US", self._next_message_id()),
            DICOMElement(self.PRIORITY, "US", priority),
            DICOMElement(self.DATA_SET_TYPE, "US", self.DATA_SET_PRESENT),
        ]

        return DIMSEMessage(
            command=DIMSECommand.C_FIND_RQ,
            command_elements=command_elements,
            data_elements=query_elements,
        )

    def build_c_move_rq(
        self,
        sop_class_uid: str,
        move_destination: str,
        query_elements: list[DICOMElement],
        priority: int = 0,
    ) -> DIMSEMessage:
        """Build a C-MOVE-RQ message.

        Args:
            sop_class_uid: SOP Class UID.
            move_destination: AE title of move destination.
            query_elements: Query dataset elements.
            priority: Request priority.

        Returns:
            DIMSE message.

        """
        command_elements = [
            DICOMElement(self.AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid),
            DICOMElement(self.COMMAND_FIELD, "US", DIMSECommand.C_MOVE_RQ.value),
            DICOMElement(self.MESSAGE_ID, "US", self._next_message_id()),
            DICOMElement(self.PRIORITY, "US", priority),
            DICOMElement(self.DATA_SET_TYPE, "US", self.DATA_SET_PRESENT),
            DICOMElement(self.MOVE_DESTINATION, "AE", move_destination),
        ]

        return DIMSEMessage(
            command=DIMSECommand.C_MOVE_RQ,
            command_elements=command_elements,
            data_elements=query_elements,
        )

    def build_c_get_rq(
        self,
        sop_class_uid: str,
        query_elements: list[DICOMElement],
        priority: int = 0,
    ) -> DIMSEMessage:
        """Build a C-GET-RQ message.

        Args:
            sop_class_uid: SOP Class UID.
            query_elements: Query dataset elements.
            priority: Request priority.

        Returns:
            DIMSE message.

        """
        command_elements = [
            DICOMElement(self.AFFECTED_SOP_CLASS_UID, "UI", sop_class_uid),
            DICOMElement(self.COMMAND_FIELD, "US", DIMSECommand.C_GET_RQ.value),
            DICOMElement(self.MESSAGE_ID, "US", self._next_message_id()),
            DICOMElement(self.PRIORITY, "US", priority),
            DICOMElement(self.DATA_SET_TYPE, "US", self.DATA_SET_PRESENT),
        ]

        return DIMSEMessage(
            command=DIMSECommand.C_GET_RQ,
            command_elements=command_elements,
            data_elements=query_elements,
        )


class QueryGenerator:
    """Generator for DICOM query datasets with fuzzing."""

    # Common query tags
    PATIENT_ID = (0x0010, 0x0020)
    PATIENT_NAME = (0x0010, 0x0010)
    STUDY_INSTANCE_UID = (0x0020, 0x000D)
    SERIES_INSTANCE_UID = (0x0020, 0x000E)
    SOP_INSTANCE_UID = (0x0008, 0x0018)
    QUERY_RETRIEVE_LEVEL = (0x0008, 0x0052)
    MODALITY = (0x0008, 0x0060)
    STUDY_DATE = (0x0008, 0x0020)
    ACCESSION_NUMBER = (0x0008, 0x0050)

    def __init__(self, config: DIMSEFuzzingConfig | None = None):
        """Initialize query generator.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or DIMSEFuzzingConfig()
        self.uid_gen = UIDGenerator()

    def generate_find_query(
        self,
        level: QueryRetrieveLevel = QueryRetrieveLevel.STUDY,
    ) -> list[DICOMElement]:
        """Generate a C-FIND query dataset.

        Args:
            level: Query/Retrieve level.

        Returns:
            Query elements.

        """
        elements = [
            DICOMElement(self.QUERY_RETRIEVE_LEVEL, "CS", level.value),
        ]

        if level == QueryRetrieveLevel.PATIENT:
            elements.extend(
                [
                    DICOMElement(self.PATIENT_ID, "LO", ""),
                    DICOMElement(self.PATIENT_NAME, "PN", "*"),
                ]
            )
        elif level == QueryRetrieveLevel.STUDY:
            elements.extend(
                [
                    DICOMElement(self.PATIENT_ID, "LO", ""),
                    DICOMElement(self.STUDY_INSTANCE_UID, "UI", ""),
                    DICOMElement(self.STUDY_DATE, "DA", ""),
                ]
            )
        elif level == QueryRetrieveLevel.SERIES:
            elements.extend(
                [
                    DICOMElement(self.STUDY_INSTANCE_UID, "UI", ""),
                    DICOMElement(self.SERIES_INSTANCE_UID, "UI", ""),
                    DICOMElement(self.MODALITY, "CS", ""),
                ]
            )
        elif level == QueryRetrieveLevel.IMAGE:
            elements.extend(
                [
                    DICOMElement(self.SERIES_INSTANCE_UID, "UI", ""),
                    DICOMElement(self.SOP_INSTANCE_UID, "UI", ""),
                ]
            )

        return elements

    def generate_fuzzed_query(
        self,
        level: QueryRetrieveLevel = QueryRetrieveLevel.STUDY,
    ) -> list[DICOMElement]:
        """Generate a fuzzed C-FIND query.

        Args:
            level: Query/Retrieve level.

        Returns:
            Fuzzed query elements.

        """
        base_query = self.generate_find_query(level)
        mutator = DatasetMutator(self.config)

        # Apply mutations
        fuzzed = mutator.generate_malformed_dataset(base_query)

        # Add wildcard attacks
        if self.config.generate_wildcard_attacks:
            fuzzed.extend(self._generate_wildcard_attacks())

        return fuzzed

    def _generate_wildcard_attacks(self) -> list[DICOMElement]:
        """Generate wildcard-based attack patterns."""
        attacks = []

        # Overly broad wildcards
        wildcards = ["*", "?*", "*?*", "%" * 100, "_" * 100]

        for wc in wildcards:
            attacks.append(DICOMElement(self.PATIENT_NAME, "PN", wc))

        # SQL-like patterns that might bypass filters
        sql_patterns = [
            "' OR '1'='1",
            "'; SELECT * FROM --",
            "UNION SELECT",
        ]

        for pattern in sql_patterns:
            attacks.append(DICOMElement(self.PATIENT_ID, "LO", pattern))

        return attacks


class DIMSEFuzzer:
    """High-level DIMSE protocol fuzzer.

    Coordinates DIMSE message generation and mutation for
    comprehensive protocol testing.
    """

    def __init__(self, config: DIMSEFuzzingConfig | None = None):
        """Initialize the DIMSE fuzzer.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or DIMSEFuzzingConfig()
        self.command_builder = DIMSECommandBuilder(self.config)
        self.dataset_mutator = DatasetMutator(self.config)
        self.uid_generator = UIDGenerator()
        self.query_generator = QueryGenerator(self.config)

    def generate_c_echo_fuzz_cases(self) -> Generator[DIMSEMessage, None, None]:
        """Generate fuzzed C-ECHO messages.

        Yields:
            Fuzzed C-ECHO messages.

        """
        # Valid C-ECHO
        yield self.command_builder.build_c_echo_rq()

        # With invalid SOP Class UIDs
        for uid in self.uid_generator.generate_malformed_uid(), "":
            yield self.command_builder.build_c_echo_rq(uid)

        # With fuzzed UIDs
        for _ in range(5):
            uid = self.uid_generator.generate_malformed_uid()
            yield self.command_builder.build_c_echo_rq(uid)

    def generate_c_store_fuzz_cases(
        self,
        base_dataset: list[DICOMElement] | None = None,
    ) -> Generator[DIMSEMessage, None, None]:
        """Generate fuzzed C-STORE messages.

        Args:
            base_dataset: Base dataset to mutate.

        Yields:
            Fuzzed C-STORE messages.

        """
        if base_dataset is None:
            base_dataset = self._generate_minimal_image_dataset()

        sop_class = SOPClass.CT_IMAGE_STORAGE.value
        sop_instance = self.uid_generator.generate_valid_uid()

        # Valid message
        yield self.command_builder.build_c_store_rq(
            sop_class, sop_instance, base_dataset
        )

        # With mutated datasets
        for _ in range(10):
            mutated = self.dataset_mutator.generate_malformed_dataset(base_dataset)
            yield self.command_builder.build_c_store_rq(
                sop_class,
                self.uid_generator.generate_valid_uid(),
                mutated,
            )

        # With invalid SOP Class UIDs
        invalid_classes = [
            "",
            self.uid_generator.generate_malformed_uid(),
            "1.2.3.4.5.6.7.8.9.0",
        ]
        for uid in invalid_classes:
            yield self.command_builder.build_c_store_rq(uid, sop_instance, base_dataset)

        # With collision UIDs
        if self.config.generate_collision_uids:
            for _ in range(3):
                collision_uid = self.uid_generator.generate_collision_uid(sop_instance)
                yield self.command_builder.build_c_store_rq(
                    sop_class, collision_uid, base_dataset
                )

    def generate_c_find_fuzz_cases(self) -> Generator[DIMSEMessage, None, None]:
        """Generate fuzzed C-FIND messages.

        Yields:
            Fuzzed C-FIND messages.

        """
        sop_class = SOPClass.STUDY_ROOT_QR_FIND.value

        # Valid queries at each level
        for level in QueryRetrieveLevel:
            query = self.query_generator.generate_find_query(level)
            yield self.command_builder.build_c_find_rq(sop_class, query)

        # Fuzzed queries
        for level in QueryRetrieveLevel:
            for _ in range(5):
                query = self.query_generator.generate_fuzzed_query(level)
                yield self.command_builder.build_c_find_rq(sop_class, query)

        # Invalid query levels
        invalid_levels = ["", "INVALID", "patient", "ROOT", " " * 10]
        for level_str in invalid_levels:
            query = [
                DICOMElement(self.query_generator.QUERY_RETRIEVE_LEVEL, "CS", level_str)
            ]
            yield self.command_builder.build_c_find_rq(sop_class, query)

    def generate_c_move_fuzz_cases(self) -> Generator[DIMSEMessage, None, None]:
        """Generate fuzzed C-MOVE messages.

        Yields:
            Fuzzed C-MOVE messages.

        """
        sop_class = SOPClass.STUDY_ROOT_QR_MOVE.value

        # Valid destinations
        destinations = [
            "STORESCU",
            "A" * 16,  # Max length
        ]

        for dest in destinations:
            query = self.query_generator.generate_find_query(QueryRetrieveLevel.STUDY)
            yield self.command_builder.build_c_move_rq(sop_class, dest, query)

        # Invalid destinations (AE title attacks)
        invalid_destinations = [
            "",  # Empty
            " " * 16,  # All spaces
            "A" * 17,  # Too long
            "A" * 100,  # Way too long
            "\x00" * 16,  # Null bytes
            "DROP TABLE;--",  # SQL injection
            "../../../etc",  # Path traversal
        ]

        for dest in invalid_destinations:
            query = self.query_generator.generate_find_query(QueryRetrieveLevel.STUDY)
            yield self.command_builder.build_c_move_rq(sop_class, dest, query)

    def _generate_minimal_image_dataset(self) -> list[DICOMElement]:
        """Generate a minimal valid image dataset."""
        return [
            DICOMElement(
                (0x0008, 0x0016), "UI", SOPClass.CT_IMAGE_STORAGE.value
            ),  # SOP Class
            DICOMElement(
                (0x0008, 0x0018), "UI", self.uid_generator.generate_valid_uid()
            ),  # SOP Instance
            DICOMElement((0x0010, 0x0010), "PN", "FUZZER^TEST"),  # Patient Name
            DICOMElement((0x0010, 0x0020), "LO", "FUZZ001"),  # Patient ID
            DICOMElement(
                (0x0020, 0x000D), "UI", self.uid_generator.generate_valid_uid()
            ),  # Study Instance
            DICOMElement(
                (0x0020, 0x000E), "UI", self.uid_generator.generate_valid_uid()
            ),  # Series Instance
            DICOMElement((0x0028, 0x0010), "US", 64),  # Rows
            DICOMElement((0x0028, 0x0011), "US", 64),  # Columns
            DICOMElement((0x0028, 0x0100), "US", 16),  # Bits Allocated
            DICOMElement((0x0028, 0x0101), "US", 12),  # Bits Stored
            DICOMElement((0x0028, 0x0102), "US", 11),  # High Bit
            DICOMElement((0x7FE0, 0x0010), "OW", b"\x00" * (64 * 64 * 2)),  # Pixel Data
        ]

    def generate_all_fuzz_cases(
        self,
    ) -> Generator[tuple[str, DIMSEMessage], None, None]:
        """Generate all fuzzing test cases.

        Yields:
            Tuples of (test_name, message).

        """
        # C-ECHO
        for i, msg in enumerate(self.generate_c_echo_fuzz_cases()):
            yield f"c_echo_{i}", msg

        # C-STORE
        for i, msg in enumerate(self.generate_c_store_fuzz_cases()):
            yield f"c_store_{i}", msg

        # C-FIND
        for i, msg in enumerate(self.generate_c_find_fuzz_cases()):
            yield f"c_find_{i}", msg

        # C-MOVE
        for i, msg in enumerate(self.generate_c_move_fuzz_cases()):
            yield f"c_move_{i}", msg

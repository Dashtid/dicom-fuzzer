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

import logging
import random
import struct
from collections.abc import Generator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class DIMSECommand(Enum):
    """DIMSE command types with their command field values."""

    # Composite commands
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
    C_CANCEL_RQ = 0x0FFF

    # Normalized commands
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


class QueryRetrieveLevel(Enum):
    """Query/Retrieve information model levels."""

    PATIENT = "PATIENT"
    STUDY = "STUDY"
    SERIES = "SERIES"
    IMAGE = "IMAGE"


class SOPClass(Enum):
    """Common SOP Class UIDs for DICOM services."""

    # Verification
    VERIFICATION = "1.2.840.10008.1.1"

    # Storage
    CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"
    MR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.4"
    CR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.1"
    US_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.6.1"
    SECONDARY_CAPTURE_STORAGE = "1.2.840.10008.5.1.4.1.1.7"
    RT_DOSE_STORAGE = "1.2.840.10008.5.1.4.1.1.481.2"
    RT_PLAN_STORAGE = "1.2.840.10008.5.1.4.1.1.481.5"
    RT_STRUCT_STORAGE = "1.2.840.10008.5.1.4.1.1.481.3"

    # Query/Retrieve
    PATIENT_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
    PATIENT_ROOT_QR_MOVE = "1.2.840.10008.5.1.4.1.2.1.2"
    PATIENT_ROOT_QR_GET = "1.2.840.10008.5.1.4.1.2.1.3"
    STUDY_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.2.1"
    STUDY_ROOT_QR_MOVE = "1.2.840.10008.5.1.4.1.2.2.2"
    STUDY_ROOT_QR_GET = "1.2.840.10008.5.1.4.1.2.2.3"

    # Worklist
    MODALITY_WORKLIST_FIND = "1.2.840.10008.5.1.4.31"


@dataclass
class DICOMElement:
    """A DICOM data element.

    Attributes:
        tag: Tuple of (group, element)
        vr: Value Representation (2-character string)
        value: Element value (bytes or native type)

    """

    tag: tuple[int, int]
    vr: str
    value: bytes | str | int | float | list

    def encode(self, explicit_vr: bool = True) -> bytes:
        """Encode element to bytes.

        Args:
            explicit_vr: Whether to use explicit VR encoding.

        Returns:
            Encoded bytes.

        """
        group, element = self.tag
        value_bytes = self._encode_value()

        if explicit_vr:
            # Check if VR has 4-byte length
            long_vrs = {"OB", "OD", "OF", "OL", "OW", "SQ", "UC", "UN", "UR", "UT"}

            if self.vr in long_vrs:
                # 4-byte length format
                return (
                    struct.pack(
                        "<HH2sHL",
                        group,
                        element,
                        self.vr.encode("ascii"),
                        0,  # Reserved
                        len(value_bytes),
                    )
                    + value_bytes
                )
            else:
                # 2-byte length format
                # Cap length at 65535 for fuzz cases with very long values
                length = min(len(value_bytes), 65535)
                return (
                    struct.pack(
                        "<HH2sH",
                        group,
                        element,
                        self.vr.encode("ascii"),
                        length,
                    )
                    + value_bytes
                )
        else:
            # Implicit VR
            return (
                struct.pack(
                    "<HHL",
                    group,
                    element,
                    len(value_bytes),
                )
                + value_bytes
            )

    def _encode_value(self) -> bytes:
        """Encode the value to bytes based on VR."""
        if isinstance(self.value, bytes):
            return self._pad_value(self.value)

        vr = self.vr

        if vr in (
            "AE",
            "AS",
            "CS",
            "DA",
            "DS",
            "DT",
            "IS",
            "LO",
            "LT",
            "PN",
            "SH",
            "ST",
            "TM",
            "UC",
            "UI",
            "UR",
            "UT",
        ):
            # String types
            if isinstance(self.value, str):
                encoded = self.value.encode("utf-8")
            else:
                encoded = str(self.value).encode("utf-8")
            return self._pad_value(encoded)

        elif vr in ("SS",):
            try:
                return struct.pack("<h", int(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                # Handle fuzzed data that doesn't match VR
                return struct.pack("<h", 0)

        elif vr in ("US",):
            try:
                return struct.pack("<H", int(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return struct.pack("<H", 0)

        elif vr in ("SL",):
            try:
                return struct.pack("<l", int(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return struct.pack("<l", 0)

        elif vr in ("UL",):
            try:
                return struct.pack("<L", int(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return struct.pack("<L", 0)

        elif vr in ("FL",):
            try:
                return struct.pack("<f", float(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return struct.pack("<f", 0.0)

        elif vr in ("FD",):
            try:
                return struct.pack("<d", float(self.value))  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return struct.pack("<d", 0.0)

        elif vr in ("OB", "OW", "OD", "OF", "OL", "UN"):
            # Binary VRs - value should be bytes but might not be after fuzzing
            # Note: bytes case already handled at top of function
            return b""

        else:
            # Default to string encoding
            if isinstance(self.value, str):
                return self._pad_value(self.value.encode("utf-8"))
            return b""

    def _pad_value(self, value: bytes) -> bytes:
        """Pad value to even length."""
        if len(value) % 2 != 0:
            # Pad with space for string VRs, null for others
            if self.vr in ("UI",):
                return value + b"\x00"
            elif self.vr in ("OB", "UN"):
                return value + b"\x00"
            else:
                return value + b" "
        return value


@dataclass
class DIMSEMessage:
    """A DIMSE message containing command and optional data.

    Attributes:
        command: The DIMSE command type
        command_elements: Elements in the command dataset
        data_elements: Elements in the data dataset (optional)
        presentation_context_id: ID for the presentation context

    """

    command: DIMSECommand
    command_elements: list[DICOMElement] = field(default_factory=list)
    data_elements: list[DICOMElement] = field(default_factory=list)
    presentation_context_id: int = 1

    def encode(self) -> bytes:
        """Encode the DIMSE message to bytes.

        Returns:
            Encoded message ready for P-DATA-TF wrapping.

        """
        # Encode command dataset
        command_data = b"".join(e.encode() for e in self.command_elements)

        # Add command group length (0000,0000)
        group_length = DICOMElement(
            tag=(0x0000, 0x0000),
            vr="UL",
            value=len(command_data),
        )
        command_data = group_length.encode() + command_data

        # Create command fragment PDV
        # Control byte: 0x03 = last fragment, command
        command_pdv = (
            struct.pack(
                ">LB",
                len(command_data) + 1,
                self.presentation_context_id,
            )
            + bytes([0x03])
            + command_data
        )

        if not self.data_elements:
            return command_pdv

        # Encode data dataset
        data_data = b"".join(e.encode() for e in self.data_elements)

        # Create data fragment PDV
        # Control byte: 0x02 = last fragment, data
        data_pdv = (
            struct.pack(
                ">LB",
                len(data_data) + 1,
                self.presentation_context_id,
            )
            + bytes([0x02])
            + data_data
        )

        return command_pdv + data_pdv


@dataclass
class FuzzingConfig:
    """Configuration for DIMSE fuzzing."""

    # Mutation parameters
    max_string_length: int = 1024
    max_sequence_depth: int = 5
    probability_invalid_vr: float = 0.1
    probability_invalid_length: float = 0.1
    probability_invalid_tag: float = 0.1

    # UID fuzzing
    fuzz_sop_class_uid: bool = True
    fuzz_sop_instance_uid: bool = True
    generate_collision_uids: bool = True

    # Query fuzzing
    fuzz_query_levels: bool = True
    generate_wildcard_attacks: bool = True

    # Dataset fuzzing
    add_private_elements: bool = True
    add_nested_sequences: bool = True
    max_elements_per_message: int = 100


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

    def __init__(self, config: FuzzingConfig | None = None):
        """Initialize the command builder.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or FuzzingConfig()
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


class DatasetMutator:
    """Mutator for DICOM dataset elements."""

    # Common VRs and their characteristics
    STRING_VRS = {
        "AE",
        "AS",
        "CS",
        "DA",
        "DS",
        "DT",
        "IS",
        "LO",
        "LT",
        "PN",
        "SH",
        "ST",
        "TM",
        "UC",
        "UI",
        "UR",
        "UT",
    }
    NUMERIC_VRS = {"SS", "US", "SL", "UL", "FL", "FD"}
    BINARY_VRS = {"OB", "OD", "OF", "OL", "OW", "UN"}

    # Interesting values for fuzzing
    INTERESTING_STRINGS = [
        "",  # Empty
        " " * 100,  # Spaces
        "\x00" * 10,  # Nulls
        "A" * 1000,  # Long
        "A" * 65536,  # Very long
        "../../../etc/passwd",  # Path traversal
        "; DROP TABLE patients;--",  # SQL injection
        "<script>alert(1)</script>",  # XSS
        "%s%s%s%s%s",  # Format string
        "\n\r\t\x0b\x0c",  # Control characters
    ]

    INTERESTING_UIDS = [
        "",  # Empty
        "1.2.3",  # Short
        "1." + "2" * 64,  # Long component
        "1.2.840.10008.1.1",  # Valid verification UID
        "1.2.840.10008.5.1.4.1.1.2",  # CT Storage
        "1.2.840.999999999999.1.1",  # Large org root
        "1.2.3.4.5.6.7.8.9.0" * 10,  # Very long
        "0.0.0.0.0.0",  # All zeros
        "1.2.abc.def",  # Invalid characters
    ]

    INTERESTING_INTEGERS = [
        0,
        1,
        -1,
        127,
        128,
        255,
        256,
        32767,
        32768,
        65535,
        65536,
        2147483647,
        2147483648,
        -2147483648,
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
    ]

    def __init__(self, config: FuzzingConfig | None = None):
        """Initialize the mutator.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or FuzzingConfig()

    def mutate_element(self, element: DICOMElement) -> DICOMElement:
        """Mutate a single DICOM element.

        Args:
            element: Element to mutate.

        Returns:
            Mutated element.

        """
        mutation_type = random.choice(
            [
                "value",
                "vr",
                "tag",
                "length",
            ]
        )

        if mutation_type == "value":
            return self._mutate_value(element)
        elif mutation_type == "vr":
            return self._mutate_vr(element)
        elif mutation_type == "tag":
            return self._mutate_tag(element)
        else:
            return self._mutate_length(element)

    def _mutate_value(self, element: DICOMElement) -> DICOMElement:
        """Mutate element value."""
        vr = element.vr
        new_value: str | int | bytes

        if vr in self.STRING_VRS:
            new_value = random.choice(self.INTERESTING_STRINGS)
        elif vr in self.NUMERIC_VRS:
            new_value = random.choice(self.INTERESTING_INTEGERS)
        elif vr == "UI":
            new_value = random.choice(self.INTERESTING_UIDS)
        else:
            # Binary mutation
            if isinstance(element.value, bytes):
                new_value = self._mutate_bytes(element.value)
            else:
                new_value = element.value  # type: ignore[assignment]

        return DICOMElement(
            tag=element.tag,
            vr=element.vr,
            value=new_value,
        )

    def _mutate_vr(self, element: DICOMElement) -> DICOMElement:
        """Mutate element VR to invalid type."""
        all_vrs = list(self.STRING_VRS | self.NUMERIC_VRS | self.BINARY_VRS)
        # Pick a different VR
        new_vr = random.choice([v for v in all_vrs if v != element.vr])

        return DICOMElement(
            tag=element.tag,
            vr=new_vr,
            value=element.value,
        )

    def _mutate_tag(self, element: DICOMElement) -> DICOMElement:
        """Mutate element tag."""
        group, elem = element.tag

        mutation = random.choice(["group", "element", "both", "invalid"])

        if mutation == "group":
            group = random.choice(
                [
                    0x0000,
                    0x0002,
                    0x0008,
                    0x0010,
                    0x0020,
                    0x7FE0,
                    0xFFFF,
                    random.randint(0, 0xFFFF),
                ]
            )
        elif mutation == "element":
            elem = random.choice(
                [0x0000, 0x0001, 0x0010, 0x0100, 0xFFFF, random.randint(0, 0xFFFF)]
            )
        elif mutation == "both":
            group = random.randint(0, 0xFFFF)
            elem = random.randint(0, 0xFFFF)
        else:
            # Create definitely invalid tag
            group = random.choice([0x0001, 0x0003, 0x0005, 0x0007])  # Odd groups
            elem = 0x0000

        return DICOMElement(
            tag=(group, elem),
            vr=element.vr,
            value=element.value,
        )

    def _mutate_length(self, element: DICOMElement) -> DICOMElement:
        """Create element with incorrect length encoding."""
        # This requires custom encoding, return element with special marker
        return DICOMElement(
            tag=element.tag,
            vr=element.vr,
            value=element.value,
        )

    def _mutate_bytes(self, data: bytes) -> bytes:
        """Mutate binary data."""
        if not data:
            return bytes([random.randint(0, 255) for _ in range(10)])

        mutation = random.choice(["flip", "insert", "delete", "replace"])

        data = bytearray(data)

        if mutation == "flip":
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 1 << random.randint(0, 7)
        elif mutation == "insert":
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))
        elif mutation == "delete" and len(data) > 1:
            pos = random.randint(0, len(data) - 1)
            del data[pos]
        elif mutation == "replace":
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)

        return bytes(data)

    def generate_malformed_dataset(
        self,
        base_elements: list[DICOMElement],
    ) -> list[DICOMElement]:
        """Generate a malformed version of a dataset.

        Args:
            base_elements: Base elements to mutate.

        Returns:
            Mutated elements.

        """
        mutated = []

        for element in base_elements:
            if random.random() < 0.3:
                mutated.append(self.mutate_element(element))
            else:
                mutated.append(element)

        # Optionally add extra elements
        if self.config.add_private_elements:
            mutated.extend(self._generate_private_elements())

        return mutated

    def _generate_private_elements(self) -> list[DICOMElement]:
        """Generate private DICOM elements for fuzzing."""
        elements = []

        # Private creator
        private_group = random.choice([0x0009, 0x0011, 0x0013, 0x0015])
        creator = DICOMElement(
            tag=(private_group, 0x0010),
            vr="LO",
            value="FUZZ PRIVATE",
        )
        elements.append(creator)

        # Private elements
        for i in range(random.randint(1, 5)):
            elem = DICOMElement(
                tag=(private_group, 0x1000 + i),
                vr=random.choice(list(self.STRING_VRS)),
                value=random.choice(self.INTERESTING_STRINGS),
            )
            elements.append(elem)

        return elements


class UIDGenerator:
    """Generator for DICOM UIDs with fuzzing capabilities."""

    # DICOM UID root for fuzzing
    FUZZ_ROOT = "1.2.999.999"

    def __init__(self) -> None:
        """Initialize UID generator."""
        self._counter = 0

    def generate_valid_uid(self, prefix: str = "") -> str:
        """Generate a valid DICOM UID.

        Args:
            prefix: UID prefix to use.

        Returns:
            Valid UID string.

        """
        if not prefix:
            prefix = self.FUZZ_ROOT

        self._counter += 1
        import time

        timestamp = int(time.time() * 1000)

        return f"{prefix}.{timestamp}.{self._counter}"

    def generate_collision_uid(self, existing_uid: str) -> str:
        """Generate a UID that might collide with existing one.

        Args:
            existing_uid: Existing UID to potentially collide with.

        Returns:
            UID that might cause collision issues.

        """
        strategies = [
            # Exact duplicate
            lambda: existing_uid,
            # Case variation (shouldn't matter for UIDs but might trigger bugs)
            lambda: existing_uid.upper() if existing_uid.islower() else existing_uid,
            # Trailing variation
            lambda: existing_uid + ".0",
            lambda: existing_uid[:-1] if existing_uid else "",
            # Prefix match
            lambda: existing_uid[: len(existing_uid) // 2] + ".999.999",
        ]

        return random.choice(strategies)()

    def generate_malformed_uid(self) -> str:
        """Generate a malformed UID.

        Returns:
            Malformed UID string.

        """
        malformed_uids = [
            "",  # Empty
            " ",  # Space
            ".",  # Just dot
            ".1.2.3",  # Leading dot
            "1.2.3.",  # Trailing dot
            "1..2.3",  # Double dot
            "1.2.3.4.5.6.7.8.9." + "0" * 100,  # Very long
            "1.2.-3.4",  # Negative
            "1.2.+3.4",  # Plus sign
            "1.2. 3.4",  # Space in middle
            "1.2.3e4.5",  # Scientific notation
            "1.2.0x10.5",  # Hex notation
            "A.B.C.D",  # Letters
            "1.2\x00.3.4",  # Null byte
            "1.2\n3.4",  # Newline
        ]

        return random.choice(malformed_uids)


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

    def __init__(self, config: FuzzingConfig | None = None):
        """Initialize query generator.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or FuzzingConfig()
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

    def __init__(self, config: FuzzingConfig | None = None):
        """Initialize the DIMSE fuzzer.

        Args:
            config: Fuzzing configuration.

        """
        self.config = config or FuzzingConfig()
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

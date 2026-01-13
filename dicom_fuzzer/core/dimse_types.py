"""DIMSE Protocol Types and Data Structures.

Shared types for DIMSE protocol fuzzing including element encoding,
message structures, and configuration. Extracted from dimse_fuzzer.py
to enable better modularity and avoid circular imports.
"""

from __future__ import annotations

import random
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from dicom_fuzzer.core.types import DIMSECommand


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


# VR type sets for encoding
_STRING_VRS = frozenset(
    {
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
)
_BINARY_VRS = frozenset({"OB", "OW", "OD", "OF", "OL", "UN"})

# Numeric VR encoding specs: (min_val, max_val, struct_format, default)
_NUMERIC_VR_SPECS: dict[str, tuple[int, int, str, int]] = {
    "SS": (-32768, 32767, "<h", 0),
    "US": (0, 65535, "<H", 0),
    "SL": (-2147483648, 2147483647, "<l", 0),
    "UL": (0, 4294967295, "<L", 0),
}

# Float VR encoding specs: (struct_format, default)
_FLOAT_VR_SPECS: dict[str, tuple[str, float]] = {
    "FL": ("<f", 0.0),
    "FD": ("<d", 0.0),
}


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
    value: bytes | str | int | float | list[bytes | str | int | float]

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

        # String VRs
        if vr in _STRING_VRS:
            return self._encode_string()

        # Numeric integer VRs
        if vr in _NUMERIC_VR_SPECS:
            return self._encode_numeric(vr)

        # Float VRs
        if vr in _FLOAT_VR_SPECS:
            return self._encode_float(vr)

        # Binary VRs - value should be bytes but might not be after fuzzing
        if vr in _BINARY_VRS:
            return b""

        # Default to string encoding
        if isinstance(self.value, str):
            return self._pad_value(self.value.encode("utf-8"))
        return b""

    def _encode_string(self) -> bytes:
        """Encode string VR value."""
        if isinstance(self.value, str):
            encoded = self.value.encode("utf-8")
        else:
            encoded = str(self.value).encode("utf-8")
        return self._pad_value(encoded)

    def _encode_numeric(self, vr: str) -> bytes:
        """Encode numeric integer VR value with clamping."""
        min_val, max_val, fmt, default = _NUMERIC_VR_SPECS[vr]
        try:
            val = int(self.value)  # type: ignore[arg-type]
            val = max(min_val, min(val, max_val))
            return struct.pack(fmt, val)
        except (ValueError, TypeError):
            return struct.pack(fmt, default)

    def _encode_float(self, vr: str) -> bytes:
        """Encode float VR value."""
        fmt, default = _FLOAT_VR_SPECS[vr]
        try:
            return struct.pack(fmt, float(self.value))  # type: ignore[arg-type]
        except (ValueError, TypeError):
            return struct.pack(fmt, default)

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
class DIMSEFuzzingConfig:
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


# Backward compatibility alias
FuzzingConfig = DIMSEFuzzingConfig


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
        timestamp = int(time.time() * 1000)

        return f"{prefix}.{timestamp}.{self._counter}"

    def generate_collision_uid(self, existing_uid: str) -> str:
        """Generate a UID that might collide with existing one.

        Args:
            existing_uid: Existing UID to potentially collide with.

        Returns:
            UID that might cause collision issues.

        """
        strategies: list[Callable[[], str]] = [
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

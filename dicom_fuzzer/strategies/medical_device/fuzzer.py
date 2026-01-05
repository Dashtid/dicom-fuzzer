"""Medical Device Security Fuzzer.

Security-focused fuzzer for medical device DICOM implementations.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.medical_device.types import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    SecurityMutation,
    VulnerabilityClass,
)

logger = logging.getLogger(__name__)


class MedicalDeviceSecurityFuzzer:
    """Security-focused fuzzer for medical device DICOM implementations.

    Generates mutations targeting specific vulnerability patterns found in
    medical device software, with focus on:
    - Buffer overflow vulnerabilities (OOB read/write)
    - Integer overflow in length fields
    - Memory corruption through malformed structures
    - DoS through resource exhaustion

    Usage:
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        mutations = fuzzer.generate_mutations(dataset)
        for mutation in mutations:
            mutated_ds = fuzzer.apply_mutation(dataset.copy(), mutation)
            # Test mutated_ds against target

    """

    # Tags commonly involved in vulnerabilities
    VULNERABLE_TAGS = {
        # String fields prone to buffer overflow
        (0x0010, 0x0010): "PatientName",
        (0x0010, 0x0020): "PatientID",
        (0x0010, 0x0030): "PatientBirthDate",
        (0x0008, 0x0018): "SOPInstanceUID",
        (0x0008, 0x0050): "AccessionNumber",
        (0x0020, 0x000D): "StudyInstanceUID",
        (0x0020, 0x000E): "SeriesInstanceUID",
        # Numeric fields prone to integer overflow
        (0x0028, 0x0010): "Rows",
        (0x0028, 0x0011): "Columns",
        (0x0028, 0x0100): "BitsAllocated",
        (0x0028, 0x0101): "BitsStored",
        (0x0028, 0x0102): "HighBit",
        (0x0028, 0x0008): "NumberOfFrames",
        # Length-dependent fields
        (0x7FE0, 0x0010): "PixelData",
        (0x0028, 0x0002): "SamplesPerPixel",
        # Private tags (often less validated)
        (0x0009, 0x0010): "PrivateCreator",
        (0x0043, 0x0010): "PrivateCreator",
    }

    def __init__(self, config: MedicalDeviceSecurityConfig | None = None):
        """Initialize the security fuzzer.

        Args:
            config: Security testing configuration

        """
        self.config = config or MedicalDeviceSecurityConfig()
        self._mutations_generated: list[SecurityMutation] = []

        logger.info(
            f"MedicalDeviceSecurityFuzzer initialized: "
            f"CVEs={len(self.config.target_cves)}, "
            f"VulnClasses={len(self.config.target_vulns)}"
        )

    def generate_mutations(self, dataset: Dataset) -> list[SecurityMutation]:
        """Generate security-focused mutations for a dataset.

        Args:
            dataset: Source DICOM dataset

        Returns:
            List of SecurityMutation objects to apply

        """
        mutations: list[SecurityMutation] = []

        # Generate mutations for each vulnerability class
        if VulnerabilityClass.OUT_OF_BOUNDS_WRITE in self.config.target_vulns:
            mutations.extend(self._generate_oob_write_mutations(dataset))

        if VulnerabilityClass.OUT_OF_BOUNDS_READ in self.config.target_vulns:
            mutations.extend(self._generate_oob_read_mutations(dataset))

        if VulnerabilityClass.INTEGER_OVERFLOW in self.config.target_vulns:
            mutations.extend(self._generate_integer_overflow_mutations(dataset))

        if VulnerabilityClass.STACK_BUFFER_OVERFLOW in self.config.target_vulns:
            mutations.extend(self._generate_stack_overflow_mutations(dataset))

        if VulnerabilityClass.HEAP_BUFFER_OVERFLOW in self.config.target_vulns:
            mutations.extend(self._generate_heap_overflow_mutations(dataset))

        if VulnerabilityClass.FORMAT_STRING in self.config.target_vulns:
            mutations.extend(self._generate_format_string_mutations(dataset))

        if VulnerabilityClass.NULL_POINTER_DEREF in self.config.target_vulns:
            mutations.extend(self._generate_null_deref_mutations(dataset))

        if VulnerabilityClass.DENIAL_OF_SERVICE in self.config.target_vulns:
            mutations.extend(self._generate_dos_mutations(dataset))

        self._mutations_generated = mutations
        logger.info(f"Generated {len(mutations)} security mutations")
        return mutations

    def _generate_oob_write_mutations(self, dataset: Dataset) -> list[SecurityMutation]:
        """Generate out-of-bounds write mutations (CVE-2025-35975 style).

        Targets scenarios where writing past buffer boundaries can occur.
        """
        mutations = []

        # String fields with excessive length
        for tag, name in self.VULNERABLE_TAGS.items():
            if tag[0] == 0x7FE0:  # Skip pixel data for string tests
                continue

            # Generate progressively longer strings
            for length in [256, 512, 1024, 4096, 65535]:
                mutations.append(
                    SecurityMutation(
                        name=f"oob_write_{name}_{length}",
                        vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                        cve_pattern=CVEPattern.CVE_2025_35975,
                        tag=tag,
                        mutated_value="A" * length,
                        description=f"OOB write via {name} ({length} bytes)",
                        severity=8,
                        exploitability="probably_exploitable",
                    )
                )

        # Pixel data with mismatched dimensions
        if self.config.fuzz_pixel_data:
            # Claim small dimensions but provide large pixel data
            mutations.append(
                SecurityMutation(
                    name="oob_write_pixel_size_mismatch",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                    cve_pattern=CVEPattern.CVE_2025_35975,
                    tag=(0x7FE0, 0x0010),
                    mutated_value={"rows": 1, "cols": 1, "data_size": 65536},
                    description="Pixel data larger than claimed dimensions",
                    severity=9,
                    exploitability="exploitable",
                )
            )

        # Add CVE-2025-5943 specific patterns (June 2025 CISA advisory)
        mutations.extend(self._generate_cve_2025_5943_mutations(dataset))

        return mutations

    def _generate_cve_2025_5943_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate CVE-2025-5943 specific mutations (June 2025 MicroDicom vuln).

        CVE-2025-5943 affects MicroDicom 3.0.0 to 3.9.6 and involves heap
        corruption during DICOM header parsing. Attack vectors include:
        - Malformed VR length fields causing heap overflow
        - Transfer syntax confusion attacks
        - Pixel data header misalignment
        - File meta information corruption

        Reference: CISA ICS-CERT Advisory ICSMA-25-160-01
        """
        mutations = []

        # 1. VR Length Field Overflow Attacks
        vr_length_attacks = [
            (0xFFFF, "max_16bit_length"),
            (0xFFFE, "boundary_16bit_length"),
            (0x8000, "signed_boundary_length"),
            (0x7FFF, "max_signed_16bit_length"),
        ]

        for length_val, name in vr_length_attacks:
            mutations.append(
                SecurityMutation(
                    name=f"cve_2025_5943_vr_length_{name}",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                    cve_pattern=CVEPattern.CVE_2025_5943,
                    tag=(0x0008, 0x0018),  # SOPInstanceUID
                    mutated_value="X" * min(length_val, 0x8000),
                    description=f"CVE-2025-5943: VR length overflow ({name})",
                    severity=9,
                    exploitability="exploitable",
                )
            )

        # 2. Transfer Syntax Confusion Attacks
        transfer_syntax_attacks = [
            ("1.2.840.10008.1.2", "implicit_vr_le"),
            ("1.2.840.10008.1.2.1", "explicit_vr_le"),
            ("1.2.840.10008.1.2.2", "explicit_vr_be"),
            ("1.2.840.10008.1.2.1.99", "invalid_ts"),
        ]

        for ts_uid, name in transfer_syntax_attacks:
            mutations.append(
                SecurityMutation(
                    name=f"cve_2025_5943_transfer_syntax_{name}",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                    cve_pattern=CVEPattern.CVE_2025_5943,
                    tag=(0x0002, 0x0010),  # TransferSyntaxUID
                    mutated_value=ts_uid,
                    description=f"CVE-2025-5943: Transfer syntax confusion ({name})",
                    severity=8,
                    exploitability="probably_exploitable",
                )
            )

        # 3. Pixel Data Header Misalignment Attacks
        if self.config.fuzz_pixel_data:
            pixel_misalign_attacks = [
                ({"rows": 0xFFFF, "cols": 0xFFFF, "data_size": 1024}, "max_dims"),
                ({"rows": 0x8001, "cols": 0x8001, "data_size": 256}, "odd_boundary"),
                ({"rows": 3, "cols": 3, "data_size": 0x10000}, "size_overflow"),
            ]

            for params, name in pixel_misalign_attacks:
                mutations.append(
                    SecurityMutation(
                        name=f"cve_2025_5943_pixel_misalign_{name}",
                        vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                        cve_pattern=CVEPattern.CVE_2025_5943,
                        tag=(0x7FE0, 0x0010),
                        mutated_value=params,
                        description=f"CVE-2025-5943: Pixel misalignment ({name})",
                        severity=9,
                        exploitability="exploitable",
                    )
                )

        # 4. File Meta Information Corruption
        file_meta_attacks = [
            ((0x0002, 0x0000), "file_meta_length"),
            ((0x0002, 0x0001), "file_meta_version"),
            ((0x0002, 0x0002), "media_sop_class"),
            ((0x0002, 0x0003), "media_sop_instance"),
        ]

        for tag, name in file_meta_attacks:
            mutations.append(
                SecurityMutation(
                    name=f"cve_2025_5943_file_meta_{name}",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                    cve_pattern=CVEPattern.CVE_2025_5943,
                    tag=tag,
                    mutated_value="X" * 0x8000,
                    description=f"CVE-2025-5943: File meta corruption ({name})",
                    severity=9,
                    exploitability="exploitable",
                )
            )

        logger.info(f"Generated {len(mutations)} CVE-2025-5943 specific mutations")
        return mutations

    def _generate_oob_read_mutations(self, dataset: Dataset) -> list[SecurityMutation]:
        """Generate out-of-bounds read mutations (CVE-2025-36521 style).

        Targets scenarios where reading past buffer boundaries can occur.
        """
        mutations = []

        # Pixel data with oversized dimensions
        dimension_tests = [
            (65535, 65535, "max_dimensions"),
            (0, 0, "zero_dimensions"),
            (1, 0, "zero_column"),
            (0, 1, "zero_row"),
            (0xFFFF, 0xFFFF, "unsigned_max"),
        ]

        for rows, cols, name in dimension_tests:
            mutations.append(
                SecurityMutation(
                    name=f"oob_read_{name}",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
                    cve_pattern=CVEPattern.CVE_2025_36521,
                    tag=(0x0028, 0x0010),  # Rows
                    mutated_value={"rows": rows, "cols": cols},
                    description=f"OOB read via {name} (rows={rows}, cols={cols})",
                    severity=8,
                    exploitability="probably_exploitable",
                )
            )

        # BitsAllocated/BitsStored mismatches
        bit_tests = [
            (32, 8, "bits_mismatch_32_8"),
            (64, 8, "bits_mismatch_64_8"),
            (0, 8, "bits_allocated_zero"),
            (8, 0, "bits_stored_zero"),
            (8, 16, "bits_stored_greater"),
        ]

        for allocated, stored, name in bit_tests:
            mutations.append(
                SecurityMutation(
                    name=f"oob_read_{name}",
                    vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
                    cve_pattern=CVEPattern.CVE_2025_36521,
                    tag=(0x0028, 0x0100),  # BitsAllocated
                    mutated_value={"bits_allocated": allocated, "bits_stored": stored},
                    description="OOB read via bit allocation mismatch",
                    severity=7,
                    exploitability="probably_not_exploitable",
                )
            )

        return mutations

    def _generate_integer_overflow_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate integer overflow mutations.

        Targets arithmetic operations that may overflow.
        """
        mutations = []

        # Rows * Columns overflow
        overflow_pairs = [
            (0x7FFF, 0x7FFF, "signed_max_product"),
            (0xFFFF, 0xFFFF, "unsigned_max_product"),
            (0x8000, 0x8000, "signed_overflow"),
            (65535, 65535, "near_4gb"),
        ]

        for rows, cols, name in overflow_pairs:
            mutations.append(
                SecurityMutation(
                    name=f"int_overflow_{name}",
                    vulnerability_class=VulnerabilityClass.INTEGER_OVERFLOW,
                    tag=(0x0028, 0x0010),
                    mutated_value={"rows": rows, "cols": cols},
                    description=f"Integer overflow via dimension multiplication ({name})",
                    severity=7,
                    exploitability="probably_exploitable",
                )
            )

        # NumberOfFrames overflow
        frame_tests = [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000]
        for frames in frame_tests:
            mutations.append(
                SecurityMutation(
                    name=f"int_overflow_frames_{frames:x}",
                    vulnerability_class=VulnerabilityClass.INTEGER_OVERFLOW,
                    tag=(0x0028, 0x0008),
                    mutated_value=frames,
                    description=f"Integer overflow via NumberOfFrames (0x{frames:X})",
                    severity=6,
                    exploitability="unknown",
                )
            )

        return mutations

    def _generate_stack_overflow_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate stack buffer overflow mutations.

        Targets fixed-size stack buffers in DICOM parsers.
        """
        mutations = []

        # Known vulnerable string lengths
        overflow_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192]

        for size in overflow_sizes:
            # Standard overflow pattern
            mutations.append(
                SecurityMutation(
                    name=f"stack_overflow_{size}",
                    vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
                    tag=(0x0010, 0x0010),  # PatientName
                    mutated_value="A" * size,
                    description=f"Stack overflow via {size}-byte PatientName",
                    severity=9,
                    exploitability="exploitable",
                )
            )

            # With null terminator bypass
            mutations.append(
                SecurityMutation(
                    name=f"stack_overflow_null_{size}",
                    vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
                    tag=(0x0010, 0x0010),
                    mutated_value="A" * (size // 2) + "\x00" + "B" * (size // 2),
                    description=f"Stack overflow with embedded null ({size} bytes)",
                    severity=8,
                    exploitability="probably_exploitable",
                )
            )

        return mutations

    def _generate_heap_overflow_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate heap buffer overflow mutations.

        Targets dynamically allocated buffers.
        """
        mutations = []

        # Large allocations that may cause heap overflow
        large_sizes = [0x10000, 0x100000, 0x1000000]

        for size in large_sizes:
            mutations.append(
                SecurityMutation(
                    name=f"heap_overflow_{size:x}",
                    vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
                    tag=(0x7FE0, 0x0010),  # PixelData
                    mutated_value={"data_size": size, "pattern": "overflow"},
                    description=f"Heap overflow via {size:,} byte pixel data",
                    severity=9,
                    exploitability="exploitable",
                )
            )

        # Sequence nesting depth (may exhaust stack/heap)
        for depth in [10, 50, 100, 500]:
            mutations.append(
                SecurityMutation(
                    name=f"heap_exhaust_depth_{depth}",
                    vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
                    tag=(0x0008, 0x1115),  # ReferencedSeriesSequence
                    mutated_value={"depth": depth},
                    description=f"Heap exhaustion via {depth}-deep sequence nesting",
                    severity=6,
                    exploitability="probably_not_exploitable",
                )
            )

        return mutations

    def _generate_format_string_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate format string vulnerability mutations.

        Targets printf-style format string vulnerabilities.
        """
        mutations = []

        format_strings = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%p%p%p%p%p%p%p%p%p%p",
            "AAAA%08x.%08x.%08x.%08x.%08x.%n",
            "%s" * 100,
            "%x" * 100,
        ]

        for i, fmt in enumerate(format_strings):
            mutations.append(
                SecurityMutation(
                    name=f"format_string_{i}",
                    vulnerability_class=VulnerabilityClass.FORMAT_STRING,
                    tag=(0x0010, 0x0010),  # PatientName
                    mutated_value=fmt,
                    description=f"Format string attack pattern {i}",
                    severity=8,
                    exploitability="probably_exploitable",
                )
            )

        return mutations

    def _generate_null_deref_mutations(
        self, dataset: Dataset
    ) -> list[SecurityMutation]:
        """Generate null pointer dereference mutations.

        Targets scenarios where null values may cause dereference.
        """
        mutations = []

        # Empty/null values in required fields
        null_targets = [
            ((0x0008, 0x0018), "SOPInstanceUID"),
            ((0x0020, 0x000D), "StudyInstanceUID"),
            ((0x0020, 0x000E), "SeriesInstanceUID"),
            ((0x0008, 0x0016), "SOPClassUID"),
        ]

        for tag, name in null_targets:
            # Empty string
            mutations.append(
                SecurityMutation(
                    name=f"null_deref_empty_{name}",
                    vulnerability_class=VulnerabilityClass.NULL_POINTER_DEREF,
                    tag=tag,
                    mutated_value="",
                    description=f"Null dereference via empty {name}",
                    severity=5,
                    exploitability="probably_not_exploitable",
                )
            )

            # Null byte only
            mutations.append(
                SecurityMutation(
                    name=f"null_deref_null_{name}",
                    vulnerability_class=VulnerabilityClass.NULL_POINTER_DEREF,
                    tag=tag,
                    mutated_value="\x00",
                    description=f"Null dereference via null byte in {name}",
                    severity=5,
                    exploitability="unknown",
                )
            )

        return mutations

    def _generate_dos_mutations(self, dataset: Dataset) -> list[SecurityMutation]:
        """Generate denial of service mutations.

        Targets resource exhaustion and infinite loop scenarios.
        """
        mutations = []

        # Resource exhaustion via large values
        dos_sizes = [
            (0xFFFFFFFF, "max_32bit"),
            (0x7FFFFFFF, "max_signed_32bit"),
            (999999999, "large_decimal"),
        ]

        for size, name in dos_sizes:
            mutations.append(
                SecurityMutation(
                    name=f"dos_frames_{name}",
                    vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
                    tag=(0x0028, 0x0008),  # NumberOfFrames
                    mutated_value=size,
                    description=f"DoS via NumberOfFrames={size}",
                    severity=4,
                    exploitability="unknown",
                )
            )

        # Circular reference in sequences (may cause infinite loop)
        mutations.append(
            SecurityMutation(
                name="dos_circular_ref",
                vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
                tag=(0x0008, 0x1115),
                mutated_value={"circular": True},
                description="DoS via circular sequence reference",
                severity=5,
                exploitability="unknown",
            )
        )

        # Deeply nested sequences
        for depth in [100, 500, 1000]:
            mutations.append(
                SecurityMutation(
                    name=f"dos_nested_{depth}",
                    vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
                    tag=(0x0008, 0x1115),
                    mutated_value={"depth": depth, "type": "dos"},
                    description=f"DoS via {depth}-level nested sequences",
                    severity=4,
                    exploitability="unknown",
                )
            )

        return mutations

    def apply_mutation(self, dataset: Dataset, mutation: SecurityMutation) -> Dataset:
        """Apply a security mutation to a dataset.

        Args:
            dataset: Dataset to mutate (should be a copy)
            mutation: Mutation to apply

        Returns:
            Mutated dataset

        """
        if mutation.tag is None:
            return dataset

        tag = mutation.tag
        value = mutation.mutated_value

        try:
            # Handle special mutation types
            if isinstance(value, dict):
                self._apply_complex_mutation(dataset, mutation)
            elif isinstance(value, str):
                # String value - direct assignment
                if tag in dataset:
                    dataset[tag].value = value
                else:
                    # Add new element
                    from pydicom.dataelem import DataElement
                    from pydicom.tag import Tag

                    vr = self._get_vr_for_tag(tag)
                    dataset.add(DataElement(Tag(tag), vr, value))
            elif isinstance(value, int):
                # Integer value
                if tag in dataset:
                    dataset[tag].value = value

            logger.debug(f"Applied mutation: {mutation.name}")

        except Exception as e:
            logger.warning(f"Failed to apply mutation {mutation.name}: {e}")

        return dataset

    def _apply_complex_mutation(
        self, dataset: Dataset, mutation: SecurityMutation
    ) -> None:
        """Apply a complex mutation requiring multiple changes.

        Args:
            dataset: Dataset to mutate
            mutation: Complex mutation to apply

        """
        value = mutation.mutated_value
        if not isinstance(value, dict):
            return

        # Handle dimension mutations
        if "rows" in value and "cols" in value:
            if (0x0028, 0x0010) in dataset:
                dataset[0x0028, 0x0010].value = value["rows"]
            if (0x0028, 0x0011) in dataset:
                dataset[0x0028, 0x0011].value = value["cols"]

        # Handle bit allocation mutations
        if "bits_allocated" in value:
            if (0x0028, 0x0100) in dataset:
                dataset[0x0028, 0x0100].value = value["bits_allocated"]
        if "bits_stored" in value:
            if (0x0028, 0x0101) in dataset:
                dataset[0x0028, 0x0101].value = value["bits_stored"]

        # Handle pixel data mutations
        if "data_size" in value:
            size = value["data_size"]
            if "pattern" in value:
                # Generate pattern data
                if value["pattern"] == "overflow":
                    pixel_data = b"\x41" * size  # 'A' pattern
                else:
                    pixel_data = os.urandom(size)
            else:
                pixel_data = os.urandom(size)

            if (0x7FE0, 0x0010) in dataset:
                dataset[0x7FE0, 0x0010].value = pixel_data

        # Handle sequence depth mutations
        if "depth" in value:
            self._create_nested_sequence(dataset, mutation.tag, value["depth"])

    def _create_nested_sequence(
        self, dataset: Dataset, tag: tuple[int, int] | None, depth: int
    ) -> None:
        """Create a deeply nested sequence structure.

        Args:
            dataset: Dataset to modify
            tag: Tag for the sequence
            depth: Nesting depth

        """
        if tag is None or depth <= 0:
            return

        from pydicom.sequence import Sequence

        def create_nested(current_depth: int) -> Sequence:
            if current_depth <= 0:
                return Sequence([Dataset()])

            inner = Dataset()
            inner.add_new(tag, "SQ", create_nested(current_depth - 1))
            return Sequence([inner])

        try:
            seq = create_nested(depth)
            if tag in dataset:
                dataset[tag].value = seq
            else:
                dataset.add_new(tag, "SQ", seq)
        except Exception as e:
            logger.warning(f"Failed to create nested sequence: {e}")

    def _get_vr_for_tag(self, tag: tuple[int, int]) -> str:
        """Get the VR (Value Representation) for a tag.

        Args:
            tag: DICOM tag

        Returns:
            VR string

        """
        # Common VR mappings
        vr_map = {
            (0x0010, 0x0010): "PN",  # PatientName
            (0x0010, 0x0020): "LO",  # PatientID
            (0x0010, 0x0030): "DA",  # PatientBirthDate
            (0x0008, 0x0018): "UI",  # SOPInstanceUID
            (0x0008, 0x0016): "UI",  # SOPClassUID
            (0x0020, 0x000D): "UI",  # StudyInstanceUID
            (0x0020, 0x000E): "UI",  # SeriesInstanceUID
            (0x0028, 0x0010): "US",  # Rows
            (0x0028, 0x0011): "US",  # Columns
            (0x0028, 0x0100): "US",  # BitsAllocated
            (0x0028, 0x0101): "US",  # BitsStored
            (0x0028, 0x0008): "IS",  # NumberOfFrames
            (0x7FE0, 0x0010): "OW",  # PixelData
        }
        return vr_map.get(tag, "LO")

    def get_mutations_by_cve(self, cve: CVEPattern) -> list[SecurityMutation]:
        """Get mutations targeting a specific CVE.

        Args:
            cve: CVE pattern to filter by

        Returns:
            List of mutations for that CVE

        """
        return [m for m in self._mutations_generated if m.cve_pattern == cve]

    def get_mutations_by_severity(
        self, min_severity: int = 7
    ) -> list[SecurityMutation]:
        """Get mutations above a severity threshold.

        Args:
            min_severity: Minimum severity (1-10)

        Returns:
            List of high-severity mutations

        """
        return [m for m in self._mutations_generated if m.severity >= min_severity]

    def get_summary(self) -> dict[str, Any]:
        """Get summary of generated mutations.

        Returns:
            Dictionary with mutation statistics

        """
        mutations = self._mutations_generated

        summary: dict[str, Any] = {
            "total_mutations": len(mutations),
            "by_vulnerability_class": {},
            "by_cve": {},
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "high_value_targets": [],
        }

        for mutation in mutations:
            # Count by vulnerability class
            vc = mutation.vulnerability_class.value
            summary["by_vulnerability_class"][vc] = (
                summary["by_vulnerability_class"].get(vc, 0) + 1
            )

            # Count by CVE
            if mutation.cve_pattern:
                cve = mutation.cve_pattern.value
                summary["by_cve"][cve] = summary["by_cve"].get(cve, 0) + 1

            # Count by severity
            if mutation.severity >= 9:
                summary["by_severity"]["critical"] += 1
            elif mutation.severity >= 7:
                summary["by_severity"]["high"] += 1
            elif mutation.severity >= 4:
                summary["by_severity"]["medium"] += 1
            else:
                summary["by_severity"]["low"] += 1

            # Track high-value targets
            if mutation.severity >= 8:
                summary["high_value_targets"].append(mutation.to_dict())

        return summary

    def print_summary(self) -> None:
        """Print formatted summary to console."""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("  Medical Device Security Fuzzing Summary")
        print("=" * 70)
        print(f"  Total Mutations: {summary['total_mutations']}")

        print("\n--- By Vulnerability Class ---")
        for vc, count in sorted(summary["by_vulnerability_class"].items()):
            print(f"  {vc}: {count}")

        print("\n--- By CVE Pattern ---")
        for cve, count in sorted(summary["by_cve"].items()):
            print(f"  {cve}: {count}")

        print("\n--- By Severity ---")
        for sev, count in summary["by_severity"].items():
            print(f"  {sev.capitalize()}: {count}")

        if summary["high_value_targets"]:
            print(
                f"\n--- High-Value Targets ({len(summary['high_value_targets'])}) ---"
            )
            for target in summary["high_value_targets"][:10]:
                print(f"  [!] {target['name']}: {target['description']}")

        print("=" * 70 + "\n")


__all__ = ["MedicalDeviceSecurityFuzzer"]

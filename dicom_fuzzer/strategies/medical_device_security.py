"""Medical Device Security Patterns for DICOM Fuzzing.

This module provides security-focused mutation patterns targeting common
vulnerabilities in medical device DICOM implementations, based on:
- CVE-2025-35975: MicroDicom out-of-bounds write (CVSS 8.8)
- CVE-2025-36521: MicroDicom out-of-bounds read (CVSS 8.8)
- CVE-2025-5943: Additional MicroDicom vulnerability
- CVE-2022-2119, CVE-2022-2120: Historical DICOM server vulnerabilities
- CVE-2025-1001: RadiAnt DICOM Viewer vulnerability

References:
- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01
- https://nvd.nist.gov/vuln/detail/cve-2025-35975
- https://nvd.nist.gov/vuln/detail/CVE-2025-36521
- https://digital.nhs.uk/cyber-alerts/2025/cc-4650

SECURITY NOTE: This module is intended for authorized security testing only.
Use only on systems you own or have explicit permission to test.

"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydicom.dataset import Dataset

logger = logging.getLogger(__name__)


class VulnerabilityClass(Enum):
    """Classes of vulnerabilities targeted by mutations."""

    OUT_OF_BOUNDS_WRITE = "oob_write"  # CVE-2025-35975
    OUT_OF_BOUNDS_READ = "oob_read"  # CVE-2025-36521
    STACK_BUFFER_OVERFLOW = "stack_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    NULL_POINTER_DEREF = "null_deref"
    MEMORY_CORRUPTION = "memory_corruption"
    DENIAL_OF_SERVICE = "dos"


class CVEPattern(Enum):
    """Specific CVE patterns to test for."""

    CVE_2025_35975 = "CVE-2025-35975"  # MicroDicom OOB write
    CVE_2025_36521 = "CVE-2025-36521"  # MicroDicom OOB read
    CVE_2025_5943 = "CVE-2025-5943"  # MicroDicom additional
    CVE_2025_1001 = "CVE-2025-1001"  # RadiAnt DICOM Viewer
    CVE_2022_2119 = "CVE-2022-2119"  # DICOM server DoS
    CVE_2022_2120 = "CVE-2022-2120"  # DICOM server RCE


@dataclass
class SecurityMutation:
    """Represents a security-focused mutation.

    Attributes:
        name: Name of the mutation
        vulnerability_class: Target vulnerability class
        cve_pattern: Related CVE pattern if any
        tag: DICOM tag to mutate
        original_value: Original value before mutation
        mutated_value: Value after mutation
        description: Description of the mutation
        severity: Severity if exploited (1-10)
        exploitability: Estimated exploitability

    """

    name: str
    vulnerability_class: VulnerabilityClass
    cve_pattern: CVEPattern | None = None
    tag: tuple[int, int] | None = None
    original_value: Any = None
    mutated_value: Any = None
    description: str = ""
    severity: int = 5
    exploitability: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "vulnerability_class": self.vulnerability_class.value,
            "cve_pattern": self.cve_pattern.value if self.cve_pattern else None,
            "tag": f"({self.tag[0]:04X},{self.tag[1]:04X})" if self.tag else None,
            "description": self.description,
            "severity": self.severity,
            "exploitability": self.exploitability,
        }


@dataclass
class MedicalDeviceSecurityConfig:
    """Configuration for medical device security testing.

    Attributes:
        target_cves: List of CVE patterns to test for
        target_vulns: List of vulnerability classes to target
        max_string_length: Maximum string length for overflow tests
        enable_destructive: Enable potentially destructive mutations
        fuzz_pixel_data: Whether to fuzz pixel data structures
        fuzz_sequence_depth: Maximum depth for nested sequence fuzzing

    """

    target_cves: list[CVEPattern] = field(default_factory=lambda: list(CVEPattern))
    target_vulns: list[VulnerabilityClass] = field(
        default_factory=lambda: list(VulnerabilityClass)
    )
    max_string_length: int = 65536
    enable_destructive: bool = True
    fuzz_pixel_data: bool = True
    fuzz_sequence_depth: int = 10


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

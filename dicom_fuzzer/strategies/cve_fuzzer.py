"""CVE Fuzzer - Applies CVE-based security mutations to DICOM files.

This fuzzer integrates CVE-inspired mutations into the standard fuzzing pipeline,
targeting known vulnerabilities in DICOM parsers.

CVEs Covered:
- CVE-2025-5943: Heap buffer overflow via large dimensions
- CVE-2025-11266: Integer underflow in encapsulated PixelData
- CVE-2020-29625: DoS via malformed length fields
- CVE-2021-41946: Path traversal via filename injection
- CVE-2022-24193: DoS via deep sequence nesting
- CVE-2019-11687: Polyglot files (handled at binary level)

Note: Some CVE mutations require binary-level modifications and are applied
during file writing. This fuzzer applies Dataset-level mutations that
trigger the same vulnerability patterns.
"""

import logging
import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import UID

logger = logging.getLogger(__name__)


class CVEFuzzer:
    """Applies CVE-based security mutations to DICOM datasets.

    This fuzzer targets known DICOM vulnerabilities by applying mutations
    that trigger heap overflows, integer overflows, path traversal, and
    other security issues in parsers.
    """

    def __init__(self) -> None:
        """Initialize CVE fuzzer with mutation registry."""
        self.mutations_applied: list[str] = []

    def apply_cve_mutations(self, dataset: Dataset) -> Dataset:
        """Apply random CVE-inspired mutations to dataset.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        # List of available CVE mutation methods
        mutations = [
            ("CVE-2025-5943:heap_overflow", self._heap_overflow_dimensions),
            ("CVE-2025-5943:integer_overflow", self._integer_overflow_dimensions),
            ("CVE-2020-29625:malformed_length", self._malformed_string_lengths),
            ("CVE-2021-41946:path_traversal", self._path_traversal),
            ("CVE-2022-24193:deep_nesting", self._deep_nesting),
            ("CVE-2019-11687:polyglot_marker", self._polyglot_marker),
            ("CVE-2025-11266:pixel_fragment", self._pixel_data_fragment_attack),
            ("GENERIC:invalid_transfer_syntax", self._invalid_transfer_syntax),
        ]

        # Apply 1-3 random mutations
        num_mutations = random.randint(1, 3)
        selected = random.sample(mutations, min(num_mutations, len(mutations)))

        for name, mutation_func in selected:
            try:
                dataset = mutation_func(dataset)
                self.mutations_applied.append(name)
                logger.debug(f"Applied CVE mutation: {name}")
            except Exception as e:
                logger.debug(f"CVE mutation {name} failed: {e}")

        return dataset

    def _heap_overflow_dimensions(self, dataset: Dataset) -> Dataset:
        """CVE-2025-5943: Set extreme image dimensions to trigger heap overflow.

        When Rows * Columns * BitsAllocated/8 exceeds allocation, parsers
        may overflow heap buffers during pixel data processing.
        """
        # Set maximum dimensions to trigger large allocations
        dataset.Rows = 65535
        dataset.Columns = 65535
        dataset.BitsAllocated = 16
        dataset.BitsStored = 16
        dataset.HighBit = 15
        dataset.SamplesPerPixel = 1

        return dataset

    def _integer_overflow_dimensions(self, dataset: Dataset) -> Dataset:
        """CVE-2025-5943: Set dimensions that cause integer overflow.

        Values chosen so that Rows * Columns overflows 32-bit integers.
        """
        overflow_pairs = [
            (32768, 32768),  # 32768^2 = 1073741824 (fits), but *2 bytes = overflow
            (46341, 46341),  # ~2^31 when multiplied
            (65535, 65535),  # Maximum 16-bit values
        ]

        rows, cols = random.choice(overflow_pairs)
        dataset.Rows = rows
        dataset.Columns = cols
        dataset.BitsAllocated = 16

        return dataset

    def _malformed_string_lengths(self, dataset: Dataset) -> Dataset:
        """CVE-2020-29625: Insert extremely long strings to trigger buffer issues.

        Parsers may allocate fixed-size buffers for certain string fields.
        """
        # Create strings that exceed typical buffer sizes
        long_string_2k = "A" * 2048
        long_string_32k = "X" * 32768

        # Apply to various string fields
        if hasattr(dataset, "PatientName"):
            dataset.PatientName = long_string_2k
        if hasattr(dataset, "InstitutionName"):
            dataset.InstitutionName = long_string_32k
        if hasattr(dataset, "StudyDescription"):
            dataset.StudyDescription = long_string_2k
        if hasattr(dataset, "SeriesDescription"):
            dataset.SeriesDescription = long_string_32k

        # Also set some private tags with long values
        dataset.add_new(Tag(0x0009, 0x0010), "LO", long_string_32k)
        dataset.add_new(Tag(0x0043, 0x0010), "LO", long_string_32k)

        return dataset

    def _path_traversal(self, dataset: Dataset) -> Dataset:
        """CVE-2021-41946: Inject path traversal payloads in file references."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "\\\\server\\share\\file",
        ]

        payload = random.choice(payloads)

        # Use LO (Long String) VR which allows more characters than CS
        # Private tags can have any VR
        dataset.add_new(Tag(0x0009, 0x1001), "LO", payload)  # Private path field

        # Also try in StorageMediaFileSetID which uses SH VR (allows paths)
        try:
            dataset.StorageMediaFileSetID = payload[:16]  # SH max 16 chars
        except Exception:
            pass

        return dataset

    def _deep_nesting(self, dataset: Dataset) -> Dataset:
        """CVE-2022-24193: Create deeply nested sequences to exhaust stack."""
        nesting_depth = random.randint(50, 200)

        # Build a deeply nested sequence structure
        inner_dataset = Dataset()
        inner_dataset.PatientName = "Nested"

        for _ in range(nesting_depth):
            wrapper = Dataset()
            wrapper.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([inner_dataset]))
            inner_dataset = wrapper

        # Add the deeply nested structure
        dataset.add_new(Tag(0x0008, 0x1115), "SQ", Sequence([inner_dataset]))

        return dataset

    def _polyglot_marker(self, dataset: Dataset) -> Dataset:
        """CVE-2019-11687: Add markers indicating polyglot potential.

        The actual PE/ELF header injection happens at binary level during save.
        This mutation adds metadata markers and modifies preamble-related fields.
        """
        # Add a marker in file meta info if available
        if hasattr(dataset, "file_meta"):
            # Set implementation class UID to something suspicious
            dataset.file_meta.ImplementationClassUID = UID("1.2.3.4.5.6.7.8.9.0.MZ")

        # Add private tag indicating polyglot test
        dataset.add_new(Tag(0x0009, 0x1000), "LO", "POLYGLOT_TEST_MARKER")

        return dataset

    def _pixel_data_fragment_attack(self, dataset: Dataset) -> Dataset:
        """CVE-2025-11266: Manipulate pixel data attributes for fragment attacks.

        Sets up conditions that may trigger integer underflow in encapsulated
        pixel data parsing by creating mismatched frame counts and dimensions.
        """
        # Set conflicting frame information
        dataset.NumberOfFrames = 10
        dataset.Rows = 1
        dataset.Columns = 1
        dataset.BitsAllocated = 8

        # Add encapsulated-related attributes
        if hasattr(dataset, "file_meta"):
            # Set to JPEG transfer syntax (encapsulated)
            dataset.file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.4.50")

        return dataset

    def _invalid_transfer_syntax(self, dataset: Dataset) -> Dataset:
        """Inject invalid transfer syntax UID to test parser robustness."""
        invalid_uids = [
            "1.2.3.4.5.6.7.8.9.0" + "." * 50,  # Excessively long
            "0.0",  # Minimal
            "1.2.840.10008.1.2.4.9999",  # Non-existent JPEG variant
            "INVALID.TRANSFER.SYNTAX",  # Non-numeric
        ]

        if hasattr(dataset, "file_meta"):
            dataset.file_meta.TransferSyntaxUID = UID(random.choice(invalid_uids))

        return dataset

    def get_mutations_applied(self) -> list[str]:
        """Return list of mutations applied in last call."""
        return self.mutations_applied.copy()

    def reset_stats(self) -> None:
        """Reset mutation tracking."""
        self.mutations_applied = []

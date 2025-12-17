"""Structure Fuzzer - DICOM File Structure Attacks

LEARNING OBJECTIVE: This module demonstrates low-level file format fuzzing,
targeting the DICOM file structure itself rather than just the data values.

CONCEPT: Many vulnerabilities exist in how parsers handle malformed file structures.
By corrupting headers, tags, and length fields, we can find parser bugs that might
lead to crashes, buffer overflows, or other security issues.
"""

import random

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class StructureFuzzer:
    """Fuzzes the underlying DICOM file structure.

    CONCEPT: DICOM files have a specific binary structure:
    - File preamble (128 bytes)
    - DICOM prefix "DICM" (4 bytes)
    - Data elements with tags, VRs, and lengths

    WHY: Attackers often target parser logic, not just data validation.
    Testing structure corruption helps find critical parsing vulnerabilities.
    """

    def __init__(self) -> None:
        """Initialize the structure fuzzer with attack patterns."""
        self.corruption_strategies = [
            self._corrupt_tag_ordering,
            self._corrupt_length_fields,
            self._insert_unexpected_tags,
            self._duplicate_tags,
        ]

    def mutate_structure(self, dataset: Dataset) -> Dataset:
        """Apply structure-level mutations to the dataset.

        CONCEPT: We randomly select corruption strategies to apply.
        Each strategy targets a different aspect of DICOM structure.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with structure corruptions

        """
        # Randomly select 1-2 corruption strategies to apply
        num_strategies = random.randint(1, 2)
        selected_strategies = random.sample(self.corruption_strategies, num_strategies)

        for strategy in selected_strategies:
            dataset = strategy(dataset)

        return dataset

    def _corrupt_tag_ordering(self, dataset: Dataset) -> Dataset:
        """Corrupt the ordering of DICOM tags.

        CONCEPT: DICOM tags should be in ascending numerical order.
        Breaking this order can expose parser assumptions and bugs.

        SECURITY: Some parsers crash or behave unexpectedly when tags
        are out of order, potentially leading to exploitable conditions.

        Args:
            dataset: Dataset to corrupt

        Returns:
            Dataset with potentially scrambled tag order

        """
        # Get all data elements as a list
        elements = list(dataset.items())

        if len(elements) > 2:
            # Swap two random elements to break ordering
            idx1, idx2 = random.sample(range(len(elements)), 2)
            elements[idx1], elements[idx2] = elements[idx2], elements[idx1]

            # Rebuild dataset with corrupted order
            new_dataset = Dataset()
            if hasattr(dataset, "file_meta"):
                new_dataset.file_meta = dataset.file_meta
            for tag, element in elements:
                new_dataset[tag] = element

            return new_dataset

        return dataset

    def _corrupt_length_fields(self, dataset: Dataset) -> Dataset:
        """Corrupt length fields in DICOM data elements.

        CONCEPT: Each DICOM element has a length field indicating data size.
        Incorrect lengths can cause buffer overflows or out-of-bounds reads.

        SECURITY IMPACT:
        - Buffer overflow (length too large)
        - Integer overflow/underflow
        - Denial of service (parser loops indefinitely)

        Args:
            dataset: Dataset to corrupt

        Returns:
            Dataset with corrupted length indicators

        """
        # Target string-type elements for length corruption
        string_tags = [
            tag
            for tag, element in dataset.items()
            if hasattr(element, "VR")
            and element.VR in ["LO", "SH", "PN", "LT", "ST", "UT"]
        ]

        if string_tags:
            # Pick a random tag to corrupt
            target_tag = random.choice(string_tags)
            element = dataset[target_tag]

            # Apply length corruption strategy
            corruption_type = random.choice(["overflow", "underflow", "mismatch"])

            if corruption_type == "overflow":
                # Make value much longer than declared (buffer overflow test)
                element.value = str(element.value) + ("X" * 10000)
            elif corruption_type == "underflow":
                # Make value very short (underflow test)
                element.value = ""
            elif corruption_type == "mismatch":
                # Add null bytes in the middle (length mismatch)
                current_value = str(element.value)
                if len(current_value) > 2:
                    insert_pos = len(current_value) // 2
                    element.value = (
                        current_value[:insert_pos]
                        + "\x00" * 5
                        + current_value[insert_pos:]
                    )

        return dataset

    def _insert_unexpected_tags(self, dataset: Dataset) -> Dataset:
        """Insert unexpected or reserved DICOM tags.

        CONCEPT: DICOM has reserved tag ranges and private tags.
        Inserting unusual tags tests parser robustness.

        SECURITY: Parsers may not validate private or unknown tags,
        potentially leading to injection attacks or memory corruption.

        Args:
            dataset: Dataset to modify

        Returns:
            Dataset with unexpected tags inserted

        """
        # Define some problematic tag values
        unusual_tags = [
            0xFFFFFFFF,  # Maximum tag value (invalid)
            0x00000000,  # Minimum tag value
            0xDEADBEEF,  # Arbitrary private tag
            0x7FE00010,  # Pixel Data tag (duplicate if already exists)
        ]

        # Insert 1-2 unusual tags
        num_tags = random.randint(1, 2)
        for _ in range(num_tags):
            tag = random.choice(unusual_tags)
            try:
                # Try to add the unusual tag with garbage data
                dataset.add_new(tag, "UN", b"\x00" * 100)
            except Exception as e:
                # If it fails, that's fine - some tags can't be added
                logger.debug(f"Failed to add unusual tag {tag}: {e}")

        return dataset

    def _duplicate_tags(self, dataset: Dataset) -> Dataset:
        """Create duplicate DICOM tags.

        CONCEPT: DICOM specification says each tag should appear once.
        Duplicates test parser handling of malformed files.

        SECURITY: Parsers might use first occurrence, last occurrence,
        or crash. This can lead to security bypasses or DoS.

        Args:
            dataset: Dataset to modify

        Returns:
            Dataset with duplicated tags

        """
        # Get existing tags
        existing_tags = list(dataset.keys())

        if existing_tags:
            # Pick a random tag to duplicate
            tag_to_duplicate = random.choice(existing_tags)

            try:
                # Get the original element
                original_element = dataset[tag_to_duplicate]

                # Try to add it again with different value
                # Note: pydicom may prevent this, but we try anyway
                if hasattr(original_element, "value"):
                    # Modify the value slightly
                    new_value = str(original_element.value) + "_DUPLICATE"
                    dataset.add_new(tag_to_duplicate, original_element.VR, new_value)
            except Exception as e:
                # If duplication fails, continue
                logger.debug(f"Failed to duplicate tag {tag_to_duplicate}: {e}")

        return dataset

    def corrupt_file_header(
        self, file_path: str, output_path: str | None = None
    ) -> str | None:
        """Directly corrupt the DICOM file header at binary level.

        CONCEPT: This operates on the raw file bytes, not the parsed dataset.
        It can corrupt the file preamble, DICM prefix, or transfer syntax.

        SECURITY IMPACT: Critical - can bypass all high-level validation
        and directly attack the parser's binary reading logic.

        Args:
            file_path: Path to input DICOM file
            output_path: Path for corrupted output (or auto-generate)

        Returns:
            Path to corrupted file, or None on failure

        """
        try:
            # Read the entire file as binary
            with open(file_path, "rb") as f:
                file_data = bytearray(f.read())

            # Apply binary corruptions
            corruption_type = random.choice(
                [
                    "corrupt_preamble",
                    "corrupt_dicm_prefix",
                    "corrupt_transfer_syntax",
                    "truncate_file",
                ]
            )

            if corruption_type == "corrupt_preamble":
                # Corrupt the 128-byte preamble
                if len(file_data) >= 128:
                    for _ in range(10):
                        pos = random.randint(0, 127)
                        file_data[pos] = random.randint(0, 255)

            elif corruption_type == "corrupt_dicm_prefix":
                # Corrupt the "DICM" prefix at bytes 128-131
                if len(file_data) >= 132:
                    file_data[128:132] = b"XXXX"

            elif corruption_type == "corrupt_transfer_syntax":
                # Corrupt transfer syntax UID (if we can find it)
                # This is a simplistic approach - just corrupt random bytes
                if len(file_data) >= 200:
                    for _ in range(5):
                        pos = random.randint(132, min(200, len(file_data) - 1))
                        file_data[pos] = random.randint(0, 255)

            elif corruption_type == "truncate_file":
                # Truncate file at random position (simulates incomplete transfer)
                if len(file_data) > 1000:
                    truncate_pos = random.randint(500, len(file_data) - 1)
                    file_data = file_data[:truncate_pos]

            # Write corrupted file
            if output_path is None:
                output_path = file_path.replace(".dcm", "_header_corrupted.dcm")

            with open(output_path, "wb") as f:
                f.write(file_data)

            return output_path

        except Exception as e:
            print(f"Header corruption failed: {e}")
            return None

"""Dictionary-Based DICOM Fuzzing Strategy

LEARNING OBJECTIVE: This module demonstrates dictionary-based fuzzing - using
domain knowledge to generate intelligent mutations.

CONCEPT: Instead of random bit flips, we replace DICOM values with values from
our dictionaries. This helps us:
1. Bypass input validation (values look valid)
2. Reach deeper code paths
3. Test edge cases systematically

WHY: Dictionary-based fuzzing is 10-100x more effective than random fuzzing for
complex formats like DICOM because it produces inputs that look valid but have
subtle problems.

This is called "smart fuzzing" or "grammar-aware fuzzing".
"""

import copy
import random

from pydicom.dataset import Dataset

from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.utils.dicom_dictionaries import DICOMDictionaries
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class DictionaryFuzzer:
    """Dictionary-based fuzzing strategy for DICOM files.

    LEARNING: This fuzzer knows about DICOM - it understands what values
    should go in which tags and can intelligently substitute malicious but
    valid-looking values.

    CONCEPT: We maintain a mapping of DICOM tags to appropriate dictionaries,
    then systematically replace values with dictionary entries.

    WHY: This finds bugs that random fuzzing misses because our inputs pass
    validation but still trigger edge cases.
    """

    # Mapping of DICOM tags to appropriate dictionaries
    # CONCEPT: Each DICOM tag has specific valid values. We know which dictionary
    # to use for each tag to generate realistic mutations.
    TAG_TO_DICTIONARY: dict[int, str] = {
        0x00080016: "sop_class_uids",  # SOP Class UID
        0x00080018: "sop_class_uids",  # SOP Instance UID (reuse class UIDs)
        0x00020010: "transfer_syntaxes",  # Transfer Syntax UID
        0x00080060: "modalities",  # Modality
        0x00100040: "patient_sex",  # Patient's Sex
        0x00080080: "institutions",  # Institution Name
        0x00080070: "manufacturers",  # Manufacturer
        0x00280004: "photometric_interpretations",  # Photometric Interpretation
        0x00080020: "dates",  # Study Date
        0x00080021: "dates",  # Series Date
        0x00080030: "times",  # Study Time
        0x00080031: "times",  # Series Time
        0x00100010: "patient_names",  # Patient's Name
        0x00081030: "study_descriptions",  # Study Description
        0x00080050: "accession_numbers",  # Accession Number
        0x00100020: "patient_ids",  # Patient ID
        0x00280030: "pixel_spacings",  # Pixel Spacing
        0x00281050: "window_centers",  # Window Center
        0x00281051: "window_widths",  # Window Width
        0x00080005: "character_sets",  # Specific Character Set
    }

    # Tags that should have UID-like values
    UID_TAGS = {
        0x00020003,  # Media Storage SOP Instance UID
        0x00080016,  # SOP Class UID
        0x00080018,  # SOP Instance UID
        0x0020000D,  # Study Instance UID
        0x0020000E,  # Series Instance UID
        0x00200052,  # Frame of Reference UID
        0x00080058,  # Failed SOP Instance UID List
    }

    # VR types that require binary data (skip mutation)
    _BINARY_VRS = frozenset({"OB", "OW", "OD", "OF", "OL", "OV", "UN"})

    # Integer VR types with their valid ranges: (min, max, wrap_or_clamp)
    # wrap_or_clamp: "wrap" = modulo, "clamp" = min/max
    _INT_VR_RANGES: dict[str, tuple[int, int, str]] = {
        "US": (0, 65535, "wrap"),
        "SS": (-32768, 32767, "clamp"),
        "UL": (0, 4294967295, "wrap"),
        "SL": (-2147483648, 2147483647, "clamp"),
    }

    def __init__(self) -> None:
        """Initialize the dictionary fuzzer."""
        self.dictionaries = DICOMDictionaries()
        self.edge_cases = DICOMDictionaries.get_edge_cases()
        self.malicious_values = DICOMDictionaries.get_malicious_values()

        logger.info(
            "Dictionary fuzzer initialized",
            dictionaries=len(DICOMDictionaries.ALL_DICTIONARIES),
            edge_cases=len(self.edge_cases),
        )

    def mutate(
        self, dataset: Dataset, severity: MutationSeverity = MutationSeverity.MODERATE
    ) -> Dataset:
        """Apply dictionary-based mutations to a DICOM dataset.

        CONCEPT: Based on severity, we apply different mutation strategies:
        - MINIMAL: Replace with valid dictionary values
        - MODERATE: Mix valid values with edge cases
        - AGGRESSIVE: Use edge cases and malicious values
        - EXTREME: Purely malicious values and format violations

        Args:
            dataset: DICOM dataset to mutate
            severity: Mutation severity level

        Returns:
            Mutated dataset

        """
        mutated = copy.deepcopy(dataset)

        # Determine number of mutations based on severity
        num_mutations = self._get_num_mutations(severity, len(dataset))

        # Select tags to mutate
        available_tags = [tag for tag in dataset.keys() if tag in mutated]
        if not available_tags:
            return mutated

        tags_to_mutate = random.sample(
            available_tags, min(num_mutations, len(available_tags))
        )

        # Apply mutations
        for tag in tags_to_mutate:
            self._mutate_tag(mutated, tag, severity)

        logger.debug(
            "Applied dictionary mutations",
            num_mutations=len(tags_to_mutate),
            severity=severity.value,
        )

        return mutated

    def _get_value_for_severity(
        self, tag_int: int, severity: MutationSeverity
    ) -> str | int | float:
        """Get a mutation value based on severity level."""
        if severity == MutationSeverity.MINIMAL:
            return self._get_valid_value(tag_int)
        elif severity == MutationSeverity.MODERATE:
            if random.random() < 0.7:
                return self._get_valid_value(tag_int)
            return self._get_edge_case_value()
        elif severity == MutationSeverity.AGGRESSIVE:
            if random.random() < 0.5:
                return self._get_edge_case_value()
            return self._get_malicious_value()
        return self._get_malicious_value()  # EXTREME

    def _convert_to_int_vr(self, value: str, vr: str) -> int:
        """Convert string value to integer for integer VR types."""
        if not value.replace(".", "").replace("-", "").isdigit():
            return 0
        int_value = int(float(value))
        min_val, max_val, mode = self._INT_VR_RANGES[vr]
        if min_val <= int_value <= max_val:
            return int_value
        if mode == "wrap":
            return abs(int_value) % (max_val + 1)
        return max(min_val, min(max_val, int_value))  # clamp

    def _convert_to_float_vr(self, value: str) -> float:
        """Convert string value to float for FL/FD VR types."""
        str_value = str(value)
        cleaned = str_value.replace(".", "").replace("-", "")
        cleaned = cleaned.replace("e", "").replace("E", "")
        return float(str_value) if cleaned.isdigit() else 0.0

    def _convert_to_string_vr(self, value: str) -> str:
        """Convert string value to numeric string for IS/DS VR types."""
        str_value = str(value)
        if str_value.replace(".", "").replace("-", "").isdigit():
            return str(float(str_value))
        return "0.0"

    def _convert_numeric_value(
        self, value: str, vr: str, tag: int
    ) -> str | int | float | None:
        """Convert string value to appropriate numeric type for VR."""
        try:
            if vr in self._INT_VR_RANGES:
                return self._convert_to_int_vr(value, vr)
            elif vr in {"FL", "FD"}:
                return self._convert_to_float_vr(value)
            elif vr in {"IS", "DS"}:
                return self._convert_to_string_vr(value)
            elif vr == "AT":
                logger.debug(f"Skipping mutation of AT tag {tag:08X}")
                return None
            return value
        except (ValueError, AttributeError):
            logger.debug(f"Skipped tag {tag:08X}: cannot convert '{value}' to {vr}")
            return None

    def _mutate_tag(
        self, dataset: Dataset, tag: int, severity: MutationSeverity
    ) -> None:
        """Mutate a specific tag using dictionary values."""
        tag_int = int(tag)
        value: str | int | float = self._get_value_for_severity(tag_int, severity)

        try:
            vr = dataset[tag].VR

            # Skip binary VR types
            if vr in self._BINARY_VRS:
                logger.debug(f"Skipping mutation of binary VR tag {tag:08X} (VR={vr})")
                return

            # Handle UI (Unique Identifier) VR specially
            if vr == "UI":
                root = random.choice(DICOMDictionaries.get_dictionary("uid_roots"))
                value = DICOMDictionaries.generate_random_uid(root)
                dataset[tag].value = value
                logger.debug(f"Mutated UI tag {tag:08X}", new_value=str(value)[:50])
                return

            # Convert string values to appropriate numeric types
            numeric_vrs = {"US", "SS", "UL", "SL", "IS", "DS", "FL", "FD", "AT"}
            if vr in numeric_vrs and isinstance(value, str):
                converted = self._convert_numeric_value(value, vr, tag)
                if converted is None:
                    return
                value = converted

            dataset[tag].value = value
            logger.debug(f"Mutated tag {tag:08X}", new_value=str(value)[:50])
        except Exception as e:
            logger.debug(f"Failed to mutate tag {tag:08X}: {e}")

    def _get_valid_value(self, tag: int) -> str:
        """Get a valid value for a tag from dictionaries.

        CONCEPT: We look up which dictionary is appropriate for this tag
        and return a random value from it.

        Args:
            tag: DICOM tag

        Returns:
            Valid dictionary value

        """
        # Check if this is a UID tag
        if tag in self.UID_TAGS:
            root = random.choice(DICOMDictionaries.get_dictionary("uid_roots"))
            return DICOMDictionaries.generate_random_uid(root)

        # Check if we have a specific dictionary for this tag
        if tag in self.TAG_TO_DICTIONARY:
            dict_name = self.TAG_TO_DICTIONARY[tag]
            return DICOMDictionaries.get_random_value(dict_name)

        # Default: return a random value from a random dictionary
        dict_name = random.choice(DICOMDictionaries.get_all_dictionary_names())
        return DICOMDictionaries.get_random_value(dict_name)

    def _get_edge_case_value(self) -> str:
        """Get an edge case value.

        CONCEPT: Edge cases are values that often cause problems:
        - Empty strings
        - Very long strings
        - Special characters
        - Null bytes

        Returns:
            Edge case value

        """
        category = random.choice(list(self.edge_cases.keys()))
        values = self.edge_cases[category]
        return random.choice(values)

    def _get_malicious_value(self) -> str:
        """Get a malicious value designed to trigger vulnerabilities.

        CONCEPT: These values specifically target common vulnerability types:
        - Buffer overflows
        - SQL injection
        - Command injection
        - Format string attacks

        Returns:
            Malicious value

        """
        category = random.choice(list(self.malicious_values.keys()))
        values = self.malicious_values[category]
        return random.choice(values)

    def _get_num_mutations(self, severity: MutationSeverity, dataset_size: int) -> int:
        """Determine how many mutations to apply based on severity.

        CONCEPT: More severe = more mutations

        Args:
            severity: Mutation severity
            dataset_size: Number of tags in dataset

        Returns:
            Number of mutations to apply

        """
        if severity == MutationSeverity.MINIMAL:
            return random.randint(1, max(2, dataset_size // 20))
        elif severity == MutationSeverity.MODERATE:
            return random.randint(2, max(5, dataset_size // 10))
        elif severity == MutationSeverity.AGGRESSIVE:
            return random.randint(5, max(10, dataset_size // 5))
        else:  # EXTREME
            return random.randint(10, max(20, dataset_size // 2))

    def get_strategy_name(self) -> str:
        """Get the strategy name."""
        return "dictionary"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can mutate the dataset.

        CONCEPT: Dictionary fuzzing works on any DICOM dataset.

        Args:
            dataset: Dataset to check

        Returns:
            True (always applicable)

        """
        return True

    def get_applicable_tags(self, dataset: Dataset) -> list[tuple[int, str]]:
        """Get tags that can be mutated with their dictionary names.

        CONCEPT: This helps with targeted fuzzing - we can see which tags
        we can intelligently mutate.

        Args:
            dataset: DICOM dataset

        Returns:
            List of (tag, dictionary_name) tuples

        """
        applicable = []

        for tag in dataset.keys():
            tag_int = int(tag)

            # Check if we have a specific dictionary for this tag
            if tag_int in self.TAG_TO_DICTIONARY:
                dict_name = self.TAG_TO_DICTIONARY[tag_int]
                applicable.append((tag_int, dict_name))
            elif tag_int in self.UID_TAGS:
                applicable.append((tag_int, "uid"))

        return applicable

    def mutate_with_specific_dictionary(
        self, dataset: Dataset, tag: int, dictionary_name: str
    ) -> Dataset:
        """Mutate a specific tag using a specific dictionary.

        CONCEPT: For targeted testing, we can specify exactly which
        dictionary to use for which tag.

        Args:
            dataset: Dataset to mutate
            tag: Tag to mutate
            dictionary_name: Name of dictionary to use

        Returns:
            Mutated dataset

        """
        mutated = copy.deepcopy(dataset)

        if tag not in mutated:
            logger.warning(f"Tag {tag:08X} not in dataset")
            return mutated

        # Get value from specified dictionary
        value = DICOMDictionaries.get_random_value(dictionary_name)

        try:
            mutated[tag].value = value
            logger.info(
                f"Mutated tag {tag:08X} with {dictionary_name} dictionary",
                value=str(value)[:50],
            )
        except Exception as e:
            logger.error(f"Failed to mutate tag {tag:08X}: {e}")

        return mutated

    def inject_edge_cases_systematically(
        self, dataset: Dataset, category: str
    ) -> list[Dataset]:
        """Generate multiple datasets by systematically injecting edge cases.

        CONCEPT: Instead of random injection, we systematically try each
        edge case in each tag. This ensures comprehensive coverage.

        Args:
            dataset: Base dataset
            category: Edge case category (e.g., 'empty', 'null_bytes')

        Returns:
            List of mutated datasets

        """
        if category not in self.edge_cases:
            logger.warning(f"Unknown edge case category: {category}")
            return []

        edge_values = self.edge_cases[category]
        mutated_datasets = []

        # Get mutable tags
        applicable_tags = [tag for tag in dataset.keys() if tag in dataset]

        # For each tag, try each edge case value
        for tag in applicable_tags:
            for edge_value in edge_values:
                mutated = copy.deepcopy(dataset)
                try:
                    mutated[tag].value = edge_value
                    mutated_datasets.append(mutated)
                except Exception:
                    # Some mutations might fail, that's OK
                    pass

        logger.info(
            f"Generated {len(mutated_datasets)} systematic mutations",
            category=category,
            tags=len(applicable_tags),
            edge_values=len(edge_values),
        )

        return mutated_datasets

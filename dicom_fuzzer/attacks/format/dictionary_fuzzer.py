"""Dictionary-Based DICOM Fuzzing Strategy.

Category: generic

Uses domain knowledge to generate intelligent mutations by replacing DICOM
values with entries from curated dictionaries. This produces inputs that
pass initial validation but may trigger edge cases in deeper code paths.
"""

from __future__ import annotations

import copy
import random

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase
from .dicom_dictionaries import DICOMDictionaries

logger = get_logger(__name__)


class DictionaryFuzzer(FormatFuzzerBase):
    """Dictionary-based fuzzing strategy for DICOM files.

    Maps DICOM tags to appropriate value dictionaries and systematically
    replaces field values with dictionary entries. This produces inputs
    that pass validation but trigger edge cases.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "dictionary"

    # Mapping of DICOM tags to appropriate dictionaries for realistic mutations
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

    # Numeric VR types that need string-to-number conversion
    _NUMERIC_VRS = frozenset({"US", "SS", "UL", "SL", "IS", "DS", "FL", "FD", "AT"})

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
        super().__init__()
        self.edge_cases = DICOMDictionaries.get_edge_cases()

        logger.info(
            "Dictionary fuzzer initialized",
            dictionaries=len(DICOMDictionaries.ALL_DICTIONARIES),
            edge_cases=len(self.edge_cases),
        )

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply dictionary-based mutations to a DICOM dataset.

        Replaces 2-5 tag values (~10% of dataset) with a mix of valid
        dictionary values (70%) and edge cases (30%). This produces files
        that slip past basic validation but trigger deeper parser bugs.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        mutated = copy.deepcopy(dataset)

        num_mutations = self._get_num_mutations(len(dataset))

        # Select tags to mutate
        available_tags = list(dataset.keys())
        if not available_tags:
            return mutated

        tags_to_mutate = random.sample(
            available_tags, min(num_mutations, len(available_tags))
        )

        # Apply mutations
        for tag in tags_to_mutate:
            self._mutate_tag(mutated, tag)

        logger.debug(
            "Applied dictionary mutations",
            num_mutations=len(tags_to_mutate),
        )

        return mutated

    def _get_mutation_value(self, tag_int: int) -> str | int | float:
        """Get a mutation value: 70% valid dictionary values, 30% edge cases.

        Valid values are realistic-but-wrong (e.g., swapping "CT" for "MR").
        Edge cases are tricky strings (empty, overlong, null bytes, special chars).
        This mix produces files that pass initial validation but stress deeper code.
        """
        if random.random() < 0.7:
            return self._get_valid_value(tag_int)
        return self._get_edge_case_value()

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

    def _mutate_tag(self, dataset: Dataset, tag: int) -> None:
        """Mutate a specific tag using dictionary values."""
        tag_int = int(tag)
        value: str | int | float = self._get_mutation_value(tag_int)

        try:
            vr = dataset[tag].VR

            # Skip binary VR types
            if vr in self._BINARY_VRS:
                logger.debug(f"Skipping mutation of binary VR tag {tag:08X} (VR={vr})")
                return

            # Handle UI (Unique Identifier) VR specially
            if vr == "UI":
                if tag_int in self.TAG_TO_DICTIONARY:
                    # Use specific dictionary (e.g., transfer syntaxes, SOP class UIDs)
                    value = DICOMDictionaries.get_random_value(
                        self.TAG_TO_DICTIONARY[tag_int]
                    )
                else:
                    root = random.choice(DICOMDictionaries.get_dictionary("uid_roots"))
                    value = DICOMDictionaries.generate_random_uid(root)
                dataset[tag].value = value
                logger.debug(f"Mutated UI tag {tag:08X}", new_value=str(value)[:50])
                return

            # Convert string values to appropriate numeric types
            if vr in self._NUMERIC_VRS and isinstance(value, str):
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
        """Get an edge case value (empty, long, special chars, null bytes).

        Returns:
            Edge case value

        """
        category = random.choice(list(self.edge_cases.keys()))
        values = self.edge_cases[category]
        return random.choice(values)

    def _get_num_mutations(self, dataset_size: int) -> int:
        """Determine how many tags to mutate.

        Mutates ~10% of the dataset (2-5 tags minimum). This is enough
        to inject meaningful corruption without making the file so broken
        that it fails at the parser level before reaching deeper code.

        Args:
            dataset_size: Number of tags in dataset

        Returns:
            Number of mutations to apply

        """
        return random.randint(2, max(5, dataset_size // 10))

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can mutate the dataset.

        Args:
            dataset: Dataset to check

        Returns:
            True (always applicable)

        """
        return True

    def get_applicable_tags(self, dataset: Dataset) -> list[tuple[int, str]]:
        """Get tags that can be mutated with their dictionary names.

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

        Tries each edge case in each tag for comprehensive coverage.

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
        applicable_tags = list(dataset.keys())

        # For each tag, try each edge case value
        for tag in applicable_tags:
            for edge_value in edge_values:
                mutated = copy.deepcopy(dataset)
                try:
                    mutated[tag].value = edge_value
                    mutated_datasets.append(mutated)
                except Exception as e:
                    logger.debug("Edge case mutation failed for tag %08X: %s", tag, e)

        logger.info(
            f"Generated {len(mutated_datasets)} systematic mutations",
            category=category,
            tags=len(applicable_tags),
            edge_values=len(edge_values),
        )

        return mutated_datasets

"""Grammar-Based DICOM Fuzzer - Advanced Mutation Engine.

Uses knowledge of DICOM structure and rules to create intelligent mutations.
Violates specific rules to find logic errors, parser bugs, and assumption
violations that random fuzzing misses.
"""

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class DicomGrammarRule:
    """Represents a DICOM grammar rule.

    CONCEPT: DICOM has many implicit rules:
    - Required tags for specific SOP Classes
    - Valid value ranges for specific VRs
    - Tag dependencies (tag A requires tag B)
    - Conditional requirements (if X, then Y must be present)
    """

    def __init__(
        self,
        rule_name: str,
        tags_involved: list[str],
        rule_type: str,
        description: str,
    ):
        """Initialize a grammar rule.

        Args:
            rule_name: Name of the rule
            tags_involved: List of DICOM tag keywords involved
            rule_type: Type of rule (required, conditional, range, etc.)
            description: Human-readable description

        """
        self.rule_name = rule_name
        self.tags_involved = tags_involved
        self.rule_type = rule_type
        self.description = description


class GrammarFuzzer:
    """Grammar-based DICOM fuzzer.

    CONCEPT: Uses knowledge of DICOM structure to create intelligent mutations
    that violate specific rules while maintaining syntactic validity.

    SECURITY: Tests parsers' handling of:
    - Missing conditionally required tags
    - Invalid tag combinations
    - Semantic inconsistencies
    - State machine violations
    """

    def __init__(self) -> None:
        """Initialize grammar fuzzer with DICOM rules."""
        self.rules = self._load_dicom_rules()
        self.sop_class_requirements = self._load_sop_class_requirements()

    def _load_dicom_rules(self) -> list[DicomGrammarRule]:
        """Load DICOM grammar rules.

        CONCEPT: These rules encode DICOM standard requirements.
        In production, this would load from DICOM specification files.

        Returns:
            List of grammar rules

        """
        rules = []

        # Rule 1: Patient-level required tags
        rules.append(
            DicomGrammarRule(
                rule_name="patient_required",
                tags_involved=["PatientName", "PatientID"],
                rule_type="required",
                description="Patient Name and ID are required for all images",
            )
        )

        # Rule 2: Study-level required tags
        rules.append(
            DicomGrammarRule(
                rule_name="study_required",
                tags_involved=["StudyInstanceUID", "StudyDate", "StudyTime"],
                rule_type="required",
                description="Study identification tags are required",
            )
        )

        # Rule 3: Series-level required tags
        rules.append(
            DicomGrammarRule(
                rule_name="series_required",
                tags_involved=["SeriesInstanceUID", "SeriesNumber", "Modality"],
                rule_type="required",
                description="Series identification tags are required",
            )
        )

        # Rule 4: Image-level required tags
        rules.append(
            DicomGrammarRule(
                rule_name="image_required",
                tags_involved=["SOPInstanceUID", "SOPClassUID", "InstanceNumber"],
                rule_type="required",
                description="Image identification tags are required",
            )
        )

        # Rule 5: Pixel data dependencies
        rules.append(
            DicomGrammarRule(
                rule_name="pixel_dependencies",
                tags_involved=[
                    "PixelData",
                    "Rows",
                    "Columns",
                    "BitsAllocated",
                    "SamplesPerPixel",
                ],
                rule_type="conditional",
                description="If PixelData exists, image description tags required",
            )
        )

        # Rule 6: CT-specific tags
        rules.append(
            DicomGrammarRule(
                rule_name="ct_specific",
                tags_involved=[
                    "Modality",
                    "SliceThickness",
                    "KVP",
                    "DataCollectionDiameter",
                ],
                rule_type="conditional",
                description="CT images require specific technical parameters",
            )
        )

        return rules

    def _load_sop_class_requirements(self) -> dict[str, set[str]]:
        """Load SOP Class specific requirements.

        CONCEPT: Different DICOM SOP Classes (CT, MR, US, etc.)
        have different required tags. This encodes those rules.

        Returns:
            Dictionary mapping SOP Class UIDs to required tags

        """
        return {
            # CT Image Storage
            "1.2.840.10008.5.1.4.1.1.2": {
                "ImageType",
                "SOPClassUID",
                "SOPInstanceUID",
                "StudyDate",
                "SeriesDate",
                "AcquisitionDate",
                "ContentDate",
                "Modality",
                "PatientName",
                "PatientID",
                "StudyInstanceUID",
                "SeriesInstanceUID",
                "StudyID",
                "SeriesNumber",
                "InstanceNumber",
                "Rows",
                "Columns",
                "PixelData",
            },
            # MR Image Storage
            "1.2.840.10008.5.1.4.1.1.4": {
                "ImageType",
                "SOPClassUID",
                "SOPInstanceUID",
                "Modality",
                "PatientName",
                "PatientID",
                "ScanningSequence",
                "SequenceVariant",
                "ScanOptions",
                "MRAcquisitionType",
            },
        }

    def violate_required_tags(self, dataset: Dataset) -> Dataset:
        """Violate required tag rules.

        CONCEPT: Remove or corrupt tags that DICOM says are required.
        Tests parser error handling for missing required elements.

        SECURITY: Many parsers assume required tags exist,
        leading to null pointer dereferences or crashes.

        Args:
            dataset: Dataset to mutate

        Returns:
            Mutated dataset with missing required tags

        """
        # Find applicable rules
        for rule in self.rules:
            if rule.rule_type == "required":
                # Randomly remove one tag from this rule
                import random

                if random.random() > 0.5:  # 50% chance
                    for tag in rule.tags_involved:
                        if hasattr(dataset, tag) and random.random() > 0.7:
                            delattr(dataset, tag)
                            break  # Remove one tag per rule

        return dataset

    def violate_conditional_rules(self, dataset: Dataset) -> Dataset:
        """Violate conditional dependency rules.

        CONCEPT: DICOM has "if X then Y" rules. For example:
        - If PixelData exists, Rows and Columns must exist
        - If Modality=CT, certain CT-specific tags must exist

        This creates test cases that violate these dependencies.

        Args:
            dataset: Dataset to mutate

        Returns:
            Mutated dataset with violated dependencies

        """
        import random

        # If PixelData exists, remove required image description tags
        if hasattr(dataset, "PixelData"):
            tags_to_remove = ["Rows", "Columns", "BitsAllocated", "SamplesPerPixel"]
            tag_to_remove = random.choice(tags_to_remove)
            if hasattr(dataset, tag_to_remove):
                delattr(dataset, tag_to_remove)

        # If Modality=CT, remove CT-specific tags
        if hasattr(dataset, "Modality") and dataset.Modality == "CT":
            ct_tags = ["SliceThickness", "KVP", "DataCollectionDiameter"]
            for tag in ct_tags:
                if hasattr(dataset, tag) and random.random() > 0.7:
                    delattr(dataset, tag)

        return dataset

    def create_inconsistent_state(self, dataset: Dataset) -> Dataset:
        """Create semantically inconsistent but syntactically valid data.

        CONCEPT: The data follows DICOM syntax rules but makes no sense:
        - Rows=10 but pixel data is 1MB
        - BitsAllocated=8 but pixel values are 16-bit
        - StudyDate is in the future
        - Patient age is negative

        SECURITY: Tests application logic, not just parser correctness.

        Args:
            dataset: Dataset to mutate

        Returns:
            Dataset with inconsistent state

        """
        from datetime import datetime, timedelta

        # Inconsistent image dimensions
        if hasattr(dataset, "Rows") and hasattr(dataset, "Columns"):
            # Set very small dimensions but don't change pixel data size
            dataset.Rows = 1
            dataset.Columns = 1
            # This creates mismatch: says 1x1 but pixel data is much larger

        # Future dates
        if hasattr(dataset, "StudyDate"):
            future_date = datetime.now() + timedelta(days=365 * 10)  # 10 years ahead
            dataset.StudyDate = future_date.strftime("%Y%m%d")

        # Negative or impossible values
        if hasattr(dataset, "SeriesNumber"):
            dataset.SeriesNumber = -999

        if hasattr(dataset, "PatientAge"):
            dataset.PatientAge = "999Y"  # 999 years old

        # Bit depth inconsistencies
        if hasattr(dataset, "BitsAllocated"):
            # Say 8-bit but values might be 16-bit
            dataset.BitsAllocated = 8
            if hasattr(dataset, "BitsStored"):
                dataset.BitsStored = 16  # Inconsistent!

        return dataset

    def violate_value_constraints(self, dataset: Dataset) -> Dataset:
        """Violate VR-specific value constraints.

        CONCEPT: Each DICOM VR has specific value constraints:
        - DA (Date): Must be YYYYMMDD
        - TM (Time): Must be HHMMSS
        - UI (UID): Must be valid UID format
        - IS/DS: Must be numeric strings

        Create values that violate these constraints.

        NOTE: Some constraints are enforced by pydicom during assignment.
        We attempt to set invalid values, but pydicom may reject them
        with ValueError. This is expected - we're testing edge cases.

        Args:
            dataset: Dataset to mutate

        Returns:
            Dataset with invalid VR values (where pydicom allows)

        """
        import random

        # Invalid UIDs
        if hasattr(dataset, "StudyInstanceUID"):
            try:
                # UIDs must be dot-separated numbers, max 64 chars
                invalid_uids = [
                    "invalid-uid-with-dashes",  # Wrong format
                    "1.2.3." + "9" * 100,  # Too long (>64 chars)
                    "1.2.abc.4",  # Contains letters
                    "",  # Empty
                ]
                dataset.StudyInstanceUID = random.choice(invalid_uids)
            except (ValueError, TypeError):
                # Pydicom rejected the invalid value, which is fine
                pass

        # Invalid numeric strings
        if hasattr(dataset, "SeriesNumber"):
            try:
                # IS (Integer String) must be numeric
                # Pydicom validates this and will raise ValueError
                dataset.SeriesNumber = "not-a-number"
            except (ValueError, TypeError):
                # Expected: pydicom validates IS values immediately
                # Try a less invalid but still problematic value
                try:
                    dataset.SeriesNumber = 999999999  # Very large number
                except (ValueError, TypeError) as fallback_err:
                    # Fallback also rejected, continue with other mutations
                    logger.debug(f"SeriesNumber mutation rejected: {fallback_err}")

        if hasattr(dataset, "SliceThickness"):
            try:
                # DS (Decimal String) must be numeric
                # Pydicom validates this and will raise ValueError
                dataset.SliceThickness = "invalid.decimal.format"
            except (ValueError, TypeError):
                # Expected: pydicom validates DS values immediately
                # Try a less invalid but still problematic value
                try:
                    dataset.SliceThickness = "999999.999999"  # Very large decimal
                except (ValueError, TypeError) as fallback_err:
                    # Fallback also rejected, continue with other mutations
                    logger.debug(f"SliceThickness mutation rejected: {fallback_err}")

        return dataset

    def apply_grammar_based_mutation(
        self, dataset: Dataset, mutation_type: str | None = None
    ) -> Dataset:
        """Apply grammar-based mutation to dataset.

        Args:
            dataset: Dataset to mutate
            mutation_type: Specific mutation type or None for random

        Returns:
            Mutated dataset

        """
        import random

        if mutation_type is None:
            mutation_types = [
                "required_tags",
                "conditional_rules",
                "inconsistent_state",
                "value_constraints",
            ]
            mutation_type = random.choice(mutation_types)

        dataset_copy = dataset.copy()

        if mutation_type == "required_tags":
            return self.violate_required_tags(dataset_copy)
        elif mutation_type == "conditional_rules":
            return self.violate_conditional_rules(dataset_copy)
        elif mutation_type == "inconsistent_state":
            return self.create_inconsistent_state(dataset_copy)
        elif mutation_type == "value_constraints":
            return self.violate_value_constraints(dataset_copy)
        else:
            return dataset_copy

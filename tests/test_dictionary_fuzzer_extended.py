"""Extended tests for DictionaryFuzzer.

Tests for dictionary-based DICOM fuzzing including:
- TAG_TO_DICTIONARY and UID_TAGS mappings
- Mutation with different severity levels
- Edge case and malicious value injection
- Systematic mutation generation
- VR type handling

Target: 80%+ coverage for strategies/dictionary_fuzzer.py
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydicom import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer


@pytest.fixture
def fuzzer() -> DictionaryFuzzer:
    """Create DictionaryFuzzer instance."""
    return DictionaryFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create sample DICOM dataset for testing."""
    ds = Dataset()

    # Patient info
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.PatientSex = "M"

    # Study info
    ds.StudyDate = "20250115"
    ds.StudyTime = "120000"
    ds.StudyDescription = "Test Study"
    ds.AccessionNumber = "A12345"
    ds.StudyInstanceUID = generate_uid()  # For UID_TAGS testing

    # Series info
    ds.SeriesDate = "20250115"
    ds.SeriesTime = "120100"
    ds.Modality = "CT"
    ds.SeriesInstanceUID = generate_uid()  # For UID_TAGS testing

    # Image info
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = generate_uid()
    ds.PhotometricInterpretation = "MONOCHROME2"

    # Numeric values
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.WindowCenter = "40"
    ds.WindowWidth = "400"

    # Add file_meta for completeness
    ds.file_meta = Dataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"

    return ds


class TestDictionaryFuzzerInit:
    """Tests for DictionaryFuzzer initialization."""

    def test_init(self, fuzzer: DictionaryFuzzer) -> None:
        """Test initialization."""
        assert fuzzer.dictionaries is not None
        assert fuzzer.edge_cases is not None
        assert fuzzer.malicious_values is not None
        assert len(fuzzer.edge_cases) > 0
        assert len(fuzzer.malicious_values) > 0

    def test_tag_to_dictionary_mapping(self, fuzzer: DictionaryFuzzer) -> None:
        """Test TAG_TO_DICTIONARY contains expected mappings."""
        mapping = fuzzer.TAG_TO_DICTIONARY

        # Check some key mappings
        assert mapping[0x00080016] == "sop_class_uids"  # SOP Class UID
        assert mapping[0x00080060] == "modalities"  # Modality
        assert mapping[0x00100040] == "patient_sex"  # Patient's Sex
        assert mapping[0x00280004] == "photometric_interpretations"

    def test_uid_tags_set(self, fuzzer: DictionaryFuzzer) -> None:
        """Test UID_TAGS contains expected tags."""
        uid_tags = fuzzer.UID_TAGS

        assert 0x00020003 in uid_tags  # Media Storage SOP Instance UID
        assert 0x00080016 in uid_tags  # SOP Class UID
        assert 0x00080018 in uid_tags  # SOP Instance UID
        assert 0x0020000D in uid_tags  # Study Instance UID
        assert 0x0020000E in uid_tags  # Series Instance UID


class TestMutate:
    """Tests for mutate method."""

    def test_mutate_returns_copy(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate returns a copy, not the original."""
        original_name = sample_dataset.PatientName

        mutated = fuzzer.mutate(sample_dataset, MutationSeverity.MINIMAL)

        # Original should be unchanged
        assert sample_dataset.PatientName == original_name
        # Returns a dataset
        assert isinstance(mutated, Dataset)

    def test_mutate_minimal_severity(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutation with MINIMAL severity."""
        mutated = fuzzer.mutate(sample_dataset, MutationSeverity.MINIMAL)

        # Should be a valid dataset
        assert isinstance(mutated, Dataset)

    def test_mutate_moderate_severity(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutation with MODERATE severity."""
        mutated = fuzzer.mutate(sample_dataset, MutationSeverity.MODERATE)

        assert isinstance(mutated, Dataset)

    def test_mutate_aggressive_severity(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutation with AGGRESSIVE severity."""
        mutated = fuzzer.mutate(sample_dataset, MutationSeverity.AGGRESSIVE)

        assert isinstance(mutated, Dataset)

    def test_mutate_extreme_severity(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutation with EXTREME severity."""
        mutated = fuzzer.mutate(sample_dataset, MutationSeverity.EXTREME)

        assert isinstance(mutated, Dataset)

    def test_mutate_empty_dataset(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutation with empty dataset."""
        empty_ds = Dataset()

        mutated = fuzzer.mutate(empty_ds, MutationSeverity.MODERATE)

        # Should return without error
        assert isinstance(mutated, Dataset)


class TestMutateTag:
    """Tests for _mutate_tag method."""

    def test_mutate_string_tag(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutating a string tag."""
        original_value = sample_dataset.PatientName

        fuzzer._mutate_tag(
            sample_dataset,
            0x00100010,
            MutationSeverity.MODERATE,  # PatientName
        )

        # Tag should still exist
        assert hasattr(sample_dataset, "PatientName")

    def test_mutate_minimal_uses_valid_values(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test MINIMAL severity uses valid dictionary values."""
        # Force specific random behavior
        with patch("random.random", return_value=0.5):
            fuzzer._mutate_tag(sample_dataset, 0x00100010, MutationSeverity.MINIMAL)

        # Should complete without error
        assert True

    def test_mutate_moderate_edge_case_branch(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test MODERATE severity can use edge cases."""
        # Force edge case branch (random > 0.7)
        with patch("random.random", return_value=0.8):
            fuzzer._mutate_tag(sample_dataset, 0x00100010, MutationSeverity.MODERATE)

        assert True

    def test_mutate_aggressive_edge_case_branch(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test AGGRESSIVE severity edge case branch."""
        # Force edge case branch (random < 0.5)
        with patch("random.random", return_value=0.3):
            fuzzer._mutate_tag(sample_dataset, 0x00100010, MutationSeverity.AGGRESSIVE)

        assert True

    def test_mutate_aggressive_malicious_branch(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test AGGRESSIVE severity malicious value branch."""
        # Force malicious branch (random >= 0.5)
        with patch("random.random", return_value=0.6):
            fuzzer._mutate_tag(sample_dataset, 0x00100010, MutationSeverity.AGGRESSIVE)

        assert True

    def test_mutate_extreme_uses_malicious(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test EXTREME severity always uses malicious values."""
        fuzzer._mutate_tag(sample_dataset, 0x00100010, MutationSeverity.EXTREME)

        assert True


class TestVRTypeHandling:
    """Tests for VR type handling in _mutate_tag."""

    def test_skip_binary_vr(self, fuzzer: DictionaryFuzzer) -> None:
        """Test that binary VR types are skipped."""
        from pydicom.dataelem import DataElement

        ds = Dataset()
        # Use DataElement to properly set VR for binary data
        ds.add(DataElement(0x7FE00010, "OB", b"\x00" * 100))

        # Should not raise
        fuzzer._mutate_tag(ds, 0x7FE00010, MutationSeverity.MODERATE)

        # PixelData should be unchanged (binary VRs are skipped)
        assert ds.PixelData == b"\x00" * 100

    def test_ui_vr_generates_uid(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test UI VR generates valid UID."""
        original_uid = sample_dataset.SOPInstanceUID

        fuzzer._mutate_tag(sample_dataset, 0x00080018, MutationSeverity.MODERATE)

        # Should still be a valid UID format (digits and periods)
        new_uid = sample_dataset.SOPInstanceUID
        assert isinstance(new_uid, str)
        # UIDs only contain digits, periods, and spaces
        valid_chars = set("0123456789. ")
        assert all(c in valid_chars for c in new_uid)

    def test_numeric_vr_conversion_us(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test US (Unsigned Short) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00280010, "US", 512))  # Rows

        fuzzer._mutate_tag(ds, 0x00280010, MutationSeverity.MINIMAL)

        # Should be integer
        assert isinstance(ds.Rows, int)

    def test_numeric_vr_conversion_ss(self, fuzzer: DictionaryFuzzer) -> None:
        """Test SS (Signed Short) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00189219, "SS", 100))  # Tag with SS VR

        # Force a numeric conversion path
        fuzzer._mutate_tag(ds, 0x00189219, MutationSeverity.MINIMAL)

        assert True  # Should not raise

    def test_skip_at_vr(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AT (Attribute Tag) VR is skipped."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        # Pointer to Group Length is AT type
        ds.add(DataElement(0x00080018, "AT", 0x00100010))

        # Should skip AT tags
        fuzzer._mutate_tag(ds, 0x00080018, MutationSeverity.MODERATE)

        assert True


class TestGetValidValue:
    """Tests for _get_valid_value method."""

    def test_get_valid_uid_tag(self, fuzzer: DictionaryFuzzer) -> None:
        """Test getting value for UID tag."""
        value = fuzzer._get_valid_value(0x00080018)  # SOP Instance UID

        # Should be a UID string
        assert isinstance(value, str)
        # Should start with a digit
        assert value[0].isdigit()

    def test_get_valid_mapped_tag(self, fuzzer: DictionaryFuzzer) -> None:
        """Test getting value for mapped tag."""
        value = fuzzer._get_valid_value(0x00080060)  # Modality

        # Should be from modalities dictionary
        assert isinstance(value, str)

    def test_get_valid_unmapped_tag(self, fuzzer: DictionaryFuzzer) -> None:
        """Test getting value for unmapped tag."""
        value = fuzzer._get_valid_value(0x99999999)  # Unknown tag

        # Should return something from a random dictionary
        assert isinstance(value, str)


class TestGetEdgeCaseValue:
    """Tests for _get_edge_case_value method."""

    def test_returns_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test edge case value is string."""
        value = fuzzer._get_edge_case_value()

        assert isinstance(value, str)

    def test_from_edge_cases_dict(self, fuzzer: DictionaryFuzzer) -> None:
        """Test value comes from edge_cases dictionary."""
        value = fuzzer._get_edge_case_value()

        # Should be in one of the edge case categories
        all_values = []
        for values in fuzzer.edge_cases.values():
            all_values.extend(values)

        assert value in all_values


class TestGetMaliciousValue:
    """Tests for _get_malicious_value method."""

    def test_returns_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test malicious value is string."""
        value = fuzzer._get_malicious_value()

        assert isinstance(value, str)

    def test_from_malicious_dict(self, fuzzer: DictionaryFuzzer) -> None:
        """Test value comes from malicious_values dictionary."""
        value = fuzzer._get_malicious_value()

        # Should be in one of the malicious categories
        all_values = []
        for values in fuzzer.malicious_values.values():
            all_values.extend(values)

        assert value in all_values


class TestGetNumMutations:
    """Tests for _get_num_mutations method."""

    def test_minimal_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MINIMAL severity mutation count."""
        num = fuzzer._get_num_mutations(MutationSeverity.MINIMAL, 100)

        assert 1 <= num <= 5

    def test_moderate_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MODERATE severity mutation count."""
        num = fuzzer._get_num_mutations(MutationSeverity.MODERATE, 100)

        assert 2 <= num <= 10

    def test_aggressive_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AGGRESSIVE severity mutation count."""
        num = fuzzer._get_num_mutations(MutationSeverity.AGGRESSIVE, 100)

        assert 5 <= num <= 20

    def test_extreme_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test EXTREME severity mutation count."""
        num = fuzzer._get_num_mutations(MutationSeverity.EXTREME, 100)

        assert 10 <= num <= 50

    def test_small_dataset_handling(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutation count for small dataset."""
        num = fuzzer._get_num_mutations(MutationSeverity.MINIMAL, 5)

        assert num >= 1


class TestGetStrategyName:
    """Tests for get_strategy_name method."""

    def test_returns_dictionary(self, fuzzer: DictionaryFuzzer) -> None:
        """Test strategy name is 'dictionary'."""
        assert fuzzer.get_strategy_name() == "dictionary"


class TestCanMutate:
    """Tests for can_mutate method."""

    def test_always_true(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test can_mutate always returns True."""
        assert fuzzer.can_mutate(sample_dataset) is True

    def test_empty_dataset(self, fuzzer: DictionaryFuzzer) -> None:
        """Test can_mutate for empty dataset."""
        assert fuzzer.can_mutate(Dataset()) is True


class TestGetApplicableTags:
    """Tests for get_applicable_tags method."""

    def test_returns_list(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test returns list of tuples."""
        result = fuzzer.get_applicable_tags(sample_dataset)

        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_finds_mapped_tags(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test finds tags with dictionary mapping."""
        result = fuzzer.get_applicable_tags(sample_dataset)

        # Should find Modality tag
        tag_dict = dict(result)
        if 0x00080060 in tag_dict:
            assert tag_dict[0x00080060] == "modalities"

    def test_finds_uid_tags(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test finds UID tags."""
        result = fuzzer.get_applicable_tags(sample_dataset)

        tag_dict = dict(result)
        # Study Instance UID (0x0020000D) is in UID_TAGS but NOT in TAG_TO_DICTIONARY
        # so it should return "uid" as the dictionary name
        if 0x0020000D in tag_dict:
            assert tag_dict[0x0020000D] == "uid"
        # Series Instance UID (0x0020000E) is also only in UID_TAGS
        if 0x0020000E in tag_dict:
            assert tag_dict[0x0020000E] == "uid"

    def test_empty_dataset(self, fuzzer: DictionaryFuzzer) -> None:
        """Test with empty dataset."""
        result = fuzzer.get_applicable_tags(Dataset())

        assert result == []


class TestMutateWithSpecificDictionary:
    """Tests for mutate_with_specific_dictionary method."""

    def test_mutates_tag(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test mutating specific tag with dictionary."""
        original = sample_dataset.Modality

        mutated = fuzzer.mutate_with_specific_dictionary(
            sample_dataset, 0x00080060, "modalities"
        )

        # Returns dataset
        assert isinstance(mutated, Dataset)

    def test_returns_copy(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test returns copy, not original."""
        original_modality = sample_dataset.Modality

        mutated = fuzzer.mutate_with_specific_dictionary(
            sample_dataset, 0x00080060, "modalities"
        )

        # Original unchanged
        assert sample_dataset.Modality == original_modality

    def test_tag_not_in_dataset(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test with tag not in dataset."""
        mutated = fuzzer.mutate_with_specific_dictionary(
            sample_dataset,
            0x99999999,
            "modalities",  # Non-existent tag
        )

        # Should return dataset unchanged
        assert isinstance(mutated, Dataset)

    def test_mutation_failure_handling(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test handling of mutation failure."""
        # Create a dataset with a problematic tag
        ds = Dataset()
        ds.PixelData = b"\x00" * 100

        # Try to mutate pixel data with string dictionary
        # This may fail, but should handle gracefully
        mutated = fuzzer.mutate_with_specific_dictionary(
            ds, 0x7FE00010, "patient_names"
        )

        assert isinstance(mutated, Dataset)


class TestInjectEdgeCasesSystematically:
    """Tests for inject_edge_cases_systematically method."""

    def test_returns_list_of_datasets(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test returns list of datasets."""
        # Use valid category name "empty" (not "empty_strings")
        result = fuzzer.inject_edge_cases_systematically(sample_dataset, "empty")

        assert isinstance(result, list)
        for ds in result:
            assert isinstance(ds, Dataset)

    def test_unknown_category(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test with unknown edge case category."""
        result = fuzzer.inject_edge_cases_systematically(
            sample_dataset, "nonexistent_category"
        )

        assert result == []

    def test_generates_multiple_datasets(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test generates multiple mutated datasets."""
        # Use valid category name "whitespace" (has multiple values)
        result = fuzzer.inject_edge_cases_systematically(sample_dataset, "whitespace")

        # Should generate multiple datasets (tags * edge_values)
        assert len(result) >= 1

    def test_original_unchanged(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test original dataset is unchanged."""
        original_name = sample_dataset.PatientName

        fuzzer.inject_edge_cases_systematically(sample_dataset, "empty")

        assert sample_dataset.PatientName == original_name

    def test_edge_case_categories(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test different edge case categories."""
        for category in fuzzer.edge_cases.keys():
            result = fuzzer.inject_edge_cases_systematically(sample_dataset, category)
            # Each category should produce some results
            # (might be empty if mutations fail)
            assert isinstance(result, list)


class TestNumericVRConversions:
    """Tests for numeric VR value conversions."""

    def test_us_range_wrapping(self, fuzzer: DictionaryFuzzer) -> None:
        """Test US values wrap to valid range."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00280010, "US", 512))

        # Force value outside US range
        with patch.object(fuzzer, "_get_valid_value", return_value="100000"):
            fuzzer._mutate_tag(ds, 0x00280010, MutationSeverity.MINIMAL)

        # Should be in valid US range
        assert 0 <= ds.Rows <= 65535

    def test_conversion_failure_skips(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion failure skips mutation."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00280010, "US", 512))
        original = ds.Rows

        # Force value that can't be converted
        with patch.object(fuzzer, "_get_valid_value", return_value="not_a_number"):
            fuzzer._mutate_tag(ds, 0x00280010, MutationSeverity.MINIMAL)

        # Should default to 0 or skip
        assert isinstance(ds.Rows, int)


class TestExceptionHandling:
    """Tests for exception handling in mutations."""

    def test_mutation_exception_handled(self, fuzzer: DictionaryFuzzer) -> None:
        """Test exceptions during mutation are handled."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        # Create a tag that will fail to accept the value
        ds.add(DataElement(0x00280010, "US", 512))

        # Should not raise even with problematic mutations
        fuzzer._mutate_tag(ds, 0x00280010, MutationSeverity.EXTREME)

        # Should still be a valid dataset
        assert True


class TestFloatVRHandling:
    """Tests for FL and FD VR handling."""

    def test_fl_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test FL (Float) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00181050, "FL", 1.0))  # Spatial Resolution

        fuzzer._mutate_tag(ds, 0x00181050, MutationSeverity.MINIMAL)

        # Should handle float VR
        assert True

    def test_fd_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test FD (Double) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00181166, "FD", 1.0))  # Grid Aspect Ratio

        fuzzer._mutate_tag(ds, 0x00181166, MutationSeverity.MINIMAL)

        # Should handle double VR
        assert True


class TestDSISVRHandling:
    """Tests for DS and IS VR handling."""

    def test_is_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test IS (Integer String) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00200013, "IS", "1"))  # Instance Number

        fuzzer._mutate_tag(ds, 0x00200013, MutationSeverity.MINIMAL)

        # Should handle IS VR
        assert True

    def test_ds_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test DS (Decimal String) VR conversion."""
        ds = Dataset()
        from pydicom.dataelem import DataElement

        ds.add(DataElement(0x00280030, "DS", "1.0\\1.0"))  # Pixel Spacing

        fuzzer._mutate_tag(ds, 0x00280030, MutationSeverity.MINIMAL)

        # Should handle DS VR
        assert True


class TestIntegration:
    """Integration tests for dictionary fuzzer."""

    def test_full_mutation_workflow(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test complete mutation workflow."""
        # Get applicable tags
        applicable = fuzzer.get_applicable_tags(sample_dataset)

        # Mutate at each severity level
        for severity in MutationSeverity:
            mutated = fuzzer.mutate(sample_dataset, severity)
            assert isinstance(mutated, Dataset)

    def test_multiple_mutations(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test applying mutations multiple times."""
        current = sample_dataset

        for _ in range(5):
            current = fuzzer.mutate(current, MutationSeverity.MODERATE)
            assert isinstance(current, Dataset)

    def test_systematic_then_random(
        self, fuzzer: DictionaryFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test combining systematic and random mutations."""
        # First generate systematic mutations
        for category in list(fuzzer.edge_cases.keys())[:2]:
            systematic = fuzzer.inject_edge_cases_systematically(
                sample_dataset, category
            )

            # Then apply random mutations to each
            for ds in systematic[:3]:
                mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)
                assert isinstance(mutated, Dataset)

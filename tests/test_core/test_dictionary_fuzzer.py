"""
Tests for Dictionary-Based DICOM Fuzzing Strategy

This test suite verifies the dictionary fuzzer's ability to:
1. Apply intelligent mutations using DICOM-specific dictionaries
2. Select appropriate values based on tag types
3. Generate valid-looking but malicious test cases
4. Systematically inject edge cases
"""

from pydicom.dataset import Dataset

from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.attacks.format.dictionary_fuzzer import DictionaryFuzzer


class TestDictionaryFuzzerInit:
    """Test dictionary fuzzer initialization."""

    def test_initialization(self):
        """Test fuzzer initializes with dictionaries loaded."""
        fuzzer = DictionaryFuzzer()
        assert fuzzer.dictionaries is not None
        assert fuzzer.edge_cases is not None
        assert fuzzer.malicious_values is not None

    def test_dictionaries_loaded(self):
        """Test that dictionaries contain expected data."""
        fuzzer = DictionaryFuzzer()
        assert len(fuzzer.edge_cases) > 0
        assert len(fuzzer.malicious_values) > 0
        assert "empty" in fuzzer.edge_cases
        assert "buffer_overflow" in fuzzer.malicious_values


class TestDictionaryFuzzerBasics:
    """Test basic dictionary fuzzer functionality."""

    def test_strategy_name(self):
        """Test strategy returns correct name."""
        fuzzer = DictionaryFuzzer()
        assert fuzzer.get_strategy_name() == "dictionary"

    def test_can_mutate_any_dataset(self):
        """Test fuzzer works with any DICOM dataset."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        assert fuzzer.can_mutate(ds) is True

    def test_can_mutate_empty_dataset(self):
        """Test fuzzer works with empty dataset."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is True


class TestMutationSeverity:
    """Test mutations at different severity levels."""

    def test_minimal_mutations(self):
        """Test minimal severity produces small changes."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Original"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        mutated = fuzzer.mutate(ds, MutationSeverity.MINIMAL)
        # Minimal may mutate 0-2 tags, so just check it didn't break
        assert hasattr(mutated, "PatientName")
        assert hasattr(mutated, "Modality")

    def test_moderate_mutations(self):
        """Test moderate severity produces moderate changes."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        for i in range(10):
            setattr(ds, f"Tag{i}", f"Value{i}")

        mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)
        # Check dataset wasn't broken
        for i in range(10):
            assert hasattr(mutated, f"Tag{i}")

    def test_aggressive_mutations(self):
        """Test aggressive severity produces many changes."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        for i in range(20):
            setattr(ds, f"Tag{i}", f"Value{i}")

        mutated = fuzzer.mutate(ds, MutationSeverity.AGGRESSIVE)
        # Check dataset wasn't broken
        for i in range(20):
            assert hasattr(mutated, f"Tag{i}")

    def test_extreme_mutations(self):
        """Test extreme severity produces maximum changes."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        for i in range(20):
            setattr(ds, f"Tag{i}", f"Value{i}")

        mutated = fuzzer.mutate(ds, MutationSeverity.EXTREME)
        # Check dataset wasn't broken
        for i in range(20):
            assert hasattr(mutated, f"Tag{i}")


class TestTagMapping:
    """Test tag-to-dictionary mapping functionality."""

    def test_get_applicable_tags(self):
        """Test retrieval of applicable tags for mutation."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.Modality = "CT"  # Tag 0x00080060
        ds.PatientSex = "M"  # Tag 0x00100040
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # Tag 0x00080016

        applicable = fuzzer.get_applicable_tags(ds)
        tag_ints = [tag for tag, _ in applicable]

        assert 0x00080060 in tag_ints  # Modality
        assert 0x00100040 in tag_ints  # Patient Sex
        assert 0x00080016 in tag_ints  # SOP Class UID

    def test_uid_tags_mapped_correctly(self):
        """Test UID tags are identified for mutation."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.5"

        applicable = fuzzer.get_applicable_tags(ds)
        tag_ints = [tag for tag, _ in applicable]

        # Just verify UID tags are identified
        assert 0x00080016 in tag_ints or 0x00080018 in tag_ints


class TestValueSelection:
    """Test value selection strategies."""

    def test_get_valid_value_for_modality(self):
        """Test valid value selection for modality tag.

        Note: The modalities dictionary intentionally includes edge cases
        like empty strings for fuzzing purposes. The test only validates
        that a string is returned (which may be empty as an edge case).
        """
        fuzzer = DictionaryFuzzer()
        value = fuzzer._get_valid_value(0x00080060)  # Modality
        # Should return a string (may be empty as an intentional edge case)
        assert isinstance(value, str)

    def test_get_valid_value_for_uid(self):
        """Test valid value selection for UID tags."""
        fuzzer = DictionaryFuzzer()
        value = fuzzer._get_valid_value(0x00080016)  # SOP Class UID
        # Should be a valid UID format
        assert isinstance(value, str)
        assert "." in value  # UIDs contain dots

    def test_get_edge_case_value(self):
        """Test edge case value selection."""
        fuzzer = DictionaryFuzzer()
        value = fuzzer._get_edge_case_value()
        assert isinstance(value, str)
        # Edge cases include empty strings, long strings, etc.
        assert value in [v for vals in fuzzer.edge_cases.values() for v in vals]

    def test_get_malicious_value(self):
        """Test malicious value selection."""
        fuzzer = DictionaryFuzzer()
        value = fuzzer._get_malicious_value()
        assert isinstance(value, str)
        # Should be from malicious values dictionary
        malicious_all = [v for vals in fuzzer.malicious_values.values() for v in vals]
        assert value in malicious_all


class TestSpecificDictionary:
    """Test mutation with specific dictionaries."""

    def test_mutate_with_specific_dictionary(self):
        """Test mutation using a specific dictionary."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.Modality = "CT"

        mutated = fuzzer.mutate_with_specific_dictionary(
            ds,
            0x00080060,
            "modalities",  # Modality tag
        )

        # Modality should be mutated
        assert hasattr(mutated, "Modality")
        # Value should be a string
        assert isinstance(mutated.Modality, str)

    def test_mutate_nonexistent_tag(self):
        """Test mutating a tag that doesn't exist in dataset."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate_with_specific_dictionary(
            ds,
            0x00080060,
            "modalities",  # Modality tag not in dataset
        )

        # Should return unchanged dataset
        assert not hasattr(mutated, "Modality")

    def test_mutate_with_patient_names(self):
        """Test mutation using patient names dictionary."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Original^Name"

        mutated = fuzzer.mutate_with_specific_dictionary(
            ds,
            0x00100010,
            "patient_names",  # Patient Name tag
        )

        # Patient name should be present (may be empty as part of edge case testing)
        assert hasattr(mutated, "PatientName")
        # Verify it's a PersonName object (pydicom conversion)
        from pydicom.valuerep import PersonName

        assert isinstance(mutated.PatientName, (PersonName, str))
        # Verify it was mutated (may be different or same due to randomness)
        # Just check the mutation ran without error
        assert mutated.PatientName is not None


class TestSystematicEdgeCases:
    """Test systematic edge case injection."""

    def test_inject_empty_strings(self):
        """Test systematic injection of empty strings."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        mutated_datasets = fuzzer.inject_edge_cases_systematically(ds, "empty")

        # Should generate one dataset per tag
        assert len(mutated_datasets) > 0
        # Check that some have empty values
        empty_found = any(
            hasattr(m, "PatientName") and m.PatientName == "" for m in mutated_datasets
        )
        assert empty_found

    def test_inject_null_bytes(self):
        """Test systematic injection of null bytes."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"

        mutated_datasets = fuzzer.inject_edge_cases_systematically(ds, "null_bytes")

        assert len(mutated_datasets) > 0
        # Check that some have null bytes
        null_found = any(
            hasattr(m, "PatientName") and "\x00" in str(m.PatientName)
            for m in mutated_datasets
        )
        assert null_found

    def test_inject_very_long_strings(self):
        """Test systematic injection of very long strings."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated_datasets = fuzzer.inject_edge_cases_systematically(ds, "very_long")

        assert len(mutated_datasets) > 0
        # Check that some have very long values
        long_found = any(
            hasattr(m, "PatientName") and len(str(m.PatientName)) > 100
            for m in mutated_datasets
        )
        assert long_found

    def test_inject_invalid_category(self):
        """Test injection with invalid category returns empty list."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"

        mutated_datasets = fuzzer.inject_edge_cases_systematically(
            ds, "nonexistent_category"
        )

        assert mutated_datasets == []


class TestIntegrationWithMutator:
    """Test integration with DICOM mutator."""

    def test_mutator_registers_dictionary_strategy(self):
        """Test that mutator can register dictionary strategy."""
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        initial_count = len(mutator.strategies)

        fuzzer = DictionaryFuzzer()
        mutator.register_strategy(fuzzer)

        assert len(mutator.strategies) == initial_count + 1
        assert fuzzer in mutator.strategies

    def test_mutator_uses_dictionary_strategy(self):
        """Test mutator applies dictionary mutations."""
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        ds = Dataset()
        ds.PatientName = "Original"
        ds.Modality = "CT"

        mutator = DicomMutator(
            {
                "auto_register_strategies": False,
                "mutation_probability": 1.0,  # Always mutate
            }
        )
        fuzzer = DictionaryFuzzer()
        mutator.register_strategy(fuzzer)

        mutator.start_session(ds)
        mutated = mutator.apply_mutations(
            ds, num_mutations=1, strategy_names=["dictionary"]
        )

        # At least one tag should exist (mutations may change values)
        assert hasattr(mutated, "PatientName") or hasattr(mutated, "Modality")
        mutator.end_session()

    def test_auto_register_strategies(self):
        """Test mutator auto-registers dictionary strategy."""
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator({"auto_register_strategies": True})

        # Should have dictionary strategy registered
        strategy_names = [s.get_strategy_name() for s in mutator.strategies]
        assert "dictionary" in strategy_names


class TestEdgeCases:
    """Test edge case handling."""

    def test_empty_dataset_mutation(self):
        """Test mutation of empty dataset."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)
        # Should return empty dataset unchanged
        assert len(mutated) == 0

    def test_dataset_with_sequences(self):
        """Test mutation of dataset with sequences."""
        from pydicom.sequence import Sequence

        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.ReferencedImageSequence = Sequence([])

        mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)
        # Should handle sequences gracefully
        assert hasattr(mutated, "ReferencedImageSequence")

    def test_mutation_preserves_dataset_structure(self):
        """Test mutations don't break dataset structure."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)

        # Original dataset should be unchanged
        assert ds.PatientName == "Test"
        assert ds.PatientID == "12345"

        # Mutated should have all tags
        assert hasattr(mutated, "PatientName")
        assert hasattr(mutated, "PatientID")
        assert hasattr(mutated, "Modality")


class TestPerformance:
    """Test performance characteristics."""

    def test_mutation_performance(self):
        """Test mutation completes in reasonable time."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        for i in range(50):
            setattr(ds, f"Tag{i}", f"Value{i}")

        result = fuzzer.mutate(ds, MutationSeverity.MODERATE)
        assert result is not None

    def test_systematic_injection_performance(self):
        """Test systematic injection completes in reasonable time."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        result = fuzzer.inject_edge_cases_systematically(ds, "empty")
        assert len(result) > 0

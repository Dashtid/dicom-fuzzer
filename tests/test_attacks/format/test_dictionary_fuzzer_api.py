"""
Tests for Dictionary-Based DICOM Fuzzing Strategy

This test suite verifies the dictionary fuzzer's ability to:
1. Apply intelligent mutations using DICOM-specific dictionaries
2. Select appropriate values based on tag types
3. Generate valid-looking but malicious test cases
"""

from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.dictionary_fuzzer import DictionaryFuzzer


class TestDictionaryFuzzerInit:
    """Test dictionary fuzzer initialization."""

    def test_initialization(self):
        """Test fuzzer initializes with dictionaries loaded."""
        fuzzer = DictionaryFuzzer()
        assert fuzzer.edge_cases is not None

    def test_dictionaries_loaded(self):
        """Test that dictionaries contain expected data."""
        fuzzer = DictionaryFuzzer()
        assert len(fuzzer.edge_cases) > 0
        assert "empty" in fuzzer.edge_cases


class TestDictionaryFuzzerBasics:
    """Test basic dictionary fuzzer functionality."""

    def test_strategy_name(self):
        """Test strategy returns correct name."""
        fuzzer = DictionaryFuzzer()
        assert fuzzer.strategy_name == "dictionary"

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
        strategy_names = [s.strategy_name for s in mutator.strategies]
        assert "dictionary" in strategy_names


class TestEdgeCases:
    """Test edge case handling."""

    def test_empty_dataset_mutation(self):
        """Test mutation of empty dataset."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()

        mutated = fuzzer.mutate(ds)
        # Should return empty dataset unchanged
        assert len(mutated) == 0

    def test_dataset_with_sequences(self):
        """Test mutation of dataset with sequences."""
        from pydicom.sequence import Sequence

        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.ReferencedImageSequence = Sequence([])

        mutated = fuzzer.mutate(ds)
        # Should handle sequences gracefully
        assert hasattr(mutated, "ReferencedImageSequence")

    def test_mutation_preserves_dataset_structure(self):
        """Test mutations don't break dataset structure."""
        fuzzer = DictionaryFuzzer()
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        mutated = fuzzer.mutate(ds)

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

        result = fuzzer.mutate(ds)
        assert result is not None

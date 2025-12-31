"""Tests for dicom_fuzzer.utils.config module.

Tests the fuzzing configuration constants and data pools.
"""

from dicom_fuzzer.utils.config import FAKE_DATA_POOLS, MUTATION_STRATEGIES


class TestMutationStrategies:
    """Tests for MUTATION_STRATEGIES configuration."""

    def test_mutation_strategies_is_dict(self):
        """Verify MUTATION_STRATEGIES is a dictionary."""
        assert isinstance(MUTATION_STRATEGIES, dict)

    def test_mutation_strategies_has_expected_keys(self):
        """Verify all expected strategy keys are present."""
        expected_keys = {
            "metadata_probability",
            "header_probability",
            "pixel_probability",
            "max_mutations_per_file",
        }
        assert set(MUTATION_STRATEGIES.keys()) == expected_keys

    def test_probability_values_in_valid_range(self):
        """Verify probability values are between 0 and 1."""
        probability_keys = [
            "metadata_probability",
            "header_probability",
            "pixel_probability",
        ]
        for key in probability_keys:
            value = MUTATION_STRATEGIES[key]
            assert 0.0 <= value <= 1.0, f"{key} should be between 0 and 1"

    def test_max_mutations_is_positive_integer(self):
        """Verify max_mutations_per_file is a positive integer."""
        value = MUTATION_STRATEGIES["max_mutations_per_file"]
        assert isinstance(value, int)
        assert value > 0

    def test_probability_values_are_numeric(self):
        """Verify probability values are numeric (int or float)."""
        probability_keys = [
            "metadata_probability",
            "header_probability",
            "pixel_probability",
        ]
        for key in probability_keys:
            value = MUTATION_STRATEGIES[key]
            assert isinstance(value, (int, float)), f"{key} should be numeric"


class TestFakeDataPools:
    """Tests for FAKE_DATA_POOLS configuration."""

    def test_fake_data_pools_is_dict(self):
        """Verify FAKE_DATA_POOLS is a dictionary."""
        assert isinstance(FAKE_DATA_POOLS, dict)

    def test_fake_data_pools_has_expected_keys(self):
        """Verify all expected pool keys are present."""
        expected_keys = {"institutions", "modalities", "manufacturers"}
        assert set(FAKE_DATA_POOLS.keys()) == expected_keys

    def test_institutions_is_non_empty_list(self):
        """Verify institutions pool contains values."""
        institutions = FAKE_DATA_POOLS["institutions"]
        assert isinstance(institutions, list)
        assert len(institutions) > 0

    def test_modalities_is_non_empty_list(self):
        """Verify modalities pool contains values."""
        modalities = FAKE_DATA_POOLS["modalities"]
        assert isinstance(modalities, list)
        assert len(modalities) > 0

    def test_manufacturers_is_non_empty_list(self):
        """Verify manufacturers pool contains values."""
        manufacturers = FAKE_DATA_POOLS["manufacturers"]
        assert isinstance(manufacturers, list)
        assert len(manufacturers) > 0

    def test_all_pool_values_are_strings(self):
        """Verify all pool values are strings."""
        for pool_name, pool_values in FAKE_DATA_POOLS.items():
            for value in pool_values:
                assert isinstance(value, str), (
                    f"Value in {pool_name} should be string: {value}"
                )

    def test_modalities_are_valid_dicom_codes(self):
        """Verify modalities are standard DICOM modality codes."""
        valid_modalities = {"CT", "MR", "US", "XR", "CR", "DX", "MG", "PT", "NM"}
        modalities = FAKE_DATA_POOLS["modalities"]
        for modality in modalities:
            assert modality in valid_modalities, f"Unknown modality: {modality}"

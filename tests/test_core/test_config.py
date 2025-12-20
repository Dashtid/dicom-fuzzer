"""
Comprehensive tests for configuration module.

Tests cover:
- Configuration values exist and are accessible
- Configuration structure and types
- Configuration value ranges and validity
- Configuration immutability concerns
"""

import pytest


class TestMutationStrategiesConfig:
    """Test MUTATION_STRATEGIES configuration."""

    def test_mutation_strategies_exists(self):
        """Test that MUTATION_STRATEGIES is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert MUTATION_STRATEGIES is not None
        assert isinstance(MUTATION_STRATEGIES, dict)

    def test_metadata_probability_exists(self):
        """Test that metadata_probability is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert "metadata_probability" in MUTATION_STRATEGIES

    def test_metadata_probability_valid_range(self):
        """Test that metadata_probability is in valid range [0, 1]."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        prob = MUTATION_STRATEGIES["metadata_probability"]
        assert isinstance(prob, (int, float))
        assert 0.0 <= prob <= 1.0

    def test_header_probability_exists(self):
        """Test that header_probability is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert "header_probability" in MUTATION_STRATEGIES

    def test_header_probability_valid_range(self):
        """Test that header_probability is in valid range [0, 1]."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        prob = MUTATION_STRATEGIES["header_probability"]
        assert isinstance(prob, (int, float))
        assert 0.0 <= prob <= 1.0

    def test_pixel_probability_exists(self):
        """Test that pixel_probability is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert "pixel_probability" in MUTATION_STRATEGIES

    def test_pixel_probability_valid_range(self):
        """Test that pixel_probability is in valid range [0, 1]."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        prob = MUTATION_STRATEGIES["pixel_probability"]
        assert isinstance(prob, (int, float))
        assert 0.0 <= prob <= 1.0

    def test_max_mutations_per_file_exists(self):
        """Test that max_mutations_per_file is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert "max_mutations_per_file" in MUTATION_STRATEGIES

    def test_max_mutations_per_file_valid_value(self):
        """Test that max_mutations_per_file is a positive integer."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        max_mut = MUTATION_STRATEGIES["max_mutations_per_file"]
        assert isinstance(max_mut, int)
        assert max_mut > 0

    def test_all_required_keys_present(self):
        """Test that all required keys are present."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        required_keys = [
            "metadata_probability",
            "header_probability",
            "pixel_probability",
            "max_mutations_per_file",
        ]

        for key in required_keys:
            assert key in MUTATION_STRATEGIES, f"Missing required key: {key}"

    def test_configuration_values(self):
        """Test specific configuration values are as expected."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        # Test documented values
        assert MUTATION_STRATEGIES["metadata_probability"] == 0.8
        assert MUTATION_STRATEGIES["header_probability"] == 0.6
        assert MUTATION_STRATEGIES["pixel_probability"] == 0.3
        assert MUTATION_STRATEGIES["max_mutations_per_file"] == 3


class TestFakeDataPoolsConfig:
    """Test FAKE_DATA_POOLS configuration."""

    def test_fake_data_pools_exists(self):
        """Test that FAKE_DATA_POOLS is defined."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert FAKE_DATA_POOLS is not None
        assert isinstance(FAKE_DATA_POOLS, dict)

    def test_institutions_exists(self):
        """Test that institutions pool is defined."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert "institutions" in FAKE_DATA_POOLS

    def test_institutions_is_list(self):
        """Test that institutions is a list."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert isinstance(FAKE_DATA_POOLS["institutions"], list)

    def test_institutions_not_empty(self):
        """Test that institutions list is not empty."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert len(FAKE_DATA_POOLS["institutions"]) > 0

    def test_institutions_contains_strings(self):
        """Test that institutions contains string values."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        for institution in FAKE_DATA_POOLS["institutions"]:
            assert isinstance(institution, str)
            assert len(institution) > 0

    def test_modalities_exists(self):
        """Test that modalities pool is defined."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert "modalities" in FAKE_DATA_POOLS

    def test_modalities_is_list(self):
        """Test that modalities is a list."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert isinstance(FAKE_DATA_POOLS["modalities"], list)

    def test_modalities_not_empty(self):
        """Test that modalities list is not empty."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert len(FAKE_DATA_POOLS["modalities"]) > 0

    def test_modalities_contains_valid_strings(self):
        """Test that modalities contains valid string values."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        for modality in FAKE_DATA_POOLS["modalities"]:
            assert isinstance(modality, str)
            assert len(modality) > 0
            # Modality codes are typically uppercase
            assert modality.isupper() or modality.isalnum()

    def test_manufacturers_exists(self):
        """Test that manufacturers pool is defined."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert "manufacturers" in FAKE_DATA_POOLS

    def test_manufacturers_is_list(self):
        """Test that manufacturers is a list."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert isinstance(FAKE_DATA_POOLS["manufacturers"], list)

    def test_manufacturers_not_empty(self):
        """Test that manufacturers list is not empty."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert len(FAKE_DATA_POOLS["manufacturers"]) > 0

    def test_manufacturers_contains_strings(self):
        """Test that manufacturers contains string values."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        for manufacturer in FAKE_DATA_POOLS["manufacturers"]:
            assert isinstance(manufacturer, str)
            assert len(manufacturer) > 0

    def test_all_required_pools_present(self):
        """Test that all required pools are present."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        required_pools = ["institutions", "modalities", "manufacturers"]

        for pool in required_pools:
            assert pool in FAKE_DATA_POOLS, f"Missing required pool: {pool}"

    def test_configuration_values(self):
        """Test specific configuration values are as expected."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        # Test documented values
        assert "General Hospital" in FAKE_DATA_POOLS["institutions"]
        assert "Medical Center" in FAKE_DATA_POOLS["institutions"]
        assert "Clinic" in FAKE_DATA_POOLS["institutions"]

        assert "CT" in FAKE_DATA_POOLS["modalities"]
        assert "MR" in FAKE_DATA_POOLS["modalities"]
        assert "US" in FAKE_DATA_POOLS["modalities"]
        assert "XR" in FAKE_DATA_POOLS["modalities"]

        assert "GE" in FAKE_DATA_POOLS["manufacturers"]
        assert "Siemens" in FAKE_DATA_POOLS["manufacturers"]
        assert "Philips" in FAKE_DATA_POOLS["manufacturers"]


class TestConfigurationIntegrity:
    """Test overall configuration integrity."""

    def test_no_conflicting_probabilities(self):
        """Test that probabilities don't conflict with max_mutations."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        # All probabilities sum should make sense with max mutations
        total_prob = (
            MUTATION_STRATEGIES["metadata_probability"]
            + MUTATION_STRATEGIES["header_probability"]
            + MUTATION_STRATEGIES["pixel_probability"]
        )

        # At least one mutation strategy should be likely to trigger
        assert total_prob > 0, "At least one mutation should have non-zero probability"

    def test_probability_ordering_is_sensible(self):
        """Test that probability ordering makes sense for fuzzing."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        # Metadata mutations should be most common (safest)
        # Pixel mutations should be least common (most likely to break files)
        metadata_prob = MUTATION_STRATEGIES["metadata_probability"]
        header_prob = MUTATION_STRATEGIES["header_probability"]
        pixel_prob = MUTATION_STRATEGIES["pixel_probability"]

        assert metadata_prob >= header_prob, (
            "Metadata should have highest or equal probability"
        )
        assert pixel_prob <= header_prob, (
            "Pixel should have lowest or equal probability"
        )

    def test_data_pools_have_variety(self):
        """Test that data pools have sufficient variety."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        # Each pool should have multiple options for good randomization
        assert len(FAKE_DATA_POOLS["institutions"]) >= 2
        assert len(FAKE_DATA_POOLS["modalities"]) >= 2
        assert len(FAKE_DATA_POOLS["manufacturers"]) >= 2

    def test_no_duplicate_values_in_pools(self):
        """Test that pools don't contain duplicate values."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        for pool_name, pool_values in FAKE_DATA_POOLS.items():
            assert len(pool_values) == len(set(pool_values)), (
                f"Duplicate values found in {pool_name}"
            )

    def test_configuration_is_importable(self):
        """Test that configuration can be imported without errors."""
        try:
            from dicom_fuzzer.utils import config

            assert hasattr(config, "MUTATION_STRATEGIES")
            assert hasattr(config, "FAKE_DATA_POOLS")
        except ImportError as e:
            pytest.fail(f"Failed to import config module: {e}")

    def test_configuration_can_be_imported_multiple_times(self):
        """Test that configuration can be imported multiple times."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES as ms1
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES as ms2

        # Should be the same object
        assert ms1 is ms2


class TestConfigurationUsage:
    """Test practical configuration usage patterns."""

    def test_accessing_mutation_probabilities(self):
        """Test accessing mutation probabilities in realistic way."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        # Simulate strategy selection based on config
        metadata_enabled = MUTATION_STRATEGIES["metadata_probability"] > 0
        header_enabled = MUTATION_STRATEGIES["header_probability"] > 0

        assert metadata_enabled, "Metadata mutations should be enabled"
        assert header_enabled, "Header mutations should be enabled"

    def test_accessing_fake_data_pools(self):
        """Test accessing fake data pools in realistic way."""
        import random

        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        # Simulate selecting random values from pools
        institution = random.choice(FAKE_DATA_POOLS["institutions"])
        modality = random.choice(FAKE_DATA_POOLS["modalities"])
        manufacturer = random.choice(FAKE_DATA_POOLS["manufacturers"])

        assert isinstance(institution, str)
        assert isinstance(modality, str)
        assert isinstance(manufacturer, str)

    def test_max_mutations_as_range_limit(self):
        """Test using max_mutations_per_file as a range limit."""
        import random

        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        max_mutations = MUTATION_STRATEGIES["max_mutations_per_file"]

        # Simulate selecting number of mutations
        num_mutations = random.randint(1, max_mutations)

        assert 1 <= num_mutations <= max_mutations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestPydanticConfiguration:
    """Test new Pydantic-based configuration system."""

    def test_settings_imports(self):
        """Test that new config module can be imported."""
        from dicom_fuzzer.core.config import Settings, get_settings

        assert Settings is not None
        assert get_settings is not None

    def test_settings_default_values(self):
        """Test settings with default values."""
        from dicom_fuzzer.core.config import Settings

        settings = Settings()
        assert settings.app_name == "DICOM-Fuzzer"
        assert settings.fuzzing.metadata_probability == 0.8
        assert settings.security.max_file_size_mb == 100

    def test_environment_helpers(self):
        """Test environment helper methods."""
        from dicom_fuzzer.core.config import Environment, Settings

        settings = Settings(environment=Environment.DEVELOPMENT)
        assert settings.is_development() is True
        assert settings.is_testing() is False
        assert settings.is_production() is False

    def test_get_settings_singleton(self):
        """Test settings singleton behavior."""
        from dicom_fuzzer.core.config import get_settings

        settings1 = get_settings(force_reload=True)
        settings2 = get_settings()

        assert settings1 is settings2

    def test_config_validation(self):
        """Test configuration validation."""
        from dicom_fuzzer.core.config import FuzzingConfig

        with pytest.raises(Exception):
            # Probability out of range
            FuzzingConfig(metadata_probability=1.5)

    def test_path_autocreation(self):
        """Test paths are created automatically."""
        import tempfile
        from pathlib import Path

        from dicom_fuzzer.core.config import PathConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test_dir"
            PathConfig(input_dir=test_path)

            assert test_path.exists()
            assert test_path.is_dir()

    def test_settings_get_summary(self):
        """Test Settings.get_summary method (line 257)."""
        from dicom_fuzzer.core.config import Settings

        settings = Settings()
        summary = settings.get_summary()

        # Check that summary contains expected sections
        assert "DICOM-Fuzzer Configuration" in summary
        assert "Environment:" in summary
        assert "Debug Mode:" in summary
        assert "Fuzzing:" in summary

    def test_load_profile(self):
        """Test load_profile function (lines 328-329)."""
        import os

        from dicom_fuzzer.core.config import load_profile

        # Save original environment
        original_env = os.environ.get("ENVIRONMENT")

        try:
            # Test loading development profile
            settings = load_profile("development")

            assert settings is not None
            assert os.environ["ENVIRONMENT"] == "development"
        finally:
            # Restore original environment
            if original_env:
                os.environ["ENVIRONMENT"] = original_env
            elif "ENVIRONMENT" in os.environ:
                del os.environ["ENVIRONMENT"]

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

        assert MUTATION_STRATEGIES is not None, "MUTATION_STRATEGIES should be defined"
        assert isinstance(MUTATION_STRATEGIES, dict), (
            "MUTATION_STRATEGIES should be a dict"
        )

    @pytest.mark.parametrize(
        "key",
        [
            pytest.param("metadata_probability", id="metadata"),
            pytest.param("header_probability", id="header"),
            pytest.param("pixel_probability", id="pixel"),
        ],
    )
    def test_probability_exists_and_valid(self, key):
        """Test that probability keys exist and are in valid range [0, 1]."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert key in MUTATION_STRATEGIES, f"Missing key: {key}"
        prob = MUTATION_STRATEGIES[key]
        assert isinstance(prob, (int, float)), f"{key} should be numeric"
        assert 0.0 <= prob <= 1.0, f"{key} should be in range [0, 1]"

    def test_max_mutations_per_file_exists(self):
        """Test that max_mutations_per_file is defined."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        assert "max_mutations_per_file" in MUTATION_STRATEGIES, (
            "max_mutations_per_file key should exist"
        )

    def test_max_mutations_per_file_valid_value(self):
        """Test that max_mutations_per_file is a positive integer."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        max_mut = MUTATION_STRATEGIES["max_mutations_per_file"]
        assert isinstance(max_mut, int), (
            f"max_mutations_per_file should be int, got {type(max_mut)}"
        )
        assert max_mut > 0, f"max_mutations_per_file should be positive, got {max_mut}"

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
        assert MUTATION_STRATEGIES["metadata_probability"] == 0.8, (
            "metadata_probability should be 0.8"
        )
        assert MUTATION_STRATEGIES["header_probability"] == 0.6, (
            "header_probability should be 0.6"
        )
        assert MUTATION_STRATEGIES["pixel_probability"] == 0.3, (
            "pixel_probability should be 0.3"
        )
        assert MUTATION_STRATEGIES["max_mutations_per_file"] == 3, (
            "max_mutations_per_file should be 3"
        )


class TestFakeDataPoolsConfig:
    """Test FAKE_DATA_POOLS configuration."""

    def test_fake_data_pools_exists(self):
        """Test that FAKE_DATA_POOLS is defined."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert FAKE_DATA_POOLS is not None, "FAKE_DATA_POOLS should be defined"
        assert isinstance(FAKE_DATA_POOLS, dict), "FAKE_DATA_POOLS should be a dict"

    @pytest.mark.parametrize(
        "pool_name",
        [
            pytest.param("institutions", id="institutions"),
            pytest.param("modalities", id="modalities"),
            pytest.param("manufacturers", id="manufacturers"),
        ],
    )
    def test_pool_exists_and_valid(self, pool_name):
        """Test that pool exists, is a non-empty list of strings."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        assert pool_name in FAKE_DATA_POOLS, f"Missing pool: {pool_name}"
        pool = FAKE_DATA_POOLS[pool_name]
        assert isinstance(pool, list), f"{pool_name} should be a list"
        assert len(pool) > 0, f"{pool_name} should not be empty"
        for item in pool:
            assert isinstance(item, str), f"Items in {pool_name} should be strings"
            assert len(item) > 0, f"Items in {pool_name} should be non-empty"

    def test_modalities_are_uppercase(self):
        """Test that modality codes follow DICOM conventions (uppercase/alphanumeric)."""
        from dicom_fuzzer.utils.config import FAKE_DATA_POOLS

        for modality in FAKE_DATA_POOLS["modalities"]:
            assert modality.isupper() or modality.isalnum(), (
                f"Modality '{modality}' should be uppercase or alphanumeric"
            )

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
        assert "General Hospital" in FAKE_DATA_POOLS["institutions"], (
            "institutions should contain 'General Hospital'"
        )
        assert "Medical Center" in FAKE_DATA_POOLS["institutions"], (
            "institutions should contain 'Medical Center'"
        )
        assert "Clinic" in FAKE_DATA_POOLS["institutions"], (
            "institutions should contain 'Clinic'"
        )

        assert "CT" in FAKE_DATA_POOLS["modalities"], "modalities should contain 'CT'"
        assert "MR" in FAKE_DATA_POOLS["modalities"], "modalities should contain 'MR'"
        assert "US" in FAKE_DATA_POOLS["modalities"], "modalities should contain 'US'"
        assert "XR" in FAKE_DATA_POOLS["modalities"], "modalities should contain 'XR'"

        assert "GE" in FAKE_DATA_POOLS["manufacturers"], (
            "manufacturers should contain 'GE'"
        )
        assert "Siemens" in FAKE_DATA_POOLS["manufacturers"], (
            "manufacturers should contain 'Siemens'"
        )
        assert "Philips" in FAKE_DATA_POOLS["manufacturers"], (
            "manufacturers should contain 'Philips'"
        )


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
        assert len(FAKE_DATA_POOLS["institutions"]) >= 2, (
            "institutions pool should have at least 2 entries"
        )
        assert len(FAKE_DATA_POOLS["modalities"]) >= 2, (
            "modalities pool should have at least 2 entries"
        )
        assert len(FAKE_DATA_POOLS["manufacturers"]) >= 2, (
            "manufacturers pool should have at least 2 entries"
        )

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

            assert hasattr(config, "MUTATION_STRATEGIES"), (
                "config module should have MUTATION_STRATEGIES attribute"
            )
            assert hasattr(config, "FAKE_DATA_POOLS"), (
                "config module should have FAKE_DATA_POOLS attribute"
            )
        except ImportError as e:
            pytest.fail(f"Failed to import config module: {e}")

    def test_configuration_can_be_imported_multiple_times(self):
        """Test that configuration can be imported multiple times."""
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES as ms1
        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES as ms2

        # Should be the same object
        assert ms1 is ms2, "Multiple imports should return the same object"


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

        assert isinstance(institution, str), "Selected institution should be a string"
        assert isinstance(modality, str), "Selected modality should be a string"
        assert isinstance(manufacturer, str), "Selected manufacturer should be a string"

    def test_max_mutations_as_range_limit(self):
        """Test using max_mutations_per_file as a range limit."""
        import random

        from dicom_fuzzer.utils.config import MUTATION_STRATEGIES

        max_mutations = MUTATION_STRATEGIES["max_mutations_per_file"]

        # Simulate selecting number of mutations
        num_mutations = random.randint(1, max_mutations)

        assert 1 <= num_mutations <= max_mutations, (
            f"num_mutations {num_mutations} should be in range [1, {max_mutations}]"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestPydanticConfiguration:
    """Test new Pydantic-based configuration system."""

    def test_settings_imports(self):
        """Test that new config module can be imported."""
        from dicom_fuzzer.core.config import Settings, get_settings

        assert Settings is not None, "Settings class should be importable"
        assert get_settings is not None, "get_settings function should be importable"

    def test_settings_default_values(self):
        """Test settings with default values."""
        from dicom_fuzzer.core.config import Settings

        settings = Settings()
        assert settings.app_name == "DICOM-Fuzzer", (
            f"app_name should be 'DICOM-Fuzzer', got '{settings.app_name}'"
        )
        assert settings.fuzzing.metadata_probability == 0.8, (
            f"metadata_probability should be 0.8, got {settings.fuzzing.metadata_probability}"
        )
        assert settings.security.max_file_size_mb == 100, (
            f"max_file_size_mb should be 100, got {settings.security.max_file_size_mb}"
        )

    def test_environment_helpers(self):
        """Test environment helper methods."""
        from dicom_fuzzer.core.config import Environment, Settings

        settings = Settings(environment=Environment.DEVELOPMENT)
        assert settings.is_development() is True, "is_development() should return True"
        assert settings.is_testing() is False, (
            "is_testing() should return False in dev mode"
        )
        assert settings.is_production() is False, (
            "is_production() should return False in dev mode"
        )

    def test_get_settings_singleton(self):
        """Test settings singleton behavior."""
        from dicom_fuzzer.core.config import get_settings

        settings1 = get_settings(force_reload=True)
        settings2 = get_settings()

        assert settings1 is settings2, "get_settings should return singleton instance"

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

            assert test_path.exists(), (
                f"Path {test_path} should be created automatically"
            )
            assert test_path.is_dir(), f"Path {test_path} should be a directory"

    def test_settings_get_summary(self):
        """Test Settings.get_summary method (line 257)."""
        from dicom_fuzzer.core.config import Settings

        settings = Settings()
        summary = settings.get_summary()

        # Check that summary contains expected sections
        assert "DICOM-Fuzzer Configuration" in summary, (
            "Summary should contain 'DICOM-Fuzzer Configuration'"
        )
        assert "Environment:" in summary, "Summary should contain 'Environment:'"
        assert "Debug Mode:" in summary, "Summary should contain 'Debug Mode:'"
        assert "Fuzzing:" in summary, "Summary should contain 'Fuzzing:'"

    def test_load_profile(self):
        """Test load_profile function (lines 328-329)."""
        import os

        from dicom_fuzzer.core.config import load_profile

        # Save original environment
        original_env = os.environ.get("ENVIRONMENT")

        try:
            # Test loading development profile
            settings = load_profile("development")

            assert settings is not None, "load_profile should return Settings instance"
            assert os.environ["ENVIRONMENT"] == "development", (
                "ENVIRONMENT should be set to 'development'"
            )
        finally:
            # Restore original environment
            if original_env:
                os.environ["ENVIRONMENT"] = original_env
            elif "ENVIRONMENT" in os.environ:
                del os.environ["ENVIRONMENT"]

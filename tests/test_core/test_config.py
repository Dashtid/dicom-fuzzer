"""Comprehensive tests for dicom_fuzzer.core.config module.

Tests Pydantic-based configuration management including environment handling,
settings validation, and profile loading.
"""

import os
from pathlib import Path

import pytest

from dicom_fuzzer.core.config import (
    Environment,
    FuzzingConfig,
    LoggingConfig,
    LogLevel,
    PathConfig,
    SecurityConfig,
    Settings,
    get_settings,
    load_profile,
)


class TestEnvironmentEnum:
    """Tests for Environment enum."""

    def test_development_value(self):
        """Test development environment value."""
        assert Environment.DEVELOPMENT.value == "development"

    def test_testing_value(self):
        """Test testing environment value."""
        assert Environment.TESTING.value == "testing"

    def test_production_value(self):
        """Test production environment value."""
        assert Environment.PRODUCTION.value == "production"

    def test_environment_is_str(self):
        """Test that Environment enum inherits from str."""
        assert isinstance(Environment.DEVELOPMENT, str)


class TestLogLevelEnum:
    """Tests for LogLevel enum."""

    def test_all_log_levels(self):
        """Test all log level values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"


class TestFuzzingConfig:
    """Tests for FuzzingConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = FuzzingConfig()
        assert config.metadata_probability == 0.8
        assert config.header_probability == 0.6
        assert config.pixel_probability == 0.3
        assert config.max_mutations_per_file == 3
        assert config.max_files_per_campaign == 1000
        assert config.max_campaign_duration_minutes == 60
        assert config.batch_size == 10
        assert config.parallel_workers == 4

    def test_custom_values(self):
        """Test custom configuration values."""
        config = FuzzingConfig(
            metadata_probability=0.5,
            header_probability=0.3,
            pixel_probability=0.1,
            max_mutations_per_file=5,
            batch_size=20,
        )
        assert config.metadata_probability == 0.5
        assert config.header_probability == 0.3
        assert config.pixel_probability == 0.1
        assert config.max_mutations_per_file == 5
        assert config.batch_size == 20

    def test_probability_bounds(self):
        """Test probability field bounds validation."""
        # Valid bounds
        config = FuzzingConfig(metadata_probability=0.0)
        assert config.metadata_probability == 0.0

        config = FuzzingConfig(metadata_probability=1.0)
        assert config.metadata_probability == 1.0

    def test_invalid_probability_bounds(self):
        """Test invalid probability values raise errors."""
        with pytest.raises(ValueError):
            FuzzingConfig(metadata_probability=-0.1)

        with pytest.raises(ValueError):
            FuzzingConfig(metadata_probability=1.1)

    def test_mutations_per_file_bounds(self):
        """Test mutations_per_file field bounds."""
        config = FuzzingConfig(max_mutations_per_file=1)
        assert config.max_mutations_per_file == 1

        config = FuzzingConfig(max_mutations_per_file=100)
        assert config.max_mutations_per_file == 100

    def test_invalid_mutations_bounds(self):
        """Test invalid mutations values raise errors."""
        with pytest.raises(ValueError):
            FuzzingConfig(max_mutations_per_file=0)

        with pytest.raises(ValueError):
            FuzzingConfig(max_mutations_per_file=101)


class TestSecurityConfig:
    """Tests for SecurityConfig class."""

    def test_default_values(self):
        """Test default security configuration."""
        config = SecurityConfig()
        assert config.max_file_size_mb == 100
        assert config.max_elements == 10000
        assert config.max_sequence_depth == 10
        assert config.max_private_tags == 100
        assert config.max_private_data_mb == 1
        assert config.strict_validation is False
        assert config.detect_null_bytes is True
        assert config.detect_long_values is True

    def test_custom_values(self):
        """Test custom security configuration."""
        config = SecurityConfig(
            max_file_size_mb=50,
            strict_validation=True,
            detect_null_bytes=False,
        )
        assert config.max_file_size_mb == 50
        assert config.strict_validation is True
        assert config.detect_null_bytes is False

    def test_file_size_bounds(self):
        """Test file size bounds."""
        config = SecurityConfig(max_file_size_mb=1)
        assert config.max_file_size_mb == 1

        config = SecurityConfig(max_file_size_mb=1000)
        assert config.max_file_size_mb == 1000

    def test_invalid_file_size_bounds(self):
        """Test invalid file size raises errors."""
        with pytest.raises(ValueError):
            SecurityConfig(max_file_size_mb=0)

        with pytest.raises(ValueError):
            SecurityConfig(max_file_size_mb=1001)


class TestPathConfig:
    """Tests for PathConfig class."""

    def test_default_paths(self, tmp_path, monkeypatch):
        """Test default path values."""
        # Change to tmp_path so directory creation works
        monkeypatch.chdir(tmp_path)
        config = PathConfig()
        assert config.input_dir == Path("./samples")
        assert config.output_dir == Path("./artifacts/fuzzed")
        assert config.crash_dir == Path("./artifacts/crashes")
        assert config.report_dir == Path("./artifacts/reports")
        assert config.log_dir == Path("./artifacts/logs")
        assert config.dicom_file_pattern == "*.dcm"

    def test_custom_paths(self, tmp_path):
        """Test custom path values."""
        config = PathConfig(
            input_dir=tmp_path / "custom_input",
            output_dir=tmp_path / "custom_output",
        )
        assert config.input_dir == tmp_path / "custom_input"
        assert config.output_dir == tmp_path / "custom_output"

    def test_directories_created(self, tmp_path):
        """Test that directories are created automatically."""
        input_dir = tmp_path / "new_input"
        output_dir = tmp_path / "new_output"

        config = PathConfig(input_dir=input_dir, output_dir=output_dir)

        assert input_dir.exists()
        assert output_dir.exists()


class TestLoggingConfig:
    """Tests for LoggingConfig class."""

    def test_default_values(self):
        """Test default logging configuration."""
        config = LoggingConfig()
        assert config.log_level == LogLevel.INFO
        assert config.log_format == "json"
        assert config.log_to_file is True
        assert config.log_to_console is True
        assert config.max_log_file_mb == 10
        assert config.log_rotation_count == 5

    def test_custom_values(self):
        """Test custom logging configuration."""
        config = LoggingConfig(
            log_level=LogLevel.DEBUG,
            log_format="console",
            log_to_file=False,
        )
        assert config.log_level == LogLevel.DEBUG
        assert config.log_format == "console"
        assert config.log_to_file is False


class TestSettings:
    """Tests for main Settings class."""

    def test_default_values(self, tmp_path, monkeypatch):
        """Test default settings."""
        monkeypatch.chdir(tmp_path)
        # Clear ENVIRONMENT env var to test true defaults
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        settings = Settings()
        assert settings.app_name == "DICOM-Fuzzer"
        assert settings.app_version == "1.0.0"
        assert settings.environment == Environment.DEVELOPMENT
        assert settings.debug is False
        assert settings.enable_profiling is False
        assert settings.enable_crash_analysis is True
        assert settings.enable_statistics is True

    def test_environment_helper_methods(self, tmp_path, monkeypatch):
        """Test is_development, is_testing, is_production methods."""
        monkeypatch.chdir(tmp_path)

        settings = Settings(environment=Environment.DEVELOPMENT)
        assert settings.is_development() is True
        assert settings.is_testing() is False
        assert settings.is_production() is False

        settings = Settings(environment=Environment.TESTING)
        assert settings.is_development() is False
        assert settings.is_testing() is True
        assert settings.is_production() is False

        settings = Settings(environment=Environment.PRODUCTION)
        assert settings.is_development() is False
        assert settings.is_testing() is False
        assert settings.is_production() is True

    def test_environment_validation(self, tmp_path, monkeypatch):
        """Test environment validation normalizes to lowercase."""
        monkeypatch.chdir(tmp_path)
        settings = Settings(environment="DEVELOPMENT")
        assert settings.environment == Environment.DEVELOPMENT

    def test_get_summary(self, tmp_path, monkeypatch):
        """Test get_summary method."""
        monkeypatch.chdir(tmp_path)
        # Clear ENVIRONMENT env var to test true defaults
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        settings = Settings()
        summary = settings.get_summary()

        assert "DICOM-Fuzzer Configuration" in summary
        assert "development" in summary
        assert "Metadata Probability" in summary
        assert "Max File Size" in summary
        assert "Level: INFO" in summary

    def test_sub_configurations(self, tmp_path, monkeypatch):
        """Test sub-configuration objects are properly initialized."""
        monkeypatch.chdir(tmp_path)
        settings = Settings()

        assert isinstance(settings.fuzzing, FuzzingConfig)
        assert isinstance(settings.security, SecurityConfig)
        assert isinstance(settings.paths, PathConfig)
        assert isinstance(settings.logging, LoggingConfig)


class TestGetSettings:
    """Tests for get_settings singleton function."""

    def test_singleton_behavior(self, tmp_path, monkeypatch):
        """Test that get_settings returns same instance."""
        monkeypatch.chdir(tmp_path)

        # Reset global settings
        import dicom_fuzzer.core.config as config_module

        config_module._settings = None

        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_force_reload(self, tmp_path, monkeypatch):
        """Test force_reload creates new instance."""
        monkeypatch.chdir(tmp_path)

        # Reset global settings
        import dicom_fuzzer.core.config as config_module

        config_module._settings = None

        settings1 = get_settings()
        settings2 = get_settings(force_reload=True)
        assert settings1 is not settings2


class TestLoadProfile:
    """Tests for load_profile function."""

    def test_load_development_profile(self, tmp_path, monkeypatch):
        """Test loading development profile."""
        monkeypatch.chdir(tmp_path)
        settings = load_profile("development")
        assert settings.environment == Environment.DEVELOPMENT

    def test_load_testing_profile(self, tmp_path, monkeypatch):
        """Test loading testing profile."""
        monkeypatch.chdir(tmp_path)
        settings = load_profile("testing")
        assert settings.environment == Environment.TESTING

    def test_load_production_profile(self, tmp_path, monkeypatch):
        """Test loading production profile."""
        monkeypatch.chdir(tmp_path)
        settings = load_profile("production")
        assert settings.environment == Environment.PRODUCTION

    def test_profile_sets_environment_variable(self, tmp_path, monkeypatch):
        """Test that load_profile sets ENVIRONMENT env var."""
        monkeypatch.chdir(tmp_path)

        # Clear any existing env var
        if "ENVIRONMENT" in os.environ:
            del os.environ["ENVIRONMENT"]

        load_profile("testing")
        assert os.environ.get("ENVIRONMENT") == "testing"


class TestEnvironmentVariables:
    """Tests for environment variable integration."""

    def test_env_var_override(self, tmp_path, monkeypatch):
        """Test that environment variables override defaults."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("DEBUG", "true")

        settings = Settings()
        assert settings.environment == Environment.PRODUCTION
        assert settings.debug is True

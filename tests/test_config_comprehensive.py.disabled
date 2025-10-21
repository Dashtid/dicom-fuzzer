"""Comprehensive tests for dicom_fuzzer.core.config module.

This test suite provides thorough coverage of configuration management,
environment handling, validation, and singleton patterns.
"""

import os
from pathlib import Path
from unittest.mock import patch

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
    """Test suite for Environment enum."""

    def test_all_environments_defined(self):
        """Test all environment values are defined."""
        assert Environment.DEVELOPMENT.value == "development"
        assert Environment.TESTING.value == "testing"
        assert Environment.PRODUCTION.value == "production"

    def test_environment_is_string_enum(self):
        """Test Environment is a string enum."""
        assert isinstance(Environment.DEVELOPMENT, str)
        assert isinstance(Environment.TESTING, str)


class TestLogLevelEnum:
    """Test suite for LogLevel enum."""

    def test_all_log_levels_defined(self):
        """Test all log levels are defined."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"


class TestFuzzingConfig:
    """Test suite for FuzzingConfig."""

    def test_default_initialization(self):
        """Test FuzzingConfig with default values."""
        config = FuzzingConfig()

        assert config.metadata_probability == 0.8
        assert config.header_probability == 0.6
        assert config.pixel_probability == 0.3
        assert config.max_mutations_per_file == 3
        assert config.max_files_per_campaign == 1000
        assert config.max_campaign_duration_minutes == 60
        assert config.batch_size == 10
        assert config.parallel_workers == 4

    def test_custom_probabilities(self):
        """Test FuzzingConfig with custom probability values."""
        config = FuzzingConfig(
            metadata_probability=0.9,
            header_probability=0.7,
            pixel_probability=0.5,
        )

        assert config.metadata_probability == 0.9
        assert config.header_probability == 0.7
        assert config.pixel_probability == 0.5

    def test_probability_validation_min(self):
        """Test probability validation at minimum bound."""
        config = FuzzingConfig(metadata_probability=0.0)
        assert config.metadata_probability == 0.0

    def test_probability_validation_max(self):
        """Test probability validation at maximum bound."""
        config = FuzzingConfig(metadata_probability=1.0)
        assert config.metadata_probability == 1.0

    def test_probability_validation_below_min(self):
        """Test probability validation fails below minimum."""
        with pytest.raises(ValueError):
            FuzzingConfig(metadata_probability=-0.1)

    def test_probability_validation_above_max(self):
        """Test probability validation fails above maximum."""
        with pytest.raises(ValueError):
            FuzzingConfig(metadata_probability=1.1)

    def test_max_mutations_validation(self):
        """Test max mutations per file validation."""
        config = FuzzingConfig(max_mutations_per_file=50)
        assert config.max_mutations_per_file == 50

    def test_max_mutations_min_bound(self):
        """Test max mutations minimum bound."""
        config = FuzzingConfig(max_mutations_per_file=1)
        assert config.max_mutations_per_file == 1

    def test_max_mutations_below_min(self):
        """Test max mutations validation fails below minimum."""
        with pytest.raises(ValueError):
            FuzzingConfig(max_mutations_per_file=0)

    def test_batch_size_validation(self):
        """Test batch size validation."""
        config = FuzzingConfig(batch_size=100)
        assert config.batch_size == 100

    def test_parallel_workers_validation(self):
        """Test parallel workers validation."""
        config = FuzzingConfig(parallel_workers=16)
        assert config.parallel_workers == 16


class TestSecurityConfig:
    """Test suite for SecurityConfig."""

    def test_default_initialization(self):
        """Test SecurityConfig with default values."""
        config = SecurityConfig()

        assert config.max_file_size_mb == 100
        assert config.max_elements == 10000
        assert config.max_sequence_depth == 10
        assert config.max_private_tags == 100
        assert config.max_private_data_mb == 1
        assert config.strict_validation is False
        assert config.detect_null_bytes is True
        assert config.detect_long_values is True

    def test_custom_file_size_limits(self):
        """Test SecurityConfig with custom file size."""
        config = SecurityConfig(max_file_size_mb=500)
        assert config.max_file_size_mb == 500

    def test_strict_validation_enabled(self):
        """Test SecurityConfig with strict validation."""
        config = SecurityConfig(strict_validation=True)
        assert config.strict_validation is True

    def test_max_elements_validation(self):
        """Test max elements validation."""
        config = SecurityConfig(max_elements=5000)
        assert config.max_elements == 5000

    def test_max_sequence_depth_bounds(self):
        """Test max sequence depth bounds."""
        config_min = SecurityConfig(max_sequence_depth=1)
        config_max = SecurityConfig(max_sequence_depth=50)

        assert config_min.max_sequence_depth == 1
        assert config_max.max_sequence_depth == 50

    def test_detection_flags(self):
        """Test security detection flags."""
        config = SecurityConfig(detect_null_bytes=False, detect_long_values=False)

        assert config.detect_null_bytes is False
        assert config.detect_long_values is False


class TestPathConfig:
    """Test suite for PathConfig."""

    def test_default_initialization(self, tmp_path):
        """Test PathConfig with default values."""
        with patch.object(Path, "mkdir"):
            config = PathConfig()

            assert config.input_dir == Path("./samples")
            assert config.output_dir == Path("./output")
            assert config.crash_dir == Path("./crashes")
            assert config.report_dir == Path("./reports")
            assert config.log_dir == Path("./logs")
            assert config.dicom_file_pattern == "*.dcm"

    def test_custom_paths(self, tmp_path):
        """Test PathConfig with custom paths."""
        config = PathConfig(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            crash_dir=tmp_path / "crashes",
            report_dir=tmp_path / "reports",
            log_dir=tmp_path / "logs",
        )

        assert config.input_dir == tmp_path / "input"
        assert config.output_dir == tmp_path / "output"

    def test_directory_creation(self, tmp_path):
        """Test that directories are created automatically."""
        input_dir = tmp_path / "auto_created" / "input"
        output_dir = tmp_path / "auto_created" / "output"

        config = PathConfig(input_dir=input_dir, output_dir=output_dir)

        assert config.input_dir.exists()
        assert config.output_dir.exists()

    def test_dicom_file_pattern_custom(self):
        """Test custom DICOM file pattern."""
        config = PathConfig(dicom_file_pattern="*.dicom")
        assert config.dicom_file_pattern == "*.dicom"


class TestLoggingConfig:
    """Test suite for LoggingConfig."""

    def test_default_initialization(self):
        """Test LoggingConfig with default values."""
        config = LoggingConfig()

        assert config.log_level == LogLevel.INFO
        assert config.log_format == "json"
        assert config.log_to_file is True
        assert config.log_to_console is True
        assert config.max_log_file_mb == 10
        assert config.log_rotation_count == 5

    def test_custom_log_level(self):
        """Test LoggingConfig with custom log level."""
        config = LoggingConfig(log_level=LogLevel.DEBUG)
        assert config.log_level == LogLevel.DEBUG

    def test_console_format(self):
        """Test LoggingConfig with console format."""
        config = LoggingConfig(log_format="console")
        assert config.log_format == "console"

    def test_file_logging_disabled(self):
        """Test LoggingConfig with file logging disabled."""
        config = LoggingConfig(log_to_file=False)
        assert config.log_to_file is False

    def test_log_rotation_settings(self):
        """Test LoggingConfig rotation settings."""
        config = LoggingConfig(max_log_file_mb=20, log_rotation_count=10)

        assert config.max_log_file_mb == 20
        assert config.log_rotation_count == 10


class TestSettings:
    """Test suite for main Settings class."""

    def test_default_initialization(self):
        """Test Settings with default values."""
        with patch.object(Path, "mkdir"):
            settings = Settings()

            assert settings.app_name == "DICOM-Fuzzer"
            assert settings.app_version == "1.0.0"
            assert settings.environment == Environment.DEVELOPMENT
            assert settings.debug is False
            assert isinstance(settings.fuzzing, FuzzingConfig)
            assert isinstance(settings.security, SecurityConfig)
            assert isinstance(settings.paths, PathConfig)
            assert isinstance(settings.logging, LoggingConfig)

    def test_custom_app_settings(self):
        """Test Settings with custom app settings."""
        with patch.object(Path, "mkdir"):
            settings = Settings(
                app_name="CustomFuzzer", app_version="2.0.0", debug=True
            )

            assert settings.app_name == "CustomFuzzer"
            assert settings.app_version == "2.0.0"
            assert settings.debug is True

    def test_environment_validation(self):
        """Test environment validation."""
        with patch.object(Path, "mkdir"):
            settings = Settings(environment="production")
            assert settings.environment == Environment.PRODUCTION

    def test_is_development(self):
        """Test is_development method."""
        with patch.object(Path, "mkdir"):
            settings = Settings(environment=Environment.DEVELOPMENT)
            assert settings.is_development() is True
            assert settings.is_testing() is False
            assert settings.is_production() is False

    def test_is_testing(self):
        """Test is_testing method."""
        with patch.object(Path, "mkdir"):
            settings = Settings(environment=Environment.TESTING)
            assert settings.is_development() is False
            assert settings.is_testing() is True
            assert settings.is_production() is False

    def test_is_production(self):
        """Test is_production method."""
        with patch.object(Path, "mkdir"):
            settings = Settings(environment=Environment.PRODUCTION)
            assert settings.is_development() is False
            assert settings.is_testing() is False
            assert settings.is_production() is True

    def test_get_summary(self):
        """Test get_summary method."""
        with patch.object(Path, "mkdir"):
            settings = Settings()
            summary = settings.get_summary()

            assert "DICOM-Fuzzer Configuration" in summary
            assert "Environment:" in summary
            assert "Fuzzing:" in summary
            assert "Security:" in summary
            assert "Paths:" in summary
            assert "Logging:" in summary
            assert "Features:" in summary

    def test_nested_fuzzing_config(self):
        """Test nested fuzzing configuration."""
        with patch.object(Path, "mkdir"):
            settings = Settings()
            assert settings.fuzzing.metadata_probability == 0.8

    def test_nested_security_config(self):
        """Test nested security configuration."""
        with patch.object(Path, "mkdir"):
            settings = Settings()
            assert settings.security.max_file_size_mb == 100

    def test_feature_flags(self):
        """Test feature flags."""
        with patch.object(Path, "mkdir"):
            settings = Settings(
                enable_profiling=True,
                enable_crash_analysis=False,
                enable_statistics=False,
            )

            assert settings.enable_profiling is True
            assert settings.enable_crash_analysis is False
            assert settings.enable_statistics is False


class TestGetSettings:
    """Test suite for get_settings singleton function."""

    def test_get_settings_returns_singleton(self):
        """Test get_settings returns same instance."""
        with patch.object(Path, "mkdir"):
            settings1 = get_settings()
            settings2 = get_settings()

            assert settings1 is settings2

    def test_get_settings_force_reload(self):
        """Test get_settings with force_reload."""
        with patch.object(Path, "mkdir"):
            settings1 = get_settings()
            settings2 = get_settings(force_reload=True)

            # Should be different instances
            assert settings1 is not settings2

    def test_get_settings_returns_settings_instance(self):
        """Test get_settings returns Settings instance."""
        with patch.object(Path, "mkdir"):
            settings = get_settings()
            assert isinstance(settings, Settings)


class TestLoadProfile:
    """Test suite for load_profile function."""

    def test_load_development_profile(self):
        """Test loading development profile."""
        with patch.object(Path, "mkdir"):
            settings = load_profile("development")
            assert settings.environment == Environment.DEVELOPMENT

    def test_load_testing_profile(self):
        """Test loading testing profile."""
        with patch.object(Path, "mkdir"):
            settings = load_profile("testing")
            assert settings.environment == Environment.TESTING

    def test_load_production_profile(self):
        """Test loading production profile."""
        with patch.object(Path, "mkdir"):
            settings = load_profile("production")
            assert settings.environment == Environment.PRODUCTION

    def test_load_profile_sets_environment_variable(self):
        """Test load_profile sets ENVIRONMENT variable."""
        with patch.object(Path, "mkdir"):
            load_profile("testing")
            assert os.environ.get("ENVIRONMENT") == "testing"


class TestEnvironmentVariableLoading:
    """Test suite for environment variable loading."""

    def test_load_from_environment_variables(self):
        """Test loading settings from environment variables."""
        with patch.object(Path, "mkdir"):
            with patch.dict(
                os.environ,
                {
                    "APP_NAME": "EnvFuzzer",
                    "APP_VERSION": "3.0.0",
                    "DEBUG": "true",
                    "ENVIRONMENT": "production",
                },
            ):
                settings = Settings()

                assert settings.app_name == "EnvFuzzer"
                assert settings.app_version == "3.0.0"
                assert settings.debug is True
                assert settings.environment == Environment.PRODUCTION

    def test_nested_config_from_env(self):
        """Test loading nested configuration from environment."""
        with patch.object(Path, "mkdir"):
            with patch.dict(
                os.environ,
                {
                    "FUZZING__METADATA_PROBABILITY": "0.95",
                    "FUZZING__MAX_MUTATIONS_PER_FILE": "10",
                    "SECURITY__MAX_FILE_SIZE_MB": "200",
                },
            ):
                settings = Settings()

                assert settings.fuzzing.metadata_probability == 0.95
                assert settings.fuzzing.max_mutations_per_file == 10
                assert settings.security.max_file_size_mb == 200


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_configuration_workflow(self, tmp_path):
        """Test complete configuration workflow."""
        # Set up environment
        with patch.dict(os.environ, {"ENVIRONMENT": "testing"}):
            settings = Settings(
                paths=PathConfig(
                    input_dir=tmp_path / "input",
                    output_dir=tmp_path / "output",
                    crash_dir=tmp_path / "crashes",
                    report_dir=tmp_path / "reports",
                    log_dir=tmp_path / "logs",
                )
            )

            # Verify environment
            assert settings.is_testing()

            # Verify directories created
            assert settings.paths.input_dir.exists()
            assert settings.paths.output_dir.exists()

            # Verify all configurations accessible
            assert settings.fuzzing.metadata_probability > 0
            assert settings.security.max_file_size_mb > 0
            assert settings.logging.log_level in LogLevel

    def test_production_configuration(self):
        """Test production-like configuration."""
        with patch.object(Path, "mkdir"):
            settings = Settings(
                environment=Environment.PRODUCTION,
                debug=False,
                fuzzing=FuzzingConfig(max_files_per_campaign=10000),
                security=SecurityConfig(strict_validation=True, max_file_size_mb=50),
                logging=LoggingConfig(log_level=LogLevel.WARNING),
            )

            assert settings.is_production()
            assert settings.debug is False
            assert settings.fuzzing.max_files_per_campaign == 10000
            assert settings.security.strict_validation is True
            assert settings.logging.log_level == LogLevel.WARNING

    def test_development_configuration(self):
        """Test development-like configuration."""
        with patch.object(Path, "mkdir"):
            settings = Settings(
                environment=Environment.DEVELOPMENT,
                debug=True,
                logging=LoggingConfig(log_level=LogLevel.DEBUG, log_format="console"),
            )

            assert settings.is_development()
            assert settings.debug is True
            assert settings.logging.log_level == LogLevel.DEBUG
            assert settings.logging.log_format == "console"

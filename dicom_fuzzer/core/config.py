"""Configuration Management - Environment-Specific Settings.

Provides environment-aware configuration with validation. Supports
development, testing, and production environments with appropriate
defaults and security settings.
"""

import os
from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Application environment types.

    - DEVELOPMENT: Local development with debug features
    - TESTING: CI/CD and test automation
    - PRODUCTION: Live deployment with strict security
    """

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    """Logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class FuzzingConfig(BaseSettings):
    """Fuzzing campaign configuration.

    Controls the behavior and intensity of fuzzing campaigns.
    """

    # Mutation probabilities (0.0 - 1.0)
    metadata_probability: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Probability of mutating metadata tags",
    )
    header_probability: float = Field(
        default=0.6, ge=0.0, le=1.0, description="Probability of mutating header"
    )
    pixel_probability: float = Field(
        default=0.3, ge=0.0, le=1.0, description="Probability of mutating pixel data"
    )

    # Campaign limits
    max_mutations_per_file: int = Field(
        default=3, ge=1, le=100, description="Maximum mutations per DICOM file"
    )
    max_files_per_campaign: int = Field(
        default=1000, ge=1, description="Maximum files to generate per campaign"
    )
    max_campaign_duration_minutes: int = Field(
        default=60, ge=1, description="Maximum campaign duration in minutes"
    )

    # Performance settings
    batch_size: int = Field(
        default=10, ge=1, le=1000, description="Number of files to process in batch"
    )
    parallel_workers: int = Field(
        default=4, ge=1, le=32, description="Number of parallel worker processes"
    )


class SecurityConfig(BaseSettings):
    """Security validation configuration.

    Thresholds to prevent generation of excessively large or malicious
    files that could harm testing infrastructure.
    """

    # File size limits
    max_file_size_mb: int = Field(
        default=100, ge=1, le=1000, description="Maximum DICOM file size in MB"
    )

    # Element limits
    max_elements: int = Field(
        default=10000, ge=100, description="Maximum DICOM elements per file"
    )
    max_sequence_depth: int = Field(
        default=10, ge=1, le=50, description="Maximum nested sequence depth"
    )
    max_private_tags: int = Field(
        default=100, ge=0, description="Maximum private tags allowed"
    )
    max_private_data_mb: int = Field(
        default=1, ge=0, le=10, description="Maximum private tag data in MB"
    )

    # Validation settings
    strict_validation: bool = Field(
        default=False, description="Enable strict DICOM compliance validation"
    )
    detect_null_bytes: bool = Field(
        default=True, description="Detect null byte injection attempts"
    )
    detect_long_values: bool = Field(
        default=True, description="Detect excessively long string values"
    )


class PathConfig(BaseSettings):
    """File system paths configuration.

    Centralized path management for consistent directory structure.
    """

    # Base directories
    input_dir: Path = Field(
        default=Path("./samples"), description="Input DICOM files directory"
    )
    output_dir: Path = Field(
        default=Path("./artifacts/fuzzed"),
        description="Generated fuzzed files directory",
    )
    crash_dir: Path = Field(
        default=Path("./artifacts/crashes"), description="Crash reports directory"
    )
    report_dir: Path = Field(
        default=Path("./artifacts/reports"), description="HTML/JSON reports directory"
    )
    log_dir: Path = Field(
        default=Path("./artifacts/logs"), description="Log files directory"
    )

    # File patterns
    dicom_file_pattern: str = Field(
        default="*.dcm", description="DICOM file glob pattern"
    )

    @field_validator("input_dir", "output_dir", "crash_dir", "report_dir", "log_dir")
    @classmethod
    def ensure_directory_exists(cls, v: Path) -> Path:
        """Create directory if it doesn't exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v


class LoggingConfig(BaseSettings):
    """Logging configuration.

    Environment-specific verbosity and output settings.
    """

    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    log_format: str = Field(default="json", description="Log format: json or console")
    log_to_file: bool = Field(default=True, description="Enable file logging")
    log_to_console: bool = Field(default=True, description="Enable console logging")
    max_log_file_mb: int = Field(
        default=10, ge=1, le=100, description="Maximum log file size in MB"
    )
    log_rotation_count: int = Field(
        default=5, ge=1, le=20, description="Number of rotated log files to keep"
    )


class Settings(BaseSettings):
    """Main application settings.

    Hierarchical configuration with validation. Loads from environment
    variables and .env file.

    Usage:
        from dicom_fuzzer.core.config import get_settings
        settings = get_settings()
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    app_name: str = Field(default="DICOM-Fuzzer", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    environment: Environment = Field(
        default=Environment.DEVELOPMENT, description="Current environment"
    )
    debug: bool = Field(default=False, description="Debug mode")

    # Sub-configurations
    fuzzing: FuzzingConfig = Field(default_factory=FuzzingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Optional features
    enable_profiling: bool = Field(
        default=False, description="Enable performance profiling"
    )
    enable_crash_analysis: bool = Field(
        default=True, description="Enable crash analysis"
    )
    enable_statistics: bool = Field(
        default=True, description="Enable statistics collection"
    )

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate and normalize environment."""
        if isinstance(v, str):
            v = v.lower()
        return v

    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == Environment.DEVELOPMENT

    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.environment == Environment.TESTING

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == Environment.PRODUCTION

    def get_summary(self) -> str:
        """Get configuration summary."""
        return f"""
DICOM-Fuzzer Configuration
==========================
Environment: {self.environment.value}
Debug Mode: {self.debug}

Fuzzing:
  - Metadata Probability: {self.fuzzing.metadata_probability}
  - Header Probability: {self.fuzzing.header_probability}
  - Pixel Probability: {self.fuzzing.pixel_probability}
  - Max Mutations/File: {self.fuzzing.max_mutations_per_file}
  - Max Files/Campaign: {self.fuzzing.max_files_per_campaign}
  - Batch Size: {self.fuzzing.batch_size}
  - Workers: {self.fuzzing.parallel_workers}

Security:
  - Max File Size: {self.security.max_file_size_mb} MB
  - Max Elements: {self.security.max_elements}
  - Strict Validation: {self.security.strict_validation}

Paths:
  - Input: {self.paths.input_dir}
  - Output: {self.paths.output_dir}
  - Crashes: {self.paths.crash_dir}
  - Reports: {self.paths.report_dir}

Logging:
  - Level: {self.logging.log_level.value}
  - Format: {self.logging.log_format}
  - To File: {self.logging.log_to_file}

Features:
  - Profiling: {self.enable_profiling}
  - Crash Analysis: {self.enable_crash_analysis}
  - Statistics: {self.enable_statistics}
"""


# Global settings instance (singleton pattern)
_settings: Settings | None = None


def get_settings(force_reload: bool = False) -> Settings:
    """Get application settings (singleton).

    Args:
        force_reload: Force reload settings from environment

    Returns:
        Settings instance

    """
    global _settings
    if _settings is None or force_reload:
        _settings = Settings()
    return _settings


def load_profile(profile_name: str) -> Settings:
    """Load settings from specific profile.

    Args:
        profile_name: Profile name (development, testing, production)

    Returns:
        Settings instance configured for profile

    """
    os.environ["ENVIRONMENT"] = profile_name
    return Settings()

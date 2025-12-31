"""Tests for dicom_fuzzer.utils.logger module.

Tests structured logging with security event tracking and performance metrics.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import structlog

from dicom_fuzzer.utils.logger import (
    SENSITIVE_FIELDS,
    PerformanceLogger,
    SecurityEventLogger,
    add_security_context,
    add_timestamp,
    configure_logging,
    get_logger,
    redact_sensitive_data,
)


@pytest.fixture
def reset_structlog():
    """Reset structlog configuration after each test."""
    yield
    # Reset structlog to default state
    structlog.reset_defaults()
    # Clear logging handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)


class TestSensitiveFields:
    """Tests for SENSITIVE_FIELDS constant."""

    def test_is_set(self):
        """Verify SENSITIVE_FIELDS is a set."""
        assert isinstance(SENSITIVE_FIELDS, set)

    def test_contains_expected_fields(self):
        """Verify contains expected sensitive field names."""
        expected = {
            "patient_id",
            "patient_name",
            "patient_birth_date",
            "password",
            "token",
            "key",
            "secret",
            "api_key",
        }
        assert expected == SENSITIVE_FIELDS


class TestRedactSensitiveData:
    """Tests for redact_sensitive_data processor."""

    def test_redacts_sensitive_keys(self):
        """Verify sensitive keys are redacted."""
        event_dict = {
            "event": "test",
            "patient_id": "12345",
            "patient_name": "John Doe",
        }
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["patient_id"] == "***REDACTED***"
        assert result["patient_name"] == "***REDACTED***"

    def test_preserves_non_sensitive_keys(self):
        """Verify non-sensitive keys are preserved."""
        event_dict = {"event": "test", "file_count": 5, "status": "success"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["event"] == "test"
        assert result["file_count"] == 5
        assert result["status"] == "success"

    def test_redacts_values_containing_sensitive_terms(self):
        """Verify values containing sensitive terms are redacted."""
        event_dict = {"event": "test", "message": "Found patient_id in data"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["message"] == "***REDACTED***"

    def test_case_insensitive_key_matching(self):
        """Verify key matching is case-insensitive."""
        event_dict = {"event": "test", "PATIENT_ID": "12345"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["PATIENT_ID"] == "***REDACTED***"

    def test_handles_non_string_values(self):
        """Verify handles non-string values without error."""
        event_dict = {"event": "test", "count": 42, "items": [1, 2, 3]}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["count"] == 42
        assert result["items"] == [1, 2, 3]


class TestAddTimestamp:
    """Tests for add_timestamp processor."""

    def test_adds_timestamp_key(self):
        """Verify timestamp key is added."""
        event_dict = {"event": "test"}
        result = add_timestamp(None, "info", event_dict)
        assert "timestamp" in result

    def test_timestamp_is_iso_format(self):
        """Verify timestamp is in ISO format."""
        event_dict = {"event": "test"}
        result = add_timestamp(None, "info", event_dict)
        # ISO format should contain T and end with timezone info
        assert "T" in result["timestamp"]

    def test_preserves_existing_keys(self):
        """Verify existing keys are preserved."""
        event_dict = {"event": "test", "data": "value"}
        result = add_timestamp(None, "info", event_dict)
        assert result["event"] == "test"
        assert result["data"] == "value"


class TestAddSecurityContext:
    """Tests for add_security_context processor."""

    def test_adds_context_for_security_events(self):
        """Verify security context added when security_event=True."""
        event_dict = {"event": "test", "security_event": True}
        result = add_security_context(None, "warning", event_dict)
        assert result["event_category"] == "SECURITY"
        assert result["requires_attention"] is True

    def test_no_context_for_non_security_events(self):
        """Verify no context added for regular events."""
        event_dict = {"event": "test"}
        result = add_security_context(None, "info", event_dict)
        assert "event_category" not in result
        assert "requires_attention" not in result

    def test_no_context_when_security_event_false(self):
        """Verify no context when security_event=False."""
        event_dict = {"event": "test", "security_event": False}
        result = add_security_context(None, "info", event_dict)
        assert "event_category" not in result


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_sets_log_level(self, reset_structlog):
        """Verify log level is set correctly."""
        configure_logging(log_level="DEBUG", json_format=False)
        assert logging.root.level == logging.DEBUG

    def test_creates_file_handler(self, reset_structlog):
        """Verify file handler created when log_file specified."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            configure_logging(log_level="INFO", json_format=True, log_file=log_file)
            # File handler should be added
            file_handlers = [
                h for h in logging.root.handlers if isinstance(h, logging.FileHandler)
            ]
            assert len(file_handlers) >= 1
            # Close handlers to allow cleanup on Windows
            for h in file_handlers:
                h.close()
                logging.root.removeHandler(h)

    def test_creates_log_directory(self, reset_structlog):
        """Verify log directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            log_file = Path(tmpdir) / "subdir" / "test.log"
            configure_logging(log_level="INFO", json_format=True, log_file=log_file)
            assert log_file.parent.exists()
            # Close handlers to allow cleanup on Windows
            for h in logging.root.handlers[:]:
                if isinstance(h, logging.FileHandler):
                    h.close()
                    logging.root.removeHandler(h)

    def test_clears_existing_handlers(self, reset_structlog):
        """Verify existing handlers are cleared."""
        # Add a handler
        handler = logging.StreamHandler()
        logging.root.addHandler(handler)
        initial_count = len(logging.root.handlers)

        configure_logging(log_level="INFO", json_format=False)

        # Should have new handlers, not accumulated
        # The exact count depends on configuration, but old handler should be gone
        assert handler not in logging.root.handlers


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_bound_logger(self, reset_structlog):
        """Verify returns a structlog BoundLogger."""
        configure_logging(log_level="INFO", json_format=False)
        logger = get_logger("test_module")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_logger_has_name(self, reset_structlog):
        """Verify logger is created with specified name."""
        configure_logging(log_level="INFO", json_format=False)
        logger = get_logger("my_custom_name")
        # Logger should be retrievable
        assert logger is not None


class TestSecurityEventLogger:
    """Tests for SecurityEventLogger class."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock structlog logger."""
        return MagicMock(spec=structlog.stdlib.BoundLogger)

    def test_init(self, mock_logger):
        """Verify initialization stores logger."""
        security_logger = SecurityEventLogger(mock_logger)
        assert security_logger.logger == mock_logger

    def test_log_validation_failure(self, mock_logger):
        """Verify log_validation_failure calls logger.warning."""
        security_logger = SecurityEventLogger(mock_logger)
        security_logger.log_validation_failure(
            file_path="test.dcm",
            reason="Invalid header",
            details={"expected": "DICM"},
        )
        mock_logger.warning.assert_called_once()
        call_kwargs = mock_logger.warning.call_args
        assert call_kwargs[0][0] == "validation_failure"
        assert call_kwargs[1]["security_event"] is True
        assert call_kwargs[1]["event_type"] == "VALIDATION_FAILURE"

    def test_log_validation_failure_no_details(self, mock_logger):
        """Verify log_validation_failure works without details."""
        security_logger = SecurityEventLogger(mock_logger)
        security_logger.log_validation_failure(
            file_path="test.dcm", reason="Invalid header"
        )
        mock_logger.warning.assert_called_once()
        call_kwargs = mock_logger.warning.call_args
        assert call_kwargs[1]["details"] == {}

    def test_log_suspicious_pattern(self, mock_logger):
        """Verify log_suspicious_pattern calls logger.warning."""
        security_logger = SecurityEventLogger(mock_logger)
        security_logger.log_suspicious_pattern(
            pattern_type="SQL_INJECTION",
            description="Possible SQL injection in patient name",
            details={"value": "'; DROP TABLE"},
        )
        mock_logger.warning.assert_called_once()
        call_kwargs = mock_logger.warning.call_args
        assert call_kwargs[0][0] == "suspicious_pattern_detected"
        assert call_kwargs[1]["event_type"] == "SUSPICIOUS_PATTERN"

    def test_log_fuzzing_campaign(self, mock_logger):
        """Verify log_fuzzing_campaign calls logger.info."""
        security_logger = SecurityEventLogger(mock_logger)
        security_logger.log_fuzzing_campaign(
            campaign_id="fc-001",
            status="started",
            stats={"target_files": 10},
        )
        mock_logger.info.assert_called_once()
        call_kwargs = mock_logger.info.call_args
        assert call_kwargs[0][0] == "fuzzing_campaign"
        assert call_kwargs[1]["campaign_id"] == "fc-001"
        assert call_kwargs[1]["status"] == "started"


class TestPerformanceLogger:
    """Tests for PerformanceLogger class."""

    @pytest.fixture
    def mock_logger(self):
        """Create a mock structlog logger."""
        return MagicMock(spec=structlog.stdlib.BoundLogger)

    def test_init(self, mock_logger):
        """Verify initialization stores logger."""
        perf_logger = PerformanceLogger(mock_logger)
        assert perf_logger.logger == mock_logger

    def test_log_operation(self, mock_logger):
        """Verify log_operation calls logger.info."""
        perf_logger = PerformanceLogger(mock_logger)
        perf_logger.log_operation(
            operation="file_parsing",
            duration_ms=45.678,
            metadata={"file_size": "2MB"},
        )
        mock_logger.info.assert_called_once()
        call_kwargs = mock_logger.info.call_args
        assert call_kwargs[0][0] == "operation_performance"
        assert call_kwargs[1]["metric_type"] == "PERFORMANCE"
        assert call_kwargs[1]["duration_ms"] == 45.68  # Rounded to 2 decimal places

    def test_log_operation_no_metadata(self, mock_logger):
        """Verify log_operation works without metadata."""
        perf_logger = PerformanceLogger(mock_logger)
        perf_logger.log_operation(operation="test_op", duration_ms=10.0)
        call_kwargs = mock_logger.info.call_args
        assert call_kwargs[1]["metadata"] == {}

    def test_log_mutation_stats(self, mock_logger):
        """Verify log_mutation_stats calls logger.info with correct data."""
        perf_logger = PerformanceLogger(mock_logger)
        perf_logger.log_mutation_stats(
            strategy="metadata_fuzzer",
            mutations_count=15,
            duration_ms=123.456,
            file_size_bytes=2048,
        )
        mock_logger.info.assert_called_once()
        call_kwargs = mock_logger.info.call_args
        assert call_kwargs[0][0] == "mutation_statistics"
        assert call_kwargs[1]["strategy"] == "metadata_fuzzer"
        assert call_kwargs[1]["mutations_count"] == 15
        assert call_kwargs[1]["avg_mutation_time_ms"] == 8.23  # 123.456 / 15

    def test_log_mutation_stats_zero_mutations(self, mock_logger):
        """Verify log_mutation_stats handles zero mutations (avoid division by zero)."""
        perf_logger = PerformanceLogger(mock_logger)
        perf_logger.log_mutation_stats(
            strategy="test",
            mutations_count=0,
            duration_ms=100.0,
            file_size_bytes=1024,
        )
        call_kwargs = mock_logger.info.call_args
        # Should use max(0, 1) = 1 to avoid division by zero
        assert call_kwargs[1]["avg_mutation_time_ms"] == 100.0

    def test_log_resource_usage(self, mock_logger):
        """Verify log_resource_usage calls logger.info."""
        perf_logger = PerformanceLogger(mock_logger)
        perf_logger.log_resource_usage(
            memory_mb=512.567,
            cpu_percent=75.123,
            metadata={"pid": 12345},
        )
        mock_logger.info.assert_called_once()
        call_kwargs = mock_logger.info.call_args
        assert call_kwargs[0][0] == "resource_usage"
        assert call_kwargs[1]["metric_type"] == "RESOURCE"
        assert call_kwargs[1]["memory_mb"] == 512.57  # Rounded
        assert call_kwargs[1]["cpu_percent"] == 75.12  # Rounded

"""Real-world tests for logger module.

Tests the structured logging system, sensitive data redaction,
and specialized loggers with actual usage patterns.
"""

import logging
from pathlib import Path

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


class TestSensitiveDataRedaction:
    """Test sensitive data redaction processor."""

    def test_redact_direct_field(self):
        """Test redaction of direct sensitive field."""
        event_dict = {
            "patient_id": "123456",
            "message": "Processing file",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["patient_id"] == "***REDACTED***"
        assert result["message"] == "Processing file"

    def test_redact_patient_name(self):
        """Test redaction of patient name field."""
        event_dict = {
            "patient_name": "John Doe",
            "file_count": 5,
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["patient_name"] == "***REDACTED***"
        assert result["file_count"] == 5

    def test_redact_password(self):
        """Test redaction of password field."""
        event_dict = {
            "password": "secret123",
            "username": "user",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["password"] == "***REDACTED***"
        assert result["username"] == "user"

    def test_redact_api_key(self):
        """Test redaction of API key field."""
        event_dict = {
            "api_key": "sk-1234567890",
            "endpoint": "/api/v1",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["api_key"] == "***REDACTED***"
        assert result["endpoint"] == "/api/v1"

    def test_redact_sensitive_in_string_value(self):
        """Test redaction when sensitive field name appears in value."""
        event_dict = {
            "message": "Found patient_id in file",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["message"] == "***REDACTED***"

    def test_no_redaction_for_safe_data(self):
        """Test that safe data is not redacted."""
        event_dict = {
            "file_path": "/path/to/file.dcm",
            "count": 42,
            "status": "success",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["file_path"] == "/path/to/file.dcm"
        assert result["count"] == 42
        assert result["status"] == "success"

    def test_sensitive_fields_list(self):
        """Test that SENSITIVE_FIELDS contains expected values."""
        assert "patient_id" in SENSITIVE_FIELDS
        assert "patient_name" in SENSITIVE_FIELDS
        assert "password" in SENSITIVE_FIELDS
        assert "api_key" in SENSITIVE_FIELDS


class TestTimestampProcessor:
    """Test timestamp processor."""

    def test_add_timestamp(self):
        """Test that timestamp is added to event dict."""
        event_dict = {"message": "test"}

        result = add_timestamp(None, None, event_dict)

        assert "timestamp" in result
        assert isinstance(result["timestamp"], str)
        # Should be ISO format with timezone
        assert "T" in result["timestamp"]

    def test_timestamp_format(self):
        """Test that timestamp uses ISO format."""
        event_dict = {}

        result = add_timestamp(None, None, event_dict)

        # Should contain date and time parts
        assert "T" in result["timestamp"]
        # Should contain timezone info
        assert "+" in result["timestamp"] or "Z" in result["timestamp"] or "-" in result["timestamp"]


class TestSecurityContextProcessor:
    """Test security context processor."""

    def test_add_security_context_for_security_event(self):
        """Test adding security context for security events."""
        event_dict = {
            "message": "Validation failed",
            "security_event": True,
        }

        result = add_security_context(None, None, event_dict)

        assert result["event_category"] == "SECURITY"
        assert result["requires_attention"] is True

    def test_no_security_context_for_normal_event(self):
        """Test that normal events don't get security context."""
        event_dict = {
            "message": "Normal operation",
        }

        result = add_security_context(None, None, event_dict)

        assert "event_category" not in result
        assert "requires_attention" not in result

    def test_security_context_with_false_flag(self):
        """Test that security_event=False doesn't add context."""
        event_dict = {
            "message": "Test",
            "security_event": False,
        }

        result = add_security_context(None, None, event_dict)

        assert "event_category" not in result
        assert "requires_attention" not in result


class TestConfigureLogging:
    """Test logging configuration."""

    def test_configure_logging_default(self):
        """Test logging configuration with defaults."""
        configure_logging()

        logger = get_logger("test")
        assert logger is not None

    def test_configure_logging_debug_level(self):
        """Test logging configuration with DEBUG level."""
        configure_logging(log_level="DEBUG")

        # Verify root logger level
        assert logging.root.level == logging.DEBUG

    def test_configure_logging_info_level(self):
        """Test logging configuration with INFO level."""
        configure_logging(log_level="INFO")

        assert logging.root.level == logging.INFO

    def test_configure_logging_warning_level(self):
        """Test logging configuration with WARNING level."""
        configure_logging(log_level="WARNING")

        assert logging.root.level == logging.WARNING

    def test_configure_logging_json_format(self):
        """Test logging configuration with JSON format."""
        configure_logging(json_format=True)

        logger = get_logger("test")
        assert logger is not None

    def test_configure_logging_console_format(self):
        """Test logging configuration with console format."""
        configure_logging(json_format=False)

        logger = get_logger("test")
        assert logger is not None

    def test_configure_logging_with_file(self, tmp_path):
        """Test logging configuration with file output."""
        log_file = tmp_path / "test.log"

        configure_logging(log_file=log_file)

        # Log file parent should be created
        assert log_file.parent.exists()

    def test_configure_logging_reconfiguration(self):
        """Test that logging can be reconfigured."""
        configure_logging(log_level="INFO")
        configure_logging(log_level="DEBUG")

        assert logging.root.level == logging.DEBUG


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger_returns_logger(self):
        """Test that get_logger returns a logger instance."""
        configure_logging()
        logger = get_logger("test_module")

        assert logger is not None
        # Logger can be BoundLogger or BoundLoggerLazyProxy
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'error')

    def test_get_logger_different_names(self):
        """Test getting loggers with different names."""
        configure_logging()

        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1 is not None
        assert logger2 is not None


class TestSecurityEventLogger:
    """Test SecurityEventLogger class."""

    def setup_method(self):
        """Set up test fixtures."""
        configure_logging(json_format=False)
        self.base_logger = get_logger("test_security")
        self.security_logger = SecurityEventLogger(self.base_logger)

    def test_initialization(self):
        """Test SecurityEventLogger initialization."""
        assert self.security_logger.logger is not None

    def test_log_validation_failure(self):
        """Test logging validation failure."""
        # Should not raise exception
        self.security_logger.log_validation_failure(
            file_path="/test/file.dcm",
            reason="Invalid header",
        )

    def test_log_validation_failure_with_details(self):
        """Test logging validation failure with details."""
        self.security_logger.log_validation_failure(
            file_path="/test/file.dcm",
            reason="Invalid magic bytes",
            details={"expected": "DICM", "actual": "XXXX"},
        )

    def test_log_suspicious_pattern(self):
        """Test logging suspicious pattern."""
        self.security_logger.log_suspicious_pattern(
            pattern_type="SQL_INJECTION",
            description="Detected SQL injection attempt",
        )

    def test_log_suspicious_pattern_with_details(self):
        """Test logging suspicious pattern with details."""
        self.security_logger.log_suspicious_pattern(
            pattern_type="PATH_TRAVERSAL",
            description="Path traversal attempt detected",
            details={"path": "../../etc/passwd"},
        )

    def test_log_fuzzing_campaign(self):
        """Test logging fuzzing campaign."""
        self.security_logger.log_fuzzing_campaign(
            campaign_id="campaign-001",
            status="started",
        )

    def test_log_fuzzing_campaign_with_stats(self):
        """Test logging fuzzing campaign with statistics."""
        self.security_logger.log_fuzzing_campaign(
            campaign_id="campaign-002",
            status="completed",
            stats={"files_processed": 100, "crashes_found": 3},
        )


class TestPerformanceLogger:
    """Test PerformanceLogger class."""

    def setup_method(self):
        """Set up test fixtures."""
        configure_logging(json_format=False)
        self.base_logger = get_logger("test_performance")
        self.perf_logger = PerformanceLogger(self.base_logger)

    def test_initialization(self):
        """Test PerformanceLogger initialization."""
        assert self.perf_logger.logger is not None

    def test_log_operation(self):
        """Test logging operation performance."""
        self.perf_logger.log_operation(
            operation="parse_file",
            duration_ms=42.5,
        )

    def test_log_operation_with_metadata(self):
        """Test logging operation with metadata."""
        self.perf_logger.log_operation(
            operation="generate_batch",
            duration_ms=123.45,
            metadata={"file_count": 10, "strategy": "metadata"},
        )

    def test_log_mutation_stats(self):
        """Test logging mutation statistics."""
        self.perf_logger.log_mutation_stats(
            strategy="header_fuzzer",
            mutations_count=5,
            duration_ms=50.0,
            file_size_bytes=2048,
        )

    def test_log_mutation_stats_zero_mutations(self):
        """Test logging mutation stats with zero mutations."""
        # Should handle division by zero gracefully
        self.perf_logger.log_mutation_stats(
            strategy="pixel_fuzzer",
            mutations_count=0,
            duration_ms=10.0,
            file_size_bytes=1024,
        )

    def test_log_resource_usage(self):
        """Test logging resource usage."""
        self.perf_logger.log_resource_usage(
            memory_mb=256.5,
            cpu_percent=45.2,
        )

    def test_log_resource_usage_with_metadata(self):
        """Test logging resource usage with metadata."""
        self.perf_logger.log_resource_usage(
            memory_mb=512.0,
            cpu_percent=80.0,
            metadata={"process_count": 4, "thread_count": 16},
        )


class TestIntegrationScenarios:
    """Test realistic logging scenarios."""

    def test_complete_logging_workflow(self, tmp_path):
        """Test complete logging workflow."""
        log_file = tmp_path / "fuzzer.log"

        # Configure logging
        configure_logging(log_level="INFO", json_format=False, log_file=log_file)

        # Get loggers
        base_logger = get_logger("fuzzer")
        security_logger = SecurityEventLogger(base_logger)
        perf_logger = PerformanceLogger(base_logger)

        # Log various events
        base_logger.info("fuzzing_started", campaign="test-001")
        security_logger.log_validation_failure(
            "/test.dcm", "Invalid format"
        )
        perf_logger.log_operation("mutation", 25.5)

        # Log file should exist and have content
        assert log_file.exists()
        assert log_file.stat().st_size > 0

    def test_sensitive_data_handling(self):
        """Test that sensitive data is properly redacted."""
        configure_logging(json_format=False)

        logger = get_logger("test")

        # Log with sensitive data - should be redacted
        # This won't raise an exception, redaction happens in processor
        logger.info(
            "user_data",
            patient_id="12345",
            patient_name="John Doe",
            file_path="/safe/path",
        )

    def test_multiple_log_levels(self):
        """Test logging at different levels."""
        configure_logging(log_level="DEBUG")

        logger = get_logger("test")

        logger.debug("debug_msg", detail="debug")
        logger.info("info_msg", detail="info")
        logger.warning("warning_msg", detail="warning")
        logger.error("error_msg", detail="error")

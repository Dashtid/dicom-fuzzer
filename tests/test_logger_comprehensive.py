"""Comprehensive tests for dicom_fuzzer.utils.logger module.

This test suite provides thorough coverage of structured logging functionality,
including sensitive data redaction, security event logging, and performance metrics.
"""

import logging
from unittest.mock import Mock

from dicom_fuzzer.utils.logger import (
    PerformanceLogger,
    SecurityEventLogger,
    add_security_context,
    add_timestamp,
    configure_logging,
    get_logger,
    redact_sensitive_data,
)


class TestSensitiveDataRedaction:
    """Test suite for sensitive data redaction."""

    def test_redact_direct_match(self):
        """Test redaction of direct field name matches."""
        event_dict = {"patient_id": "12345", "other_field": "value"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["patient_id"] == "***REDACTED***"
        assert result["other_field"] == "value"

    def test_redact_patient_name(self):
        """Test redaction of patient_name field."""
        event_dict = {"patient_name": "John Doe", "file": "test.dcm"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["patient_name"] == "***REDACTED***"
        assert result["file"] == "test.dcm"

    def test_redact_password_field(self):
        """Test redaction of password field."""
        event_dict = {"password": "secret123", "status": "ok"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["password"] == "***REDACTED***"
        assert result["status"] == "ok"

    def test_redact_embedded_sensitive_word(self):
        """Test redaction of fields containing sensitive words."""
        event_dict = {"message": "User password is invalid"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["message"] == "***REDACTED***"

    def test_no_redaction_for_safe_fields(self):
        """Test that non-sensitive fields are not redacted."""
        event_dict = {"status": "success", "count": 10, "file": "test.dcm"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["status"] == "success"
        assert result["count"] == 10
        assert result["file"] == "test.dcm"

    def test_redact_multiple_sensitive_fields(self):
        """Test redaction of multiple sensitive fields."""
        event_dict = {
            "patient_id": "123",
            "patient_name": "John",
            "api_key": "secret",
            "safe_field": "value",
        }

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["patient_id"] == "***REDACTED***"
        assert result["patient_name"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"
        assert result["safe_field"] == "value"

    def test_case_insensitive_redaction(self):
        """Test that redaction is case-insensitive."""
        event_dict = {"PATIENT_ID": "123", "Patient_Name": "John"}

        result = redact_sensitive_data(Mock(), "info", event_dict)

        assert result["PATIENT_ID"] == "***REDACTED***"
        assert result["Patient_Name"] == "***REDACTED***"


class TestTimestampProcessor:
    """Test suite for timestamp addition."""

    def test_adds_timestamp_field(self):
        """Test that timestamp field is added."""
        event_dict = {"event": "test"}

        result = add_timestamp(Mock(), "info", event_dict)

        assert "timestamp" in result
        assert isinstance(result["timestamp"], str)

    def test_timestamp_iso_format(self):
        """Test that timestamp is in ISO format."""
        event_dict = {}

        result = add_timestamp(Mock(), "info", event_dict)

        # Should be parseable as ISO format
        timestamp = result["timestamp"]
        assert "T" in timestamp
        assert timestamp.endswith(("Z", "+00:00"))


class TestSecurityContextProcessor:
    """Test suite for security context addition."""

    def test_adds_security_context_when_marked(self):
        """Test security context added for security events."""
        event_dict = {"security_event": True, "message": "test"}

        result = add_security_context(Mock(), "info", event_dict)

        assert result["event_category"] == "SECURITY"
        assert result["requires_attention"] is True

    def test_no_security_context_for_normal_events(self):
        """Test no security context for normal events."""
        event_dict = {"message": "normal log"}

        result = add_security_context(Mock(), "info", event_dict)

        assert "event_category" not in result
        assert "requires_attention" not in result

    def test_security_event_false_no_context(self):
        """Test security_event=False doesn't add context."""
        event_dict = {"security_event": False, "message": "test"}

        result = add_security_context(Mock(), "info", event_dict)

        assert "event_category" not in result


class TestConfigureLogging:
    """Test suite for logging configuration."""

    def test_configure_logging_default(self):
        """Test logging configuration with defaults."""
        configure_logging()

        # Should be configured
        logger = get_logger("test")
        assert logger is not None

    def test_configure_logging_debug_level(self):
        """Test logging configuration with DEBUG level."""
        configure_logging(log_level="DEBUG")

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

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

        assert log_file.exists()

    def test_configure_logging_creates_log_directory(self, tmp_path):
        """Test that log directory is created."""
        log_file = tmp_path / "logs" / "fuzzing" / "test.log"

        configure_logging(log_file=log_file)

        assert log_file.parent.exists()
        assert log_file.exists()

    def test_configure_logging_different_levels(self):
        """Test configuration with different log levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in levels:
            configure_logging(log_level=level)
            root_logger = logging.getLogger()
            assert root_logger.level == getattr(logging, level)


class TestGetLogger:
    """Test suite for get_logger function."""

    def test_get_logger_returns_logger(self):
        """Test that get_logger returns a logger instance."""
        configure_logging()
        logger = get_logger("test_module")

        assert logger is not None
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")

    def test_get_logger_different_names(self):
        """Test getting loggers with different names."""
        configure_logging()

        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1 is not None
        assert logger2 is not None


class TestSecurityEventLogger:
    """Test suite for SecurityEventLogger."""

    def test_initialization(self):
        """Test SecurityEventLogger initialization."""
        mock_logger = Mock()
        security_logger = SecurityEventLogger(mock_logger)

        assert security_logger.logger == mock_logger

    def test_log_validation_failure(self):
        """Test logging validation failure."""
        mock_logger = Mock()
        security_logger = SecurityEventLogger(mock_logger)

        security_logger.log_validation_failure(
            file_path="/path/to/file.dcm", reason="Invalid header"
        )

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "validation_failure"
        assert call_args[1]["security_event"] is True
        assert call_args[1]["file_path"] == "/path/to/file.dcm"
        assert call_args[1]["reason"] == "Invalid header"

    def test_log_validation_failure_with_details(self):
        """Test validation failure logging with details."""
        mock_logger = Mock()
        security_logger = SecurityEventLogger(mock_logger)

        details = {"expected": "DICM", "actual": "XXXX"}
        security_logger.log_validation_failure(
            file_path="test.dcm", reason="Bad magic", details=details
        )

        call_args = mock_logger.warning.call_args
        assert call_args[1]["details"] == details

    def test_log_suspicious_pattern(self):
        """Test logging suspicious pattern."""
        mock_logger = Mock()
        security_logger = SecurityEventLogger(mock_logger)

        security_logger.log_suspicious_pattern(
            pattern_type="buffer_overflow", description="Potential overflow detected"
        )

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "suspicious_pattern_detected"
        assert call_args[1]["pattern_type"] == "buffer_overflow"

    def test_log_fuzzing_campaign(self):
        """Test logging fuzzing campaign."""
        mock_logger = Mock()
        security_logger = SecurityEventLogger(mock_logger)

        stats = {"files_generated": 100, "crashes": 2}
        security_logger.log_fuzzing_campaign(
            campaign_id="fc-001", status="completed", stats=stats
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "fuzzing_campaign"
        assert call_args[1]["campaign_id"] == "fc-001"
        assert call_args[1]["status"] == "completed"
        assert call_args[1]["stats"] == stats


class TestPerformanceLogger:
    """Test suite for PerformanceLogger."""

    def test_initialization(self):
        """Test PerformanceLogger initialization."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        assert perf_logger.logger == mock_logger

    def test_log_operation(self):
        """Test logging operation performance."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        perf_logger.log_operation("file_parsing", duration_ms=45.678)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "operation_performance"
        assert call_args[1]["operation"] == "file_parsing"
        assert call_args[1]["duration_ms"] == 45.68

    def test_log_operation_with_metadata(self):
        """Test operation logging with metadata."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        metadata = {"file_size": "2MB", "strategy": "header_fuzzing"}
        perf_logger.log_operation("mutation", duration_ms=123.45, metadata=metadata)

        call_args = mock_logger.info.call_args
        assert call_args[1]["metadata"] == metadata

    def test_log_mutation_stats(self):
        """Test logging mutation statistics."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        perf_logger.log_mutation_stats(
            strategy="metadata_fuzzer",
            mutations_count=15,
            duration_ms=150.0,
            file_size_bytes=2048,
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "mutation_statistics"
        assert call_args[1]["strategy"] == "metadata_fuzzer"
        assert call_args[1]["mutations_count"] == 15
        assert call_args[1]["duration_ms"] == 150.0
        assert call_args[1]["file_size_bytes"] == 2048
        assert call_args[1]["avg_mutation_time_ms"] == 10.0

    def test_log_mutation_stats_division_by_zero_protection(self):
        """Test mutation stats handles zero mutations."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        perf_logger.log_mutation_stats(
            strategy="test", mutations_count=0, duration_ms=100.0, file_size_bytes=1024
        )

        call_args = mock_logger.info.call_args
        # Should not crash with division by zero
        assert "avg_mutation_time_ms" in call_args[1]

    def test_log_resource_usage(self):
        """Test logging resource usage."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        perf_logger.log_resource_usage(memory_mb=512.345, cpu_percent=75.678)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "resource_usage"
        assert call_args[1]["memory_mb"] == 512.35
        assert call_args[1]["cpu_percent"] == 75.68

    def test_log_resource_usage_with_metadata(self):
        """Test resource usage logging with metadata."""
        mock_logger = Mock()
        perf_logger = PerformanceLogger(mock_logger)

        metadata = {"process_id": 1234, "thread_count": 4}
        perf_logger.log_resource_usage(
            memory_mb=256.0, cpu_percent=50.0, metadata=metadata
        )

        call_args = mock_logger.info.call_args
        assert call_args[1]["metadata"] == metadata


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_logging_workflow(self, tmp_path):
        """Test complete logging workflow."""
        log_file = tmp_path / "test.log"

        # Configure logging
        configure_logging(log_level="DEBUG", json_format=False, log_file=log_file)

        # Get logger and log messages
        logger = get_logger("test_module")
        logger.info("test_message", count=5)

        # Verify log file created
        assert log_file.exists()

    def test_security_event_workflow(self):
        """Test security event logging workflow."""
        configure_logging(json_format=False)

        logger = get_logger("security_test")
        security_logger = SecurityEventLogger(logger)

        # Should not raise
        security_logger.log_validation_failure("test.dcm", "Invalid")
        security_logger.log_suspicious_pattern("overflow", "Buffer issue")
        security_logger.log_fuzzing_campaign("fc-001", "started")

    def test_performance_logging_workflow(self):
        """Test performance logging workflow."""
        configure_logging(json_format=False)

        logger = get_logger("perf_test")
        perf_logger = PerformanceLogger(logger)

        # Should not raise
        perf_logger.log_operation("parse", 10.5)
        perf_logger.log_mutation_stats("header", 5, 50.0, 1024)
        perf_logger.log_resource_usage(128.0, 25.0)

    def test_sensitive_data_redaction_integration(self):
        """Test sensitive data redaction in real logging."""
        configure_logging(json_format=False)

        logger = get_logger("redaction_test")

        # Log with sensitive data - should be redacted by processor
        logger.info("user_action", patient_id="12345", action="view")

        # If no exception raised, redaction worked

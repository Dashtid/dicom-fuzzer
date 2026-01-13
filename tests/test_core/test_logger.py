"""
Comprehensive tests for structured logging system.
"""

import pytest

from dicom_fuzzer.utils.logger import (
    PerformanceLogger,
    SecurityEventLogger,
    add_security_context,
    add_timestamp,
    configure_logging,
    get_logger,
    redact_sensitive_data,
)


class TestBasicLogging:
    """Test basic logging functionality."""

    def test_configure_logging_with_file(self, tmp_path):
        """Test logging configuration with file output."""
        log_file = tmp_path / "test.log"
        configure_logging(log_level="INFO", json_format=True, log_file=log_file)

        logger = get_logger("test")
        logger.info("test_message", data="value")

        assert log_file.exists()
        content = log_file.read_text()
        assert "test_message" in content
        assert "data" in content

    def test_configure_logging_console_format(self, reset_structlog):
        """Test logging configuration with console format (line 131)."""
        configure_logging(log_level="INFO", json_format=False)

        logger = get_logger("test")
        # Should not raise any errors
        logger.info("test_message", data="value")

        # Verify logger was configured correctly
        assert logger is not None
        assert hasattr(logger, "info")

    def test_get_logger_returns_bound_logger(self, reset_structlog):
        """Test get_logger returns proper structlog BoundLogger."""
        configure_logging()
        logger = get_logger("test")

        # Logger should be a proxy or filtering bound logger
        assert logger is not None
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_multiple_loggers(self, reset_structlog):
        """Test getting multiple logger instances."""
        configure_logging()
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        assert logger1 is not None
        assert logger2 is not None
        # Both should have logging methods
        assert hasattr(logger1, "info")
        assert hasattr(logger2, "info")


class TestSensitiveDataRedaction:
    """Test sensitive data redaction functionality."""

    def test_redact_patient_name(self):
        """Test patient name is redacted."""
        event_dict = {"event": "test", "patient_name": "John Doe"}

        result = redact_sensitive_data(None, None, event_dict)

        assert result["patient_name"] == "***REDACTED***"

    def test_redact_multiple_sensitive_fields(self):
        """Test multiple sensitive fields are redacted."""
        event_dict = {
            "event": "test",
            "patient_id": "PAT123",
            "patient_birth_date": "19800101",
            "password": "secret123",
            "normal_field": "keep_this",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["patient_id"] == "***REDACTED***"
        assert result["patient_birth_date"] == "***REDACTED***"
        assert result["password"] == "***REDACTED***"
        assert result["normal_field"] == "keep_this"

    def test_redact_sensitive_in_string_values(self):
        """Test sensitive data in string values is redacted."""
        event_dict = {"event": "test", "message": "Processing patient_name: John Doe"}

        result = redact_sensitive_data(None, None, event_dict)

        assert result["message"] == "***REDACTED***"

    def test_case_insensitive_redaction(self):
        """Test redaction is case-insensitive."""
        event_dict = {
            "event": "test",
            "Patient_Name": "John Doe",
            "PATIENT_ID": "PAT123",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["Patient_Name"] == "***REDACTED***"
        assert result["PATIENT_ID"] == "***REDACTED***"

    def test_redact_api_key(self):
        """Test redaction of API key field."""
        event_dict = {
            "api_key": "sk-1234567890",
            "endpoint": "/api/v1",
        }

        result = redact_sensitive_data(None, None, event_dict)

        assert result["api_key"] == "***REDACTED***"
        assert result["endpoint"] == "/api/v1"

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


class TestTimestampProcessor:
    """Test timestamp processor."""

    def test_adds_iso_timestamp(self):
        """Test ISO timestamp is added to events."""
        event_dict = {"event": "test"}

        result = add_timestamp(None, None, event_dict)

        assert "timestamp" in result
        # Verify it's ISO format by parsing it
        from datetime import datetime

        datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))


class TestSecurityContextProcessor:
    """Test security context processor."""

    def test_marks_security_events(self):
        """Test security events are properly marked."""
        event_dict = {"event": "test", "security_event": True}

        result = add_security_context(None, None, event_dict)

        assert result["event_category"] == "SECURITY"
        assert result["requires_attention"] is True

    def test_non_security_events_unchanged(self):
        """Test non-security events are not modified."""
        event_dict = {"event": "test"}

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
    """Test logging configuration with various log levels."""

    def test_configure_logging_debug_level(self):
        """Test logging configuration with DEBUG level."""
        import logging

        configure_logging(log_level="DEBUG")
        assert logging.root.level == logging.DEBUG

    def test_configure_logging_info_level(self):
        """Test logging configuration with INFO level."""
        import logging

        configure_logging(log_level="INFO")
        assert logging.root.level == logging.INFO

    def test_configure_logging_warning_level(self):
        """Test logging configuration with WARNING level."""
        import logging

        configure_logging(log_level="WARNING")
        assert logging.root.level == logging.WARNING

    def test_configure_logging_reconfiguration(self):
        """Test that logging can be reconfigured."""
        import logging

        configure_logging(log_level="INFO")
        configure_logging(log_level="DEBUG")
        assert logging.root.level == logging.DEBUG


class TestSecurityEventLogger:
    """Test SecurityEventLogger functionality."""

    def test_log_validation_failure(self, tmp_path, reset_structlog):
        """Test logging validation failures."""
        log_file = tmp_path / "security.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        sec_logger = SecurityEventLogger(logger)

        sec_logger.log_validation_failure(
            file_path="test.dcm",
            reason="Invalid header",
            details={"expected": "DICM", "actual": "XXXX"},
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "validation_failure" in content
        assert "test.dcm" in content
        assert "Invalid header" in content

    def test_log_suspicious_pattern(self, tmp_path, reset_structlog):
        """Test logging suspicious patterns."""
        log_file = tmp_path / "security.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        sec_logger = SecurityEventLogger(logger)

        sec_logger.log_suspicious_pattern(
            pattern_type="BUFFER_OVERFLOW",
            description="Extremely large tag length",
            details={"tag": "(0008,0016)", "length": 999999},
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "suspicious_pattern_detected" in content
        assert "BUFFER_OVERFLOW" in content

    def test_log_fuzzing_campaign(self, tmp_path, reset_structlog):
        """Test logging fuzzing campaign events."""
        log_file = tmp_path / "security.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        sec_logger = SecurityEventLogger(logger)

        sec_logger.log_fuzzing_campaign(
            campaign_id="fc-2025-001",
            status="started",
            stats={"files": 100, "strategies": 4},
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "fc-2025-001" in content
        assert "started" in content


class TestPerformanceLogger:
    """Test PerformanceLogger functionality."""

    def test_log_operation(self, tmp_path, reset_structlog):
        """Test logging operation performance."""
        log_file = tmp_path / "perf.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        perf_logger = PerformanceLogger(logger)

        perf_logger.log_operation(
            operation="file_parsing", duration_ms=123.45, metadata={"file_size": "2MB"}
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "file_parsing" in content
        assert "123.45" in content
        assert "PERFORMANCE" in content

    def test_log_mutation_stats(self, tmp_path, reset_structlog):
        """Test logging mutation statistics."""
        log_file = tmp_path / "perf.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        perf_logger = PerformanceLogger(logger)

        perf_logger.log_mutation_stats(
            strategy="metadata_fuzzer",
            mutations_count=15,
            duration_ms=200.0,
            file_size_bytes=2048,
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "metadata_fuzzer" in content
        assert "13.33" in content  # avg_mutation_time_ms

    def test_log_resource_usage(self, tmp_path, reset_structlog):
        """Test logging resource usage."""
        log_file = tmp_path / "perf.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")
        perf_logger = PerformanceLogger(logger)

        perf_logger.log_resource_usage(
            memory_mb=256.5, cpu_percent=45.2, metadata={"process": "fuzzer"}
        )

        assert log_file.exists()
        content = log_file.read_text()
        assert "256.5" in content
        assert "45.2" in content
        assert "RESOURCE" in content


class TestIntegration:
    """Integration tests for the logging system."""

    def test_full_logging_workflow(self, tmp_path, reset_structlog):
        """Test complete logging workflow with file output."""
        log_file = tmp_path / "integration.log"
        configure_logging(log_level="INFO", json_format=True, log_file=log_file)

        logger = get_logger("integration_test")
        sec_logger = SecurityEventLogger(logger)
        perf_logger = PerformanceLogger(logger)

        # Log various events
        logger.info("test_started", test="integration")
        sec_logger.log_validation_failure("test.dcm", "Test error")
        perf_logger.log_operation("test_op", 50.0)

        # Verify log file contains all events
        assert log_file.exists()
        content = log_file.read_text()

        # Verify key events are logged
        assert "test_started" in content
        assert "validation_failure" in content
        assert "operation_performance" in content

    def test_sensitive_data_not_in_logs(self, tmp_path, reset_structlog):
        """Test that sensitive data never appears in logs."""
        log_file = tmp_path / "sensitive.log"
        configure_logging(json_format=True, log_file=log_file)
        logger = get_logger("test")

        # Log event with sensitive data
        logger.info(
            "patient_record",
            patient_name="John Doe",
            patient_id="PAT12345",
            file_count=5,
        )

        assert log_file.exists()
        content = log_file.read_text()

        # Verify sensitive data is redacted
        assert "***REDACTED***" in content
        assert "John Doe" not in content
        assert "PAT12345" not in content
        # Non-sensitive data should remain
        assert "file_count" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

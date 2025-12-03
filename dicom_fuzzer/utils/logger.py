"""DICOM Fuzzer Structured Logging System

Provides structured logging with security event tracking and performance metrics.
Uses structlog for consistent, analyzable log output.
"""

import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

SENSITIVE_FIELDS = {
    "patient_id",
    "patient_name",
    "patient_birth_date",
    "password",
    "token",
    "key",
    "secret",
    "api_key",
}


def redact_sensitive_data(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Processor to redact sensitive data from log entries.

    Args:
        logger: The wrapped logger instance
        method_name: The name of the method being called
        event_dict: The event dictionary to process

    Returns:
        Processed event dictionary with sensitive data redacted

    """
    for key, value in event_dict.items():
        if key.lower() in SENSITIVE_FIELDS:
            event_dict[key] = "***REDACTED***"
        elif isinstance(value, str):
            for sensitive_field in SENSITIVE_FIELDS:
                if sensitive_field in value.lower():
                    event_dict[key] = "***REDACTED***"
                    break

    return event_dict


def add_timestamp(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Processor to add ISO-formatted timestamp to log entries.

    Args:
        logger: The wrapped logger instance
        method_name: The name of the method being called
        event_dict: The event dictionary to process

    Returns:
        Event dictionary with timestamp added

    """
    event_dict["timestamp"] = datetime.now(UTC).isoformat()
    return event_dict


def add_security_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Processor to mark and enhance security-related events.

    Args:
        logger: The wrapped logger instance
        method_name: The name of the method being called
        event_dict: The event dictionary to process

    Returns:
        Event dictionary with security context added

    """
    if event_dict.get("security_event"):
        event_dict["event_category"] = "SECURITY"
        event_dict["requires_attention"] = True

    return event_dict


def configure_logging(
    log_level: str = "INFO", json_format: bool = True, log_file: Path | None = None
) -> None:
    """Configure structlog for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Whether to output JSON format (True) or human-readable (False)
        log_file: Optional file path to write logs to

    Example:
        >>> configure_logging(log_level="DEBUG", json_format=True)
        >>> logger = structlog.get_logger("dicom_fuzzer")
        >>> logger.info("fuzzing_started", target="example.dcm")

    """
    # Clear existing handlers to allow reconfiguration
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
        force=True,  # Force reconfiguration even if handlers exist
    )

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        add_timestamp,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_sensitive_data,
        add_security_context,
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        logging.root.addHandler(file_handler)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a configured structlog logger.

    Args:
        name: Logger name (typically module name using __name__)

    Returns:
        Configured structlog BoundLogger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("operation_complete", duration_ms=123, status="success")

    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger


class SecurityEventLogger:
    """Specialized logger for security-related events."""

    def __init__(self, logger: structlog.stdlib.BoundLogger):
        """Initialize security event logger.

        Args:
            logger: Base structlog logger to use

        """
        self.logger = logger

    def log_validation_failure(
        self, file_path: str, reason: str, details: dict[str, Any] | None = None
    ) -> None:
        """Log DICOM validation failure.

        Args:
            file_path: Path to the file that failed validation
            reason: Reason for validation failure
            details: Additional details about the failure

        """
        self.logger.warning(
            "validation_failure",
            security_event=True,
            event_type="VALIDATION_FAILURE",
            file_path=file_path,
            reason=reason,
            details=details or {},
        )

    def log_suspicious_pattern(
        self,
        pattern_type: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log detection of suspicious pattern.

        Args:
            pattern_type: Type of suspicious pattern detected
            description: Human-readable description
            details: Additional details about the pattern

        """
        self.logger.warning(
            "suspicious_pattern_detected",
            security_event=True,
            event_type="SUSPICIOUS_PATTERN",
            pattern_type=pattern_type,
            description=description,
            details=details or {},
        )

    def log_fuzzing_campaign(
        self, campaign_id: str, status: str, stats: dict[str, Any] | None = None
    ) -> None:
        """Log fuzzing campaign status.

        Args:
            campaign_id: Unique identifier for the campaign
            status: Campaign status (started, completed, failed)
            stats: Campaign statistics

        """
        self.logger.info(
            "fuzzing_campaign",
            security_event=True,
            event_type="FUZZING_CAMPAIGN",
            campaign_id=campaign_id,
            status=status,
            stats=stats or {},
        )


class PerformanceLogger:
    """Specialized logger for performance metrics."""

    def __init__(self, logger: structlog.stdlib.BoundLogger):
        """Initialize performance logger.

        Args:
            logger: Base structlog logger to use

        """
        self.logger = logger

    def log_operation(
        self,
        operation: str,
        duration_ms: float,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log performance of an operation.

        Args:
            operation: Name of the operation
            duration_ms: Duration in milliseconds
            metadata: Additional operation metadata

        """
        self.logger.info(
            "operation_performance",
            metric_type="PERFORMANCE",
            operation=operation,
            duration_ms=round(duration_ms, 2),
            metadata=metadata or {},
        )

    def log_mutation_stats(
        self,
        strategy: str,
        mutations_count: int,
        duration_ms: float,
        file_size_bytes: int,
    ) -> None:
        """Log mutation operation statistics.

        Args:
            strategy: Mutation strategy used
            mutations_count: Number of mutations applied
            duration_ms: Total duration in milliseconds
            file_size_bytes: Resulting file size in bytes

        """
        self.logger.info(
            "mutation_statistics",
            metric_type="PERFORMANCE",
            strategy=strategy,
            mutations_count=mutations_count,
            duration_ms=round(duration_ms, 2),
            file_size_bytes=file_size_bytes,
            avg_mutation_time_ms=round(duration_ms / max(mutations_count, 1), 2),
        )

    def log_resource_usage(
        self,
        memory_mb: float,
        cpu_percent: float,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log resource usage metrics.

        Args:
            memory_mb: Memory usage in megabytes
            cpu_percent: CPU usage percentage
            metadata: Additional resource metadata

        """
        self.logger.info(
            "resource_usage",
            metric_type="RESOURCE",
            memory_mb=round(memory_mb, 2),
            cpu_percent=round(cpu_percent, 2),
            metadata=metadata or {},
        )


if __name__ == "__main__":
    """Test the logging system."""
    print("Testing DICOM Fuzzer Structured Logger...\n")

    configure_logging(log_level="DEBUG", json_format=False)

    logger = get_logger("test_logger")

    print("Testing basic logging:")
    logger.debug("debug_message", detail="This is a debug message")
    logger.info("info_message", detail="This is an info message")
    logger.warning("warning_message", detail="This is a warning message")
    logger.error("error_message", detail="This is an error message")

    print("\nTesting security event logging:")
    security_logger = SecurityEventLogger(logger)
    security_logger.log_validation_failure(
        file_path="test.dcm",
        reason="Invalid header",
        details={"expected": "DICM", "actual": "XXXX"},
    )
    security_logger.log_fuzzing_campaign(
        campaign_id="fc-2025-001",
        status="started",
        stats={"target_files": 5, "strategies": 3},
    )

    print("\nTesting performance logging:")
    perf_logger = PerformanceLogger(logger)
    perf_logger.log_operation(
        operation="file_parsing", duration_ms=45.23, metadata={"file_size": "2.3MB"}
    )
    perf_logger.log_mutation_stats(
        strategy="metadata_fuzzer",
        mutations_count=15,
        duration_ms=123.45,
        file_size_bytes=2048,
    )

    print("\nTesting sensitive data redaction:")
    logger.info("user_data", patient_name="John Doe", file_count=5)

    print("\nLogger testing complete!")

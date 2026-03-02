"""DICOM Fuzzer Structured Logging System

Provides structured logging with security event tracking and performance metrics.
Uses structlog for consistent, analyzable log output.
"""

import logging
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _PlainFormatter(logging.Formatter):
    """Formatter that strips ANSI color codes for plain-text log files."""

    def format(self, record: logging.LogRecord) -> str:
        return _ANSI_RE.sub("", super().format(record))


def configure_logging(
    log_level: str = "INFO",
    json_format: bool = True,
    log_file: Path | None = None,
    console_level: str | None = None,
) -> None:
    """Configure dual-channel logging: console (human dashboard) + file (forensic record).

    Console shows ``console_level`` and above (default: same as ``log_level``).
    File always captures DEBUG so every detail is available for post-mortem.

    Args:
        log_level: Minimum logging level for the overall system.
        json_format: Whether to output JSON format (True) or human-readable (False).
        log_file: Optional file path to write logs to.
        console_level: Logging level for console output. If None, uses ``log_level``.

    Example:
        >>> configure_logging(log_level="DEBUG", console_level="INFO", log_file=Path("run.log"))
        >>> logger = structlog.get_logger("dicom_fuzzer")
        >>> logger.debug("only_in_file")   # appears in run.log only
        >>> logger.info("both_channels")   # appears on console AND in file

    """
    if console_level is None:
        console_level = log_level

    # Clear existing handlers to allow reconfiguration
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Root logger at DEBUG so the file handler sees everything.
    # Console handler level gates what the user sees on screen.
    root_level = logging.DEBUG if log_file else getattr(logging, console_level.upper())

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, console_level.upper()))
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logging.root.setLevel(root_level)
    logging.root.addHandler(console_handler)

    processors: list[Processor] = [
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

    # structlog filter at DEBUG so it never pre-filters messages
    # that the file handler needs to capture.
    structlog_level = (
        logging.DEBUG if log_file else getattr(logging, console_level.upper())
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(structlog_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(_PlainFormatter("%(message)s"))
        logging.root.addHandler(file_handler)


@contextmanager
def suppress_console() -> Iterator[None]:
    """Temporarily suppress console logging during noisy phases.

    Raises the console StreamHandler level to CRITICAL so only print()
    and tqdm output reach stdout. The file handler stays at DEBUG,
    so all messages are still captured for post-mortem analysis.
    """
    for handler in logging.root.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        ):
            old_level = handler.level
            handler.setLevel(logging.CRITICAL)
            try:
                yield
            finally:
                handler.setLevel(old_level)
            return
    yield


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

"""
DICOM Fuzzer Logging Utility

LEARNING OBJECTIVE: This module teaches how to create a structured logging system
that can be used throughout our application.

CONCEPT: We're building a "logger factory" - a function that creates customized
loggers for different parts of our application.
"""

# LEARNING: Import statements bring in code from other modules
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import json
from datetime import datetime, timezone

# LEARNING: These are "type hints" - they help us know what type of data to expect
LogLevel = str  # This creates an alias - LogLevel is just a string, but more descriptive


class SecurityAwareFormatter(logging.Formatter):
    """
    LEARNING: This is a custom class that inherits from logging.Formatter

    CONCEPT: Inheritance means our class gets all the features of logging.Formatter,
    but we can customize how it behaves. Think of it like inheriting traits from
    your parents, but you can also develop your own unique characteristics.

    WHY: We need custom formatting for security applications to ensure sensitive
    data doesn't accidentally get logged.
    """

    # LEARNING: Class variables are shared by all instances of the class
    SENSITIVE_FIELDS = {
        'patient_id', 'patient_name', 'patient_birth_date',
        'password', 'token', 'key', 'secret'
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        LEARNING: This method overrides the parent class's format method

        CONCEPT: When we "override" a method, we're saying "I want to do this
        differently than my parent class does it."

        Args:
            record: A LogRecord object containing the message and metadata

        Returns:
            str: The formatted log message as a string
        """
        # LEARNING: We call the parent's format method first to get basic formatting
        formatted_message = super().format(record)

        # LEARNING: Then we add our own security filtering
        return self._sanitize_sensitive_data(formatted_message)

    def _sanitize_sensitive_data(self, message: str) -> str:
        """
        LEARNING: Methods starting with _ are "private" - meant for internal use only

        CONCEPT: This is like having a private helper function that only this class uses.

        WHY: We don't want to accidentally log patient names or other sensitive data
        """
        # LEARNING: This is a simple implementation - in real apps, you'd use regex
        for sensitive_field in self.SENSITIVE_FIELDS:
            if sensitive_field.lower() in message.lower():
                # LEARNING: We replace sensitive data with asterisks
                message = message.replace(sensitive_field, "***REDACTED***")

        return message


def setup_logger(
    name: str,
    level: LogLevel = "INFO",
    log_file: Optional[Path] = None,
    include_console: bool = True,
    json_format: bool = False
) -> logging.Logger:
    """
    LEARNING: This is a "factory function" - it creates and configures logger objects

    CONCEPT: Instead of manually setting up loggers everywhere in our code,
    we have one function that does it consistently. This is called the
    "Factory Pattern" in programming.

    Args:
        name: The name for this logger (usually the module name)
        level: How verbose the logging should be (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file to write logs to
        include_console: Whether to also print logs to the console
        json_format: Whether to format logs as JSON (useful for automated analysis)

    Returns:
        logging.Logger: A configured logger ready to use

    EXAMPLE:
        # Create a logger for the parser module
        logger = setup_logger("dicom_fuzzer.parser", level="DEBUG")
        logger.info("Starting to parse DICOM file")
    """

    # LEARNING: logging.getLogger() gets or creates a logger with the given name
    logger = logging.getLogger(name)

    # LEARNING: Clear any existing handlers (in case this function is called multiple times)
    logger.handlers.clear()

    # LEARNING: Set the logging level - this controls which messages get through
    logger.setLevel(getattr(logging, level.upper()))

    # LEARNING: Create a formatter - this controls how log messages look
    if json_format:
        # LEARNING: JSON format is good for automated log analysis tools
        formatter = JsonFormatter()
    else:
        # LEARNING: Human-readable format is good for development and debugging
        formatter = SecurityAwareFormatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    # LEARNING: Set up console output (if requested)
    if include_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # LEARNING: Set up file output (if requested)
    if log_file:
        # LEARNING: Make sure the directory exists before trying to create the file
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # LEARNING: Return the configured logger
    return logger


class JsonFormatter(logging.Formatter):
    """
    LEARNING: Another custom formatter, this one outputs JSON format

    CONCEPT: JSON (JavaScript Object Notation) is a standard way to structure data
    that both humans and computers can easily read.

    WHY: JSON logs can be automatically analyzed by security tools to detect patterns
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Convert a log record to JSON format

        LEARNING: We're building a dictionary (key-value pairs) and then
        converting it to JSON format.
        """
        # LEARNING: Create a dictionary with the information we want to log
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),  # ISO format is standard
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # LEARNING: Add extra fields if they exist
        if hasattr(record, 'extra_data'):
            log_entry['extra'] = record.extra_data

        # LEARNING: Convert dictionary to JSON string
        return json.dumps(log_entry)


def get_default_logger(module_name: str) -> logging.Logger:
    """
    LEARNING: This is a convenience function for getting a standard logger

    CONCEPT: We create a simple function that applies our most common settings.
    This reduces repetitive code throughout our application.

    Args:
        module_name: Usually __name__ (the current module's name)

    Returns:
        logging.Logger: A logger with standard settings

    EXAMPLE:
        # At the top of any module:
        logger = get_default_logger(__name__)
    """
    return setup_logger(
        name=module_name,
        level="INFO",
        include_console=True,
        json_format=False
    )


def log_security_event(
    logger: logging.Logger,
    event_type: str,
    description: str,
    extra_data: Optional[Dict[str, Any]] = None
) -> None:
    """
    LEARNING: This is a specialized function for logging security-related events

    CONCEPT: In cybersecurity, certain events are so important that we want to
    make sure they're logged in a consistent format.

    Args:
        logger: The logger to use
        event_type: Type of security event (e.g., "SUSPICIOUS_FILE", "FUZZING_STARTED")
        description: Human-readable description
        extra_data: Additional data to include in the log

    WHY: Security teams need consistent, searchable logs to detect threats
    """
    # LEARNING: Create a structured message
    security_log_entry = {
        'security_event': True,  # Flag to identify security events
        'event_type': event_type,
        'description': description,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    # LEARNING: Add any extra data provided
    if extra_data:
        security_log_entry['details'] = extra_data

    # LEARNING: Log at WARNING level so it gets attention
    logger.warning(f"SECURITY_EVENT: {json.dumps(security_log_entry)}")


# LEARNING: This code runs when the module is imported
if __name__ == "__main__":
    """
    LEARNING: This is a common Python pattern for testing modules

    CONCEPT: When you run "python logger.py" directly, this code will execute.
    But when you import this module, this code will NOT execute.
    """
    # Demo the logger functionality
    print("Testing DICOM Fuzzer Logger...")

    # Create a test logger
    test_logger = setup_logger("test_logger", level="DEBUG")

    # Test different log levels
    test_logger.debug("This is a debug message")
    test_logger.info("This is an info message")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")

    # Test security logging
    log_security_event(
        test_logger,
        "FUZZING_STARTED",
        "Beginning DICOM file fuzzing campaign",
        {"target_file": "example.dcm", "mutation_count": 100}
    )

    print("Logger testing complete!")
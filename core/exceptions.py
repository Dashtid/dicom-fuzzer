"""Custom exceptions for DICOM fuzzing operations.

This module defines the exception hierarchy for the DICOM fuzzer,
providing detailed error information and categorization.
"""

from typing import Optional, Any, Dict


class DicomFuzzingError(Exception):
    """Base exception for DICOM fuzzing operations.

    This serves as the root exception for all DICOM fuzzing related errors,
    providing a common interface for error handling.

    Attributes:
        message: Human-readable error description
        error_code: Optional error code for categorization
        context: Additional context information
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}


class ValidationError(DicomFuzzingError):
    """Raised when DICOM data validation fails.

    This exception is raised when DICOM data doesn't conform to expected
    standards or when validation rules are violated.
    """
    pass


class ParsingError(DicomFuzzingError):
    """Raised when DICOM file parsing fails.

    This exception indicates issues with reading or interpreting DICOM data,
    including malformed files or unsupported formats.
    """
    pass


class MutationError(DicomFuzzingError):
    """Raised when DICOM data mutation fails.

    This exception occurs when mutation operations cannot be completed,
    either due to invalid parameters or data constraints.
    """
    pass


class NetworkTimeoutError(DicomFuzzingError):
    """Raised when network operations timeout.

    This exception is specific to DICOM network operations that exceed
    configured timeout limits.
    """
    pass


class SecurityViolationError(DicomFuzzingError):
    """Raised when security constraints are violated.

    This exception indicates attempts to perform operations that violate
    security policies or constraints.
    """
    pass


class ConfigurationError(DicomFuzzingError):
    """Raised when configuration is invalid or missing.

    This exception occurs when required configuration is missing or
    contains invalid values.
    """
    pass
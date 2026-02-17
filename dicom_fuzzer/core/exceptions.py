"""Custom exceptions for DICOM fuzzing operations.

This module defines the exception hierarchy for the DICOM fuzzer,
providing detailed error information and categorization.
"""

from typing import Any


class DicomFuzzingError(Exception):
    """Base exception for DICOM fuzzing operations.

    Attributes:
        message: Human-readable error description
        error_code: Optional error code for categorization
        context: Additional context information

    """

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}


class ValidationError(DicomFuzzingError):
    """Raised when DICOM data validation fails."""

    pass


class ParsingError(DicomFuzzingError):
    """Raised when DICOM file parsing fails."""

    pass


class SecurityViolationError(DicomFuzzingError):
    """Raised when security constraints are violated."""

    pass


class ResourceExhaustedError(DicomFuzzingError):
    """Raised when system resources are exhausted."""

    pass

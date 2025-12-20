"""
Comprehensive tests for custom exception classes.

Tests cover:
- Exception class hierarchy and inheritance
- Exception initialization with various parameters
- Error message handling
- Error code and context attributes
- Exception catching and type checking
- String representation
"""

import pytest

from dicom_fuzzer.core.exceptions import (
    ConfigurationError,
    DicomFuzzingError,
    MutationError,
    NetworkTimeoutError,
    ParsingError,
    SecurityViolationError,
    ValidationError,
)


class TestDicomFuzzingError:
    """Test base DicomFuzzingError exception class."""

    def test_basic_initialization(self):
        """Test creating exception with just a message."""
        error = DicomFuzzingError("Test error message")

        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.error_code is None
        assert error.context == {}

    def test_initialization_with_error_code(self):
        """Test creating exception with error code."""
        error = DicomFuzzingError("Test error", error_code="ERR001")

        assert error.message == "Test error"
        assert error.error_code == "ERR001"
        assert error.context == {}

    def test_initialization_with_context(self):
        """Test creating exception with context."""
        context = {"file": "test.dcm", "line": 42}
        error = DicomFuzzingError("Test error", context=context)

        assert error.message == "Test error"
        assert error.error_code is None
        assert error.context == {"file": "test.dcm", "line": 42}

    def test_initialization_with_all_parameters(self):
        """Test creating exception with all parameters."""
        context = {"detail": "Invalid header"}
        error = DicomFuzzingError("Test error", error_code="ERR002", context=context)

        assert error.message == "Test error"
        assert error.error_code == "ERR002"
        assert error.context == {"detail": "Invalid header"}

    def test_context_defaults_to_empty_dict(self):
        """Test that context defaults to empty dict when None."""
        error = DicomFuzzingError("Test", context=None)

        assert error.context == {}
        assert isinstance(error.context, dict)

    def test_can_be_raised(self):
        """Test that exception can be raised."""
        with pytest.raises(DicomFuzzingError) as exc_info:
            raise DicomFuzzingError("Test error")

        assert str(exc_info.value) == "Test error"

    def test_can_be_caught_as_exception(self):
        """Test that exception can be caught as base Exception."""
        with pytest.raises(Exception):
            raise DicomFuzzingError("Test error")

    def test_inherits_from_exception(self):
        """Test that DicomFuzzingError inherits from Exception."""
        error = DicomFuzzingError("Test")

        assert isinstance(error, Exception)
        assert isinstance(error, DicomFuzzingError)


class TestValidationError:
    """Test ValidationError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ValidationError inherits from DicomFuzzingError."""
        error = ValidationError("Validation failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ValidationError)

    def test_basic_initialization(self):
        """Test creating ValidationError."""
        error = ValidationError("Invalid DICOM structure")

        assert str(error) == "Invalid DICOM structure"
        assert error.message == "Invalid DICOM structure"

    def test_with_context(self):
        """Test ValidationError with context."""
        context = {"tag": "(0010,0010)", "reason": "Missing required tag"}
        error = ValidationError("Validation failed", context=context)

        assert error.context["tag"] == "(0010,0010)"
        assert error.context["reason"] == "Missing required tag"

    def test_can_be_raised_and_caught(self):
        """Test raising and catching ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            raise ValidationError("Test validation error")

        assert "validation error" in str(exc_info.value).lower()

    def test_can_be_caught_as_base_class(self):
        """Test that ValidationError can be caught as DicomFuzzingError."""
        with pytest.raises(DicomFuzzingError):
            raise ValidationError("Test")


class TestParsingError:
    """Test ParsingError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ParsingError inherits from DicomFuzzingError."""
        error = ParsingError("Parsing failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ParsingError)

    def test_basic_initialization(self):
        """Test creating ParsingError."""
        error = ParsingError("Failed to parse DICOM file")

        assert str(error) == "Failed to parse DICOM file"
        assert error.message == "Failed to parse DICOM file"

    def test_with_file_context(self):
        """Test ParsingError with file context."""
        context = {"file": "corrupt.dcm", "position": 1024}
        error = ParsingError("Parsing failed", error_code="PARSE001", context=context)

        assert error.error_code == "PARSE001"
        assert error.context["file"] == "corrupt.dcm"
        assert error.context["position"] == 1024

    def test_can_be_raised_and_caught(self):
        """Test raising and catching ParsingError."""
        with pytest.raises(ParsingError) as exc_info:
            raise ParsingError("Test parsing error")

        assert "parsing error" in str(exc_info.value).lower()


class TestMutationError:
    """Test MutationError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that MutationError inherits from DicomFuzzingError."""
        error = MutationError("Mutation failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, MutationError)

    def test_basic_initialization(self):
        """Test creating MutationError."""
        error = MutationError("Failed to mutate dataset")

        assert str(error) == "Failed to mutate dataset"
        assert error.message == "Failed to mutate dataset"

    def test_with_mutation_context(self):
        """Test MutationError with mutation context."""
        context = {"strategy": "header_fuzzer", "tag": "(0008,0016)"}
        error = MutationError("Mutation failed", context=context)

        assert error.context["strategy"] == "header_fuzzer"
        assert error.context["tag"] == "(0008,0016)"

    def test_can_be_raised_and_caught(self):
        """Test raising and catching MutationError."""
        with pytest.raises(MutationError) as exc_info:
            raise MutationError("Test mutation error")

        assert "mutation error" in str(exc_info.value).lower()


class TestNetworkTimeoutError:
    """Test NetworkTimeoutError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that NetworkTimeoutError inherits from DicomFuzzingError."""
        error = NetworkTimeoutError("Connection timeout")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, NetworkTimeoutError)

    def test_basic_initialization(self):
        """Test creating NetworkTimeoutError."""
        error = NetworkTimeoutError("Network operation timed out")

        assert str(error) == "Network operation timed out"
        assert error.message == "Network operation timed out"

    def test_with_network_context(self):
        """Test NetworkTimeoutError with network context."""
        context = {"host": "pacs.hospital.com", "port": 11112, "timeout": 30}
        error = NetworkTimeoutError("Timeout", error_code="NET001", context=context)

        assert error.error_code == "NET001"
        assert error.context["host"] == "pacs.hospital.com"
        assert error.context["port"] == 11112
        assert error.context["timeout"] == 30

    def test_can_be_raised_and_caught(self):
        """Test raising and catching NetworkTimeoutError."""
        with pytest.raises(NetworkTimeoutError) as exc_info:
            raise NetworkTimeoutError("Test timeout error")

        assert "timeout error" in str(exc_info.value).lower()


class TestSecurityViolationError:
    """Test SecurityViolationError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that SecurityViolationError inherits from DicomFuzzingError."""
        error = SecurityViolationError("Security violation")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, SecurityViolationError)

    def test_basic_initialization(self):
        """Test creating SecurityViolationError."""
        error = SecurityViolationError("Security policy violated")

        assert str(error) == "Security policy violated"
        assert error.message == "Security policy violated"

    def test_with_security_context(self):
        """Test SecurityViolationError with security context."""
        context = {
            "violation": "buffer_overflow",
            "tag": "(0009,1001)",
            "size": 999999,
        }
        error = SecurityViolationError("Security violation", context=context)

        assert error.context["violation"] == "buffer_overflow"
        assert error.context["tag"] == "(0009,1001)"
        assert error.context["size"] == 999999

    def test_can_be_raised_and_caught(self):
        """Test raising and catching SecurityViolationError."""
        with pytest.raises(SecurityViolationError) as exc_info:
            raise SecurityViolationError("Test security violation")

        assert "security violation" in str(exc_info.value).lower()


class TestConfigurationError:
    """Test ConfigurationError exception class."""

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ConfigurationError inherits from DicomFuzzingError."""
        error = ConfigurationError("Invalid configuration")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ConfigurationError)

    def test_basic_initialization(self):
        """Test creating ConfigurationError."""
        error = ConfigurationError("Missing required configuration")

        assert str(error) == "Missing required configuration"
        assert error.message == "Missing required configuration"

    def test_with_config_context(self):
        """Test ConfigurationError with configuration context."""
        context = {"key": "max_file_size", "expected": "int", "got": "str"}
        error = ConfigurationError(
            "Invalid config", error_code="CFG001", context=context
        )

        assert error.error_code == "CFG001"
        assert error.context["key"] == "max_file_size"
        assert error.context["expected"] == "int"
        assert error.context["got"] == "str"

    def test_can_be_raised_and_caught(self):
        """Test raising and catching ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            raise ConfigurationError("Test configuration error")

        assert "configuration error" in str(exc_info.value).lower()


class TestExceptionHierarchy:
    """Test exception class hierarchy and relationships."""

    def test_all_exceptions_inherit_from_base(self):
        """Test that all custom exceptions inherit from DicomFuzzingError."""
        exceptions = [
            ValidationError("test"),
            ParsingError("test"),
            MutationError("test"),
            NetworkTimeoutError("test"),
            SecurityViolationError("test"),
            ConfigurationError("test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, DicomFuzzingError)
            assert isinstance(exc, Exception)

    def test_exception_type_checking(self):
        """Test that exception types can be distinguished."""
        validation_error = ValidationError("test")
        parsing_error = ParsingError("test")

        assert isinstance(validation_error, ValidationError)
        assert not isinstance(validation_error, ParsingError)
        assert isinstance(parsing_error, ParsingError)
        assert not isinstance(parsing_error, ValidationError)

    def test_catching_specific_exception_types(self):
        """Test catching specific exception types."""

        def raise_validation_error():
            raise ValidationError("Validation failed")

        def raise_parsing_error():
            raise ParsingError("Parsing failed")

        # Catch specific type
        with pytest.raises(ValidationError):
            raise_validation_error()

        # Don't catch wrong type
        with pytest.raises(ParsingError):
            raise_parsing_error()

    def test_catching_base_exception(self):
        """Test that all custom exceptions can be caught with base class."""
        exceptions_to_test = [
            ValidationError("test"),
            ParsingError("test"),
            MutationError("test"),
            NetworkTimeoutError("test"),
            SecurityViolationError("test"),
            ConfigurationError("test"),
        ]

        for exc in exceptions_to_test:
            with pytest.raises(DicomFuzzingError):
                raise exc


class TestExceptionUsage:
    """Test practical exception usage patterns."""

    def test_exception_in_try_except_block(self):
        """Test exception handling in try-except block."""
        try:
            raise ValidationError("Test error", error_code="VAL001")
        except ValidationError as e:
            assert e.message == "Test error"
            assert e.error_code == "VAL001"

    def test_exception_with_complex_context(self):
        """Test exception with complex context data."""
        context = {
            "file": "test.dcm",
            "tags": [(0x0010, 0x0010), (0x0010, 0x0020)],
            "metadata": {"size": 2048, "format": "DICOM"},
        }
        error = ParsingError("Complex error", context=context)

        assert error.context["file"] == "test.dcm"
        assert len(error.context["tags"]) == 2
        assert error.context["metadata"]["size"] == 2048

    def test_exception_context_mutation(self):
        """Test modifying exception context after creation."""
        error = MutationError("Test")

        # Add context after creation
        error.context["added_key"] = "added_value"

        assert "added_key" in error.context
        assert error.context["added_key"] == "added_value"

    def test_multiple_exception_handling(self):
        """Test handling multiple exception types."""

        def risky_operation(operation_type):
            if operation_type == "validate":
                raise ValidationError("Validation failed")
            elif operation_type == "parse":
                raise ParsingError("Parsing failed")
            elif operation_type == "mutate":
                raise MutationError("Mutation failed")

        # Test catching specific types
        with pytest.raises(ValidationError):
            risky_operation("validate")

        with pytest.raises(ParsingError):
            risky_operation("parse")

        with pytest.raises(MutationError):
            risky_operation("mutate")

        # Test catching with base class
        with pytest.raises(DicomFuzzingError):
            risky_operation("validate")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

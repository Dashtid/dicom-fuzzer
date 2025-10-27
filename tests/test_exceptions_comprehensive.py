"""
Comprehensive tests for DICOM fuzzer exceptions.

Achieves 95%+ coverage of core/exceptions.py module.
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
    """Tests for DicomFuzzingError base exception."""

    def test_basic_initialization(self):
        """Test basic error initialization with message only."""
        error = DicomFuzzingError("Test error message")

        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.error_code is None
        assert error.context == {}

    def test_with_error_code(self):
        """Test error initialization with error code."""
        error = DicomFuzzingError("Test error", error_code="ERR001")

        assert error.message == "Test error"
        assert error.error_code == "ERR001"
        assert error.context == {}

    def test_with_context(self):
        """Test error initialization with context."""
        context = {"file": "test.dcm", "line": 42}
        error = DicomFuzzingError("Test error", context=context)

        assert error.message == "Test error"
        assert error.error_code is None
        assert error.context == {"file": "test.dcm", "line": 42}

    def test_with_all_parameters(self):
        """Test error initialization with all parameters."""
        context = {"module": "parser", "function": "parse_header"}
        error = DicomFuzzingError(
            "Complete error", error_code="ERR999", context=context
        )

        assert error.message == "Complete error"
        assert error.error_code == "ERR999"
        assert error.context == {"module": "parser", "function": "parse_header"}

    def test_context_defaults_to_empty_dict(self):
        """Test that context defaults to empty dict when None."""
        error = DicomFuzzingError("Test", context=None)

        assert error.context == {}
        assert isinstance(error.context, dict)

    def test_is_exception_subclass(self):
        """Test that DicomFuzzingError is an Exception."""
        error = DicomFuzzingError("Test")

        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that error can be raised and caught."""
        with pytest.raises(DicomFuzzingError) as exc_info:
            raise DicomFuzzingError("Test error")

        assert str(exc_info.value) == "Test error"

    def test_can_be_caught_as_exception(self):
        """Test that error can be caught as base Exception."""
        with pytest.raises(Exception) as exc_info:
            raise DicomFuzzingError("Test error")

        assert isinstance(exc_info.value, DicomFuzzingError)

    def test_empty_message(self):
        """Test error with empty message."""
        error = DicomFuzzingError("")

        assert error.message == ""
        assert str(error) == ""

    def test_complex_context(self):
        """Test error with complex context data."""
        context = {
            "nested": {"data": [1, 2, 3]},
            "count": 42,
            "flag": True,
        }
        error = DicomFuzzingError("Complex error", context=context)

        assert error.context["nested"]["data"] == [1, 2, 3]
        assert error.context["count"] == 42
        assert error.context["flag"] is True


class TestValidationError:
    """Tests for ValidationError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that ValidationError is a DicomFuzzingError."""
        error = ValidationError("Validation failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ValidationError)

    def test_basic_usage(self):
        """Test basic ValidationError usage."""
        error = ValidationError("Invalid DICOM tag")

        assert str(error) == "Invalid DICOM tag"
        assert error.message == "Invalid DICOM tag"

    def test_with_context(self):
        """Test ValidationError with context."""
        error = ValidationError(
            "Tag validation failed",
            error_code="VAL001",
            context={"tag": "0010,0010", "expected": "PN"},
        )

        assert error.error_code == "VAL001"
        assert error.context["tag"] == "0010,0010"

    def test_can_be_raised_and_caught(self):
        """Test raising and catching ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            raise ValidationError("Validation failed")

        assert "Validation failed" in str(exc_info.value)

    def test_caught_as_base_class(self):
        """Test catching as DicomFuzzingError."""
        with pytest.raises(DicomFuzzingError):
            raise ValidationError("Test")


class TestParsingError:
    """Tests for ParsingError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that ParsingError is a DicomFuzzingError."""
        error = ParsingError("Parse failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ParsingError)

    def test_basic_usage(self):
        """Test basic ParsingError usage."""
        error = ParsingError("Malformed DICOM file")

        assert str(error) == "Malformed DICOM file"

    def test_with_file_context(self):
        """Test ParsingError with file context."""
        error = ParsingError(
            "Invalid file format",
            context={"file": "corrupt.dcm", "offset": 1024},
        )

        assert error.context["file"] == "corrupt.dcm"
        assert error.context["offset"] == 1024

    def test_can_be_raised(self):
        """Test raising ParsingError."""
        with pytest.raises(ParsingError):
            raise ParsingError("Parse error")


class TestMutationError:
    """Tests for MutationError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that MutationError is a DicomFuzzingError."""
        error = MutationError("Mutation failed")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, MutationError)

    def test_basic_usage(self):
        """Test basic MutationError usage."""
        error = MutationError("Cannot mutate tag")

        assert str(error) == "Cannot mutate tag"

    def test_with_mutation_context(self):
        """Test MutationError with mutation context."""
        error = MutationError(
            "Mutation constraint violation",
            context={"strategy": "bit_flip", "position": 42},
        )

        assert error.context["strategy"] == "bit_flip"
        assert error.context["position"] == 42

    def test_can_be_raised(self):
        """Test raising MutationError."""
        with pytest.raises(MutationError):
            raise MutationError("Mutation error")


class TestNetworkTimeoutError:
    """Tests for NetworkTimeoutError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that NetworkTimeoutError is a DicomFuzzingError."""
        error = NetworkTimeoutError("Timeout")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, NetworkTimeoutError)

    def test_basic_usage(self):
        """Test basic NetworkTimeoutError usage."""
        error = NetworkTimeoutError("Connection timeout")

        assert str(error) == "Connection timeout"

    def test_with_network_context(self):
        """Test NetworkTimeoutError with network context."""
        error = NetworkTimeoutError(
            "DICOM C-STORE timeout",
            context={"host": "192.168.1.100", "port": 11112, "timeout": 30},
        )

        assert error.context["host"] == "192.168.1.100"
        assert error.context["port"] == 11112
        assert error.context["timeout"] == 30

    def test_can_be_raised(self):
        """Test raising NetworkTimeoutError."""
        with pytest.raises(NetworkTimeoutError):
            raise NetworkTimeoutError("Network timeout")


class TestSecurityViolationError:
    """Tests for SecurityViolationError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that SecurityViolationError is a DicomFuzzingError."""
        error = SecurityViolationError("Security violation")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, SecurityViolationError)

    def test_basic_usage(self):
        """Test basic SecurityViolationError usage."""
        error = SecurityViolationError("Access denied")

        assert str(error) == "Access denied"

    def test_with_security_context(self):
        """Test SecurityViolationError with security context."""
        error = SecurityViolationError(
            "Unauthorized access attempt",
            error_code="SEC403",
            context={"resource": "/admin", "user": "anonymous"},
        )

        assert error.error_code == "SEC403"
        assert error.context["resource"] == "/admin"
        assert error.context["user"] == "anonymous"

    def test_can_be_raised(self):
        """Test raising SecurityViolationError."""
        with pytest.raises(SecurityViolationError):
            raise SecurityViolationError("Security error")


class TestConfigurationError:
    """Tests for ConfigurationError exception."""

    def test_is_dicom_fuzzing_error(self):
        """Test that ConfigurationError is a DicomFuzzingError."""
        error = ConfigurationError("Config error")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, ConfigurationError)

    def test_basic_usage(self):
        """Test basic ConfigurationError usage."""
        error = ConfigurationError("Missing configuration")

        assert str(error) == "Missing configuration"

    def test_with_config_context(self):
        """Test ConfigurationError with config context."""
        error = ConfigurationError(
            "Invalid configuration value",
            context={"key": "max_workers", "value": -1, "expected": ">0"},
        )

        assert error.context["key"] == "max_workers"
        assert error.context["value"] == -1
        assert error.context["expected"] == ">0"

    def test_can_be_raised(self):
        """Test raising ConfigurationError."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Configuration error")


class TestExceptionHierarchy:
    """Tests for exception hierarchy and polymorphism."""

    def test_all_inherit_from_base(self):
        """Test all exceptions inherit from DicomFuzzingError."""
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

    def test_catch_all_with_base_class(self):
        """Test catching all custom exceptions with base class."""
        errors_caught = []

        for error_class in [
            ValidationError,
            ParsingError,
            MutationError,
            NetworkTimeoutError,
            SecurityViolationError,
            ConfigurationError,
        ]:
            try:
                raise error_class("Test error")
            except DicomFuzzingError as e:
                errors_caught.append(e)

        assert len(errors_caught) == 6

    def test_specific_exception_catching(self):
        """Test catching specific exception types."""
        with pytest.raises(ValidationError):
            raise ValidationError("Test")

        with pytest.raises(ParsingError):
            raise ParsingError("Test")

        with pytest.raises(MutationError):
            raise MutationError("Test")

    def test_exception_type_differentiation(self):
        """Test differentiating between exception types."""

        def raise_error(error_type: str):
            if error_type == "validation":
                raise ValidationError("Validation failed")
            elif error_type == "parsing":
                raise ParsingError("Parse failed")
            else:
                raise MutationError("Mutation failed")

        # Test catching specific types
        with pytest.raises(ValidationError):
            raise_error("validation")

        with pytest.raises(ParsingError):
            raise_error("parsing")

        with pytest.raises(MutationError):
            raise_error("other")


class TestRealWorldUsageScenarios:
    """Tests for realistic usage scenarios."""

    def test_validation_error_scenario(self):
        """Test realistic validation error scenario."""

        def validate_dicom_tag(tag_value):
            if not isinstance(tag_value, str):
                raise ValidationError(
                    "Tag value must be string",
                    error_code="VAL001",
                    context={"received_type": type(tag_value).__name__},
                )

        with pytest.raises(ValidationError) as exc_info:
            validate_dicom_tag(123)

        assert exc_info.value.error_code == "VAL001"
        assert exc_info.value.context["received_type"] == "int"

    def test_parsing_error_scenario(self):
        """Test realistic parsing error scenario."""

        def parse_dicom_file(file_path):
            raise ParsingError(
                "Invalid DICOM preamble",
                error_code="PARSE002",
                context={"file": file_path, "offset": 0},
            )

        with pytest.raises(ParsingError) as exc_info:
            parse_dicom_file("/path/to/corrupt.dcm")

        assert "Invalid DICOM preamble" in str(exc_info.value)
        assert exc_info.value.context["file"] == "/path/to/corrupt.dcm"

    def test_mutation_error_scenario(self):
        """Test realistic mutation error scenario."""

        def mutate_pixel_data(data, strategy):
            if strategy not in ["bit_flip", "byte_swap"]:
                raise MutationError(
                    f"Unknown mutation strategy: {strategy}",
                    context={"valid_strategies": ["bit_flip", "byte_swap"]},
                )

        with pytest.raises(MutationError) as exc_info:
            mutate_pixel_data(b"data", "invalid_strategy")

        assert "Unknown mutation strategy" in str(exc_info.value)

    def test_error_chaining(self):
        """Test error chaining with context."""

        def inner_function():
            raise ValidationError("Inner validation failed")

        def outer_function():
            try:
                inner_function()
            except ValidationError as e:
                raise ConfigurationError(
                    "Configuration requires valid input",
                    context={"original_error": str(e)},
                ) from e

        with pytest.raises(ConfigurationError) as exc_info:
            outer_function()

        assert "Configuration requires valid input" in str(exc_info.value)
        assert exc_info.value.context["original_error"] == "Inner validation failed"
        assert exc_info.value.__cause__ is not None

"""Real-world tests for exceptions module.

Tests all custom exception classes and their behaviors.
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
    """Test base DicomFuzzingError exception."""

    def test_basic_initialization(self):
        """Test creating exception with just a message."""
        error = DicomFuzzingError("Test error")

        assert str(error) == "Test error"
        assert error.message == "Test error"
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
        assert error.context == context
        assert error.context["file"] == "test.dcm"
        assert error.context["line"] == 42

    def test_initialization_with_all_parameters(self):
        """Test creating exception with all parameters."""
        context = {"tag": "0010,0010"}
        error = DicomFuzzingError(
            "Complete error", error_code="ERR999", context=context
        )

        assert error.message == "Complete error"
        assert error.error_code == "ERR999"
        assert error.context == context

    def test_can_be_raised(self):
        """Test that exception can be raised and caught."""
        with pytest.raises(DicomFuzzingError) as exc_info:
            raise DicomFuzzingError("Raised error")

        assert str(exc_info.value) == "Raised error"

    def test_inherits_from_exception(self):
        """Test that DicomFuzzingError inherits from Exception."""
        error = DicomFuzzingError("Test")

        assert isinstance(error, Exception)

    def test_empty_context_default(self):
        """Test that context defaults to empty dict."""
        error = DicomFuzzingError("Test", context=None)

        assert error.context == {}


class TestValidationError:
    """Test ValidationError exception."""

    def test_basic_initialization(self):
        """Test creating ValidationError."""
        error = ValidationError("Validation failed")

        assert str(error) == "Validation failed"
        assert error.message == "Validation failed"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ValidationError inherits from DicomFuzzingError."""
        error = ValidationError("Test")

        assert isinstance(error, DicomFuzzingError)
        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that ValidationError can be raised."""
        with pytest.raises(ValidationError):
            raise ValidationError("Invalid data")

    def test_can_be_caught_as_base_exception(self):
        """Test that ValidationError can be caught as DicomFuzzingError."""
        with pytest.raises(DicomFuzzingError):
            raise ValidationError("Invalid")

    def test_with_error_code_and_context(self):
        """Test ValidationError with all parameters."""
        context = {"expected": "DICM", "actual": "XXXX"}
        error = ValidationError("Invalid header", error_code="VAL001", context=context)

        assert error.message == "Invalid header"
        assert error.error_code == "VAL001"
        assert error.context["expected"] == "DICM"


class TestParsingError:
    """Test ParsingError exception."""

    def test_basic_initialization(self):
        """Test creating ParsingError."""
        error = ParsingError("Parsing failed")

        assert str(error) == "Parsing failed"
        assert error.message == "Parsing failed"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ParsingError inherits from DicomFuzzingError."""
        error = ParsingError("Test")

        assert isinstance(error, DicomFuzzingError)

    def test_can_be_raised(self):
        """Test that ParsingError can be raised."""
        with pytest.raises(ParsingError):
            raise ParsingError("Malformed file")


class TestMutationError:
    """Test MutationError exception."""

    def test_basic_initialization(self):
        """Test creating MutationError."""
        error = MutationError("Mutation failed")

        assert str(error) == "Mutation failed"
        assert error.message == "Mutation failed"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that MutationError inherits from DicomFuzzingError."""
        error = MutationError("Test")

        assert isinstance(error, DicomFuzzingError)

    def test_can_be_raised(self):
        """Test that MutationError can be raised."""
        with pytest.raises(MutationError):
            raise MutationError("Cannot mutate")


class TestNetworkTimeoutError:
    """Test NetworkTimeoutError exception."""

    def test_basic_initialization(self):
        """Test creating NetworkTimeoutError."""
        error = NetworkTimeoutError("Connection timeout")

        assert str(error) == "Connection timeout"
        assert error.message == "Connection timeout"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that NetworkTimeoutError inherits from DicomFuzzingError."""
        error = NetworkTimeoutError("Test")

        assert isinstance(error, DicomFuzzingError)

    def test_can_be_raised(self):
        """Test that NetworkTimeoutError can be raised."""
        with pytest.raises(NetworkTimeoutError):
            raise NetworkTimeoutError("Timeout after 30s")


class TestSecurityViolationError:
    """Test SecurityViolationError exception."""

    def test_basic_initialization(self):
        """Test creating SecurityViolationError."""
        error = SecurityViolationError("Security violation")

        assert str(error) == "Security violation"
        assert error.message == "Security violation"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that SecurityViolationError inherits from DicomFuzzingError."""
        error = SecurityViolationError("Test")

        assert isinstance(error, DicomFuzzingError)

    def test_can_be_raised(self):
        """Test that SecurityViolationError can be raised."""
        with pytest.raises(SecurityViolationError):
            raise SecurityViolationError("Unauthorized access")


class TestConfigurationError:
    """Test ConfigurationError exception."""

    def test_basic_initialization(self):
        """Test creating ConfigurationError."""
        error = ConfigurationError("Config invalid")

        assert str(error) == "Config invalid"
        assert error.message == "Config invalid"

    def test_inherits_from_dicom_fuzzing_error(self):
        """Test that ConfigurationError inherits from DicomFuzzingError."""
        error = ConfigurationError("Test")

        assert isinstance(error, DicomFuzzingError)

    def test_can_be_raised(self):
        """Test that ConfigurationError can be raised."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Missing required config")


class TestExceptionHierarchy:
    """Test exception hierarchy and catching behavior."""

    def test_catch_all_with_base_exception(self):
        """Test catching all custom exceptions with base class."""
        exceptions = [
            ValidationError("test"),
            ParsingError("test"),
            MutationError("test"),
            NetworkTimeoutError("test"),
            SecurityViolationError("test"),
            ConfigurationError("test"),
        ]

        for exc in exceptions:
            with pytest.raises(DicomFuzzingError):
                raise exc

    def test_specific_exception_types_are_distinct(self):
        """Test that each exception type is distinct."""
        validation_err = ValidationError("test")
        parsing_err = ParsingError("test")

        assert type(validation_err) is not type(parsing_err)
        assert isinstance(validation_err, ValidationError)
        assert isinstance(parsing_err, ParsingError)
        assert not isinstance(validation_err, ParsingError)
        assert not isinstance(parsing_err, ValidationError)


class TestExceptionUsageScenarios:
    """Test realistic exception usage scenarios."""

    def test_validation_error_with_context(self):
        """Test ValidationError with detailed context."""
        try:
            # Simulate validation failure
            raise ValidationError(
                "Invalid DICOM tag",
                error_code="VAL002",
                context={
                    "tag": "(0010,0010)",
                    "expected_vr": "PN",
                    "actual_vr": "LO",
                },
            )
        except ValidationError as e:
            assert e.error_code == "VAL002"
            assert e.context["tag"] == "(0010,0010)"

    def test_parsing_error_with_file_info(self):
        """Test ParsingError with file information."""
        try:
            raise ParsingError(
                "Failed to read DICOM file",
                error_code="PARSE001",
                context={"file_path": "/path/to/file.dcm", "offset": 1024},
            )
        except ParsingError as e:
            assert "file_path" in e.context
            assert e.context["offset"] == 1024

    def test_mutation_error_with_mutation_details(self):
        """Test MutationError with mutation details."""
        try:
            raise MutationError(
                "Mutation strategy failed",
                context={
                    "strategy": "header_fuzzer",
                    "target_tag": "(0002,0010)",
                    "reason": "Tag is read-only",
                },
            )
        except MutationError as e:
            assert e.context["strategy"] == "header_fuzzer"

    def test_exception_chaining(self):
        """Test exception chaining with from clause."""
        try:
            try:
                raise ValueError("Original error")
            except ValueError as e:
                raise ParsingError("Failed to parse") from e
        except ParsingError as e:
            assert e.__cause__ is not None
            assert isinstance(e.__cause__, ValueError)

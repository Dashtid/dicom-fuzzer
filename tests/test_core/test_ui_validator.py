"""Tests for UIValidator module.

Tests UI validation functionality with mocked pywinauto.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.ui_validator import (
    ExpectedValues,
    UIValidationResult,
    UIValidator,
    create_validation_callback,
)


class TestExpectedValues:
    """Test ExpectedValues dataclass."""

    def test_default_values(self):
        """Test default values are None/empty."""
        expected = ExpectedValues()
        assert expected.patient_id is None
        assert expected.patient_name is None
        assert expected.study_date is None
        assert expected.series_count is None
        assert expected.modality is None
        assert expected.custom_checks == {}

    def test_with_values(self):
        """Test creating with specific values."""
        expected = ExpectedValues(
            patient_id="TEST001",
            patient_name="Doe^John",
            study_date="20240115",
            series_count=3,
            modality="CT",
            custom_checks={"accession": "ACC123"},
        )
        assert expected.patient_id == "TEST001"
        assert expected.patient_name == "Doe^John"
        assert expected.study_date == "20240115"
        assert expected.series_count == 3
        assert expected.modality == "CT"
        assert expected.custom_checks == {"accession": "ACC123"}


class TestUIValidationResult:
    """Test UIValidationResult dataclass."""

    def test_default_passed(self):
        """Test default passed result."""
        result = UIValidationResult(passed=True)
        assert result.passed is True
        assert result.checks == {}
        assert result.errors == []
        assert result.warnings == []
        assert result.extracted_text == ""

    def test_failed_result(self):
        """Test failed result with errors."""
        result = UIValidationResult(
            passed=False,
            checks={"patient_id": False},
            errors=["Patient ID not found"],
            warnings=["Modality not verified"],
        )
        assert result.passed is False
        assert result.checks == {"patient_id": False}
        assert "Patient ID not found" in result.errors


class TestUIValidator:
    """Test UIValidator class."""

    def test_init_defaults(self):
        """Test default initialization."""
        validator = UIValidator()
        assert validator.process_name == "Hermes.exe"
        assert validator.window_title_pattern == ".*Affinity.*"
        assert validator.app is None
        assert validator._connected_pid is None

    def test_init_custom(self):
        """Test initialization with custom values."""
        validator = UIValidator(
            process_name="CustomViewer.exe",
            window_title_pattern=".*Custom.*",
        )
        assert validator.process_name == "CustomViewer.exe"
        assert validator.window_title_pattern == ".*Custom.*"

    def test_is_connected_false(self):
        """Test is_connected returns False when not connected."""
        validator = UIValidator()
        assert validator.is_connected() is False

    def test_disconnect(self):
        """Test disconnect clears connection state."""
        validator = UIValidator()
        validator.app = MagicMock()
        validator._connected_pid = 1234
        validator.disconnect()
        assert validator.app is None
        assert validator._connected_pid is None

    def test_connect_success(self):
        """Test successful connection with mocked pywinauto."""
        mock_app = MagicMock()
        mock_app_class = MagicMock()
        mock_app_class.return_value.connect.return_value = mock_app

        # Mock the import inside the connect method
        import sys

        mock_pywinauto = MagicMock()
        mock_pywinauto.Application = mock_app_class
        sys.modules["pywinauto"] = mock_pywinauto

        try:
            validator = UIValidator()
            result = validator.connect(1234)

            assert result is True
            assert validator.is_connected() is True
            assert validator._connected_pid == 1234
        finally:
            del sys.modules["pywinauto"]

    def test_connect_failure(self):
        """Test connection failure with mocked pywinauto."""
        mock_app_class = MagicMock()
        mock_app_class.return_value.connect.side_effect = Exception("Process not found")

        import sys

        mock_pywinauto = MagicMock()
        mock_pywinauto.Application = mock_app_class
        sys.modules["pywinauto"] = mock_pywinauto

        try:
            validator = UIValidator()
            result = validator.connect(9999)

            assert result is False
            assert validator.is_connected() is False
        finally:
            del sys.modules["pywinauto"]

    def test_validate_not_connected(self):
        """Test validation fails when not connected."""
        validator = UIValidator()
        expected = ExpectedValues(patient_id="TEST001")

        result = validator.validate_patient_info(expected)

        assert result.passed is False
        assert "Not connected" in result.errors[0]


class TestUIValidatorValidation:
    """Test UIValidator validation methods with mocked pywinauto."""

    @pytest.fixture
    def connected_validator(self):
        """Create a validator with mocked connection."""
        validator = UIValidator()
        validator.app = MagicMock()
        validator._connected_pid = 1234
        return validator

    @pytest.fixture
    def mock_window(self):
        """Create a mock window with sample text."""
        window = MagicMock()
        window.exists.return_value = True
        window.window_text.return_value = "Affinity - Patient View"

        # Mock descendants
        control1 = MagicMock()
        control1.window_text.return_value = "Patient ID: TEST001"
        control2 = MagicMock()
        control2.window_text.return_value = "Patient Name: John Doe"
        control3 = MagicMock()
        control3.window_text.return_value = "Modality: CT"

        window.descendants.return_value = [control1, control2, control3]
        return window

    def test_validate_patient_id_found(self, connected_validator, mock_window):
        """Test patient ID validation succeeds."""
        connected_validator.app.window.return_value = mock_window
        expected = ExpectedValues(patient_id="TEST001")

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is True
        assert result.checks.get("patient_id") is True

    def test_validate_patient_id_not_found(self, connected_validator, mock_window):
        """Test patient ID validation fails when not found."""
        connected_validator.app.window.return_value = mock_window
        expected = ExpectedValues(patient_id="WRONG_ID")

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is False
        assert result.checks.get("patient_id") is False
        assert any("WRONG_ID" in err for err in result.errors)

    def test_validate_patient_name_dicom_format(self, connected_validator, mock_window):
        """Test patient name validation with DICOM format."""
        connected_validator.app.window.return_value = mock_window
        # DICOM format: LastName^FirstName
        expected = ExpectedValues(patient_name="Doe^John")

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is True
        assert result.checks.get("patient_name") is True

    def test_validate_modality(self, connected_validator, mock_window):
        """Test modality validation."""
        connected_validator.app.window.return_value = mock_window
        expected = ExpectedValues(modality="CT")

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is True
        assert result.checks.get("modality") is True

    def test_validate_window_not_found(self, connected_validator):
        """Test validation fails when window not found."""
        mock_window = MagicMock()
        mock_window.exists.return_value = False
        connected_validator.app.window.return_value = mock_window

        expected = ExpectedValues(patient_id="TEST001")
        result = connected_validator.validate_patient_info(expected)

        assert result.passed is False
        assert "not found" in result.errors[0]

    def test_validate_custom_checks(self, connected_validator, mock_window):
        """Test custom check validation."""
        # Add custom text to mock
        custom_control = MagicMock()
        custom_control.window_text.return_value = "Accession: ACC123"
        mock_window.descendants.return_value.append(custom_control)

        connected_validator.app.window.return_value = mock_window
        expected = ExpectedValues(custom_checks={"accession": "ACC123"})

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is True
        assert result.checks.get("custom_accession") is True

    def test_validate_custom_check_not_found(self, connected_validator, mock_window):
        """Test custom check fails when value not found."""
        connected_validator.app.window.return_value = mock_window
        expected = ExpectedValues(custom_checks={"missing": "NOT_THERE"})

        result = connected_validator.validate_patient_info(expected)

        assert result.passed is False
        assert result.checks.get("custom_missing") is False


class TestCheckErrorDialogs:
    """Test error dialog detection."""

    @pytest.fixture
    def connected_validator(self):
        """Create a validator with mocked connection."""
        validator = UIValidator()
        validator.app = MagicMock()
        validator._connected_pid = 1234
        return validator

    def test_no_error_dialogs(self, connected_validator):
        """Test no errors when no error dialogs present."""
        window = MagicMock()
        window.window_text.return_value = "Normal Window"
        connected_validator.app.windows.return_value = [window]

        errors = connected_validator.check_error_dialogs()

        assert errors == []

    def test_error_dialog_detected(self, connected_validator):
        """Test error dialog is detected."""
        normal_window = MagicMock()
        normal_window.window_text.return_value = "Normal Window"

        error_window = MagicMock()
        error_window.window_text.return_value = "Error Loading File"
        error_window.descendants.return_value = []

        connected_validator.app.windows.return_value = [normal_window, error_window]

        errors = connected_validator.check_error_dialogs()

        assert len(errors) == 1
        assert "Error Loading File" in errors[0]

    def test_warning_dialog_detected(self, connected_validator):
        """Test warning dialog is detected."""
        warning_window = MagicMock()
        warning_window.window_text.return_value = "Warning: Invalid Data"
        warning_window.descendants.return_value = []

        connected_validator.app.windows.return_value = [warning_window]

        errors = connected_validator.check_error_dialogs()

        assert len(errors) == 1
        assert "Warning" in errors[0]

    def test_not_connected(self):
        """Test error when not connected."""
        validator = UIValidator()
        errors = validator.check_error_dialogs()
        assert "Not connected" in errors[0]


class TestCheckRenderingState:
    """Test rendering state checks."""

    @pytest.fixture
    def connected_validator(self):
        """Create a validator with mocked connection."""
        validator = UIValidator()
        validator.app = MagicMock()
        validator._connected_pid = 1234
        return validator

    @pytest.fixture
    def mock_window_with_content(self):
        """Create a mock window with normal content."""
        window = MagicMock()
        window.exists.return_value = True
        window.window_text.return_value = "Affinity - Patient View"

        control = MagicMock()
        control.window_text.return_value = (
            "Patient ID: TEST001 - CT Study - 3 Series loaded successfully"
        )
        window.descendants.return_value = [control]
        return window

    def test_rendering_ok(self, connected_validator, mock_window_with_content):
        """Test rendering state is OK with normal content."""
        connected_validator.app.window.return_value = mock_window_with_content

        result = connected_validator.check_rendering_state()

        assert result.passed is True
        assert result.checks.get("has_content") is True
        assert result.checks.get("no_error_messages") is True

    def test_loading_indicator_warning(self, connected_validator):
        """Test warning when loading indicator visible."""
        window = MagicMock()
        window.exists.return_value = True
        window.window_text.return_value = "Affinity"

        control = MagicMock()
        control.window_text.return_value = (
            "Loading... Please wait while data is processed"
        )
        window.descendants.return_value = [control]

        connected_validator.app.window.return_value = window

        result = connected_validator.check_rendering_state()

        assert result.checks.get("no_loading_indicator") is False
        assert any("Loading" in w for w in result.warnings)

    def test_empty_content_error(self, connected_validator):
        """Test error when content area is empty."""
        window = MagicMock()
        window.exists.return_value = True
        window.window_text.return_value = "Affinity"
        window.descendants.return_value = []

        connected_validator.app.window.return_value = window

        result = connected_validator.check_rendering_state()

        assert result.passed is False
        assert result.checks.get("has_content") is False

    def test_error_message_in_content(self, connected_validator):
        """Test error when error message visible in content."""
        window = MagicMock()
        window.exists.return_value = True
        window.window_text.return_value = "Affinity"

        control = MagicMock()
        control.window_text.return_value = (
            "Error loading DICOM files. The format is not supported."
        )
        window.descendants.return_value = [control]

        connected_validator.app.window.return_value = window

        result = connected_validator.check_rendering_state()

        assert result.passed is False
        assert result.checks.get("no_error_messages") is False


class TestNameVariants:
    """Test DICOM name variant generation."""

    def test_dicom_name_variants(self):
        """Test DICOM name generates correct variants."""
        validator = UIValidator()

        variants = validator._get_name_variants("Doe^John")

        assert "Doe^John" in variants
        assert "John Doe" in variants
        assert "Doe, John" in variants
        assert "John" in variants
        assert "Doe" in variants

    def test_simple_name(self):
        """Test simple name without separator."""
        validator = UIValidator()

        variants = validator._get_name_variants("SimpleName")

        assert variants == ["SimpleName"]

    def test_three_part_name(self):
        """Test three-part DICOM name."""
        validator = UIValidator()

        variants = validator._get_name_variants("Doe^John^Middle")

        assert "Doe^John^Middle" in variants
        assert "John Doe" in variants


class TestDateVariants:
    """Test DICOM date variant generation."""

    def test_dicom_date_variants(self):
        """Test DICOM date generates correct variants."""
        validator = UIValidator()

        variants = validator._get_date_variants("20240115")

        assert "20240115" in variants
        assert "2024-01-15" in variants
        assert "01/15/2024" in variants
        assert "15/01/2024" in variants
        assert "15 Jan 2024" in variants

    def test_invalid_date_format(self):
        """Test invalid date format returns as-is."""
        validator = UIValidator()

        variants = validator._get_date_variants("invalid")

        assert variants == ["invalid"]


class TestValidationCallback:
    """Test validation callback factory."""

    def test_create_callback(self):
        """Test callback creation."""
        expected = ExpectedValues(patient_id="TEST001")
        callback = create_validation_callback(expected)

        assert callable(callback)

    @patch("dicom_fuzzer.core.ui_validator.UIValidator")
    def test_callback_connects_and_validates(self, mock_validator_class):
        """Test callback connects to process and validates."""
        mock_validator = MagicMock()
        mock_validator.connect.return_value = True
        mock_validator.validate_patient_info.return_value = UIValidationResult(
            passed=True,
            checks={"patient_id": True},
        )
        mock_validator_class.return_value = mock_validator

        expected = ExpectedValues(patient_id="TEST001")
        callback = create_validation_callback(expected, process_name="Test.exe")

        result = callback(1234)

        mock_validator.connect.assert_called_once_with(1234)
        mock_validator.validate_patient_info.assert_called_once_with(expected)
        mock_validator.disconnect.assert_called_once()
        assert result.passed is True

    @patch("dicom_fuzzer.core.ui_validator.UIValidator")
    def test_callback_connection_failure(self, mock_validator_class):
        """Test callback handles connection failure."""
        mock_validator = MagicMock()
        mock_validator.connect.return_value = False
        mock_validator_class.return_value = mock_validator

        expected = ExpectedValues(patient_id="TEST001")
        callback = create_validation_callback(expected)

        result = callback(9999)

        assert result.passed is False
        assert "Failed to connect" in result.message

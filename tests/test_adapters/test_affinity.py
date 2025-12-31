"""Tests for Affinity adapter with mocked pywinauto."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestAffinityAdapterBasics:
    """Test AffinityAdapter basic properties."""

    @pytest.fixture
    def mock_pywinauto(self):
        """Mock pywinauto module."""
        mock_module = MagicMock()
        mock_app_class = MagicMock()
        mock_module.Application = mock_app_class
        return mock_module, mock_app_class

    @pytest.fixture
    def adapter_with_mock(self, mock_pywinauto):
        """Create adapter with mocked pywinauto."""
        mock_module, mock_app_class = mock_pywinauto
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            yield adapter, mock_app_class
        finally:
            if "pywinauto" in sys.modules:
                del sys.modules["pywinauto"]

    def test_adapter_name(self, adapter_with_mock):
        """Test adapter name property."""
        adapter, _ = adapter_with_mock
        assert adapter.name == "Hermes Affinity"

    def test_supported_viewers(self, adapter_with_mock):
        """Test supported viewers list."""
        adapter, _ = adapter_with_mock
        viewers = adapter.supported_viewers
        assert "Hermes.exe" in viewers
        assert "Affinity.exe" in viewers

    def test_timing_constants(self, adapter_with_mock):
        """Test timing constants match RF helpers."""
        adapter, _ = adapter_with_mock
        assert adapter.MINIMAL_PAUSE == 0.15
        assert adapter.BRIEF_PAUSE == 0.3
        assert adapter.WAIT_FOR_ACTION == 1.0
        assert adapter.WAIT_FOR_DATA_LOAD == 3.0

    def test_initial_state(self, adapter_with_mock):
        """Test adapter starts disconnected."""
        adapter, _ = adapter_with_mock
        assert adapter.is_connected() is False
        assert adapter.app is None
        assert adapter._connected_pid is None


class TestAffinityAdapterConnection:
    """Test AffinityAdapter connection handling."""

    @pytest.fixture
    def mock_pywinauto(self):
        """Create mock pywinauto module."""
        mock_module = MagicMock()
        mock_app = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.process = 1234

        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        return mock_module, mock_app, mock_window

    def test_connect_by_pid(self, mock_pywinauto):
        """Test connecting by process ID."""
        mock_module, mock_app, mock_window = mock_pywinauto
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.connect(pid=1234)

            assert result is True
            assert adapter.is_connected() is True
            assert adapter._connected_pid == 1234
        finally:
            del sys.modules["pywinauto"]

    def test_connect_window_not_found(self, mock_pywinauto):
        """Test connection fails when window not found."""
        mock_module, mock_app, mock_window = mock_pywinauto
        mock_window.exists.return_value = False
        # Also mock the windows() fallback to return empty list
        mock_app.return_value.connect.return_value.windows.return_value = []
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.connect(pid=1234)

            assert result is False
            assert adapter.is_connected() is False
        finally:
            del sys.modules["pywinauto"]

    def test_connect_exception(self, mock_pywinauto):
        """Test connection handles exceptions."""
        mock_module, mock_app, _ = mock_pywinauto
        mock_app.return_value.connect.side_effect = Exception("Process not found")
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.connect(pid=9999)

            assert result is False
            assert adapter.is_connected() is False
        finally:
            del sys.modules["pywinauto"]

    def test_disconnect(self, mock_pywinauto):
        """Test disconnect clears state."""
        mock_module, mock_app, mock_window = mock_pywinauto
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)
            assert adapter.is_connected() is True

            adapter.disconnect()
            assert adapter.is_connected() is False
            assert adapter.app is None
            assert adapter._connected_pid is None
        finally:
            del sys.modules["pywinauto"]


class TestAffinityAdapterLoadStudy:
    """Test AffinityAdapter study loading."""

    @pytest.fixture
    def connected_adapter(self):
        """Create connected adapter with mocks."""
        mock_module = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True
        mock_window.set_focus.return_value = None
        mock_window.type_keys.return_value = None
        mock_window.window_text.return_value = "Affinity - Test"

        # Mock series control for selection
        mock_series_control = MagicMock()
        mock_series_control.window_text.return_value = "CT Series 001"
        # Mock element_info.control_type for the click logic
        mock_series_control.element_info.control_type = "ListItem"
        mock_series_control.click_input.return_value = None

        # Mock Datalist container with series control inside
        mock_datalist = MagicMock()
        mock_datalist.exists.return_value = True
        mock_datalist.descendants.return_value = [mock_series_control]

        # Mock search box
        mock_search_box = MagicMock()
        mock_search_box.exists.return_value = True

        # child_window returns different mocks based on arguments
        def child_window_side_effect(**kwargs):
            if kwargs.get("auto_id") == "Datalist":
                return mock_datalist
            return mock_search_box

        mock_window.child_window.side_effect = child_window_side_effect
        mock_window.descendants.return_value = [mock_series_control]

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.windows.return_value = []
        mock_app_instance.process = 1234

        mock_app = MagicMock()
        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)
            yield adapter, mock_window, mock_series_control
        finally:
            if "pywinauto" in sys.modules:
                del sys.modules["pywinauto"]

    def test_load_study_not_connected(self):
        """Test load_study fails when not connected."""
        mock_module = MagicMock()
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.load_study_into_viewport(Path("./test"))

            assert result.success is False
            assert "Not connected" in result.error_message
        finally:
            del sys.modules["pywinauto"]

    def test_load_study_success(self, connected_adapter):
        """Test successful study loading."""
        adapter, mock_window, mock_control = connected_adapter

        with patch("time.sleep"):  # Skip actual delays
            result = adapter.load_study_into_viewport(
                Path("./test_study"),
                series_name="CT Series",
            )

        assert result.success is True
        assert result.rendered_series == 1
        assert result.details["search_term"] == "CT Series"

    def test_load_study_uses_path_name_if_no_series(self, connected_adapter):
        """Test study loading uses path name when no series specified."""
        adapter, mock_window, mock_control = connected_adapter
        # Update mock to match the path name that will be searched
        mock_control.window_text.return_value = "my_study"

        with patch("time.sleep"):
            result = adapter.load_study_into_viewport(Path("./my_study"))

        assert result.success is True
        assert result.details["search_term"] == "my_study"

    def test_load_study_series_not_found(self, connected_adapter):
        """Test load fails when series not found."""
        adapter, mock_window, mock_control = connected_adapter
        mock_control.window_text.return_value = "Other Series"

        with patch("time.sleep"):
            result = adapter.load_study_into_viewport(
                Path("./test"),
                series_name="NonexistentSeries",
            )

        assert result.success is False
        assert "not found" in result.error_message


class TestAffinityAdapterPatientInfo:
    """Test AffinityAdapter patient info extraction."""

    @pytest.fixture
    def connected_adapter(self):
        """Create connected adapter with patient info text."""
        mock_module = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True
        mock_window.window_text.return_value = "Affinity - Patient View"

        # Mock controls with patient info text
        mock_controls = []
        texts = [
            "Patient ID: TEST001",
            "Patient Name: John Doe",
            "Study Date: 2024-01-15",
            "Modality: CT",
            "Accession: ACC123",
        ]
        for text in texts:
            control = MagicMock()
            control.window_text.return_value = text
            mock_controls.append(control)

        mock_window.descendants.return_value = mock_controls

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.process = 1234

        mock_app = MagicMock()
        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)
            yield adapter, mock_window
        finally:
            if "pywinauto" in sys.modules:
                del sys.modules["pywinauto"]

    def test_get_patient_info_not_connected(self):
        """Test patient info extraction fails when not connected."""
        mock_module = MagicMock()
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            info = adapter.get_displayed_patient_info()

            assert info.extraction_method == "failed"
        finally:
            del sys.modules["pywinauto"]

    def test_get_patient_info_extracts_id(self, connected_adapter):
        """Test patient ID extraction."""
        adapter, _ = connected_adapter
        info = adapter.get_displayed_patient_info()

        assert info.patient_id == "TEST001"

    def test_get_patient_info_extracts_modality(self, connected_adapter):
        """Test modality extraction."""
        adapter, _ = connected_adapter
        info = adapter.get_displayed_patient_info()

        assert info.modality == "CT"

    def test_get_patient_info_extraction_method(self, connected_adapter):
        """Test extraction method is set correctly."""
        adapter, _ = connected_adapter
        info = adapter.get_displayed_patient_info()

        assert info.extraction_method == "text_scrape"

    def test_get_patient_info_includes_raw_text(self, connected_adapter):
        """Test raw text is captured."""
        adapter, _ = connected_adapter
        info = adapter.get_displayed_patient_info()

        assert len(info.raw_text) > 0
        assert "Patient ID" in info.raw_text


class TestAffinityAdapterErrorDialogs:
    """Test AffinityAdapter error dialog detection."""

    @pytest.fixture
    def connected_adapter_with_dialogs(self):
        """Create adapter with mock error dialogs."""
        mock_module = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True

        # Mock error dialog window
        error_window = MagicMock()
        error_window.window_text.return_value = "Error Loading File"

        warning_window = MagicMock()
        warning_window.window_text.return_value = "Warning: Invalid Data"

        normal_window = MagicMock()
        normal_window.window_text.return_value = "Normal Window"

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.windows.return_value = [
            error_window,
            warning_window,
            normal_window,
        ]
        mock_app_instance.process = 1234

        mock_app = MagicMock()
        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)
            yield adapter
        finally:
            if "pywinauto" in sys.modules:
                del sys.modules["pywinauto"]

    def test_check_error_dialogs_not_connected(self):
        """Test error check when not connected."""
        mock_module = MagicMock()
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            errors = adapter.check_error_dialogs()

            assert "Not connected" in errors
        finally:
            del sys.modules["pywinauto"]

    def test_check_error_dialogs_detects_errors(self, connected_adapter_with_dialogs):
        """Test error dialogs are detected."""
        adapter = connected_adapter_with_dialogs
        errors = adapter.check_error_dialogs()

        assert len(errors) == 2
        assert any("Error" in e for e in errors)
        assert any("Warning" in e for e in errors)


class TestAffinityAdapterScreenshot:
    """Test AffinityAdapter screenshot capture."""

    def test_capture_screenshot_not_connected(self, tmp_path):
        """Test screenshot fails when not connected."""
        mock_module = MagicMock()
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.capture_screenshot(tmp_path / "test.png")

            assert result is False
        finally:
            del sys.modules["pywinauto"]

    def test_capture_screenshot_success(self, tmp_path):
        """Test successful screenshot capture."""
        mock_module = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True

        mock_image = MagicMock()
        mock_window.capture_as_image.return_value = mock_image

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.process = 1234

        mock_app = MagicMock()
        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)

            screenshot_path = tmp_path / "screenshot.png"
            result = adapter.capture_screenshot(screenshot_path)

            assert result is True
            mock_image.save.assert_called_once()
        finally:
            del sys.modules["pywinauto"]


class TestAffinityAdapterCloseStudy:
    """Test AffinityAdapter study closing."""

    def test_close_study_not_connected(self):
        """Test close study fails when not connected."""
        mock_module = MagicMock()
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            result = adapter.close_study()

            assert result is False
        finally:
            del sys.modules["pywinauto"]

    def test_close_study_sends_escape(self):
        """Test close study sends Escape key."""
        mock_module = MagicMock()
        mock_window = MagicMock()
        mock_window.exists.return_value = True

        mock_app_instance = MagicMock()
        mock_app_instance.window.return_value = mock_window
        mock_app_instance.process = 1234

        mock_app = MagicMock()
        mock_app.return_value.connect.return_value = mock_app_instance

        mock_module.Application = mock_app
        sys.modules["pywinauto"] = mock_module

        try:
            from dicom_fuzzer.adapters.affinity import AffinityAdapter

            adapter = AffinityAdapter()
            adapter.connect(pid=1234)

            with patch("time.sleep"):
                result = adapter.close_study()

            assert result is True
            mock_window.type_keys.assert_called_with("{ESC}")
        finally:
            del sys.modules["pywinauto"]

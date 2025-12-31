"""Tests for adapter base classes and registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from dicom_fuzzer.adapters.base import PatientInfo, RenderResult, ViewerAdapter


class TestRenderResult:
    """Test RenderResult dataclass."""

    def test_default_values(self):
        """Test default values for success result."""
        result = RenderResult(success=True)
        assert result.success is True
        assert result.rendered_series == 0
        assert result.error_message is None
        assert result.screenshot_path is None
        assert result.load_time_seconds == 0.0
        assert result.details == {}

    def test_failure_result(self):
        """Test failure result with error message."""
        result = RenderResult(
            success=False,
            error_message="Series not found",
            load_time_seconds=5.2,
        )
        assert result.success is False
        assert result.error_message == "Series not found"
        assert result.load_time_seconds == 5.2

    def test_success_result_with_details(self):
        """Test success result with all fields."""
        result = RenderResult(
            success=True,
            rendered_series=3,
            screenshot_path=Path("./test.png"),
            load_time_seconds=2.5,
            details={"search_term": "CT Series"},
        )
        assert result.success is True
        assert result.rendered_series == 3
        assert result.screenshot_path == Path("./test.png")
        assert result.details["search_term"] == "CT Series"


class TestPatientInfo:
    """Test PatientInfo dataclass."""

    def test_default_values(self):
        """Test default values."""
        info = PatientInfo()
        assert info.patient_id is None
        assert info.patient_name is None
        assert info.study_date is None
        assert info.modality is None
        assert info.accession_number is None
        assert info.raw_text == ""
        assert info.extraction_method == "ui"

    def test_with_extracted_values(self):
        """Test with extracted values."""
        info = PatientInfo(
            patient_id="TEST001",
            patient_name="Doe^John",
            study_date="2024-01-15",
            modality="CT",
            extraction_method="ocr",
        )
        assert info.patient_id == "TEST001"
        assert info.patient_name == "Doe^John"
        assert info.study_date == "2024-01-15"
        assert info.modality == "CT"
        assert info.extraction_method == "ocr"


class ConcreteAdapter(ViewerAdapter):
    """Concrete implementation for testing abstract class."""

    def __init__(self):
        self._connected = False
        self._pid = None

    @property
    def name(self) -> str:
        return "Test Adapter"

    @property
    def supported_viewers(self) -> list[str]:
        return ["test.exe"]

    def connect(self, pid: int | None = None, process_name: str | None = None) -> bool:
        self._connected = True
        self._pid = pid
        return True

    def disconnect(self) -> None:
        self._connected = False
        self._pid = None

    def is_connected(self) -> bool:
        return self._connected

    def load_study_into_viewport(
        self,
        study_path: Path,
        series_name: str | None = None,
        timeout: float = 30.0,
    ) -> RenderResult:
        if not self.is_connected():
            return RenderResult(success=False, error_message="Not connected")
        return RenderResult(success=True, rendered_series=1)

    def get_displayed_patient_info(self) -> PatientInfo:
        return PatientInfo(patient_id="TEST", extraction_method="test")

    def close_study(self) -> bool:
        return True


class TestViewerAdapterInterface:
    """Test ViewerAdapter abstract interface."""

    def test_timing_constants(self):
        """Test default timing constants."""
        adapter = ConcreteAdapter()
        assert adapter.MINIMAL_PAUSE == 0.15
        assert adapter.BRIEF_PAUSE == 0.3
        assert adapter.WAIT_FOR_ACTION == 1.0
        assert adapter.WAIT_FOR_DATA_LOAD == 3.0

    def test_connect_disconnect_flow(self):
        """Test connection lifecycle."""
        adapter = ConcreteAdapter()
        assert adapter.is_connected() is False

        result = adapter.connect(pid=1234)
        assert result is True
        assert adapter.is_connected() is True

        adapter.disconnect()
        assert adapter.is_connected() is False

    def test_name_property(self):
        """Test name property."""
        adapter = ConcreteAdapter()
        assert adapter.name == "Test Adapter"

    def test_supported_viewers_property(self):
        """Test supported_viewers property."""
        adapter = ConcreteAdapter()
        assert "test.exe" in adapter.supported_viewers

    def test_load_study_requires_connection(self):
        """Test load_study fails when not connected."""
        adapter = ConcreteAdapter()
        result = adapter.load_study_into_viewport(Path("./test"))
        assert result.success is False
        assert "Not connected" in result.error_message

    def test_load_study_when_connected(self):
        """Test load_study succeeds when connected."""
        adapter = ConcreteAdapter()
        adapter.connect(pid=1234)
        result = adapter.load_study_into_viewport(Path("./test"))
        assert result.success is True
        assert result.rendered_series == 1

    def test_default_capture_screenshot(self):
        """Test default screenshot capture returns False."""
        adapter = ConcreteAdapter()
        result = adapter.capture_screenshot(Path("./test.png"))
        assert result is False

    def test_default_check_error_dialogs(self):
        """Test default error dialog check returns empty list."""
        adapter = ConcreteAdapter()
        errors = adapter.check_error_dialogs()
        assert errors == []

    def test_default_wait_for_idle(self):
        """Test default wait_for_idle returns True."""
        adapter = ConcreteAdapter()
        result = adapter.wait_for_idle(timeout=1.0)
        assert result is True

    def test_default_get_viewer_version(self):
        """Test default get_viewer_version returns None."""
        adapter = ConcreteAdapter()
        version = adapter.get_viewer_version()
        assert version is None


class TestAdapterRegistry:
    """Test adapter registration and discovery."""

    def test_list_adapters(self):
        """Test listing available adapters."""
        from dicom_fuzzer.adapters import list_adapters

        adapters = list_adapters()
        # May include 'affinity' if pywinauto is available
        assert isinstance(adapters, list)

    def test_get_unknown_adapter(self):
        """Test getting unknown adapter raises ValueError."""
        from dicom_fuzzer.adapters import get_adapter

        with pytest.raises(ValueError, match="Unknown adapter"):
            get_adapter("nonexistent_adapter")

    def test_register_adapter(self):
        """Test registering a custom adapter."""
        from dicom_fuzzer.adapters import get_adapter, list_adapters, register_adapter

        # Register test adapter
        register_adapter("test", ConcreteAdapter)

        # Verify it's listed
        adapters = list_adapters()
        assert "test" in adapters

        # Verify we can get it
        adapter = get_adapter("test")
        assert adapter.name == "Test Adapter"

    def test_get_affinity_adapter_if_available(self):
        """Test getting affinity adapter (may or may not be available)."""
        from dicom_fuzzer.adapters import get_adapter, list_adapters

        adapters = list_adapters()
        if "affinity" in adapters:
            adapter = get_adapter("affinity")
            assert adapter.name == "Hermes Affinity"
            assert "Hermes.exe" in adapter.supported_viewers

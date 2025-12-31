"""Base classes for viewer automation adapters.

This module defines the abstract interface that all viewer adapters must
implement. The adapter pattern allows the fuzzer to work with different
DICOM viewers through a common interface.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RenderResult:
    """Result of loading/rendering a study in a viewer.

    Attributes:
        success: True if study was successfully loaded and rendered.
        rendered_series: Number of series that rendered successfully.
        error_message: Error description if success is False.
        screenshot_path: Path to screenshot if captured.
        load_time_seconds: Time taken to load the study.
        details: Additional adapter-specific details.

    """

    success: bool
    rendered_series: int = 0
    error_message: str | None = None
    screenshot_path: Path | None = None
    load_time_seconds: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatientInfo:
    """Patient information extracted from viewer UI.

    Attributes:
        patient_id: Patient ID displayed in UI.
        patient_name: Patient name displayed in UI.
        study_date: Study date displayed in UI.
        modality: Modality displayed in UI.
        accession_number: Accession number if displayed.
        raw_text: Raw text extracted (for OCR-based extraction).
        extraction_method: How the info was extracted ('ui', 'ocr', 'mixed').

    """

    patient_id: str | None = None
    patient_name: str | None = None
    study_date: str | None = None
    modality: str | None = None
    accession_number: str | None = None
    raw_text: str = ""
    extraction_method: str = "ui"


class ViewerAdapter(ABC):
    """Abstract base class for viewer-specific automation.

    Adapters translate generic fuzzer operations into viewer-specific
    UI automation sequences. Each viewer (Affinity, OHIF, etc.) has
    its own adapter implementation.

    The workflow for using an adapter is:
        1. connect() - Attach to running viewer process
        2. load_study_into_viewport() - Load and render a study
        3. get_displayed_patient_info() - Extract visible patient info
        4. capture_screenshot() - Capture current state
        5. close_study() - Close current study
        6. disconnect() - Detach from viewer

    Example:
        >>> adapter = AffinityAdapter()
        >>> if adapter.connect(pid=1234):
        ...     result = adapter.load_study_into_viewport(study_path)
        ...     if result.success:
        ...         info = adapter.get_displayed_patient_info()
        ...         adapter.capture_screenshot(Path("./screenshot.png"))
        ...     adapter.close_study()
        ...     adapter.disconnect()

    """

    # Timing constants (can be overridden by subclasses)
    MINIMAL_PAUSE: float = 0.15  # Keyboard input delay
    BRIEF_PAUSE: float = 0.3  # UI state change
    WAIT_FOR_ACTION: float = 1.0  # Button click response
    WAIT_FOR_DATA_LOAD: float = 3.0  # Data loading/rendering

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter name for display and logging.

        Returns:
            Human-readable adapter name.

        """
        ...

    @property
    @abstractmethod
    def supported_viewers(self) -> list[str]:
        """List of viewer process names this adapter supports.

        Returns:
            List of process names (e.g., ["Hermes.exe", "Affinity.exe"]).

        """
        ...

    @abstractmethod
    def connect(self, pid: int | None = None, process_name: str | None = None) -> bool:
        """Connect to a running viewer application.

        Establishes connection to the viewer's UI automation interface.
        Either pid or process_name must be provided.

        Args:
            pid: Process ID of the viewer.
            process_name: Process name to find (uses first match).

        Returns:
            True if connection successful, False otherwise.

        """
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the viewer application.

        Releases automation resources. Safe to call even if not connected.
        """
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if adapter is connected to a viewer.

        Returns:
            True if connected, False otherwise.

        """
        ...

    @abstractmethod
    def load_study_into_viewport(
        self,
        study_path: Path,
        series_name: str | None = None,
        timeout: float = 30.0,
    ) -> RenderResult:
        """Load a study into the viewer's viewport.

        This is the main operation - it should:
        1. Navigate to the study in the viewer's browser
        2. Select the appropriate series
        3. Double-click or otherwise load into viewport
        4. Wait for rendering to complete

        Args:
            study_path: Path to the study directory.
            series_name: Specific series to load (if None, load first/default).
            timeout: Maximum time to wait for render completion.

        Returns:
            RenderResult indicating success/failure and details.

        """
        ...

    @abstractmethod
    def get_displayed_patient_info(self) -> PatientInfo:
        """Extract patient information from the viewer's display.

        Extracts visible patient demographics from the viewport overlay
        or info panel. May use OCR for overlay text.

        Returns:
            PatientInfo with extracted values.

        """
        ...

    @abstractmethod
    def close_study(self) -> bool:
        """Close the currently loaded study.

        Clears the viewport and returns viewer to neutral state.

        Returns:
            True if study closed successfully.

        """
        ...

    def capture_screenshot(self, output_path: Path) -> bool:
        """Capture a screenshot of the viewer window.

        Default implementation returns False. Override if viewer
        supports screenshot capture.

        Args:
            output_path: Path to save screenshot.

        Returns:
            True if screenshot captured successfully.

        """
        return False

    def check_error_dialogs(self) -> list[str]:
        """Check for error/warning dialogs.

        Scans for popup dialogs indicating errors.

        Returns:
            List of error dialog descriptions found.

        """
        return []

    def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait for the viewer to become idle.

        Useful after operations to ensure UI has settled.

        Args:
            timeout: Maximum wait time in seconds.

        Returns:
            True if idle state reached, False if timeout.

        """
        return True

    def get_viewer_version(self) -> str | None:
        """Get the viewer application version.

        Returns:
            Version string if available, None otherwise.

        """
        return None

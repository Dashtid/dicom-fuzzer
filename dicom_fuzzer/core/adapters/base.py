"""Base classes for viewer automation adapters.

This module defines the abstract interface that all viewer adapters must
implement. The adapter pattern allows the fuzzer to work with different
DICOM viewers through a common interface.
"""

from __future__ import annotations

import functools
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, ParamSpec, TypeVar

    P = ParamSpec("P")
    T = TypeVar("T")

logger = logging.getLogger(__name__)


class UIOperationError(Exception):
    """Exception raised when a UI operation fails after retries.

    Attributes:
        operation: Name of the operation that failed.
        attempts: Number of retry attempts made.
        last_error: The last exception that caused the failure.

    """

    def __init__(
        self,
        operation: str,
        attempts: int,
        last_error: Exception | None = None,
    ) -> None:
        self.operation = operation
        self.attempts = attempts
        self.last_error = last_error
        message = f"UI operation '{operation}' failed after {attempts} attempts"
        if last_error:
            message += f": {last_error}"
        super().__init__(message)


def retry_ui_operation(
    max_attempts: int = 3,
    delay: float = 0.5,
    backoff: float = 1.5,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator for retrying flaky UI operations with exponential backoff.

    Use this decorator on adapter methods that interact with the UI and may
    fail due to timing issues, window state changes, or transient errors.

    Args:
        max_attempts: Maximum number of attempts (default 3).
        delay: Initial delay between attempts in seconds (default 0.5).
        backoff: Multiplier for delay after each attempt (default 1.5).
        exceptions: Tuple of exception types to catch and retry.

    Returns:
        Decorated function that will retry on failure.

    Example:
        @retry_ui_operation(max_attempts=3, delay=0.3)
        def click_button(self) -> bool:
            self.window.button.click()
            return True

    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            last_exception: Exception | None = None
            current_delay = delay

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        logger.debug(
                            f"Retry {attempt}/{max_attempts} for {func.__name__}: {e}"
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.warning(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )

            # All attempts exhausted - raise or return False depending on return type
            # Check if function returns bool to maintain backward compatibility
            return_annotation = getattr(func, "__annotations__", {}).get("return")
            if return_annotation is bool or str(return_annotation) == "bool":
                return False  # type: ignore[return-value]

            raise UIOperationError(func.__name__, max_attempts, last_exception)

        return wrapper

    return decorator


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

"""Affinity viewer adapter using pywinauto.

This adapter translates fuzzer operations to pywinauto UI automation
for the Hermes Affinity DICOM viewer. It implements the keyboard-first
workflow used by the test automation framework.

Workflow:
    1. Connect to Hermes.exe process
    2. Focus search field (Ctrl+F)
    3. Type series/study name
    4. Double-click matching item to load into viewport
    5. Wait for render completion
    6. Extract patient info via OCR (overlay text)

Note:
    Patient demographics are rendered as viewport overlay text, not as
    standard UI controls with automation IDs. OCR extraction is required
    for reading patient info from the display.

"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from .base import (
    PatientInfo,
    RenderResult,
    UIOperationError,
    ViewerAdapter,
    retry_ui_operation,
)

if TYPE_CHECKING:
    from pywinauto import Application
    from pywinauto.controls.uiawrapper import UIAWrapper

logger = structlog.get_logger(__name__)


class AffinityAdapter(ViewerAdapter):
    """Adapter for Hermes Affinity DICOM viewer.

    Uses pywinauto with UIA backend to automate the Affinity viewer.
    Translates the keyboard-first workflow from the RF test automation.

    Timing Constants (matching RF retry_helpers.robot):
        MINIMAL_PAUSE: 0.15s - Keyboard input delay
        BRIEF_PAUSE: 0.3s - UI state change
        WAIT_FOR_ACTION: 1.0s - Button click response
        WAIT_FOR_DATA_LOAD: 3.0s - Data loading/rendering

    Known Automation IDs:
        - SearchTextBox: Search input field
        - Minimize, Maximize, Close: Window buttons
    """

    # Override base timing constants
    MINIMAL_PAUSE = 0.15
    BRIEF_PAUSE = 0.3
    WAIT_FOR_ACTION = 1.0
    WAIT_FOR_DATA_LOAD = 3.0

    # Window patterns - Affinity uses "Default" as window title, or may include "Affinity"
    MAIN_WINDOW_PATTERNS = [
        r"^Default$",  # Default Affinity window title
        r".*Affinity.*",  # If renamed/customized
        r".*Hermes.*",  # Alternative branding
    ]

    # Known automation IDs
    SEARCH_TEXTBOX_ID = "SearchTextBox"

    def __init__(self) -> None:
        """Initialize the Affinity adapter."""
        self.app: Application | None = None
        self._connected_pid: int | None = None
        self._main_window: UIAWrapper | None = None

    @property
    def name(self) -> str:
        """Adapter name."""
        return "Hermes Affinity"

    @property
    def supported_viewers(self) -> list[str]:
        """Supported viewer process names."""
        return ["Hermes.exe", "Affinity.exe"]

    def _find_main_window(self) -> bool:
        """Find the main window using pattern matching or fallback."""
        if self.app is None:
            return False
        for pattern in self.MAIN_WINDOW_PATTERNS:
            try:
                window = self.app.window(title_re=pattern)
                if window.exists():
                    self._main_window = window
                    logger.debug(f"Found window matching pattern: {pattern}")
                    return True
            except Exception:
                continue
        # Fallback: try first window
        try:
            windows = self.app.windows()
            if windows:
                self._main_window = windows[0]
                logger.debug(f"Using first window: {self._main_window.window_text()}")
                return True
        except Exception:
            pass  # Window enumeration may fail; returning False is the correct fallback
        return False

    def connect(self, pid: int | None = None, process_name: str | None = None) -> bool:
        """Connect to Affinity viewer.

        Args:
            pid: Process ID to connect to.
            process_name: Process name (defaults to Hermes.exe).

        Returns:
            True if connected successfully.

        """
        try:
            from pywinauto import Application

            if pid is not None:
                self.app = Application(backend="uia").connect(process=pid)
                self._connected_pid = pid
            elif process_name:
                self.app = Application(backend="uia").connect(path=process_name)
                self._connected_pid = self.app.process
            else:
                self.app = Application(backend="uia").connect(path="Hermes.exe")
                self._connected_pid = self.app.process

            if not self._find_main_window():
                logger.warning("Main window not found")
                self.disconnect()
                return False

            logger.debug(f"Connected to Affinity (PID: {self._connected_pid})")
            return True

        except ImportError:
            logger.error("pywinauto not installed. Install with: pip install pywinauto")
            return False
        except Exception as e:
            logger.warning(f"Failed to connect to Affinity: {e}")
            self.disconnect()
            return False

    def disconnect(self) -> None:
        """Disconnect from the viewer."""
        self.app = None
        self._connected_pid = None
        self._main_window = None

    def is_connected(self) -> bool:
        """Check if connected to viewer."""
        return self.app is not None and self._main_window is not None

    def load_study_into_viewport(
        self,
        study_path: Path,
        series_name: str | None = None,
        timeout: float = 30.0,
    ) -> RenderResult:
        """Load a study into the viewport.

        Implements the keyboard-first workflow:
        1. Focus search field (Ctrl+F)
        2. Type series/study name
        3. Double-click to load
        4. Wait for render

        Args:
            study_path: Path to study (used to derive search term if no series_name).
            series_name: Series name to search for and load.
            timeout: Maximum wait time for render completion.

        Returns:
            RenderResult with success/failure details.

        """
        if not self.is_connected():
            return RenderResult(
                success=False,
                error_message="Not connected to Affinity",
            )

        start_time = time.time()

        try:
            # Derive search term if not provided
            search_term = series_name or study_path.name

            # Step 1: Focus search field using keyboard shortcut
            if not self._focus_search_field():
                return RenderResult(
                    success=False,
                    error_message="Failed to focus search field",
                )

            # Step 2: Type search term
            if not self._type_search(search_term):
                return RenderResult(
                    success=False,
                    error_message="Failed to type search term",
                )

            # Step 3: Wait for search results to populate
            time.sleep(self.WAIT_FOR_ACTION)

            # Step 4: Select and double-click the highlighted search result
            if not self._select_and_load_series(search_term):
                return RenderResult(
                    success=False,
                    error_message=f"Series '{search_term}' not found in browser",
                )

            # Step 5: Wait for render and switch to new study window
            time.sleep(self.WAIT_FOR_DATA_LOAD)
            self._switch_to_study_window()

            # Step 6: Check for errors
            errors = self.check_error_dialogs()
            if errors:
                return RenderResult(
                    success=False,
                    error_message=f"Error dialogs: {'; '.join(errors)}",
                )

            # Step 7: Wait for idle
            self.wait_for_idle(timeout=timeout - (time.time() - start_time))

            load_time = time.time() - start_time
            window_title = (
                self._main_window.window_text() if self._main_window else None
            )

            return RenderResult(
                success=True,
                rendered_series=1,
                load_time_seconds=load_time,
                details={"search_term": search_term, "window_title": window_title},
            )

        except Exception as e:
            logger.error(f"Error loading study: {e}")
            return RenderResult(
                success=False,
                error_message=str(e),
            )

    @retry_ui_operation(max_attempts=3, delay=0.3, backoff=1.5)
    def _focus_search_field(self) -> bool:
        """Focus the search field using Ctrl+F.

        Translates RF keyword: `Press Keys    None    ctrl+f`

        Returns:
            True if search field was focused.

        Raises:
            Exception: If focus operation fails (triggers retry).

        """
        # Ensure main window is focused
        self._main_window.set_focus()
        time.sleep(self.MINIMAL_PAUSE)

        # Send Ctrl+F to focus search
        self._main_window.type_keys("^f")
        time.sleep(self.BRIEF_PAUSE)

        # Verify search field is focused
        search_box = self._main_window.child_window(auto_id=self.SEARCH_TEXTBOX_ID)
        if search_box.exists():
            logger.debug("Search field focused successfully")
            return True

        # Verification failed - raise to trigger retry
        raise UIOperationError("focus_search_field", 1, None)

    @retry_ui_operation(max_attempts=2, delay=0.2, backoff=1.5)
    def _type_search(self, text: str) -> bool:
        """Type text into the search field.

        Translates RF keyword: `Send Keys    ${series_name}`

        Args:
            text: Text to type.

        Returns:
            True if text was typed successfully.

        """
        # Try to find and use search box directly
        search_box = self._main_window.child_window(auto_id=self.SEARCH_TEXTBOX_ID)
        if search_box.exists():
            search_box.set_focus()
            time.sleep(self.MINIMAL_PAUSE)
            # Clear existing text and type new
            search_box.type_keys("^a", pause=self.MINIMAL_PAUSE)
            search_box.type_keys(text, pause=self.MINIMAL_PAUSE, with_spaces=True)
            logger.debug("Typed search text via search box", text=text[:30])
            return True

        # Fallback: type directly (search field should be focused)
        logger.debug("Search box not found, typing directly")
        self._main_window.type_keys(text, pause=self.MINIMAL_PAUSE, with_spaces=True)
        return True

    @retry_ui_operation(max_attempts=3, delay=0.5, backoff=1.5)
    def _select_and_load_series(self, series_name: str) -> bool:
        """Click to select the search result, then press Enter to load.

        After typing in the search box, Affinity filters the list but doesn't
        auto-select. Need to click the matching item first, then Enter/double-click.

        UI Hierarchy (discovered via diagnostic):
            ListItem (ListBoxItem) <- CLICK THIS
              └── Custom (SeriesDescTextblock)
                    └── Custom (EditableTextBlock)
                          └── Text (TextBlock) <- Text we match

        Args:
            series_name: Series name that was searched for.

        Returns:
            True if series was found, clicked, and loaded.

        """
        pattern = re.escape(series_name)

        # Target the Datalist specifically to avoid clicking wrong elements
        search_container = self._main_window
        try:
            datalist = self._main_window.child_window(auto_id="Datalist")
            if datalist.exists():
                search_container = datalist
                logger.debug("Searching within Datalist")
        except Exception as e:
            logger.debug("Datalist not found, searching whole window", error=str(e))

        # Find and click the matching item in the filtered list
        found_match = False
        last_click_error: Exception | None = None

        for control in search_container.descendants():
            try:
                title = control.window_text()
                if title and re.search(pattern, title, re.IGNORECASE):
                    ctrl_type = control.element_info.control_type
                    logger.debug(
                        "Found match",
                        title=title[:50],
                        control_type=ctrl_type,
                    )

                    # TextBlock/Text elements are not clickable - find parent
                    # Navigate up to find the ListItem or first clickable ancestor
                    clickable = control
                    if ctrl_type in ("Text", "TextBlock"):
                        clickable = self._find_clickable_ancestor(control)
                        if clickable:
                            anc_type = clickable.element_info.control_type
                            logger.debug("Using ancestor", ancestor_type=anc_type)
                        else:
                            # Fallback: use parent
                            clickable = control.parent()
                            logger.debug("Using immediate parent")

                    # Click to select, then Enter to load
                    logger.debug("Clicking to select")
                    clickable.click_input()
                    time.sleep(self.BRIEF_PAUSE)
                    logger.debug("Pressing Enter to load")
                    self._main_window.type_keys("{ENTER}")
                    found_match = True
                    break
            except Exception as e:
                # Log and continue to next control - this control may not be the right one
                last_click_error = e
                logger.debug("Control interaction failed", error=str(e))
                continue

        if not found_match:
            if last_click_error:
                logger.warning(
                    "Series not found in browser",
                    series_name=series_name,
                    last_error=str(last_click_error),
                )
            else:
                logger.warning("Series not found in browser", series_name=series_name)
            # Raise to trigger retry
            raise UIOperationError(
                "select_and_load_series",
                1,
                last_click_error or ValueError(f"Series '{series_name}' not found"),
            )

        # Don't verify here - window reference may be stale after Enter
        # Verification happens in load_study_into_viewport via _switch_to_study_window
        logger.debug("Series click + Enter sent successfully")
        return True

    def _find_clickable_ancestor(self, control: object) -> object | None:
        """Find a clickable ancestor for the Text element.

        UI Hierarchy - clicking the immediate parent (Custom) + Enter works:
            ListItem (ListBoxItem)
              └── Custom (SeriesDescTextblock)
                    └── Custom (EditableTextBlock) <- Click this
                          └── Text (TextBlock) <- Text we match

        Args:
            control: Starting control to search from.

        Returns:
            Clickable ancestor or None (falls back to immediate parent).

        """
        # Custom elements work for click + Enter
        clickable_types = {"ListItem", "DataItem", "TreeItem", "Custom"}
        try:
            current = control.parent()
            # Walk up max 5 levels
            for _ in range(5):
                if current is None:
                    break
                ctrl_type = current.element_info.control_type
                if ctrl_type in clickable_types:
                    return current
                current = current.parent()
        except Exception as e:
            logger.debug("Error walking ancestor tree", error=str(e))
        return None

    def _switch_to_study_window(self) -> bool:
        """Switch to the study window after loading.

        When a study is loaded via Enter, the window title may change from
        "Default" to the study name (e.g., "PET-CT [25-Feb-2016]"), or a new
        window may open. This method re-acquires the main window reference.

        Returns:
            True if window was re-acquired successfully.

        """
        try:
            # Re-acquire window reference - the title may have changed
            windows = self.app.windows()
            if not windows:
                return False

            # Prefer a window that's NOT "Default" (has study loaded)
            for window in windows:
                title = window.window_text()
                if title and title != "Default":
                    logger.debug(f"Switched to study window: {title}")
                    self._main_window = window
                    return True

            # Fallback: use first available window
            self._main_window = windows[0]
            logger.debug(f"Using window: {self._main_window.window_text()}")
            return True

        except Exception as e:
            logger.debug(f"Error switching window: {e}")
            return False

    def get_displayed_patient_info(self) -> PatientInfo:
        """Extract patient info from the display.

        Patient demographics in Affinity are rendered as viewport overlay
        text, not as standard UI controls. This method extracts all visible
        text and attempts to parse patient info.

        For accurate extraction, consider using OCR on a captured screenshot.

        Returns:
            PatientInfo with extracted values (may be incomplete).

        """
        if not self.is_connected():
            return PatientInfo(extraction_method="failed")

        try:
            # Extract all visible text from the main window
            all_text = self._extract_all_text()

            # Attempt to parse patient info from text
            # These patterns are heuristic - actual format depends on viewer config
            patient_id = self._extract_pattern(
                all_text, r"(?:ID|Patient ID)[:\s]*(\S+)"
            )
            patient_name = self._extract_pattern(
                all_text, r"(?:Name|Patient)[:\s]*([^,\n]+)"
            )
            study_date = self._extract_pattern(
                all_text, r"(?:Date|Study Date)[:\s]*(\d{4}[-/]?\d{2}[-/]?\d{2})"
            )
            modality = self._extract_pattern(all_text, r"\b(CT|MR|PT|NM|US|XA|CR)\b")
            accession = self._extract_pattern(
                all_text, r"(?:Accession|ACC)[:\s#]*(\S+)"
            )

            return PatientInfo(
                patient_id=patient_id,
                patient_name=patient_name,
                study_date=study_date,
                modality=modality,
                accession_number=accession,
                raw_text=all_text[:2000],  # Truncate for storage
                extraction_method="text_scrape",
            )

        except Exception as e:
            logger.warning(f"Failed to extract patient info: {e}")
            return PatientInfo(
                raw_text=f"Error: {e}",
                extraction_method="failed",
            )

    def _extract_pattern(self, text: str, pattern: str) -> str | None:
        """Extract first match of a regex pattern from text.

        Args:
            text: Text to search.
            pattern: Regex pattern with one capture group.

        Returns:
            Captured group if found, None otherwise.

        """
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.group(1):
            return match.group(1).strip()
        return None

    def _extract_all_text(self) -> str:
        """Extract all visible text from the main window.

        Returns:
            Concatenated text from all UI elements.

        """
        texts = []

        try:
            # Get window's own text
            window_text = self._main_window.window_text()
            if window_text:
                texts.append(window_text)

            # Get text from all descendants
            for control in self._main_window.descendants():
                try:
                    text = control.window_text()
                    if text and text not in texts:
                        texts.append(text)
                except Exception:
                    # Expected for some control types - skip silently
                    continue

        except Exception as e:
            logger.debug(f"Error extracting text: {e}")

        return " ".join(texts)

    def close_study(self) -> bool:
        """Close the currently loaded study.

        Sends Escape key to close/deselect current study.

        Returns:
            True if close operation was sent.

        """
        if not self.is_connected():
            return False

        try:
            self._main_window.set_focus()
            time.sleep(self.MINIMAL_PAUSE)
            self._main_window.type_keys("{ESC}")
            time.sleep(self.BRIEF_PAUSE)
            return True
        except Exception as e:
            logger.warning(f"Failed to close study: {e}")
            return False

    def capture_screenshot(self, output_path: Path) -> bool:
        """Capture screenshot of the main window.

        Args:
            output_path: Path to save screenshot.

        Returns:
            True if screenshot captured successfully.

        """
        if not self.is_connected():
            return False

        try:
            image = self._main_window.capture_as_image()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            image.save(str(output_path))
            return True
        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")
            return False

    def check_error_dialogs(self) -> list[str]:
        """Check for error/warning dialogs.

        Returns:
            List of error dialog descriptions.

        """
        if not self.is_connected():
            return ["Not connected"]

        errors = []
        error_keywords = [
            "error",
            "warning",
            "failed",
            "exception",
            "crash",
            "fatal",
            "cannot",
            "unable",
            "invalid",
        ]

        try:
            for window in self.app.windows():
                title = window.window_text().lower()
                if any(word in title for word in error_keywords):
                    errors.append(f"Dialog: {window.window_text()}")
        except Exception as e:
            logger.debug(f"Error checking dialogs: {e}")

        return errors

    def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait for the viewer to become idle.

        Watches for loading indicators to disappear.

        Args:
            timeout: Maximum wait time.

        Returns:
            True if idle state reached.

        """
        if not self.is_connected():
            return False

        loading_indicators = ["loading", "please wait", "initializing"]
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                all_text = self._extract_all_text().lower()
                if not any(ind in all_text for ind in loading_indicators):
                    return True
            except Exception as e:
                logger.debug("Error checking idle state", error=str(e))
            time.sleep(0.5)

        return False

    def get_viewer_version(self) -> str | None:
        """Get Affinity version from window title or about dialog.

        Returns:
            Version string if found.

        """
        if not self.is_connected():
            return None

        try:
            title = self._main_window.window_text()
            # Try to extract version from title (format varies)
            match = re.search(r"(\d+\.\d+(?:\.\d+)*)", title)
            if match:
                return match.group(1)
        except Exception as e:
            logger.debug("Error extracting viewer version", error=str(e))

        return None

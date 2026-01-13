"""UI validation for WinUI DICOM viewers.

This module provides pywinauto-based UI validation to detect clinical safety issues
such as incorrect patient information display, wrong measurements, or missing series.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pywinauto import Application

logger = logging.getLogger(__name__)


@dataclass
class ExpectedValues:
    """Expected values to validate against UI display.

    Attributes:
        patient_id: Expected patient ID string.
        patient_name: Expected patient name string.
        study_date: Expected study date string.
        series_count: Expected number of series.
        modality: Expected modality string.
        custom_checks: Additional key-value pairs to validate.

    """

    patient_id: str | None = None
    patient_name: str | None = None
    study_date: str | None = None
    series_count: int | None = None
    modality: str | None = None
    custom_checks: dict[str, str] = field(default_factory=dict)


@dataclass
class UIValidationResult:
    """Result of UI validation checks.

    Attributes:
        passed: True if all validation checks passed.
        checks: Dictionary mapping check names to pass/fail status.
        errors: List of error messages for failed checks.
        warnings: List of warning messages for non-critical issues.
        extracted_text: All text extracted from the UI (for debugging).

    """

    passed: bool
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extracted_text: str = ""


class UIValidator:
    """Validate displayed values match DICOM input.

    Uses pywinauto with the 'uia' backend to connect to WinUI applications
    and extract displayed text for validation against expected DICOM values.

    Example:
        >>> validator = UIValidator(process_name="Hermes.exe")
        >>> if validator.connect(process_pid):
        ...     expected = ExpectedValues(patient_id="TEST001", patient_name="Doe^John")
        ...     result = validator.validate_patient_info(expected)
        ...     if not result.passed:
        ...         print(f"Validation failed: {result.errors}")

    """

    def __init__(
        self,
        process_name: str = "Hermes.exe",
        window_title_pattern: str | None = None,
    ):
        """Initialize the UI validator.

        Args:
            process_name: Name of the target process (e.g., "Hermes.exe").
            window_title_pattern: Regex pattern for main window title.
                Defaults to ".*Affinity.*" for Hermes Affinity.

        """
        self.process_name = process_name
        self.window_title_pattern = window_title_pattern or ".*Affinity.*"
        self.app: Application | None = None
        self._connected_pid: int | None = None

    def connect(self, pid: int) -> bool:
        """Connect to a running application by process ID.

        Args:
            pid: Process ID of the running application.

        Returns:
            True if connection successful, False otherwise.

        """
        try:
            from pywinauto import Application

            self.app = Application(backend="uia").connect(process=pid)
            self._connected_pid = pid
            logger.debug(f"Connected to process {pid}")
            return True
        except ImportError:
            logger.error("pywinauto not installed. Install with: pip install pywinauto")
            return False
        except Exception as e:
            logger.warning(f"Failed to connect to process {pid}: {e}")
            self.app = None
            self._connected_pid = None
            return False

    def disconnect(self) -> None:
        """Disconnect from the current application."""
        self.app = None
        self._connected_pid = None

    def is_connected(self) -> bool:
        """Check if validator is connected to an application.

        Returns:
            True if connected, False otherwise.

        """
        return self.app is not None and self._connected_pid is not None

    def _check_value(
        self,
        displayed_text: str,
        value: str | None,
        check_name: str,
        variants_func: Callable[[str], list[str]] | None = None,
    ) -> tuple[bool | None, str | None]:
        """Check if a value or its variants are in displayed text.

        Returns:
            Tuple of (found or None if no value, error message or None)

        """
        if not value:
            return None, None
        if variants_func:
            found = any(v in displayed_text for v in variants_func(value))
        else:
            found = value in displayed_text
        error = None if found else f"{check_name} '{value}' not found in UI"
        return found, error

    def _check_series_count(
        self, displayed_text: str, count: int | None
    ) -> tuple[bool | None, str | None]:
        """Check if series count is visible in UI."""
        if count is None:
            return None, None
        count_str = str(count)
        text_lower = displayed_text.lower()
        found = (
            f"{count_str} series" in text_lower
            or f"series: {count_str}" in text_lower
            or f"({count_str})" in displayed_text
        )
        error = None if found else f"Series count '{count}' not confirmed in UI"
        return found, error

    def _run_validations(
        self, displayed_text: str, expected: ExpectedValues
    ) -> tuple[dict[str, bool], list[str], list[str]]:
        """Run all validation checks and return results."""
        errors: list[str] = []
        warnings: list[str] = []
        checks: dict[str, bool] = {}

        validations = [
            (expected.patient_id, "patient_id", "Patient ID", None, True),
            (
                expected.patient_name,
                "patient_name",
                "Patient name",
                self._get_name_variants,
                True,
            ),
            (
                expected.study_date,
                "study_date",
                "Study date",
                self._get_date_variants,
                False,
            ),
            (expected.modality, "modality", "Modality", None, False),
        ]

        for value, key, label, variants_func, is_error in validations:
            found, msg = self._check_value(displayed_text, value, label, variants_func)
            if found is not None:
                checks[key] = found
                if msg:
                    (errors if is_error else warnings).append(msg)

        found, msg = self._check_series_count(displayed_text, expected.series_count)
        if found is not None:
            checks["series_count"] = found
            if msg:
                warnings.append(msg)

        for key, value in expected.custom_checks.items():
            found = value in displayed_text
            checks[f"custom_{key}"] = found
            if not found:
                errors.append(f"Custom check '{key}': '{value}' not found in UI")

        return checks, errors, warnings

    def validate_patient_info(self, expected: ExpectedValues) -> UIValidationResult:
        """Check displayed patient info matches expected values."""
        if not self.is_connected():
            return UIValidationResult(
                passed=False, errors=["Not connected to application"]
            )

        try:
            main_window = self.app.window(title_re=self.window_title_pattern)
            if not main_window.exists():
                return UIValidationResult(
                    passed=False,
                    errors=[
                        f"Main window not found (pattern: {self.window_title_pattern})"
                    ],
                )

            displayed_text = self._extract_all_text(main_window)
            checks, errors, warnings = self._run_validations(displayed_text, expected)

            return UIValidationResult(
                passed=len(errors) == 0,
                checks=checks,
                errors=errors,
                warnings=warnings,
                extracted_text=displayed_text[:2000],
            )

        except Exception as e:
            logger.error(f"Error during validation: {e}")
            return UIValidationResult(passed=False, errors=[f"Validation error: {e}"])

    def check_error_dialogs(self) -> list[str]:
        """Check for error/warning dialogs in the application.

        Scans all windows belonging to the application for dialog boxes
        that might indicate errors, warnings, or exceptions.

        Returns:
            List of error dialog descriptions found.

        """
        if not self.is_connected():
            return ["Not connected to application"]

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

        errors: list[str] = []

        try:
            for window in self.app.windows():
                title = window.window_text().lower()
                if any(word in title for word in error_keywords):
                    window_text = self._extract_all_text(window)
                    errors.append(
                        f"Error dialog '{window.window_text()}': {window_text[:200]}"
                    )
        except Exception as e:
            logger.warning(f"Error checking dialogs: {e}")

        return errors

    def check_rendering_state(self) -> UIValidationResult:
        """Check if the application appears to be rendering correctly.

        Looks for signs of rendering issues such as:
        - Blank/empty main content area
        - Loading indicators that persist too long
        - Error messages in the viewport

        Returns:
            UIValidationResult with rendering status.

        """
        if not self.is_connected():
            return UIValidationResult(
                passed=False,
                errors=["Not connected to application"],
            )

        checks: dict[str, bool] = {}
        errors: list[str] = []
        warnings: list[str] = []

        try:
            main_window = self.app.window(title_re=self.window_title_pattern)
            if not main_window.exists():
                return UIValidationResult(
                    passed=False,
                    errors=["Main window not found"],
                )

            displayed_text = self._extract_all_text(main_window)

            # Check for loading indicators
            loading_indicators = ["loading", "please wait", "initializing"]
            has_loading = any(
                ind in displayed_text.lower() for ind in loading_indicators
            )
            checks["no_loading_indicator"] = not has_loading
            if has_loading:
                warnings.append("Loading indicator still visible")

            # Check for error messages in content
            error_indicators = ["error loading", "failed to load", "cannot display"]
            has_error = any(ind in displayed_text.lower() for ind in error_indicators)
            checks["no_error_messages"] = not has_error
            if has_error:
                errors.append("Error message visible in content area")

            # Check that some content is present
            # Minimum expected: some text beyond just window chrome
            has_content = len(displayed_text.strip()) > 50
            checks["has_content"] = has_content
            if not has_content:
                errors.append("Content area appears empty")

            return UIValidationResult(
                passed=len(errors) == 0,
                checks=checks,
                errors=errors,
                warnings=warnings,
                extracted_text=displayed_text[:2000],
            )

        except Exception as e:
            logger.error(f"Error checking rendering state: {e}")
            return UIValidationResult(
                passed=False,
                errors=[f"Rendering check error: {e}"],
            )

    def get_window_screenshot(self, output_path: str) -> bool:
        """Capture a screenshot of the main application window.

        Args:
            output_path: Path to save the screenshot image.

        Returns:
            True if screenshot was saved successfully.

        """
        if not self.is_connected():
            return False

        try:
            main_window = self.app.window(title_re=self.window_title_pattern)
            if main_window.exists():
                image = main_window.capture_as_image()
                image.save(output_path)
                return True
        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")

        return False

    def _extract_all_text(self, window: object) -> str:
        """Recursively extract all text from window and descendants.

        Args:
            window: pywinauto window wrapper object.

        Returns:
            Concatenated string of all visible text.

        """
        texts: list[str] = []

        try:
            # Get window's own text
            window_text = window.window_text()
            if window_text:
                texts.append(window_text)

            # Recursively get text from all descendants
            for control in window.descendants():
                try:
                    text = control.window_text()
                    if text and text not in texts:  # Avoid duplicates
                        texts.append(text)
                except Exception:
                    # Some controls may not support text extraction
                    pass
        except Exception as e:
            logger.debug(f"Error extracting text: {e}")

        return " ".join(texts)

    def _get_name_variants(self, dicom_name: str) -> list[str]:
        """Get various display formats for a DICOM name.

        DICOM names use ^ as separator (e.g., "Doe^John^Middle").
        UI might display as "John Doe", "Doe, John", etc.

        Args:
            dicom_name: DICOM-format name string.

        Returns:
            List of possible display variants.

        """
        variants = [dicom_name]

        if "^" in dicom_name:
            parts = dicom_name.split("^")
            if len(parts) >= 2:
                last_name = parts[0]
                first_name = parts[1]
                # Common display formats
                variants.extend(
                    [
                        f"{first_name} {last_name}",
                        f"{last_name}, {first_name}",
                        f"{last_name} {first_name}",
                        first_name,
                        last_name,
                    ]
                )

        return variants

    def _get_date_variants(self, dicom_date: str) -> list[str]:
        """Get various display formats for a DICOM date.

        DICOM dates are YYYYMMDD format. UI might display as
        "2024-01-15", "01/15/2024", "15 Jan 2024", etc.

        Args:
            dicom_date: DICOM-format date string (YYYYMMDD).

        Returns:
            List of possible display variants.

        """
        variants = [dicom_date]

        if len(dicom_date) == 8 and dicom_date.isdigit():
            year = dicom_date[:4]
            month = dicom_date[4:6]
            day = dicom_date[6:8]

            month_names = [
                "",
                "Jan",
                "Feb",
                "Mar",
                "Apr",
                "May",
                "Jun",
                "Jul",
                "Aug",
                "Sep",
                "Oct",
                "Nov",
                "Dec",
            ]
            month_int = int(month)
            month_name = month_names[month_int] if month_int <= 12 else ""

            variants.extend(
                [
                    f"{year}-{month}-{day}",
                    f"{month}/{day}/{year}",
                    f"{day}/{month}/{year}",
                    f"{day} {month_name} {year}",
                    f"{month_name} {day}, {year}",
                    f"{int(day)} {month_name} {year}",
                ]
            )

        return variants


def create_validation_callback(
    expected: ExpectedValues,
    process_name: str = "Hermes.exe",
) -> callable:
    """Create a validation callback for use with phased observation.

    This factory function creates a callback suitable for use with
    TargetHarness.test_study_with_phases() validation callbacks.

    Args:
        expected: Expected values to validate against.
        process_name: Name of the target process.

    Returns:
        Callback function that takes a PID and returns ValidationResult.

    """
    from dicom_fuzzer.core.target_harness import (
        ValidationResult as HarnessValidationResult,
    )

    def callback(pid: int) -> HarnessValidationResult:
        validator = UIValidator(process_name=process_name)
        if not validator.connect(pid):
            return HarnessValidationResult(
                passed=False,
                message="Failed to connect to application for UI validation",
            )

        try:
            result = validator.validate_patient_info(expected)
            return HarnessValidationResult(
                passed=result.passed,
                message="; ".join(result.errors) if result.errors else None,
                details={
                    "checks": result.checks,
                    "warnings": result.warnings,
                },
            )
        finally:
            validator.disconnect()

    return callback

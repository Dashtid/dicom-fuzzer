"""DICOM Viewer Harness Module

This module provides tools for testing DICOM viewers with fuzzed data, including
support for both 2D (single-file) and 3D (multi-slice series) testing scenarios.

KEY COMPONENTS:
- ViewerLauncher3D: Launch viewers with complete 3D series folders
- ViewerConfig: Configuration for different DICOM viewer applications
- SeriesTestResult: Results from 3D series testing

USAGE:
    from dicom_fuzzer.harness import ViewerLauncher3D, ViewerConfig, ViewerType

    # Create configuration
    config = ViewerConfig(
        viewer_type=ViewerType.GENERIC,
        executable_path=Path("/path/to/viewer"),
        command_template="{folder_path}",
        timeout_seconds=60
    )

    # Launch viewer with series
    launcher = ViewerLauncher3D(config)
    result = launcher.launch_with_series(series_folder)

    if result.crashed:
        print(f"Crash detected!")

SECURITY NOTE:
This module is designed for security testing of DICOM viewers in isolated
environments. Based on 2025 CVE research, several popular viewers have known
vulnerabilities when processing malformed DICOM files and series.

See viewer_profiles.yaml for pre-configured viewer settings.
"""

from .viewer_launcher_3d import (
    SeriesTestResult,
    ViewerConfig,
    ViewerLauncher3D,
    ViewerType,
    create_generic_config,
)

__all__ = [
    # Core classes
    "ViewerLauncher3D",
    "ViewerConfig",
    "SeriesTestResult",
    "ViewerType",
    # Helper functions
    "create_generic_config",
]

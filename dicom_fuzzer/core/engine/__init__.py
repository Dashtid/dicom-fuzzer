"""Fuzzing engines and orchestrators."""

from .generator import DICOMGenerator
from .gui_fuzzer import GUIFuzzer
from .gui_monitor import GUIMonitor
from .gui_monitor_types import GUIResponse, MonitorConfig
from .synthetic import (
    SyntheticDataGenerator,
    SyntheticDicomGenerator,
    SyntheticPatient,
    SyntheticSeries,
    SyntheticStudy,
    generate_sample_files,
)

# Backward compatibility alias
ResponseAwareFuzzer = GUIFuzzer

__all__ = [
    "DICOMGenerator",
    "GUIFuzzer",
    "GUIMonitor",
    "GUIResponse",
    "MonitorConfig",
    "ResponseAwareFuzzer",
    "SyntheticDataGenerator",
    "SyntheticDicomGenerator",
    "SyntheticPatient",
    "SyntheticSeries",
    "SyntheticStudy",
    "generate_sample_files",
]

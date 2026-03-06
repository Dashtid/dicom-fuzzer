"""Shared fixtures for crash module tests."""

import pytest

from dicom_fuzzer.core.crash.crash_analyzer import CrashAnalyzer


@pytest.fixture
def analyzer(tmp_path):
    """Provide a CrashAnalyzer with isolated crash directory."""
    return CrashAnalyzer(crash_dir=str(tmp_path / "crashes"))

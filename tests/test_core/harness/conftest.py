"""Shared fixtures for harness module tests."""

import pytest

from dicom_fuzzer.core.harness.target_runner import TargetRunner


@pytest.fixture(autouse=True)
def _isolate_target_runner_crash_dir(tmp_path, monkeypatch):
    """Redirect TargetRunner default crash_dir to tmp_path.

    Prevents tests from creating ``./artifacts/crashes/`` and
    ``./artifacts/crashes/dumps/`` in the real project directory.
    """
    isolated_crash_dir = str(tmp_path / "crashes")

    original_init = TargetRunner.__init__

    def patched_init(self, *args, crash_dir=isolated_crash_dir, **kwargs):
        original_init(self, *args, crash_dir=crash_dir, **kwargs)

    monkeypatch.setattr(TargetRunner, "__init__", patched_init)

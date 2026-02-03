"""Tests for GUI Fuzzer module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.engine.gui_fuzzer import GUIFuzzer
from dicom_fuzzer.core.engine.gui_monitor_types import (
    MonitorConfig,
    ResponseType,
)


class TestGUIFuzzer:
    """Tests for GUIFuzzer class."""

    def test_init_nonexistent_target(self) -> None:
        """Test fuzzer raises error for nonexistent target."""
        with pytest.raises(FileNotFoundError):
            GUIFuzzer("/nonexistent/path/to/app.exe")

    def test_init_with_existing_target(self, tmp_path: Path) -> None:
        """Test fuzzer initialization with existing target."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target))

        assert fuzzer.target_executable == target
        assert fuzzer.timeout == 10.0  # Default
        assert fuzzer.monitor is not None
        assert fuzzer.enable_state_coverage is True
        assert fuzzer.state_tracker is not None

    def test_init_disable_state_coverage(self, tmp_path: Path) -> None:
        """Test fuzzer with state coverage disabled."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target), enable_state_coverage=False)

        assert fuzzer.enable_state_coverage is False
        assert fuzzer.state_tracker is None

    def test_custom_config(self, tmp_path: Path) -> None:
        """Test fuzzer with custom config."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        config = MonitorConfig(poll_interval=0.5)
        fuzzer = GUIFuzzer(str(target), config=config, timeout=5.0)

        assert fuzzer.timeout == 5.0
        assert fuzzer.monitor.config.poll_interval == 0.5

    @patch("subprocess.Popen")
    def test_test_file(self, mock_popen: MagicMock, tmp_path: Path) -> None:
        """Test the test_file method."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")

        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        fuzzer = GUIFuzzer(str(target), timeout=0.1)
        responses = fuzzer.test_file(test_file)

        assert isinstance(responses, list)

    @patch("subprocess.Popen")
    def test_test_file_handles_exception(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Test test_file handles exceptions gracefully."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")

        mock_popen.side_effect = OSError("Cannot start process")

        fuzzer = GUIFuzzer(str(target), timeout=0.1)
        responses = fuzzer.test_file(test_file)

        assert len(responses) >= 1
        assert any(r.response_type == ResponseType.CRASH for r in responses)

    @patch("subprocess.Popen")
    def test_run_campaign(self, mock_popen: MagicMock, tmp_path: Path) -> None:
        """Test running a campaign."""
        target = tmp_path / "test_app.exe"
        target.write_bytes(b"dummy")

        test_files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"dicom")
            test_files.append(f)

        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        fuzzer = GUIFuzzer(str(target), timeout=0.1)
        results = fuzzer.run_campaign(test_files)

        assert results["total_files"] == 3
        assert results["files_tested"] == 3
        assert "responses" in results
        assert "summary" in results
        assert "state_coverage" in results
        assert "interesting_inputs" in results

    @patch("subprocess.Popen")
    def test_run_campaign_completes_all_files(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Test campaign processes all files."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        test_files = [tmp_path / f"test_{i}.dcm" for i in range(3)]
        for f in test_files:
            f.write_bytes(b"dicom")

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        fuzzer = GUIFuzzer(str(target), timeout=0.1)
        results = fuzzer.run_campaign(test_files)

        assert results["files_tested"] == len(test_files)

    def test_get_state_coverage_enabled(self, tmp_path: Path) -> None:
        """Test get_state_coverage when enabled."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target), enable_state_coverage=True)
        coverage = fuzzer.get_state_coverage()

        assert isinstance(coverage, dict)
        assert "unique_states" in coverage

    def test_get_state_coverage_disabled(self, tmp_path: Path) -> None:
        """Test get_state_coverage when disabled."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target), enable_state_coverage=False)
        coverage = fuzzer.get_state_coverage()

        assert coverage == {}

    def test_get_interesting_inputs_enabled(self, tmp_path: Path) -> None:
        """Test get_interesting_inputs when enabled."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target), enable_state_coverage=True)
        inputs = fuzzer.get_interesting_inputs()

        assert isinstance(inputs, list)

    def test_get_interesting_inputs_disabled(self, tmp_path: Path) -> None:
        """Test get_interesting_inputs when disabled."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target), enable_state_coverage=False)
        inputs = fuzzer.get_interesting_inputs()

        assert inputs == []

    def test_response_to_state_mapping(self, tmp_path: Path) -> None:
        """Test _response_to_state mapping."""
        target = tmp_path / "app.exe"
        target.write_bytes(b"dummy")

        fuzzer = GUIFuzzer(str(target))

        # Test known mappings
        assert fuzzer._response_to_state(ResponseType.NORMAL) == "normal"
        assert fuzzer._response_to_state(ResponseType.CRASH) == "crash"
        assert fuzzer._response_to_state(ResponseType.HANG) == "hang"
        assert fuzzer._response_to_state(ResponseType.ERROR_DIALOG) == "error_dialog"


class TestBackwardCompatibility:
    """Test backward compatibility aliases."""

    def test_responseawarefuzzer_alias_from_gui_monitor(self) -> None:
        """Verify ResponseAwareFuzzer alias from gui_monitor."""
        from dicom_fuzzer.core.engine.gui_monitor import ResponseAwareFuzzer

        assert ResponseAwareFuzzer is GUIFuzzer

    def test_responseawarefuzzer_alias_from_core(self) -> None:
        """Verify ResponseAwareFuzzer alias from core."""
        from dicom_fuzzer.core import ResponseAwareFuzzer

        assert ResponseAwareFuzzer is GUIFuzzer

    def test_guifuzzer_from_gui_monitor(self) -> None:
        """Verify GUIFuzzer from gui_monitor."""
        from dicom_fuzzer.core.engine.gui_monitor import GUIFuzzer as GUIFuzzerAlias

        assert GUIFuzzerAlias is GUIFuzzer

    def test_guifuzzer_from_core(self) -> None:
        """Verify GUIFuzzer from core."""
        from dicom_fuzzer.core import GUIFuzzer as GUIFuzzerAlias

        assert GUIFuzzerAlias is GUIFuzzer

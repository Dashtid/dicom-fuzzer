"""Comprehensive tests for CLI main module to improve coverage.

These tests focus on the main() function and untested code paths.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.main import (
    apply_resource_limits,
    main,
    parse_strategies,
    parse_target_config,
)
from dicom_fuzzer.core.resource_manager import ResourceLimits


class TestParseTargetConfig:
    """Tests for parse_target_config function."""

    def test_parse_valid_config(self, tmp_path: Path) -> None:
        """Test parsing a valid JSON config file."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"target": "/path/to/app", "timeout": 10}')

        config = parse_target_config(str(config_file))

        assert config["target"] == "/path/to/app"
        assert config["timeout"] == 10

    def test_parse_nonexistent_config(self) -> None:
        """Test error when config file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            parse_target_config("/nonexistent/config.json")

    def test_parse_invalid_json(self, tmp_path: Path) -> None:
        """Test error when config file contains invalid JSON."""
        import json

        config_file = tmp_path / "bad_config.json"
        config_file.write_text("not valid json {")

        with pytest.raises(json.JSONDecodeError):
            parse_target_config(str(config_file))

    def test_parse_empty_config(self, tmp_path: Path) -> None:
        """Test parsing empty JSON object."""
        config_file = tmp_path / "empty.json"
        config_file.write_text("{}")

        config = parse_target_config(str(config_file))

        assert config == {}


class TestApplyResourceLimits:
    """Tests for apply_resource_limits function."""

    def test_apply_none_limits(self) -> None:
        """Test apply_resource_limits with None does nothing."""
        # Should not raise
        apply_resource_limits(None)

    def test_apply_dict_limits(self) -> None:
        """Test apply_resource_limits with dict creates ResourceLimits."""
        limits_dict = {
            "max_memory_mb": 1024,
            "max_cpu_seconds": 30,
        }

        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            apply_resource_limits(limits_dict)

            mock_manager.check_available_resources.assert_called_once()

    def test_apply_resource_limits_instance(self) -> None:
        """Test apply_resource_limits with ResourceLimits instance."""
        limits = ResourceLimits(max_memory_mb=2048, max_cpu_seconds=60)

        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            apply_resource_limits(limits)

            mock_manager.check_available_resources.assert_called_once()


class TestParseStrategiesExtended:
    """Extended tests for parse_strategies function."""

    def test_parse_strategies_none(self) -> None:
        """Test parse_strategies with None input."""
        result = parse_strategies(None)
        assert result == []

    def test_parse_strategies_empty_string(self) -> None:
        """Test parse_strategies with empty string."""
        result = parse_strategies("")
        assert result == []

    def test_parse_strategies_whitespace_only(self) -> None:
        """Test parse_strategies with whitespace only."""
        result = parse_strategies("   ")
        assert result == []

    def test_parse_strategies_all_valid(self) -> None:
        """Test parse_strategies with all valid strategies."""
        result = parse_strategies("metadata,header,pixel,structure")
        assert set(result) == {"metadata", "header", "pixel", "structure"}

    def test_parse_strategies_case_insensitive(self) -> None:
        """Test parse_strategies normalizes to lowercase."""
        result = parse_strategies("METADATA,Header,PIXEL")
        assert set(result) == {"metadata", "header", "pixel"}

    def test_parse_strategies_with_spaces(self) -> None:
        """Test parse_strategies trims whitespace."""
        result = parse_strategies(" metadata , header , pixel ")
        assert set(result) == {"metadata", "header", "pixel"}


class TestMainFunction:
    """Tests for the main() function."""

    @pytest.fixture
    def sample_dicom(self, tmp_path: Path) -> Path:
        """Create a minimal DICOM file for testing."""
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import generate_uid

        file_path = tmp_path / "test.dcm"
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

        dataset = FileDataset(
            str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )
        dataset.PatientName = "Test^Patient"
        dataset.PatientID = "TEST123"
        dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
        dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        dataset.save_as(str(file_path), write_like_original=False)

        return file_path

    def test_main_basic_generation(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() generates files successfully."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "5",
                "-o",
                str(output_dir),
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(f"{output_dir}/test_{i}.dcm") for i in range(5)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {"metadata": 3, "header": 2}
                mock_generator_class.return_value = mock_generator

                result = main()

        assert result == 0

    def test_main_with_strategies(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() with specific strategies."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-s",
                "metadata,header",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(f"{output_dir}/test_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

        assert result == 0

    def test_main_with_verbose(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() with verbose flag."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-v",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                for f in mock_files:
                    f.parent.mkdir(parents=True, exist_ok=True)
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

        assert result == 0

    def test_main_invalid_input_file(self, tmp_path: Path) -> None:
        """Test main() exits with error for nonexistent input file."""
        with patch(
            "sys.argv",
            ["dicom-fuzzer", "/nonexistent/file.dcm", "-o", str(tmp_path)],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1

    def test_main_invalid_strategies_only(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test main() exits when all strategies are invalid."""
        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-o",
                str(tmp_path),
                "-s",
                "invalid1,invalid2",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1

    def test_main_with_resource_limits(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test main() with resource limit arguments."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "--max-memory",
                "512",
                "--max-cpu-time",
                "10",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_generator.generate_batch.return_value = [
                    Path(f"{output_dir}/test_{i}.dcm") for i in range(3)
                ]
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                result = main()

        assert result == 0

    def test_main_keyboard_interrupt(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() handles keyboard interrupt."""
        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "100",
                "-o",
                str(tmp_path),
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator_class.side_effect = KeyboardInterrupt()

                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 130

    def test_main_general_exception(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() handles general exceptions."""
        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "5",
                "-o",
                str(tmp_path),
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator_class.side_effect = RuntimeError("Test error")

                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1

    def test_main_with_target_executable(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test main() with target executable."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.touch()

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--timeout",
                "1.0",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch("dicom_fuzzer.cli.main.TargetRunner") as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.return_value = {MagicMock(): []}
                    mock_runner.get_summary.return_value = "Summary"
                    mock_runner_class.return_value = mock_runner

                    result = main()

        assert result == 0

    def test_main_with_gui_mode(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() with GUI mode."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.touch()

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--gui-mode",
                "--timeout",
                "1.0",
                "--memory-limit",
                "512",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch(
                    "dicom_fuzzer.cli.main.GUITargetRunner"
                ) as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.return_value = {MagicMock(): []}
                    mock_runner.get_summary.return_value = "GUI Summary"
                    mock_runner_class.return_value = mock_runner

                    result = main()

        assert result == 0

    def test_main_gui_mode_without_psutil(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test main() exits when GUI mode requested but psutil not available."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.touch()

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--gui-mode",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch("dicom_fuzzer.cli.main.HAS_PSUTIL", False):
                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 1

    def test_main_target_not_found(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() handles target executable not found."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                "/nonexistent/target",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch("dicom_fuzzer.cli.main.TargetRunner") as mock_runner_class:
                    mock_runner_class.side_effect = FileNotFoundError(
                        "Target not found"
                    )

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 1

    def test_main_target_testing_exception(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test main() handles exceptions during target testing."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.touch()

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch("dicom_fuzzer.cli.main.TargetRunner") as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.side_effect = RuntimeError(
                        "Campaign error"
                    )
                    mock_runner_class.return_value = mock_runner

                    with pytest.raises(SystemExit) as exc_info:
                        main()

        assert exc_info.value.code == 1

    def test_main_with_tqdm_progress(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() uses tqdm progress bar when available."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "25",  # >= 20 to trigger tqdm
                "-o",
                str(output_dir),
            ],
        ):
            with patch("dicom_fuzzer.cli.main.HAS_TQDM", True):
                with patch(
                    "dicom_fuzzer.cli.main.DICOMGenerator"
                ) as mock_generator_class:
                    mock_generator = MagicMock()
                    mock_generator.generate_batch.return_value = [
                        Path(f"{output_dir}/test_{i}.dcm") for i in range(25)
                    ]
                    mock_generator.stats = MagicMock()
                    mock_generator.stats.skipped_due_to_write_errors = 0
                    mock_generator.stats.strategies_used = {}
                    mock_generator_class.return_value = mock_generator

                    with patch("dicom_fuzzer.cli.main.tqdm") as mock_tqdm:
                        mock_pbar = MagicMock()
                        mock_pbar.__enter__ = MagicMock(return_value=mock_pbar)
                        mock_pbar.__exit__ = MagicMock(return_value=False)
                        mock_tqdm.return_value = mock_pbar

                        result = main()

        assert result == 0

    def test_main_health_check_fails(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() exits when pre-campaign health check fails."""
        output_dir = tmp_path / "output"

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "5",
                "-o",
                str(output_dir),
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.main.pre_campaign_health_check"
            ) as mock_health_check:
                mock_health_check.return_value = (False, ["Critical error"])

                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1

    def test_main_with_stop_on_crash(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test main() with --stop-on-crash flag."""
        output_dir = tmp_path / "output"
        target_exe = tmp_path / "target.exe"
        target_exe.touch()

        with patch(
            "sys.argv",
            [
                "dicom-fuzzer",
                str(sample_dicom),
                "-c",
                "3",
                "-o",
                str(output_dir),
                "-t",
                str(target_exe),
                "--stop-on-crash",
            ],
        ):
            with patch("dicom_fuzzer.cli.main.DICOMGenerator") as mock_generator_class:
                mock_generator = MagicMock()
                mock_files = [Path(f"{output_dir}/test_{i}.dcm") for i in range(3)]
                mock_generator.generate_batch.return_value = mock_files
                mock_generator.stats = MagicMock()
                mock_generator.stats.skipped_due_to_write_errors = 0
                mock_generator.stats.strategies_used = {}
                mock_generator_class.return_value = mock_generator

                with patch("dicom_fuzzer.cli.main.TargetRunner") as mock_runner_class:
                    mock_runner = MagicMock()
                    mock_runner.run_campaign.return_value = {MagicMock(): []}
                    mock_runner.get_summary.return_value = "Summary"
                    mock_runner_class.return_value = mock_runner

                    result = main()

        assert result == 0
        # Verify stop_on_crash was passed
        mock_runner.run_campaign.assert_called_once()
        call_kwargs = mock_runner.run_campaign.call_args[1]
        assert call_kwargs.get("stop_on_crash") is True


class TestPreCampaignHealthCheckExtended:
    """Extended tests for pre_campaign_health_check."""

    def test_health_check_low_disk_space_warning(self, tmp_path: Path, capsys) -> None:
        """Test warning when disk space is low but acceptable."""
        from dicom_fuzzer.cli.main import pre_campaign_health_check

        output_dir = tmp_path / "output"

        # Mock disk_usage to return low but acceptable space
        with patch("shutil.disk_usage") as mock_disk:
            # 500MB free
            mock_disk.return_value = MagicMock(free=500 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=True
            )

        assert passed is True
        captured = capsys.readouterr()
        assert "Low disk space" in captured.out or len(issues) > 0

    def test_health_check_critical_low_disk_space(self, tmp_path: Path) -> None:
        """Test failure when disk space is critically low."""
        from dicom_fuzzer.cli.main import pre_campaign_health_check

        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            # 50MB free (below 100MB threshold)
            mock_disk.return_value = MagicMock(free=50 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(output_dir=output_dir)

        assert passed is False
        assert any("Insufficient disk space" in issue for issue in issues)

    def test_health_check_target_not_file(self, tmp_path: Path) -> None:
        """Test failure when target is not a file."""
        from dicom_fuzzer.cli.main import pre_campaign_health_check

        output_dir = tmp_path / "output"
        target_dir = tmp_path / "target_dir"
        target_dir.mkdir()

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, target=str(target_dir)
        )

        assert passed is False
        assert any("not a file" in issue for issue in issues)

    def test_health_check_resource_limits_warnings(
        self, tmp_path: Path, capsys
    ) -> None:
        """Test warnings for very low resource limits."""
        from dicom_fuzzer.cli.main import pre_campaign_health_check

        output_dir = tmp_path / "output"
        limits = ResourceLimits(
            max_memory_mb=64,  # Below 128MB threshold
            max_cpu_seconds=0.5,  # Below 1s threshold
        )

        passed, issues = pre_campaign_health_check(
            output_dir=output_dir, resource_limits=limits, verbose=True
        )

        captured = capsys.readouterr()
        assert "Memory limit very low" in captured.out or any(
            "memory" in i.lower() for i in issues
        )

    def test_health_check_old_python_warning(self, tmp_path: Path, capsys) -> None:
        """Test warning for older Python versions."""
        from collections import namedtuple

        from dicom_fuzzer.cli.main import pre_campaign_health_check

        output_dir = tmp_path / "output"

        # Create a proper named tuple that supports comparison
        VersionInfo = namedtuple(
            "version_info", ["major", "minor", "micro", "releaselevel", "serial"]
        )
        mock_version = VersionInfo(3, 10, 0, "final", 0)

        with patch.object(sys, "version_info", mock_version):
            passed, issues = pre_campaign_health_check(
                output_dir=output_dir, verbose=True
            )

        # Should still pass but may have warning about older Python
        assert passed is True


class TestGUITargetRunnerNoSuchProcess:
    """Test GUITargetRunner handles NoSuchProcess during monitoring."""

    def test_execute_test_process_dies_during_monitoring(self, tmp_path: Path) -> None:
        """Test execute_test when process dies during memory monitoring."""
        import psutil

        from dicom_fuzzer.cli.main import GUITargetRunner

        target = tmp_path / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=5.0,
            crash_dir=str(tmp_path / "crashes"),
        )

        test_file = tmp_path / "test.dcm"
        test_file.touch()

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_process.communicate.return_value = (b"", b"")
            mock_popen.return_value = mock_process

            with patch("psutil.Process") as mock_psutil_process:
                mock_psutil_process.side_effect = psutil.NoSuchProcess(12345)

                with patch.object(runner, "_kill_process_tree"):
                    result = runner.execute_test(test_file)

        assert result.crashed is True

    def test_execute_test_exception_during_launch(self, tmp_path: Path) -> None:
        """Test execute_test handles exception during process launch."""
        from dicom_fuzzer.cli.main import GUITargetRunner

        target = tmp_path / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=5.0,
            crash_dir=str(tmp_path / "crashes"),
        )

        test_file = tmp_path / "test.dcm"
        test_file.touch()

        with patch("subprocess.Popen") as mock_popen:
            mock_popen.side_effect = OSError("Failed to start process")

            result = runner.execute_test(test_file)

        assert result.crashed is True
        assert "Failed to start process" in result.stderr


class TestGUITargetRunnerInitNoPsutil:
    """Test GUITargetRunner initialization without psutil."""

    def test_init_raises_without_psutil(self, tmp_path: Path) -> None:
        """Test GUITargetRunner raises ImportError without psutil."""
        from dicom_fuzzer.cli.main import GUITargetRunner

        target = tmp_path / "target.exe"
        target.touch()

        with patch("dicom_fuzzer.cli.main.HAS_PSUTIL", False):
            with pytest.raises(ImportError) as exc_info:
                GUITargetRunner(
                    target_executable=str(target),
                    crash_dir=str(tmp_path / "crashes"),
                )

        assert "psutil" in str(exc_info.value)

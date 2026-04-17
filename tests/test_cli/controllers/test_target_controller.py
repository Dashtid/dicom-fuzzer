"""Tests for TargetTestingController.

Tests the CLI target testing controller in
dicom_fuzzer.cli.target_controller module.
"""

from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.controllers.target_controller import (
    HAS_PSUTIL,
    TargetTestingController,
)
from dicom_fuzzer.core.harness.target_runner import ExecutionStatus


class TestDisplayHeader:
    """Tests for _display_header method."""

    def test_display_header_gui_mode(self, capsys: pytest.CaptureFixture) -> None:
        """Test header display in GUI mode."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=2.0)
        files = [Path("test1.dcm"), Path("test2.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=512
        )

        captured = capsys.readouterr()
        assert "Target Application Testing (GUI mode)" in captured.out
        assert "GUI (app killed after timeout)" in captured.out
        assert "512MB" in captured.out
        assert "2.0s delay" in captured.out

    def test_display_header_cli_mode(self, capsys: pytest.CaptureFixture) -> None:
        """Test header display in CLI mode."""
        args = Namespace(target="/path/to/app", timeout=5)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=False, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Target Application Testing" in captured.out
        assert "GUI" not in captured.out

    def test_display_header_no_memory_limit(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header display without memory limit."""
        args = Namespace(target="/path/to/app", timeout=5, startup_delay=0.0)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Mem limit" not in captured.out

    def test_display_header_no_startup_delay(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header display without startup delay."""
        args = Namespace(target="/path/to/app", timeout=5, startup_delay=0.0)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Startup" not in captured.out

    def test_display_header_shows_file_count(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header shows correct file count."""
        args = Namespace(target="/path/to/app", timeout=5)
        files = [Path(f"test{i}.dcm") for i in range(100)]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=False, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "100" in captured.out


class TestCreateRunner:
    """Tests for _create_runner method."""

    @patch("dicom_fuzzer.cli.controllers.target_controller.TargetRunner")
    def test_create_cli_runner(self, mock_runner: MagicMock, tmp_path: Path) -> None:
        """Test creating CLI runner."""
        args = Namespace(target="/path/to/app", timeout=5)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        runner = TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=False,
            memory_limit=None,
            resource_limits=None,
        )

        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["target_executable"] == "/path/to/app"
        assert call_kwargs["timeout"] == 5

    @pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed")
    @patch("dicom_fuzzer.cli.controllers.target_controller.GUITargetRunner")
    def test_create_gui_runner_with_psutil(
        self, mock_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test creating GUI runner when psutil is available."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=1.0)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        runner = TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=True,
            memory_limit=512,
            resource_limits=None,
        )

        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["target_executable"] == "/path/to/app"
        assert call_kwargs["memory_limit_mb"] == 512
        assert call_kwargs["startup_delay"] == 1.0

    @patch("dicom_fuzzer.cli.controllers.target_controller.HAS_PSUTIL", False)
    def test_create_gui_runner_without_psutil(self, tmp_path: Path) -> None:
        """Test GUI runner creation fails without psutil."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=0.0)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.raises(SystemExit) as exc_info:
            TargetTestingController._create_runner(
                args=args,
                output_dir=output_dir,
                gui_mode=True,
                memory_limit=None,
                resource_limits=None,
            )

        assert exc_info.value.code == 1

    @patch("dicom_fuzzer.cli.controllers.target_controller.TargetRunner")
    def test_create_runner_with_resource_limits(
        self, mock_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test creating runner with resource limits."""
        args = Namespace(target="/path/to/app", timeout=5)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_limits = MagicMock()

        TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=False,
            memory_limit=None,
            resource_limits=mock_limits,
        )

        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["resource_limits"] == mock_limits


class TestRun:
    """Tests for run method."""

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._generate_report"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._record_crashes"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_success(
        self,
        mock_header: MagicMock,
        mock_create_runner: MagicMock,
        mock_record: MagicMock,
        mock_report: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test successful run."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = {s: [] for s in ExecutionStatus}
        mock_runner.get_summary.return_value = "Test Summary"
        mock_create_runner.return_value = mock_runner
        mock_report.return_value = None

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        mock_runner.run_campaign.assert_called_once()
        mock_record.assert_called_once()

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_file_not_found(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with FileNotFoundError."""
        args = Namespace(
            target="/nonexistent/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = FileNotFoundError("Target not found")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_import_error(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with ImportError."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = ImportError("Missing dependency")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_general_exception(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with general exception."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = RuntimeError("Something went wrong")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_general_exception_verbose(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with general exception in verbose mode."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=True,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = RuntimeError("Something went wrong")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._generate_report"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._record_crashes"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_with_resource_limits_logging(
        self,
        mock_header: MagicMock,
        mock_create_runner: MagicMock,
        mock_record: MagicMock,
        mock_report: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test run logs resource limits message."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = {s: [] for s in ExecutionStatus}
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner
        mock_report.return_value = None

        mock_limits = MagicMock()

        result = TargetTestingController.run(
            args, files, output_dir, resource_limits=mock_limits
        )

        assert result == 0


class TestGetAttrDefaults:
    """Tests for getattr default value handling."""

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._generate_report"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._record_crashes"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_without_gui_mode_attr(
        self,
        mock_header: MagicMock,
        mock_create_runner: MagicMock,
        mock_record: MagicMock,
        mock_report: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test run when gui_mode attr is missing (uses default False)."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = {s: [] for s in ExecutionStatus}
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner
        mock_report.return_value = None

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        call_kwargs = mock_create_runner.call_args[1]
        assert call_kwargs["gui_mode"] is False

    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._generate_report"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._record_crashes"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._create_runner"
    )
    @patch(
        "dicom_fuzzer.cli.controllers.target_controller.TargetTestingController._display_header"
    )
    def test_run_without_memory_limit_attr(
        self,
        mock_header: MagicMock,
        mock_create_runner: MagicMock,
        mock_record: MagicMock,
        mock_report: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test run when memory_limit attr is missing (uses default None)."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = {s: [] for s in ExecutionStatus}
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner
        mock_report.return_value = None

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        call_kwargs = mock_create_runner.call_args[1]
        assert call_kwargs["memory_limit"] is None


class TestRecordCrashes:
    """Tests for _record_crashes method."""

    def test_records_crash_into_session(self, tmp_path: Path) -> None:
        """Test that crash results are recorded into the session."""
        from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
        )

        test_file = tmp_path / "fuzzed.dcm"
        test_file.write_bytes(b"fake dicom")
        resolved = test_file.resolve()

        file_id = session.start_file_fuzzing(resolved, resolved, "high")
        session.end_file_fuzzing(resolved)

        # Create a mock crash result
        crash_result = MagicMock()
        crash_result.test_file = resolved
        crash_result.exit_code = 1
        crash_result.windows_crash_info = None
        crash_result.memory_limit_exceeded = False
        crash_result.peak_memory_mb = 0.0

        results = {s: [] for s in ExecutionStatus}
        results[ExecutionStatus.CRASH] = [crash_result]

        TargetTestingController._record_crashes(
            session, results, {resolved: file_id}, "/path/to/app"
        )

        assert len(session.crashes) == 1
        assert session.crashes[0].crash_type == "crash"
        assert session.crashes[0].severity == "high"
        assert session.crashes[0].return_code == 1
        assert '"/path/to/app"' in session.crashes[0].reproduction_command

    def test_records_hang_into_session(self, tmp_path: Path) -> None:
        """Test that hang results are recorded into the session."""
        from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
        )

        test_file = tmp_path / "fuzzed.dcm"
        test_file.write_bytes(b"fake dicom")
        resolved = test_file.resolve()

        file_id = session.start_file_fuzzing(resolved, resolved, "medium")
        session.end_file_fuzzing(resolved)

        hang_result = MagicMock()
        hang_result.test_file = resolved
        hang_result.execution_time = 10.0

        results = {s: [] for s in ExecutionStatus}
        results[ExecutionStatus.HANG] = [hang_result]

        TargetTestingController._record_crashes(
            session, results, {resolved: file_id}, "/path/to/app"
        )

        assert len(session.crashes) == 1
        assert session.crashes[0].crash_type == "hang"
        assert session.crashes[0].severity == "medium"
        assert session.crashes[0].exception_type == "Timeout"

    def test_records_windows_crash_info(self, tmp_path: Path) -> None:
        """Test that Windows NTSTATUS info is captured in crash record."""
        from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
        )

        test_file = tmp_path / "fuzzed.dcm"
        test_file.write_bytes(b"fake dicom")
        resolved = test_file.resolve()

        file_id = session.start_file_fuzzing(resolved, resolved, "high")
        session.end_file_fuzzing(resolved)

        # Mock Windows crash info
        crash_info = MagicMock()
        crash_info.exception_name = "ACCESS_VIOLATION"
        crash_info.description = "Memory access violation"
        crash_info.severity = "CRITICAL"

        crash_result = MagicMock()
        crash_result.test_file = resolved
        crash_result.exit_code = -1073741819  # 0xC0000005
        crash_result.windows_crash_info = crash_info
        crash_result.memory_limit_exceeded = False
        crash_result.peak_memory_mb = 0.0

        results = {s: [] for s in ExecutionStatus}
        results[ExecutionStatus.CRASH] = [crash_result]

        TargetTestingController._record_crashes(
            session, results, {resolved: file_id}, "/path/to/app"
        )

        assert len(session.crashes) == 1
        assert session.crashes[0].exception_type == "ACCESS_VIOLATION"
        assert session.crashes[0].severity == "critical"

    def test_skips_unknown_files(self, tmp_path: Path) -> None:
        """Test that crashes for unregistered files are skipped."""
        from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
        )

        unknown_file = (tmp_path / "unknown.dcm").resolve()
        crash_result = MagicMock()
        crash_result.test_file = unknown_file
        crash_result.exit_code = 1
        crash_result.windows_crash_info = None

        results = {s: [] for s in ExecutionStatus}
        results[ExecutionStatus.CRASH] = [crash_result]

        TargetTestingController._record_crashes(session, results, {}, "/path/to/app")

        assert len(session.crashes) == 0


class TestGenerateReport:
    """Tests for _generate_report method."""

    def test_generates_html_report(self, tmp_path: Path) -> None:
        """Test that HTML report is generated from session data."""
        from dicom_fuzzer.core.session.fuzzing_session import FuzzingSession

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
        )

        report_path = TargetTestingController._generate_report(session, tmp_path)

        assert report_path is not None
        assert report_path.exists()
        assert report_path.suffix == ".html"

    def test_returns_none_on_failure(self, tmp_path: Path) -> None:
        """Test that None is returned when report generation fails."""
        mock_session = MagicMock()
        mock_session.generate_session_report.side_effect = RuntimeError("fail")

        report_path = TargetTestingController._generate_report(mock_session, tmp_path)

        assert report_path is None


class TestLoadMutationMap:
    """Tests for _load_mutation_map backward-compat and new format parsing."""

    def test_new_format_returns_strategy_and_variant(self, tmp_path: Path) -> None:
        """New dict-value format must be returned as-is."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "fuzz_001.dcm": {
                        "strategy": "pixel",
                        "variant": "_dimension_mismatch",
                    }
                }
            )
        )
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result["fuzz_001.dcm"]["strategy"] == "pixel"
        assert result["fuzz_001.dcm"]["variant"] == "_dimension_mismatch"

    def test_old_format_normalizes_to_dict(self, tmp_path: Path) -> None:
        """Old string-value format must be normalized to {strategy, variant: None}."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(json.dumps({"fuzz_001.dcm": "header"}))
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result["fuzz_001.dcm"]["strategy"] == "header"
        assert result["fuzz_001.dcm"]["variant"] is None

    def test_missing_map_returns_empty(self, tmp_path: Path) -> None:
        """Missing mutation_map.json must return empty dict without error."""
        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result == {}

    def test_empty_files_list_returns_empty(self) -> None:
        """Empty file list must return empty dict without error."""
        result = TargetTestingController._load_mutation_map([])
        assert result == {}

    def test_wrapped_format_with_seed_unwraps_correctly(self, tmp_path: Path) -> None:
        """New {seed, mutations} wrapper format must be unwrapped transparently."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "seed": 42,
                    "mutations": {
                        "fuzz_001.dcm": {
                            "strategy": "pixel",
                            "variant": "_extreme_contradiction",
                        }
                    },
                }
            )
        )
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result["fuzz_001.dcm"]["strategy"] == "pixel"
        assert result["fuzz_001.dcm"]["variant"] == "_extreme_contradiction"


class TestLoadSeedFromMap:
    """Tests for _load_seed_from_map seed extraction."""

    def test_returns_seed_from_wrapped_format(self, tmp_path: Path) -> None:
        """Must return the integer seed from the {seed, mutations} format."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "seed": 99999,
                    "mutations": {
                        "fuzz_001.dcm": {"strategy": "pixel", "variant": None}
                    },
                }
            )
        )
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_seed_from_map([f])

        assert result == 99999

    def test_returns_none_when_seed_absent(self, tmp_path: Path) -> None:
        """Old-format map with no seed key must return None."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(json.dumps({"fuzz_001.dcm": "header"}))
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_seed_from_map([f])

        assert result is None

    def test_returns_none_when_map_missing(self, tmp_path: Path) -> None:
        """Missing mutation_map.json must return None without error."""
        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        f = fuzz_dir / "fuzz_001.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_seed_from_map([f])

        assert result is None

    def test_returns_none_for_empty_files_list(self) -> None:
        """Empty file list must return None without error."""
        result = TargetTestingController._load_seed_from_map([])
        assert result is None


class TestLoadMutationMapBinaryMutations:
    """Tests for binary_mutations key in _load_mutation_map output."""

    def test_reads_binary_mutations_from_map(self, tmp_path: Path) -> None:
        """binary_mutations list in mutation_map.json must appear in normalized entry."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "seed": 1,
                    "mutations": {
                        "f.dcm": {
                            "strategy": "structure",
                            "variant": None,
                            "binary_mutations": ["_corrupt_tag_ordering"],
                        }
                    },
                }
            )
        )
        f = fuzz_dir / "f.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result["f.dcm"]["binary_mutations"] == ["_corrupt_tag_ordering"]

    def test_binary_mutations_defaults_empty_when_absent(self, tmp_path: Path) -> None:
        """Entry without binary_mutations key must yield [] in normalized output."""
        import json

        fuzz_dir = tmp_path / "fuzzed"
        fuzz_dir.mkdir()
        map_path = fuzz_dir / "mutation_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "seed": 2,
                    "mutations": {"f.dcm": {"strategy": "header", "variant": None}},
                }
            )
        )
        f = fuzz_dir / "f.dcm"
        f.write_bytes(b"")

        result = TargetTestingController._load_mutation_map([f])

        assert result["f.dcm"]["binary_mutations"] == []

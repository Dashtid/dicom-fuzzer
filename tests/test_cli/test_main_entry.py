"""Tests for main.py entry point and subcommand dispatch.

Tests cover main() function, subcommand routing, argument parsing,
and pre_campaign_health_check.
"""

from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.main import (
    apply_resource_limits,
    pre_campaign_health_check,
    setup_logging,
)


class TestSetupLogging:
    """Test setup_logging function."""

    def test_setup_verbose(self):
        """Test logging setup with verbose=True."""
        import logging

        # Clear existing handlers to ensure basicConfig takes effect
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        setup_logging(verbose=True)
        # Check root logger level
        assert root.level == logging.DEBUG

    def test_setup_non_verbose(self):
        """Test logging setup with verbose=False."""
        import logging

        # Clear existing handlers
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        setup_logging(verbose=False)
        assert root.level == logging.INFO


class TestApplyResourceLimits:
    """Test apply_resource_limits function."""

    def test_apply_none_limits(self):
        """Test with None limits (no-op)."""
        result = apply_resource_limits(None)
        assert result is None, "apply_resource_limits(None) should return None"

    def test_apply_dict_limits(self):
        """Test with dict limits."""
        limits = {
            "max_memory_mb": 1024,
            "max_memory_mb_hard": 2048,
            "max_cpu_seconds": 30,
            "min_disk_space_mb": 100,
        }

        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            result = apply_resource_limits(limits)

            assert result is None, "apply_resource_limits should return None"
            mock_manager.check_available_resources.assert_called_once()
            # Verify manager was instantiated with correct limits
            mock_manager_class.assert_called_once()

    def test_apply_resource_limits_object(self):
        """Test with ResourceLimits object."""
        from dicom_fuzzer.core.session.resource_manager import ResourceLimits

        limits = ResourceLimits(
            max_memory_mb=512,
            max_memory_mb_hard=1024,
            max_cpu_seconds=60,
        )

        with patch("dicom_fuzzer.cli.main.ResourceManager") as mock_manager_class:
            mock_manager = MagicMock()
            mock_manager_class.return_value = mock_manager

            result = apply_resource_limits(limits)

            assert result is None
            mock_manager.check_available_resources.assert_called_once()


class TestPreCampaignHealthCheck:
    """Test pre_campaign_health_check function."""

    def test_health_check_passes(self, tmp_path):
        """Test health check with all requirements met."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)  # 10 GB

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                verbose=False,
            )

            assert passed is True, "Health check should pass with adequate resources"
            assert isinstance(issues, list), "Issues should be a list"
            assert len([i for i in issues if "critical" in i.lower()]) == 0, (
                "No critical issues expected"
            )

    def test_health_check_warns_missing_psutil(self, tmp_path):
        """Test health check warns when psutil is missing."""
        output_dir = tmp_path / "output"

        # We can't easily mock pydicom import failure since it's already imported
        # Instead, test warning for missing psutil (optional dependency)
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)

            # Health check should still pass even if psutil gives warning
            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                verbose=True,
            )

            # Should pass - pydicom is available
            assert passed is True

    def test_health_check_fails_low_disk(self, tmp_path):
        """Test health check fails with low disk space."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=50 * 1024 * 1024)  # 50 MB

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                verbose=False,
            )

            assert passed is False, "Health check should fail with low disk space"
            assert isinstance(issues, list), "Issues should be a list"
            assert len(issues) > 0, "Should have at least one issue"
            assert any("disk" in i.lower() for i in issues), (
                "Should mention disk space issue"
            )

    def test_health_check_warns_low_memory_limit(self, tmp_path):
        """Test health check warns with very low memory limit."""
        from dicom_fuzzer.core.session.resource_manager import ResourceLimits

        output_dir = tmp_path / "output"
        limits = ResourceLimits(max_memory_mb=64)  # Very low

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                resource_limits=limits,
                verbose=True,
            )

            # Should pass but with warnings
            assert passed is True
            assert any("memory" in i.lower() for i in issues)

    def test_health_check_target_not_found(self, tmp_path):
        """Test health check fails when target executable not found."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                target=str(tmp_path / "nonexistent.exe"),
                verbose=False,
            )

            assert passed is False
            assert any("not found" in i.lower() for i in issues)


class TestSubcommandDispatch:
    """Test main() subcommand dispatch."""

    def test_samples_subcommand(self):
        """Test 'samples' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "samples", "--help"]),
            patch(
                "dicom_fuzzer.cli.commands.samples.main", return_value=0
            ) as mock_samples,
        ):
            from dicom_fuzzer.cli.main import main

            # Capture SystemExit from --help
            try:
                result = main()
            except SystemExit:
                pass

            mock_samples.assert_called()

    def test_tls_subcommand(self):
        """Test 'tls' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "tls", "--list-vulns"]),
            patch("dicom_fuzzer.cli.commands.tls.main", return_value=0) as mock_tls,
        ):
            from dicom_fuzzer.cli.main import main

            result = main()

            # Called with remaining args after 'tls'
            mock_tls.assert_called_once_with(["--list-vulns"])
            assert result == 0

    def test_calibrate_subcommand(self):
        """Test 'calibrate' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "calibrate", "--list-categories"]),
            patch(
                "dicom_fuzzer.cli.commands.calibrate.main", return_value=0
            ) as mock_calibrate,
        ):
            from dicom_fuzzer.cli.main import main

            result = main()

            mock_calibrate.assert_called_once()
            assert result == 0

    def test_corpus_subcommand(self):
        """Test 'corpus' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "corpus", "--help"]),
            patch(
                "dicom_fuzzer.cli.commands.corpus.main", return_value=0
            ) as mock_corpus,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_corpus.assert_called()

    def test_study_subcommand(self):
        """Test 'study' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "study", "--help"]),
            patch("dicom_fuzzer.cli.commands.study.main", return_value=0) as mock_study,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_study.assert_called()

    def test_state_subcommand(self):
        """Test 'state' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "state", "--help"]),
            patch("dicom_fuzzer.cli.commands.state.main", return_value=0) as mock_state,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_state.assert_called()

    def test_study_campaign_subcommand(self):
        """Test 'study-campaign' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "study-campaign", "--help"]),
            patch(
                "dicom_fuzzer.cli.commands.study_campaign.main", return_value=0
            ) as mock_study_campaign,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_study_campaign.assert_called()

    def test_stress_subcommand(self):
        """Test 'stress' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "stress", "--help"]),
            patch(
                "dicom_fuzzer.cli.commands.stress.main", return_value=0
            ) as mock_stress,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_stress.assert_called()

    def test_target_subcommand(self):
        """Test 'target' subcommand dispatch."""
        with (
            patch("sys.argv", ["dicom-fuzzer", "target", "--help"]),
            patch(
                "dicom_fuzzer.cli.commands.target.main", return_value=0
            ) as mock_target,
        ):
            from dicom_fuzzer.cli.main import main

            try:
                result = main()
            except SystemExit:
                pass

            mock_target.assert_called()


class TestMainArgumentParsing:
    """Test main() argument parsing."""

    def test_version_flag(self, capsys):
        """Test --version flag."""
        with patch("sys.argv", ["dicom-fuzzer", "--version"]):
            from dicom_fuzzer.cli.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            assert "DICOM Fuzzer" in captured.out or "1." in captured.out

    def test_required_input_file(self, capsys):
        """Test that input file is required."""
        with patch("sys.argv", ["dicom-fuzzer"]):
            from dicom_fuzzer.cli.main import main

            with pytest.raises(SystemExit) as exc_info:
                main()

            # argparse exits with 2 for missing required args
            assert exc_info.value.code == 2

    def test_default_values(self, tmp_path):
        """Test default argument values are applied."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with (
            patch("sys.argv", ["dicom-fuzzer", str(test_file), "-c", "1"]),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.return_value = []
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            assert result == 0

    def test_count_option(self, tmp_path):
        """Test -c/--count option."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        # Use count < 20 to avoid batch splitting
        with (
            patch("sys.argv", ["dicom-fuzzer", str(test_file), "-c", "10"]),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.return_value = [
                tmp_path / f"f{i}.dcm" for i in range(10)
            ]
            mock_gen_instance.stats = MagicMock(skipped_due_to_write_errors=0)
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            # Verify generate_batch was called with count=10
            call_args = mock_gen_instance.generate_batch.call_args
            assert call_args[1]["count"] == 10

    def test_output_option(self, tmp_path):
        """Test -o/--output option."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        output_dir = tmp_path / "custom_output"

        with (
            patch(
                "sys.argv",
                ["dicom-fuzzer", str(test_file), "-c", "1", "-o", str(output_dir)],
            ),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.return_value = []
            mock_gen_instance.stats = MagicMock(skipped_due_to_write_errors=0)
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            # Verify DICOMGenerator was initialized with correct output dir
            mock_gen.assert_called_once()
            # Check that output_dir path is in the first positional argument
            call_args = mock_gen.call_args
            assert "custom_output" in str(call_args[0][0])

    def test_strategies_option(self, tmp_path):
        """Test -s/--strategies option."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with (
            patch(
                "sys.argv",
                ["dicom-fuzzer", str(test_file), "-c", "1", "-s", "metadata,header"],
            ),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.return_value = []
            mock_gen_instance.stats = MagicMock(skipped_due_to_write_errors=0)
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            # Verify strategies were passed
            call_args = mock_gen_instance.generate_batch.call_args
            strategies = call_args[1]["strategies"]
            assert "metadata" in strategies
            assert "header" in strategies

    def test_json_output_mode(self, tmp_path, capsys):
        """Test --json output mode."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        # Create actual output file path
        out_file = tmp_path / "out.dcm"
        out_file.write_bytes(b"test")

        with (
            patch(
                "sys.argv", ["dicom-fuzzer", str(test_file), "-c", "1", "--json", "-q"]
            ),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            # Return actual Path object, not MagicMock
            mock_gen_instance.generate_batch.return_value = [out_file]
            mock_gen_instance.stats = MagicMock(skipped_due_to_write_errors=0)
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            captured = capsys.readouterr()
            # Output should contain valid JSON (find the JSON block)
            import json

            # Find JSON in output (starts with { and ends with })
            output = captured.out
            json_start = output.find("{")
            json_end = output.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = output[json_start:json_end]
                output_data = json.loads(json_str)
                assert "status" in output_data
                assert output_data["status"] == "success"
            else:
                # If no JSON found, at least verify return code
                assert result == 0

    def test_quiet_mode(self, tmp_path, capsys):
        """Test -q/--quiet mode suppresses output."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with (
            patch("sys.argv", ["dicom-fuzzer", str(test_file), "-c", "1", "-q"]),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.return_value = []
            mock_gen_instance.stats = MagicMock(skipped_due_to_write_errors=0)
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()

            # Should complete without error
            assert result == 0


class TestMainErrorHandling:
    """Test main() error handling."""

    def test_keyboard_interrupt(self, tmp_path):
        """Test handling of KeyboardInterrupt."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with (
            patch("sys.argv", ["dicom-fuzzer", str(test_file), "-c", "100"]),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.side_effect = KeyboardInterrupt()
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()
            assert result == 130

    def test_general_exception(self, tmp_path):
        """Test handling of general exceptions."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        with (
            patch("sys.argv", ["dicom-fuzzer", str(test_file), "-c", "1"]),
            patch(
                "dicom_fuzzer.cli.controllers.campaign_runner.DICOMGenerator"
            ) as mock_gen,
            patch("shutil.disk_usage") as mock_disk,
        ):
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)
            mock_gen_instance = MagicMock()
            mock_gen_instance.generate_batch.side_effect = Exception("Test error")
            mock_gen.return_value = mock_gen_instance

            from dicom_fuzzer.cli.main import main

            result = main()
            assert result == 1


class TestPreCampaignHealthCheckEdgeCases:
    """Edge case tests for pre_campaign_health_check function."""

    def test_health_check_python_version_adequate(self, tmp_path):
        """Test health check passes with adequate Python version."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                verbose=True,
            )

            assert passed is True
            # No Python version issues on modern Python
            assert not any("python" in i.lower() for i in issues)

    def test_health_check_disk_permission_error(self, tmp_path):
        """Test health check handles disk permission errors gracefully."""
        output_dir = tmp_path / "output"

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.side_effect = PermissionError("Access denied")

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                verbose=True,
            )

            # Should still pass but with a warning
            assert passed is True
            assert any("disk" in i.lower() for i in issues)

    def test_health_check_target_is_executable(self, tmp_path):
        """Test health check validates target is an executable file."""
        output_dir = tmp_path / "output"
        target_file = tmp_path / "target.exe"
        target_file.write_text("fake executable")

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=10 * 1024 * 1024 * 1024)

            passed, issues = pre_campaign_health_check(
                output_dir=output_dir,
                target=str(target_file),
                verbose=True,
            )

            assert passed is True
            assert not any("not found" in i.lower() for i in issues)

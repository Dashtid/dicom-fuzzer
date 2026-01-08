"""Tests for CLI Argument Parser.

Tests the argument parser configuration in
dicom_fuzzer.cli.argument_parser module.
"""

import argparse

import pytest

from dicom_fuzzer.cli.argument_parser import VERSION, create_parser


class TestCreateParser:
    """Tests for create_parser function."""

    def test_create_parser_returns_parser(self) -> None:
        """Test create_parser returns ArgumentParser instance."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_description(self) -> None:
        """Test parser has description."""
        parser = create_parser()
        assert "DICOM Fuzzer" in parser.description


class TestBasicArgs:
    """Tests for basic argument group."""

    def test_input_file_required(self) -> None:
        """Test input_file is a required argument."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])  # No args should fail

    def test_input_file_positional(self) -> None:
        """Test input_file is positional."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.input_file == "test.dcm"

    def test_count_default(self) -> None:
        """Test count has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.count == 100

    def test_count_custom(self) -> None:
        """Test count can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-c", "50"])
        assert args.count == 50

    def test_output_default(self) -> None:
        """Test output has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.output == "./artifacts/campaigns"

    def test_output_custom(self) -> None:
        """Test output can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-o", "/custom/output"])
        assert args.output == "/custom/output"

    def test_recursive_flag(self) -> None:
        """Test recursive flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-r"])
        assert args.recursive is True

    def test_verbose_flag(self) -> None:
        """Test verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-v"])
        assert args.verbose is True

    def test_quiet_flag(self) -> None:
        """Test quiet flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-q"])
        assert args.quiet is True

    def test_json_flag(self) -> None:
        """Test JSON output flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--json"])
        assert args.json is True

    def test_strategies_option(self) -> None:
        """Test strategies option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-s", "metadata,header"])
        assert args.strategies == "metadata,header"


class TestTargetArgs:
    """Tests for target argument group."""

    def test_target_default(self) -> None:
        """Test target has no default."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.target is None

    def test_target_custom(self) -> None:
        """Test target can be set."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "-t", "/path/to/app.exe"])
        assert args.target == "/path/to/app.exe"

    def test_timeout_default(self) -> None:
        """Test timeout has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.timeout == 5.0

    def test_timeout_custom(self) -> None:
        """Test timeout can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--timeout", "30.0"])
        assert args.timeout == 30.0

    def test_stop_on_crash_flag(self) -> None:
        """Test stop-on-crash flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--stop-on-crash"])
        assert args.stop_on_crash is True

    def test_gui_mode_flag(self) -> None:
        """Test GUI mode flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--gui-mode"])
        assert args.gui_mode is True

    def test_memory_limit_option(self) -> None:
        """Test memory limit option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--memory-limit", "4096"])
        assert args.memory_limit == 4096

    def test_startup_delay_default(self) -> None:
        """Test startup delay has default."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.startup_delay == 0.0

    def test_startup_delay_custom(self) -> None:
        """Test startup delay can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--startup-delay", "2.0"])
        assert args.startup_delay == 2.0


class TestResourceArgs:
    """Tests for resource limit argument group."""

    def test_max_memory_option(self) -> None:
        """Test max-memory option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--max-memory", "2048"])
        assert args.max_memory == 2048

    def test_max_memory_hard_option(self) -> None:
        """Test max-memory-hard option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--max-memory-hard", "4096"])
        assert args.max_memory_hard == 4096

    def test_max_cpu_time_option(self) -> None:
        """Test max-cpu-time option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--max-cpu-time", "60"])
        assert args.max_cpu_time == 60

    def test_min_disk_space_option(self) -> None:
        """Test min-disk-space option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--min-disk-space", "2048"])
        assert args.min_disk_space == 2048


class TestNetworkArgs:
    """Tests for network fuzzing argument group."""

    def test_network_fuzz_flag(self) -> None:
        """Test network-fuzz flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--network-fuzz"])
        assert args.network_fuzz is True

    def test_host_default(self) -> None:
        """Test host has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.host == "localhost"

    def test_host_custom(self) -> None:
        """Test host can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--host", "192.168.1.100"])
        assert args.host == "192.168.1.100"

    def test_port_default(self) -> None:
        """Test port has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.port == 11112

    def test_port_custom(self) -> None:
        """Test port can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--port", "4242"])
        assert args.port == 4242

    def test_ae_title_default(self) -> None:
        """Test AE title has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.ae_title == "FUZZ_SCU"

    def test_ae_title_custom(self) -> None:
        """Test AE title can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--ae-title", "MY_AE"])
        assert args.ae_title == "MY_AE"

    def test_network_strategy_default(self) -> None:
        """Test network strategy has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.network_strategy == "all"

    def test_network_strategy_choices(self) -> None:
        """Test network strategy valid choices."""
        parser = create_parser()

        valid_strategies = [
            "malformed_pdu",
            "invalid_length",
            "buffer_overflow",
            "integer_overflow",
            "null_bytes",
            "unicode_injection",
            "protocol_state",
            "timing_attack",
            "all",
        ]

        for strategy in valid_strategies:
            args = parser.parse_args(["test.dcm", "--network-strategy", strategy])
            assert args.network_strategy == strategy

    def test_network_strategy_invalid(self) -> None:
        """Test invalid network strategy raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["test.dcm", "--network-strategy", "invalid"])


class TestSecurityArgs:
    """Tests for security testing argument group."""

    def test_security_fuzz_flag(self) -> None:
        """Test security-fuzz flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--security-fuzz"])
        assert args.security_fuzz is True

    def test_target_cves_option(self) -> None:
        """Test target-cves option."""
        parser = create_parser()
        args = parser.parse_args(
            ["test.dcm", "--target-cves", "CVE-2025-35975,CVE-2025-36521"]
        )
        assert args.target_cves == "CVE-2025-35975,CVE-2025-36521"

    def test_vuln_classes_option(self) -> None:
        """Test vuln-classes option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--vuln-classes", "oob_write,oob_read"])
        assert args.vuln_classes == "oob_write,oob_read"

    def test_security_report_option(self) -> None:
        """Test security-report option."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--security-report", "report.json"])
        assert args.security_report == "report.json"


class TestMonitorArgs:
    """Tests for response monitoring argument group."""

    def test_response_aware_flag(self) -> None:
        """Test response-aware flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--response-aware"])
        assert args.response_aware is True

    def test_detect_dialogs_flag(self) -> None:
        """Test detect-dialogs flag."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--detect-dialogs"])
        assert args.detect_dialogs is True

    def test_memory_threshold_default(self) -> None:
        """Test memory-threshold has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.memory_threshold == 1024

    def test_memory_threshold_custom(self) -> None:
        """Test memory-threshold can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--memory-threshold", "2048"])
        assert args.memory_threshold == 2048

    def test_hang_timeout_default(self) -> None:
        """Test hang-timeout has default value."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert args.hang_timeout == 30.0

    def test_hang_timeout_custom(self) -> None:
        """Test hang-timeout can be customized."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--hang-timeout", "60.0"])
        assert args.hang_timeout == 60.0


class TestVersionFlag:
    """Tests for version flag."""

    def test_version_flag(self) -> None:
        """Test version flag shows version and exits."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_version_constant(self) -> None:
        """Test VERSION constant is defined."""
        assert VERSION is not None
        assert "DICOM Fuzzer" in VERSION


class TestCombinedArgs:
    """Tests for combined argument usage."""

    def test_parse_all_groups(self) -> None:
        """Test parsing arguments from all groups."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "input.dcm",
                "-c",
                "50",
                "-o",
                "./output",
                "-t",
                "/app.exe",
                "--timeout",
                "10.0",
                "--gui-mode",
                "--network-fuzz",
                "--host",
                "192.168.1.1",
                "--port",
                "4242",
                "--security-fuzz",
                "--response-aware",
            ]
        )

        assert args.input_file == "input.dcm"
        assert args.count == 50
        assert args.output == "./output"
        assert args.target == "/app.exe"
        assert args.timeout == 10.0
        assert args.gui_mode is True
        assert args.network_fuzz is True
        assert args.host == "192.168.1.1"
        assert args.port == 4242
        assert args.security_fuzz is True
        assert args.response_aware is True

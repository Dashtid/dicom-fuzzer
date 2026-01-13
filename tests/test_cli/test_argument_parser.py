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
        assert parser is not None
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_description(self) -> None:
        """Test parser has description."""
        parser = create_parser()
        assert parser.description is not None
        assert "DICOM Fuzzer" in parser.description


class TestInputFileArg:
    """Tests for input_file positional argument."""

    def test_input_file_required(self) -> None:
        """Test input_file is a required argument."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_input_file_positional(self) -> None:
        """Test input_file is positional."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert hasattr(args, "input_file")
        assert args.input_file == "test.dcm"


class TestBooleanFlags:
    """Tests for boolean flag arguments."""

    @pytest.mark.parametrize(
        ("flag", "attr_name"),
        [
            ("-r", "recursive"),
            ("-v", "verbose"),
            ("-q", "quiet"),
            ("--json", "json"),
            ("--stop-on-crash", "stop_on_crash"),
            ("--gui-mode", "gui_mode"),
            ("--network-fuzz", "network_fuzz"),
            ("--security-fuzz", "security_fuzz"),
            ("--response-aware", "response_aware"),
            ("--detect-dialogs", "detect_dialogs"),
        ],
    )
    def test_boolean_flag(self, flag: str, attr_name: str) -> None:
        """Test boolean flags are parsed correctly."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", flag])
        assert hasattr(args, attr_name)
        assert getattr(args, attr_name) is True


class TestDefaultValues:
    """Tests for default argument values."""

    @pytest.mark.parametrize(
        ("attr_name", "expected_default"),
        [
            ("count", 100),
            ("output", "./artifacts/campaigns"),
            ("target", None),
            ("timeout", 5.0),
            ("startup_delay", 0.0),
            ("host", "localhost"),
            ("port", 11112),
            ("ae_title", "FUZZ_SCU"),
            ("network_strategy", "all"),
            ("memory_threshold", 1024),
            ("hang_timeout", 30.0),
        ],
    )
    def test_default_value(self, attr_name: str, expected_default) -> None:
        """Test arguments have correct default values."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm"])
        assert hasattr(args, attr_name)
        assert getattr(args, attr_name) == expected_default


class TestIntegerOptions:
    """Tests for integer option arguments."""

    @pytest.mark.parametrize(
        ("flag", "value", "attr_name"),
        [
            ("-c", "50", "count"),
            ("--memory-limit", "4096", "memory_limit"),
            ("--max-memory", "2048", "max_memory"),
            ("--max-memory-hard", "4096", "max_memory_hard"),
            ("--max-cpu-time", "60", "max_cpu_time"),
            ("--min-disk-space", "2048", "min_disk_space"),
            ("--port", "4242", "port"),
            ("--memory-threshold", "2048", "memory_threshold"),
        ],
    )
    def test_integer_option(self, flag: str, value: str, attr_name: str) -> None:
        """Test integer options are parsed correctly."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", flag, value])
        result = getattr(args, attr_name)
        assert isinstance(result, int)
        assert result == int(value)


class TestFloatOptions:
    """Tests for float option arguments."""

    @pytest.mark.parametrize(
        ("flag", "value", "attr_name"),
        [
            ("--timeout", "30.0", "timeout"),
            ("--startup-delay", "2.0", "startup_delay"),
            ("--hang-timeout", "60.0", "hang_timeout"),
        ],
    )
    def test_float_option(self, flag: str, value: str, attr_name: str) -> None:
        """Test float options are parsed correctly."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", flag, value])
        result = getattr(args, attr_name)
        assert isinstance(result, float)
        assert result == float(value)


class TestStringOptions:
    """Tests for string option arguments."""

    @pytest.mark.parametrize(
        ("flag", "value", "attr_name"),
        [
            ("-o", "/custom/output", "output"),
            ("-t", "/path/to/app.exe", "target"),
            ("-s", "metadata,header", "strategies"),
            ("--host", "192.168.1.100", "host"),
            ("--ae-title", "MY_AE", "ae_title"),
            ("--target-cves", "CVE-2025-35975,CVE-2025-36521", "target_cves"),
            ("--vuln-classes", "oob_write,oob_read", "vuln_classes"),
            ("--security-report", "report.json", "security_report"),
        ],
    )
    def test_string_option(self, flag: str, value: str, attr_name: str) -> None:
        """Test string options are parsed correctly."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", flag, value])
        result = getattr(args, attr_name)
        assert isinstance(result, str)
        assert result == value


class TestNetworkStrategy:
    """Tests for network strategy choice argument."""

    @pytest.mark.parametrize(
        "strategy",
        [
            "malformed_pdu",
            "invalid_length",
            "buffer_overflow",
            "integer_overflow",
            "null_bytes",
            "unicode_injection",
            "protocol_state",
            "timing_attack",
            "all",
        ],
    )
    def test_network_strategy_valid(self, strategy: str) -> None:
        """Test valid network strategy choices."""
        parser = create_parser()
        args = parser.parse_args(["test.dcm", "--network-strategy", strategy])
        assert isinstance(args.network_strategy, str)
        assert args.network_strategy == strategy

    def test_network_strategy_invalid(self) -> None:
        """Test invalid network strategy raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["test.dcm", "--network-strategy", "invalid"])


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
        assert isinstance(VERSION, str)
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

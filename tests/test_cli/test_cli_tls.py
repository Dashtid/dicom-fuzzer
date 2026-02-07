"""Tests for TLS security testing CLI subcommand.

Tests for dicom_fuzzer.cli.tls module.
"""

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.commands import tls


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = tls.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_scan_action(self):
        """Test --scan argument."""
        parser = tls.create_parser()
        args = parser.parse_args(["--scan", "pacs.example.com"])
        assert args.scan == "pacs.example.com"

    def test_parser_list_vulns_action(self):
        """Test --list-vulns argument."""
        parser = tls.create_parser()
        args = parser.parse_args(["--list-vulns"])
        assert args.list_vulns is True

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = tls.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--scan", "host", "--list-vulns"])

    def test_parser_connection_options(self):
        """Test connection options."""
        parser = tls.create_parser()
        args = parser.parse_args(
            ["--scan", "host", "--port", "11113", "--no-tls", "--timeout", "30"]
        )
        assert args.port == 11113
        assert args.no_tls is True
        assert args.timeout == 30

    def test_parser_dicom_options(self):
        """Test DICOM options."""
        parser = tls.create_parser()
        args = parser.parse_args(
            ["--scan", "host", "--calling-ae", "MY_SCU", "--called-ae", "MY_SCP"]
        )
        assert args.calling_ae == "MY_SCU"
        assert args.called_ae == "MY_SCP"

    def test_parser_output_options(self):
        """Test output options."""
        parser = tls.create_parser()
        args = parser.parse_args(
            ["--scan", "host", "-o", "./reports", "--format", "json", "-v"]
        )
        assert args.output == "./reports"
        assert args.format == "json"
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = tls.create_parser()
        args = parser.parse_args(["--scan", "host"])
        assert args.port == 11112
        assert args.no_tls is False
        assert args.timeout == 10
        assert args.calling_ae == "FUZZ_SCU"
        assert args.called_ae == "PACS"
        assert args.output is None
        assert args.format == "text"
        assert args.verbose is False


class TestRunScan:
    """Test run_scan function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_scan_basic(self, capsys):
        """Test basic scan."""
        args = argparse.Namespace(
            scan="pacs.example.com",
            port=11112,
            no_tls=False,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=None,
            format="text",
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_vulnerabilities.return_value = ["heartbleed", "poodle"]

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            return_value=mock_fuzzer,
        ):
            result = tls.run_scan(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "TLS Security Scan" in captured.out
        assert "pacs.example.com" in captured.out
        assert "Scan complete" in captured.out

    def test_run_scan_with_output_json(self, temp_dir, capsys):
        """Test scan with JSON output."""
        output_dir = temp_dir / "reports"

        args = argparse.Namespace(
            scan="pacs.example.com",
            port=11112,
            no_tls=False,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=str(output_dir),
            format="json",
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_vulnerabilities.return_value = ["heartbleed"]

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            return_value=mock_fuzzer,
        ):
            result = tls.run_scan(args)

        assert result == 0
        assert output_dir.exists()

        # Find the report file
        report_files = list(output_dir.glob("tls_scan_*.json"))
        assert len(report_files) == 1

        with open(report_files[0]) as f:
            data = json.load(f)
        assert "target" in data

        captured = capsys.readouterr()
        assert "Report saved" in captured.out

    def test_run_scan_with_output_text(self, temp_dir, capsys):
        """Test scan with text output."""
        output_dir = temp_dir / "reports"

        args = argparse.Namespace(
            scan="pacs.example.com",
            port=11112,
            no_tls=False,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=str(output_dir),
            format="text",
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_vulnerabilities.return_value = []

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            return_value=mock_fuzzer,
        ):
            result = tls.run_scan(args)

        assert result == 0

        # Find the report file
        report_files = list(output_dir.glob("tls_scan_*.text"))
        assert len(report_files) == 1

        content = report_files[0].read_text()
        assert "TLS Security Scan" in content

    def test_run_scan_no_tls(self, capsys):
        """Test scan without TLS."""
        args = argparse.Namespace(
            scan="pacs.example.com",
            port=104,
            no_tls=True,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=None,
            format="text",
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_vulnerabilities.return_value = []

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            return_value=mock_fuzzer,
        ) as mock_create:
            result = tls.run_scan(args)

        assert result == 0
        # Verify use_tls=False was passed
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs["use_tls"] is False

        captured = capsys.readouterr()
        assert "Disabled" in captured.out

    def test_run_scan_import_error(self, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            scan="pacs.example.com",
            port=11112,
            no_tls=False,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=None,
            format="text",
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = tls.run_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out

    def test_run_scan_exception_verbose(self, capsys):
        """Test exception handling with verbose flag."""
        args = argparse.Namespace(
            scan="pacs.example.com",
            port=11112,
            no_tls=False,
            calling_ae="FUZZ_SCU",
            called_ae="PACS",
            output=None,
            format="text",
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.attacks.network.tls.fuzzer.create_dicom_tls_fuzzer",
            side_effect=ConnectionError("Connection refused"),
        ):
            result = tls.run_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Scan failed" in captured.out


class TestRunListVulns:
    """Test run_list_vulns function."""

    def test_list_vulns_output(self, capsys):
        """Test list vulnerabilities displays all vulns."""
        args = argparse.Namespace()

        result = tls.run_list_vulns(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify vulnerabilities are listed
        assert "heartbleed" in captured.out
        assert "poodle" in captured.out
        assert "beast" in captured.out
        assert "drown" in captured.out
        assert "sweet32" in captured.out
        assert "weak_dh" in captured.out
        assert "null_cipher" in captured.out
        assert "rc4" in captured.out

        # Verify CVE references
        assert "CVE-2014-0160" in captured.out
        assert "CVE-2014-3566" in captured.out


class TestMain:
    """Test main function."""

    def test_main_scan(self):
        """Test main with --scan."""
        with patch.object(tls, "run_scan", return_value=0) as mock_run:
            result = tls.main(["--scan", "pacs.example.com"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_vulns(self):
        """Test main with --list-vulns."""
        with patch.object(tls, "run_list_vulns", return_value=0) as mock_run:
            result = tls.main(["--list-vulns"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            tls.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["tls", "--list-vulns"]):
            with patch.object(tls, "run_list_vulns", return_value=0) as mock_run:
                result = tls.main(None)

        assert result == 0
        mock_run.assert_called_once()

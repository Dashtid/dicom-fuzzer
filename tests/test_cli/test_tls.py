"""
Tests for tls.py - TLS Subcommand for DICOM Fuzzer.

Tests cover argument parsing, vulnerability listing, and TLS scanning.
"""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.tls import (
    create_parser,
    main,
    run_list_vulns,
    run_scan,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_defaults(self):
        """Test default argument values."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "localhost"])

        assert args.scan == "localhost"
        assert args.port == 11112
        assert args.no_tls is False
        assert args.timeout == 10
        assert args.calling_ae == "FUZZ_SCU"
        assert args.called_ae == "PACS"
        assert args.output is None
        assert args.format == "text"
        assert args.verbose is False

    def test_parser_with_list_vulns(self):
        """Test parser with --list-vulns flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-vulns"])

        assert args.list_vulns is True
        assert args.scan is None

    def test_parser_custom_port(self):
        """Test custom port argument."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "pacs.example.com", "--port", "4242"])

        assert args.port == 4242

    def test_parser_no_tls_flag(self):
        """Test --no-tls flag."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "localhost", "--no-tls"])

        assert args.no_tls is True

    def test_parser_custom_timeout(self):
        """Test custom timeout."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "localhost", "--timeout", "30"])

        assert args.timeout == 30

    def test_parser_dicom_options(self):
        """Test DICOM AE title options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--scan",
                "localhost",
                "--calling-ae",
                "MY_SCU",
                "--called-ae",
                "MY_PACS",
            ]
        )

        assert args.calling_ae == "MY_SCU"
        assert args.called_ae == "MY_PACS"

    def test_parser_output_options(self):
        """Test output directory and format."""
        parser = create_parser()
        args = parser.parse_args(
            ["--scan", "localhost", "-o", "/reports", "--format", "json"]
        )

        assert args.output == "/reports"
        assert args.format == "json"

    def test_parser_format_choices(self):
        """Test valid format choices."""
        parser = create_parser()

        for fmt in ["json", "text"]:
            args = parser.parse_args(["--scan", "localhost", "--format", fmt])
            assert args.format == fmt

    def test_parser_verbose_flag(self):
        """Test verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "localhost", "-v"])

        assert args.verbose is True

    def test_parser_mutually_exclusive(self):
        """Test that --scan and --list-vulns are mutually exclusive."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["--scan", "localhost", "--list-vulns"])

    def test_parser_requires_action(self):
        """Test that either --scan or --list-vulns is required."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestRunListVulns:
    """Test run_list_vulns function."""

    def test_returns_zero(self):
        """Test that function returns 0."""
        args = argparse.Namespace()
        result = run_list_vulns(args)

        assert result == 0

    def test_prints_vulnerabilities(self, capsys):
        """Test that function prints vulnerability information."""
        args = argparse.Namespace()
        run_list_vulns(args)

        captured = capsys.readouterr()
        output = captured.out

        # Check for known vulnerabilities
        assert "heartbleed" in output.lower()
        assert "poodle" in output.lower()
        assert "beast" in output.lower()

    def test_prints_cve_numbers(self, capsys):
        """Test that function prints CVE numbers."""
        args = argparse.Namespace()
        run_list_vulns(args)

        captured = capsys.readouterr()
        output = captured.out

        # Check for CVE format
        assert "CVE-" in output

    def test_prints_header(self, capsys):
        """Test that function prints header."""
        args = argparse.Namespace()
        run_list_vulns(args)

        captured = capsys.readouterr()
        output = captured.out

        assert "Testable TLS Vulnerabilities" in output


class TestRunScan:
    """Test run_scan function."""

    def test_scan_with_mock_fuzzer(self, tmp_path, capsys):
        """Test successful TLS scan."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = ["heartbleed", "poodle"]
            mock_create_fuzzer.return_value = mock_fuzzer

            args = argparse.Namespace(
                scan="localhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=None,
                format="text",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 0
            mock_create_fuzzer.assert_called_once_with(
                host="localhost",
                port=11112,
                use_tls=True,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
            )

    def test_scan_with_no_tls(self, capsys):
        """Test scan without TLS."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = []
            mock_create_fuzzer.return_value = mock_fuzzer

            args = argparse.Namespace(
                scan="localhost",
                port=104,
                no_tls=True,
                calling_ae="SCU",
                called_ae="SCP",
                output=None,
                format="text",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 0
            # use_tls should be False when --no-tls is set
            call_kwargs = mock_create_fuzzer.call_args[1]
            assert call_kwargs["use_tls"] is False

    def test_scan_saves_json_report(self, tmp_path, capsys):
        """Test scan saves JSON report when output specified."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = ["heartbleed"]
            mock_create_fuzzer.return_value = mock_fuzzer

            args = argparse.Namespace(
                scan="testhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=str(tmp_path),
                format="json",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 0

            # Check report file was created
            report_file = tmp_path / "tls_scan_testhost.json"
            assert report_file.exists()

            # Check content is valid JSON
            import json

            with open(report_file) as f:
                report = json.load(f)

            assert "target" in report
            assert "vulnerabilities_checked" in report

    def test_scan_saves_text_report(self, tmp_path, capsys):
        """Test scan saves text report when output specified."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = ["poodle"]
            mock_create_fuzzer.return_value = mock_fuzzer

            args = argparse.Namespace(
                scan="testhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=str(tmp_path),
                format="text",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 0

            # Check report file was created
            report_file = tmp_path / "tls_scan_testhost.text"
            assert report_file.exists()

            content = report_file.read_text()
            assert "TLS Security Scan" in content

    def test_scan_import_error(self, capsys):
        """Test handling when TLS fuzzer import fails."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer",
            side_effect=ImportError("TLS module not available"),
        ):
            args = argparse.Namespace(
                scan="localhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=None,
                format="text",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "not available" in captured.out.lower()

    def test_scan_exception_handling(self, capsys):
        """Test handling of general exceptions during scan."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer",
            side_effect=Exception("Connection failed"),
        ):
            args = argparse.Namespace(
                scan="localhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=None,
                format="text",
                verbose=False,
            )

            result = run_scan(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "failed" in captured.out.lower()

    def test_scan_verbose_traceback(self, capsys):
        """Test verbose mode prints traceback on error."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer",
            side_effect=Exception("Test error"),
        ):
            args = argparse.Namespace(
                scan="localhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=None,
                format="text",
                verbose=True,
            )

            result = run_scan(args)

            assert result == 1
            captured = capsys.readouterr()
            # With verbose, should show more details
            assert "Test error" in captured.out or "Traceback" in captured.err

    def test_scan_creates_output_directory(self, tmp_path):
        """Test scan creates output directory if needed."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = []
            mock_create_fuzzer.return_value = mock_fuzzer

            output_dir = tmp_path / "nested" / "reports"

            args = argparse.Namespace(
                scan="testhost",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=str(output_dir),
                format="text",
                verbose=False,
            )

            run_scan(args)

            assert output_dir.exists()


class TestMain:
    """Test main entry point."""

    def test_main_list_vulns(self, capsys):
        """Test main dispatches to list vulns."""
        result = main(["--list-vulns"])

        assert result == 0
        captured = capsys.readouterr()
        assert "heartbleed" in captured.out.lower()

    def test_main_scan(self):
        """Test main dispatches to scan."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = []
            mock_create_fuzzer.return_value = mock_fuzzer

            result = main(["--scan", "localhost"])

            assert result == 0

    def test_main_with_all_options(self, tmp_path):
        """Test main with all command line options."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = ["test_vuln"]
            mock_create_fuzzer.return_value = mock_fuzzer

            result = main(
                [
                    "--scan",
                    "pacs.example.com",
                    "--port",
                    "11113",
                    "--calling-ae",
                    "TEST_SCU",
                    "--called-ae",
                    "TEST_PACS",
                    "-o",
                    str(tmp_path),
                    "--format",
                    "json",
                ]
            )

            assert result == 0

            # Verify options were passed correctly
            call_kwargs = mock_create_fuzzer.call_args[1]
            assert call_kwargs["host"] == "pacs.example.com"
            assert call_kwargs["port"] == 11113
            assert call_kwargs["calling_ae"] == "TEST_SCU"
            assert call_kwargs["called_ae"] == "TEST_PACS"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_scan_prints_header(self, capsys):
        """Test scan prints header with target info."""
        with patch(
            "dicom_fuzzer.core.dicom_tls_fuzzer.create_dicom_tls_fuzzer"
        ) as mock_create_fuzzer:
            mock_fuzzer = MagicMock()
            mock_fuzzer.get_vulnerabilities.return_value = []
            mock_create_fuzzer.return_value = mock_fuzzer

            args = argparse.Namespace(
                scan="testserver.local",
                port=11112,
                no_tls=False,
                calling_ae="FUZZ_SCU",
                called_ae="PACS",
                output=None,
                format="text",
                verbose=False,
            )

            run_scan(args)

            captured = capsys.readouterr()
            assert "testserver.local" in captured.out
            assert "11112" in captured.out

    def test_vuln_list_includes_descriptions(self, capsys):
        """Test vulnerability list includes descriptions."""
        args = argparse.Namespace()
        run_list_vulns(args)

        captured = capsys.readouterr()
        output = captured.out

        # Check for some descriptions
        assert "memory" in output.lower() or "disclosure" in output.lower()
        assert "attack" in output.lower() or "cipher" in output.lower()

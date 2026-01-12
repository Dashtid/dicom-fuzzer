"""Tests for security_controller.py.

Coverage target: 26% -> 70%+
Tests medical device security vulnerability testing controller.
"""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.security_controller import (
    CVE_MAP,
    HAS_SECURITY_FUZZER,
    VULN_MAP,
    SecurityFuzzingController,
)


class TestSecurityFuzzingControllerAvailability:
    """Tests for availability checking."""

    def test_is_available(self) -> None:
        """Test is_available returns correct value."""
        result = SecurityFuzzingController.is_available()
        assert result == HAS_SECURITY_FUZZER

    def test_cve_map_populated_if_available(self) -> None:
        """Test CVE_MAP is populated when security fuzzer available."""
        if HAS_SECURITY_FUZZER:
            assert len(CVE_MAP) > 0
            assert "CVE-2025-1001" in CVE_MAP

    def test_vuln_map_populated_if_available(self) -> None:
        """Test VULN_MAP is populated when security fuzzer available."""
        if HAS_SECURITY_FUZZER:
            assert len(VULN_MAP) > 0
            assert "oob_write" in VULN_MAP
            assert "stack_overflow" in VULN_MAP


class TestSecurityFuzzingControllerParseCVEs:
    """Tests for _parse_cves method."""

    def test_parse_cves_none_input(self) -> None:
        """Test parsing None CVE string."""
        result = SecurityFuzzingController._parse_cves(None)
        assert result is None

    def test_parse_cves_empty_string(self) -> None:
        """Test parsing empty CVE string."""
        result = SecurityFuzzingController._parse_cves("")
        assert result is None

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_cves_valid_single(self) -> None:
        """Test parsing single valid CVE."""
        result = SecurityFuzzingController._parse_cves("CVE-2025-1001")
        assert result is not None
        assert len(result) == 1

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_cves_valid_multiple(self) -> None:
        """Test parsing multiple valid CVEs."""
        result = SecurityFuzzingController._parse_cves("CVE-2025-1001,CVE-2022-2119")
        assert result is not None
        assert len(result) == 2

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_cves_case_insensitive(self) -> None:
        """Test CVE parsing is case insensitive."""
        result = SecurityFuzzingController._parse_cves("cve-2025-1001")
        assert result is not None
        assert len(result) == 1

    def test_parse_cves_unknown_cve(self, capsys) -> None:
        """Test parsing unknown CVE prints warning."""
        result = SecurityFuzzingController._parse_cves("CVE-9999-9999")

        # Should return None (no valid CVEs)
        assert result is None

        # Should print warning
        captured = capsys.readouterr()
        assert "Unknown CVE" in captured.out

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_cves_mixed_valid_invalid(self, capsys) -> None:
        """Test parsing mix of valid and invalid CVEs."""
        result = SecurityFuzzingController._parse_cves("CVE-2025-1001,CVE-INVALID")

        assert result is not None
        assert len(result) == 1  # Only valid one

        captured = capsys.readouterr()
        assert "Unknown CVE" in captured.out


class TestSecurityFuzzingControllerParseVulnClasses:
    """Tests for _parse_vuln_classes method."""

    def test_parse_vuln_none_input(self) -> None:
        """Test parsing None vulnerability string."""
        result = SecurityFuzzingController._parse_vuln_classes(None)
        assert result is None

    def test_parse_vuln_empty_string(self) -> None:
        """Test parsing empty vulnerability string."""
        result = SecurityFuzzingController._parse_vuln_classes("")
        assert result is None

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_vuln_valid_single(self) -> None:
        """Test parsing single valid vulnerability class."""
        result = SecurityFuzzingController._parse_vuln_classes("oob_write")
        assert result is not None
        assert len(result) == 1

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_vuln_valid_multiple(self) -> None:
        """Test parsing multiple valid vulnerability classes."""
        result = SecurityFuzzingController._parse_vuln_classes(
            "oob_write,stack_overflow"
        )
        assert result is not None
        assert len(result) == 2

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_parse_vuln_case_insensitive(self) -> None:
        """Test vulnerability parsing is case insensitive."""
        result = SecurityFuzzingController._parse_vuln_classes("OOB_WRITE")
        assert result is not None
        assert len(result) == 1

    def test_parse_vuln_unknown(self, capsys) -> None:
        """Test parsing unknown vulnerability class."""
        result = SecurityFuzzingController._parse_vuln_classes("unknown_vuln")

        assert result is None

        captured = capsys.readouterr()
        assert "Unknown vulnerability class" in captured.out


class TestSecurityFuzzingControllerRun:
    """Tests for run method."""

    @pytest.fixture
    def sample_dicom(self, tmp_path: Path) -> Path:
        """Create sample DICOM file."""
        dicom_file = tmp_path / "test.dcm"
        # Minimal DICOM-like content
        dicom_file.write_bytes(
            b"DICM" + b"\x00" * 128 + b"\x02\x00\x00\x00UL\x04\x00\x80\x00\x00\x00"
        )
        return dicom_file

    @pytest.fixture
    def output_dir(self, tmp_path: Path) -> Path:
        """Create output directory."""
        out = tmp_path / "output"
        out.mkdir()
        return out

    @pytest.fixture
    def basic_args(self) -> Namespace:
        """Create basic args namespace."""
        args = Namespace()
        args.verbose = False
        args.target_cves = None
        args.vuln_classes = None
        args.security_report = None
        args.target = None
        return args

    def test_run_not_available(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test run when security fuzzer not available."""
        with patch("dicom_fuzzer.cli.security_controller.HAS_SECURITY_FUZZER", False):
            result = SecurityFuzzingController.run(
                args=basic_args,
                input_file=sample_dicom,
                output_dir=output_dir,
            )

            assert result == 1  # Failure

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_run_success(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test successful run."""
        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.MedicalDeviceSecurityFuzzer"
            ) as mock_fuzzer_class:
                mock_fuzzer = MagicMock()
                mock_fuzzer_class.return_value = mock_fuzzer
                mock_fuzzer.generate_mutations.return_value = []

                result = SecurityFuzzingController.run(
                    args=basic_args,
                    input_file=sample_dicom,
                    output_dir=output_dir,
                )

                assert result == 0

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_run_with_cve_filter(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test run with CVE filter."""
        basic_args.target_cves = "CVE-2025-1001"

        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.MedicalDeviceSecurityFuzzer"
            ) as mock_fuzzer_class:
                mock_fuzzer = MagicMock()
                mock_fuzzer_class.return_value = mock_fuzzer
                mock_fuzzer.generate_mutations.return_value = []

                result = SecurityFuzzingController.run(
                    args=basic_args,
                    input_file=sample_dicom,
                    output_dir=output_dir,
                )

                assert result == 0

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_run_exception_handling(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test run handles exceptions gracefully."""
        with patch("pydicom.dcmread") as mock_read:
            mock_read.side_effect = Exception("Failed to read DICOM")

            result = SecurityFuzzingController.run(
                args=basic_args,
                input_file=sample_dicom,
                output_dir=output_dir,
            )

            assert result == 1

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_run_exception_verbose(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test run shows traceback in verbose mode."""
        basic_args.verbose = True

        with patch("pydicom.dcmread") as mock_read:
            mock_read.side_effect = Exception("Failed to read DICOM")

            result = SecurityFuzzingController.run(
                args=basic_args,
                input_file=sample_dicom,
                output_dir=output_dir,
            )

            assert result == 1


class TestSecurityFuzzingControllerSaveReport:
    """Tests for _save_report method."""

    @pytest.fixture
    def basic_args(self, tmp_path: Path) -> Namespace:
        """Create args with report path."""
        args = Namespace()
        args.security_report = str(tmp_path / "report.json")
        return args

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_save_report_creates_file(
        self, basic_args: Namespace, tmp_path: Path
    ) -> None:
        """Test report is saved to file."""
        mock_fuzzer = MagicMock()
        mock_fuzzer.get_summary.return_value = {
            "total_mutations": 10,
            "cves_tested": ["CVE-2025-1001"],
        }

        SecurityFuzzingController._save_report(basic_args, mock_fuzzer)

        report_path = Path(basic_args.security_report)
        assert report_path.exists()

        with open(report_path) as f:
            data = json.load(f)
        assert data["total_mutations"] == 10

    def test_save_report_no_path(self) -> None:
        """Test save_report does nothing when no path specified."""
        args = Namespace()
        args.security_report = None

        mock_fuzzer = MagicMock()

        # Should not raise
        SecurityFuzzingController._save_report(args, mock_fuzzer)

        mock_fuzzer.get_summary.assert_not_called()


class TestSecurityFuzzingControllerApplyMutations:
    """Tests for _apply_mutations method."""

    @pytest.fixture
    def sample_dicom(self, tmp_path: Path) -> Path:
        """Create sample DICOM file."""
        dicom_file = tmp_path / "test.dcm"
        dicom_file.write_bytes(b"DICM" + b"\x00" * 200)
        return dicom_file

    @pytest.fixture
    def output_dir(self, tmp_path: Path) -> Path:
        """Create output directory."""
        out = tmp_path / "output"
        out.mkdir()
        return out

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_apply_mutations_creates_files(
        self, sample_dicom: Path, output_dir: Path
    ) -> None:
        """Test mutations are applied and files created."""
        mock_mutation = MagicMock()
        mock_mutation.name = "test_mutation"

        mock_fuzzer = MagicMock()

        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds
            mock_fuzzer.apply_mutation.return_value = mock_ds

            SecurityFuzzingController._apply_mutations(
                input_file=sample_dicom,
                output_dir=output_dir,
                mutations=[mock_mutation],
                security_fuzzer=mock_fuzzer,
            )

            # Output directory should be created
            security_output = output_dir / "security_fuzzed"
            assert security_output.exists()

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_apply_mutations_handles_exception(
        self, sample_dicom: Path, output_dir: Path
    ) -> None:
        """Test mutation application handles exceptions gracefully."""
        mock_mutation = MagicMock()
        mock_mutation.name = "failing_mutation"

        mock_fuzzer = MagicMock()
        mock_fuzzer.apply_mutation.side_effect = Exception("Mutation failed")

        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            # Should not raise
            SecurityFuzzingController._apply_mutations(
                input_file=sample_dicom,
                output_dir=output_dir,
                mutations=[mock_mutation],
                security_fuzzer=mock_fuzzer,
            )

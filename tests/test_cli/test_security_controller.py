"""Tests for security_controller.py.

Coverage target: 26% -> 70%+
Tests CVE-based security fuzzing controller using ExploitPatternApplicator.
"""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.security_controller import (
    HAS_SECURITY_FUZZER,
    SecurityFuzzingController,
)


class TestSecurityFuzzingControllerAvailability:
    """Tests for availability checking."""

    def test_is_available(self) -> None:
        """Test is_available returns correct value."""
        result = SecurityFuzzingController.is_available()
        assert result == HAS_SECURITY_FUZZER

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_get_available_cves_populated(self) -> None:
        """Test get_available_cves returns CVE list when available."""
        from dicom_fuzzer.strategies.exploit import get_available_cves

        cves = get_available_cves()
        assert len(cves) > 0
        # Check for known CVEs
        assert any("CVE-2025" in cve for cve in cves)

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_get_mutations_by_category_populated(self) -> None:
        """Test get_mutations_by_category returns mutations for valid categories."""
        from dicom_fuzzer.strategies.exploit import CVECategory, get_mutations_by_category

        # Test that at least some categories have mutations
        total_mutations = 0
        for category in CVECategory:
            mutations = get_mutations_by_category(category)
            total_mutations += len(mutations)

        # Should have mutations across categories
        assert total_mutations > 0


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
                "dicom_fuzzer.cli.security_controller.ExploitPatternApplicator"
            ) as mock_applicator_class:
                mock_applicator = MagicMock()
                mock_applicator_class.return_value = mock_applicator
                mock_applicator.apply_exploit_patterns.return_value = mock_ds
                mock_applicator.get_patterns_applied.return_value = ["CVE-2025-1001"]

                with patch(
                    "dicom_fuzzer.cli.security_controller.get_available_cves"
                ) as mock_get_cves:
                    mock_get_cves.return_value = ["CVE-2025-1001", "CVE-2022-2119"]

                    result = SecurityFuzzingController.run(
                        args=basic_args,
                        input_file=sample_dicom,
                        output_dir=output_dir,
                    )

                    assert result == 0

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_run_with_target(
        self, sample_dicom: Path, output_dir: Path, basic_args: Namespace
    ) -> None:
        """Test run with target specified triggers file generation."""
        basic_args.target = str(sample_dicom)

        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.ExploitPatternApplicator"
            ) as mock_applicator_class:
                mock_applicator = MagicMock()
                mock_applicator_class.return_value = mock_applicator
                mock_applicator.apply_exploit_patterns.return_value = mock_ds
                mock_applicator.get_patterns_applied.return_value = []

                with patch(
                    "dicom_fuzzer.cli.security_controller.get_available_cves"
                ) as mock_get_cves:
                    mock_get_cves.return_value = []

                    with patch.object(
                        SecurityFuzzingController, "_save_fuzzed_files"
                    ) as mock_save:
                        result = SecurityFuzzingController.run(
                            args=basic_args,
                            input_file=sample_dicom,
                            output_dir=output_dir,
                        )

                        assert result == 0
                        mock_save.assert_called_once()

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
        patterns_applied = ["CVE-2025-1001", "CVE-2022-2119"]

        SecurityFuzzingController._save_report(basic_args, patterns_applied)

        report_path = Path(basic_args.security_report)
        assert report_path.exists()

        with open(report_path) as f:
            data = json.load(f)
        assert data["total_patterns"] == 2
        assert "CVE-2025-1001" in data["patterns_applied"]

    def test_save_report_no_path(self) -> None:
        """Test save_report does nothing when no path specified."""
        args = Namespace()
        args.security_report = None

        # Should not raise
        SecurityFuzzingController._save_report(args, [])


class TestSecurityFuzzingControllerSaveFuzzedFiles:
    """Tests for _save_fuzzed_files method."""

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
    def test_save_fuzzed_files_creates_directory(
        self, sample_dicom: Path, output_dir: Path
    ) -> None:
        """Test fuzzed files directory is created."""
        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.apply_cve_mutation"
            ) as mock_apply:
                mock_apply.return_value = mock_ds

                with patch(
                    "dicom_fuzzer.cli.security_controller.get_available_cves"
                ) as mock_get_cves:
                    mock_get_cves.return_value = ["CVE-2025-1001"]

                    SecurityFuzzingController._save_fuzzed_files(
                        input_file=sample_dicom,
                        output_dir=output_dir,
                        num_files=1,
                    )

                    # Output directory should be created
                    security_output = output_dir / "security_fuzzed"
                    assert security_output.exists()

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_save_fuzzed_files_handles_exception(
        self, sample_dicom: Path, output_dir: Path
    ) -> None:
        """Test file generation handles exceptions gracefully."""
        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.apply_cve_mutation"
            ) as mock_apply:
                mock_apply.side_effect = Exception("Mutation failed")

                with patch(
                    "dicom_fuzzer.cli.security_controller.get_available_cves"
                ) as mock_get_cves:
                    mock_get_cves.return_value = ["CVE-2025-1001"]

                    # Should not raise
                    SecurityFuzzingController._save_fuzzed_files(
                        input_file=sample_dicom,
                        output_dir=output_dir,
                        num_files=1,
                    )

    @pytest.mark.skipif(not HAS_SECURITY_FUZZER, reason="Security fuzzer not available")
    def test_save_fuzzed_files_respects_num_files(
        self, sample_dicom: Path, output_dir: Path
    ) -> None:
        """Test num_files parameter limits generated files."""
        with patch("pydicom.dcmread") as mock_read:
            mock_ds = MagicMock()
            mock_read.return_value = mock_ds

            with patch(
                "dicom_fuzzer.cli.security_controller.apply_cve_mutation"
            ) as mock_apply:
                mock_apply.return_value = mock_ds

                with patch(
                    "dicom_fuzzer.cli.security_controller.get_available_cves"
                ) as mock_get_cves:
                    mock_get_cves.return_value = [
                        "CVE-2025-1001",
                        "CVE-2022-2119",
                        "CVE-2022-2120",
                    ]

                    SecurityFuzzingController._save_fuzzed_files(
                        input_file=sample_dicom,
                        output_dir=output_dir,
                        num_files=2,  # Only generate 2 files
                    )

                    # Should only call apply for 2 CVEs
                    assert mock_apply.call_count == 2

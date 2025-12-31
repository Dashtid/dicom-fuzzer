"""Tests for cve_reproductions/generator.py - CVE Sample Generator.

Tests cover CVE database, sample generation for specific CVEs, and CLI.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.generators.cve_reproductions.generator import (
    CVE_DATABASE,
    CVEInfo,
    CVESampleGenerator,
    generate_cve_readme,
    main,
)


class TestCVEInfo:
    """Test CVEInfo dataclass."""

    def test_cve_info_creation(self):
        """Test CVEInfo can be created."""
        info = CVEInfo(
            cve_id="CVE-2024-TEST",
            product="Test Product",
            vulnerability_type="Buffer Overflow",
            cvss=7.5,
            year=2024,
            description="Test vulnerability",
            affected_versions="< 1.0",
            fixed_version="1.0",
        )

        assert info.cve_id == "CVE-2024-TEST"
        assert info.cvss == 7.5

    def test_cve_info_with_references(self):
        """Test CVEInfo with references list."""
        info = CVEInfo(
            cve_id="CVE-2024-TEST",
            product="Test",
            vulnerability_type="Test",
            cvss=5.0,
            year=2024,
            description="Test",
            affected_versions="< 1.0",
            fixed_version="1.0",
            references=["https://example.com/cve"],
        )

        assert len(info.references) == 1


class TestCVEDatabase:
    """Test CVE_DATABASE content."""

    def test_database_contains_known_cves(self):
        """Test database contains expected CVEs."""
        assert "CVE-2019-11687" in CVE_DATABASE
        assert "CVE-2022-2119" in CVE_DATABASE
        assert "CVE-2024-22100" in CVE_DATABASE

    def test_database_entries_have_required_fields(self):
        """Test all entries have required fields."""
        for cve_id, info in CVE_DATABASE.items():
            assert info.cve_id == cve_id
            assert info.product is not None
            assert info.vulnerability_type is not None
            assert info.year > 0


class TestCVESampleGeneratorInit:
    """Test CVESampleGenerator initialization."""

    def test_init_with_output_dir(self, tmp_path):
        """Test initialization with output directory."""
        generator = CVESampleGenerator(tmp_path)
        assert generator.output_dir == tmp_path

    def test_init_with_string_path(self, tmp_path):
        """Test initialization with string path."""
        generator = CVESampleGenerator(str(tmp_path))
        assert generator.output_dir == tmp_path


class TestCreateBaseDicom:
    """Test create_base_dicom method."""

    def test_create_base_dicom_returns_dataset(self, tmp_path):
        """Test that create_base_dicom returns a valid dataset."""
        generator = CVESampleGenerator(tmp_path)
        ds = generator.create_base_dicom()

        assert ds.PatientName == "CVE^TEST"
        assert ds.PatientID == "CVE-TEST-001"
        assert ds.Modality == "OT"


class TestGenerateCve201911687:
    """Test CVE-2019-11687 sample generation."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2019_11687()

        assert path.exists()
        assert "cve_2019_11687" in str(path)

    def test_preamble_contains_mz(self, tmp_path):
        """Test that preamble contains MZ header."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2019_11687()

        with open(path, "rb") as f:
            preamble = f.read(2)

        assert preamble == b"MZ"


class TestGenerateCve20222119:
    """Test CVE-2022-2119 sample generation."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2022_2119()

        assert path.exists()

    def test_contains_path_traversal(self, tmp_path):
        """Test that sample contains path traversal patterns."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2022_2119()

        import pydicom

        ds = pydicom.dcmread(path)

        assert ".." in ds.PatientID


class TestGenerateCve20222121:
    """Test CVE-2022-2121 sample generation."""

    def test_generates_truncated_sample(self, tmp_path):
        """Test that truncated sample is generated."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2022_2121()

        assert path.exists()
        # File should be truncated (small size)
        assert path.stat().st_size < 300


class TestGenerateCve202422100:
    """Test CVE-2024-22100 sample generation."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2024_22100()

        assert path.exists()


class TestGenerateCve202428877:
    """Test CVE-2024-28877 sample generation."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2024_28877()

        assert path.exists()

    def test_contains_oversized_strings(self, tmp_path):
        """Test that sample contains oversized strings."""
        generator = CVESampleGenerator(tmp_path)
        path = generator.generate_cve_2024_28877()

        import pydicom

        ds = pydicom.dcmread(path)

        assert len(ds.InstitutionName) > 1000


class TestGenerateAll:
    """Test generate_all method."""

    def test_generates_all_samples(self, tmp_path):
        """Test that all CVE samples are generated."""
        generator = CVESampleGenerator(tmp_path)
        results = generator.generate_all()

        # Should have entries for all CVEs
        assert "CVE-2019-11687" in results
        assert "CVE-2022-2119" in results
        assert "CVE-2024-22100" in results

    def test_returns_paths(self, tmp_path):
        """Test that paths are returned for successful generations."""
        generator = CVESampleGenerator(tmp_path)
        results = generator.generate_all()

        for cve_id, path in results.items():
            if path is not None:
                assert Path(path).exists()


class TestGenerateCVEReadme:
    """Test generate_cve_readme function."""

    def test_generates_readme(self, tmp_path):
        """Test that README is generated."""
        generate_cve_readme("CVE-2019-11687", tmp_path)

        readme_path = tmp_path / "cve_2019_11687" / "README.md"
        assert readme_path.exists()

    def test_readme_contains_cve_info(self, tmp_path):
        """Test that README contains CVE information."""
        generate_cve_readme("CVE-2019-11687", tmp_path)

        readme_path = tmp_path / "cve_2019_11687" / "README.md"
        content = readme_path.read_text()

        assert "CVE-2019-11687" in content
        assert "DICOM" in content

    def test_unknown_cve_raises_error(self, tmp_path):
        """Test that unknown CVE raises ValueError."""
        with pytest.raises(ValueError, match="Unknown CVE"):
            generate_cve_readme("CVE-9999-99999", tmp_path)


class TestMain:
    """Test main CLI function."""

    def test_main_list(self, capsys):
        """Test --list option."""
        with patch("sys.argv", ["generator", "--list"]):
            main()

        captured = capsys.readouterr()
        assert "Available CVEs" in captured.out
        assert "CVE-2019-11687" in captured.out

    def test_main_generate_specific_cve(self, tmp_path):
        """Test generating specific CVE."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--cve", "CVE-2019-11687"],
        ):
            main()

        assert (tmp_path / "cve_2019_11687").exists()

    def test_main_generate_readme(self, tmp_path):
        """Test --readme option."""
        with patch(
            "sys.argv", ["generator", "--output-dir", str(tmp_path), "--readme"]
        ):
            main()

        # Should create README files for CVEs
        readme_files = list(tmp_path.rglob("README.md"))
        assert len(readme_files) > 0

    def test_main_unknown_cve(self, tmp_path, capsys):
        """Test unknown CVE handling."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--cve", "CVE-9999-99999"],
        ):
            main()

        captured = capsys.readouterr()
        assert "Unknown CVE" in captured.out

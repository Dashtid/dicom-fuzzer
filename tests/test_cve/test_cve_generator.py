"""Tests for CVE Generator - Deterministic CVE file generation."""

import pytest

from dicom_fuzzer.cve import (
    CVEGenerator,
    CVE_REGISTRY,
    CVECategory,
    CVEInfo,
    get_cve_info,
    get_cves_by_category,
    get_cves_by_product,
    list_cves,
)
from dicom_fuzzer.cve.generator import CVEFile


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def generator() -> CVEGenerator:
    """Create a CVEGenerator instance."""
    return CVEGenerator()


@pytest.fixture
def template_bytes() -> bytes:
    """Create minimal DICOM-like template bytes."""
    # Minimal structure: 128 preamble + DICM + some data
    return b"\x00" * 128 + b"DICM" + b"\x00" * 100


# =============================================================================
# Registry Tests
# =============================================================================
class TestCVERegistry:
    """Tests for CVE registry functions."""

    def test_list_cves_returns_list(self) -> None:
        """Test list_cves returns a list of CVE IDs."""
        cves = list_cves()
        assert isinstance(cves, list)
        assert len(cves) > 0

    def test_list_cves_sorted(self) -> None:
        """Test list_cves returns sorted list."""
        cves = list_cves()
        assert cves == sorted(cves)

    def test_all_cves_have_cve_prefix(self) -> None:
        """Test all CVE IDs start with CVE-."""
        for cve_id in list_cves():
            assert cve_id.startswith("CVE-")

    def test_get_cve_info_existing(self) -> None:
        """Test get_cve_info for existing CVE."""
        info = get_cve_info("CVE-2025-5943")
        assert info is not None
        assert isinstance(info, CVEInfo)
        assert info.cve_id == "CVE-2025-5943"

    def test_get_cve_info_nonexistent(self) -> None:
        """Test get_cve_info for nonexistent CVE."""
        info = get_cve_info("CVE-9999-99999")
        assert info is None

    def test_get_cves_by_category(self) -> None:
        """Test filtering CVEs by category."""
        heap_cves = get_cves_by_category(CVECategory.HEAP_OVERFLOW)
        assert len(heap_cves) > 0
        for cve in heap_cves:
            assert cve.category == CVECategory.HEAP_OVERFLOW

    def test_get_cves_by_product(self) -> None:
        """Test filtering CVEs by product."""
        microdicom_cves = get_cves_by_product("MicroDicom")
        assert len(microdicom_cves) > 0
        for cve in microdicom_cves:
            assert "microdicom" in cve.affected_product.lower()

    def test_get_cves_by_product_case_insensitive(self) -> None:
        """Test product filtering is case insensitive."""
        upper = get_cves_by_product("MICRODICOM")
        lower = get_cves_by_product("microdicom")
        assert len(upper) == len(lower)


class TestCVEInfo:
    """Tests for CVEInfo dataclass."""

    def test_cve_info_attributes(self) -> None:
        """Test CVEInfo has expected attributes."""
        info = get_cve_info("CVE-2025-5943")
        assert info is not None
        assert hasattr(info, "cve_id")
        assert hasattr(info, "description")
        assert hasattr(info, "category")
        assert hasattr(info, "severity")
        assert hasattr(info, "affected_product")
        assert hasattr(info, "target_component")
        assert hasattr(info, "variants")

    def test_cve_info_to_dict(self) -> None:
        """Test CVEInfo.to_dict()."""
        info = get_cve_info("CVE-2025-5943")
        assert info is not None
        d = info.to_dict()
        assert isinstance(d, dict)
        assert "cve_id" in d
        assert d["cve_id"] == "CVE-2025-5943"


# =============================================================================
# Generator Tests
# =============================================================================
class TestCVEGenerator:
    """Tests for CVEGenerator class."""

    def test_available_cves(self, generator: CVEGenerator) -> None:
        """Test available_cves property."""
        cves = generator.available_cves
        assert isinstance(cves, list)
        assert len(cves) > 0
        assert cves == sorted(cves)

    def test_get_info(self, generator: CVEGenerator) -> None:
        """Test get_info method."""
        info = generator.get_info("CVE-2025-5943")
        assert info is not None
        assert info.cve_id == "CVE-2025-5943"

    def test_generate_single_cve(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generating files for a single CVE."""
        files = generator.generate("CVE-2025-5943", template_bytes)
        assert len(files) > 0
        for f in files:
            assert isinstance(f, CVEFile)
            assert f.cve_id == "CVE-2025-5943"
            assert len(f.data) > 0

    def test_generate_unknown_cve_raises(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generating unknown CVE raises ValueError."""
        with pytest.raises(ValueError, match="Unknown CVE"):
            generator.generate("CVE-9999-99999", template_bytes)

    def test_generate_case_insensitive(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test CVE ID matching is case insensitive."""
        files1 = generator.generate("CVE-2025-5943", template_bytes)
        files2 = generator.generate("cve-2025-5943", template_bytes)
        assert len(files1) == len(files2)

    def test_generate_one(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generate_one returns single file."""
        file = generator.generate_one("CVE-2025-5943", template_bytes)
        assert isinstance(file, CVEFile)
        assert file.cve_id == "CVE-2025-5943"

    def test_generate_all(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generate_all returns files for all CVEs."""
        all_files = generator.generate_all(template_bytes)
        assert isinstance(all_files, dict)
        assert len(all_files) == len(generator.available_cves)

    def test_generate_by_category(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generate_by_category filters correctly."""
        files = generator.generate_by_category("heap_overflow", template_bytes)
        assert len(files) > 0
        for cve_id in files:
            info = get_cve_info(cve_id)
            assert info is not None
            assert info.category == CVECategory.HEAP_OVERFLOW

    def test_generate_by_product(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test generate_by_product filters correctly."""
        files = generator.generate_by_product("MicroDicom", template_bytes)
        assert len(files) > 0


# =============================================================================
# CVEFile Tests
# =============================================================================
class TestCVEFile:
    """Tests for CVEFile dataclass."""

    def test_filename_format(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test CVEFile.filename format."""
        files = generator.generate("CVE-2025-5943", template_bytes)
        for f in files:
            assert f.filename.startswith("CVE-2025-5943_")
            assert f.filename.endswith(".dcm")

    def test_save_creates_file(
        self, generator: CVEGenerator, template_bytes: bytes, tmp_path
    ) -> None:
        """Test CVEFile.save creates file."""
        files = generator.generate("CVE-2025-5943", template_bytes)
        path = files[0].save(tmp_path)
        assert path.exists()
        assert path.read_bytes() == files[0].data


# =============================================================================
# Determinism Tests
# =============================================================================
class TestDeterminism:
    """Tests to verify output is deterministic (not random)."""

    def test_same_input_same_output(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test same input produces same output."""
        files1 = generator.generate("CVE-2025-5943", template_bytes)
        files2 = generator.generate("CVE-2025-5943", template_bytes)

        assert len(files1) == len(files2)
        for f1, f2 in zip(files1, files2):
            assert f1.variant == f2.variant
            assert f1.data == f2.data

    def test_all_variants_generated(
        self, generator: CVEGenerator, template_bytes: bytes
    ) -> None:
        """Test all variants are generated, not randomly selected."""
        info = get_cve_info("CVE-2025-5943")
        assert info is not None

        files = generator.generate("CVE-2025-5943", template_bytes)
        assert len(files) == info.variants


# =============================================================================
# Coverage Tests
# =============================================================================
class TestCVECoverage:
    """Tests to verify CVE coverage."""

    def test_all_registry_cves_have_mutations(self) -> None:
        """Test all CVEs in registry have corresponding mutations."""
        from dicom_fuzzer.cve.payloads import CVE_MUTATIONS

        for cve_id in CVE_REGISTRY:
            assert cve_id in CVE_MUTATIONS, f"Missing mutation for {cve_id}"

    def test_all_categories_covered(self) -> None:
        """Test major vulnerability categories are covered."""
        categories_found = {cve.category for cve in CVE_REGISTRY.values()}
        expected = {
            CVECategory.HEAP_OVERFLOW,
            CVECategory.OUT_OF_BOUNDS_READ,
            CVECategory.OUT_OF_BOUNDS_WRITE,
            CVECategory.PATH_TRAVERSAL,
        }
        assert expected.issubset(categories_found)

    def test_recent_cves_included(self) -> None:
        """Test 2025 CVEs are included."""
        cves_2025 = [cve for cve in list_cves() if cve.startswith("CVE-2025")]
        assert len(cves_2025) >= 5, "Should have at least 5 2025 CVEs"

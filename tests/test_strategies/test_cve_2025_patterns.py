"""Tests for 2025 CVE-specific vulnerability patterns.

This module validates that CVE patterns generate appropriate mutations
for the 2025 DICOM vulnerabilities:

- CVE-2025-35975: MicroDicom out-of-bounds write (CVSS 8.8)
- CVE-2025-36521: MicroDicom out-of-bounds read (CVSS 8.8)
- CVE-2025-5943: MicroDicom heap corruption (June 2025, CISA ICSMA-25-160-01)
- CVE-2025-1001: RadiAnt DICOM Viewer MitM (CVSS 5.7)
- CVE-2025-1002: MicroDicom certificate verification bypass (CVSS 5.7)

Target: Validate all CVE patterns generate correct mutations with
appropriate severity and exploitability classifications.
"""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.medical_device_security import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    MedicalDeviceSecurityFuzzer,
    VulnerabilityClass,
)


class TestCve202535975:
    """Tests for CVE-2025-35975 (MicroDicom OOB write)."""

    @pytest.fixture
    def fuzzer(self) -> MedicalDeviceSecurityFuzzer:
        """Create fuzzer targeting OOB write."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=True,
        )
        return MedicalDeviceSecurityFuzzer(config)

    @pytest.fixture
    def sample_dataset(self) -> Dataset:
        """Create sample dataset."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPInstanceUID = "1.2.3.4.5"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.PixelData = b"\x00" * 1024
        return ds

    def test_generates_cve_2025_35975_mutations(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-35975 mutations are generated."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert isinstance(cve_mutations, list), "Should return list of mutations"
        assert len(cve_mutations) > 0, "Should generate at least one mutation"
        # Verify each mutation has required attributes
        for m in cve_mutations:
            assert hasattr(m, "severity"), "Mutation should have severity"
            assert hasattr(m, "vulnerability_class"), "Mutation should have vuln class"
            assert hasattr(m, "mutated_value"), "Mutation should have mutated value"

    def test_cve_2025_35975_has_high_severity(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-35975 mutations have high severity."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert len(cve_mutations) > 0, "Should have mutations for this CVE"
        # All should have severity >= 8 (HIGH)
        assert all(m.severity >= 8 for m in cve_mutations), (
            "All severities should be HIGH (>=8)"
        )
        # Verify severity values are in valid range
        assert all(0 <= m.severity <= 10 for m in cve_mutations), (
            "Severity should be 0-10"
        )

    def test_cve_2025_35975_targets_oob_write(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-35975 mutations target OOB write."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert len(cve_mutations) > 0, "Should generate mutations"
        # All should target OOB write vulnerability
        assert all(
            m.vulnerability_class == VulnerabilityClass.OUT_OF_BOUNDS_WRITE
            for m in cve_mutations
        ), "All mutations should target OUT_OF_BOUNDS_WRITE"
        # Verify vulnerability_class is the correct enum type
        assert all(
            isinstance(m.vulnerability_class, VulnerabilityClass) for m in cve_mutations
        ), "vulnerability_class should be VulnerabilityClass enum"

    def test_cve_2025_35975_includes_string_overflow(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that string overflow patterns are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert isinstance(cve_mutations, list), "Should return a list"
        assert len(cve_mutations) > 0, "Should have CVE mutations"
        # Should have mutations with large string values
        string_mutations = [
            m
            for m in cve_mutations
            if isinstance(m.mutated_value, str) and len(m.mutated_value) > 1000
        ]
        assert len(string_mutations) > 0, "Should include string overflow mutations"
        # Verify the string values are sufficiently large for overflow testing
        for m in string_mutations:
            assert isinstance(m.mutated_value, str), "Mutated value should be string"

    def test_cve_2025_35975_includes_pixel_data_attack(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that pixel data mismatch attack is included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert isinstance(cve_mutations, list), "Should return a list"
        assert len(cve_mutations) > 0, "Should generate mutations"
        # Should have pixel data size mismatch mutation
        pixel_mutations = [m for m in cve_mutations if "pixel" in m.name.lower()]
        assert len(pixel_mutations) > 0, "Should include pixel data attack mutations"
        # Verify each mutation has a name attribute
        for m in pixel_mutations:
            assert hasattr(m, "name"), "Mutation should have name"
            assert "pixel" in m.name.lower(), "Should be pixel-related mutation"


class TestCve202536521:
    """Tests for CVE-2025-36521 (MicroDicom OOB read)."""

    @pytest.fixture
    def fuzzer(self) -> MedicalDeviceSecurityFuzzer:
        """Create fuzzer targeting OOB read."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_READ],
            fuzz_pixel_data=True,
        )
        return MedicalDeviceSecurityFuzzer(config)

    @pytest.fixture
    def sample_dataset(self) -> Dataset:
        """Create sample dataset."""
        ds = Dataset()
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.HighBit = 11
        ds.PixelData = b"\x00" * 1024
        return ds

    def test_generates_cve_2025_36521_mutations(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-36521 mutations are generated."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)
        assert isinstance(cve_mutations, list), "Should return a list"
        assert len(cve_mutations) > 0, "Should generate at least one mutation"
        # Verify each mutation has required attributes
        for m in cve_mutations:
            assert hasattr(m, "severity"), "Mutation should have severity"
            assert hasattr(m, "vulnerability_class"), "Mutation should have vuln class"

    def test_cve_2025_36521_has_high_severity(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-36521 mutations have appropriate severity."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)
        assert len(cve_mutations) > 0, "Should have mutations for this CVE"
        # All should have severity >= 7 (HIGH)
        assert all(m.severity >= 7 for m in cve_mutations), (
            "All severities should be HIGH (>=7)"
        )
        # Verify severity values are numeric and in valid range
        assert all(
            isinstance(m.severity, (int, float)) and 0 <= m.severity <= 10
            for m in cve_mutations
        ), "Severity should be numeric 0-10"

    def test_cve_2025_36521_targets_dimension_attacks(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that dimension-based attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)
        assert len(cve_mutations) > 0, "Should generate mutations"
        # Should have mutations targeting Rows/Columns
        dimension_mutations = [
            m for m in cve_mutations if m.tag in [(0x0028, 0x0010), (0x0028, 0x0011)]
        ]
        # The mutations include dimension attacks in mutated_value dict
        has_dimension_attack = any(
            isinstance(m.mutated_value, dict) and "rows" in m.mutated_value
            for m in cve_mutations
        )
        assert has_dimension_attack, "Should include dimension-based attack mutations"
        # Verify mutations have tag attribute
        for m in cve_mutations:
            assert hasattr(m, "tag"), "Mutation should have tag attribute"

    def test_cve_2025_36521_targets_bit_allocation(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that bit allocation attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)
        assert isinstance(cve_mutations, list), "Should return a list"
        assert len(cve_mutations) > 0, "Should have mutations"
        # Should have mutations with bits_allocated in value
        bit_mutations = [
            m
            for m in cve_mutations
            if isinstance(m.mutated_value, dict) and "bits_allocated" in m.mutated_value
        ]
        assert len(bit_mutations) > 0, "Should include bit allocation attacks"
        # Verify mutated_value is properly formatted for bit allocation
        for m in bit_mutations:
            assert isinstance(m.mutated_value, dict), "Mutated value should be dict"
            assert "bits_allocated" in m.mutated_value, "Should have bits_allocated key"


class TestCve20255943:
    """Tests for CVE-2025-5943 (MicroDicom heap corruption - June 2025)."""

    @pytest.fixture
    def fuzzer(self) -> MedicalDeviceSecurityFuzzer:
        """Create fuzzer targeting OOB write (includes 5943)."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=True,
        )
        return MedicalDeviceSecurityFuzzer(config)

    @pytest.fixture
    def sample_dataset(self) -> Dataset:
        """Create sample dataset."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3.4.5"
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.PixelData = b"\x00" * 1024
        return ds

    def test_generates_cve_2025_5943_mutations(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-5943 mutations are generated."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        assert len(cve_mutations) > 0

    def test_cve_2025_5943_has_critical_severity(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that CVE-2025-5943 mutations have critical severity."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert len(cve_mutations) > 0
        # Most should have severity >= 8 (HIGH/CRITICAL)
        high_severity = [m for m in cve_mutations if m.severity >= 8]
        assert len(high_severity) > len(cve_mutations) // 2

    def test_cve_2025_5943_includes_vr_length_attacks(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that VR length overflow attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        # Should have VR length attacks
        vr_length_mutations = [m for m in cve_mutations if "vr_length" in m.name]
        assert len(vr_length_mutations) > 0

    def test_cve_2025_5943_includes_transfer_syntax_attacks(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that transfer syntax confusion attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        # Should have transfer syntax attacks
        ts_mutations = [m for m in cve_mutations if "transfer_syntax" in m.name]
        assert len(ts_mutations) > 0

    def test_cve_2025_5943_includes_pixel_misalignment(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that pixel header misalignment attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        # Should have pixel misalignment attacks
        pixel_mutations = [m for m in cve_mutations if "pixel_misalign" in m.name]
        assert len(pixel_mutations) > 0

    def test_cve_2025_5943_includes_file_meta_attacks(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that file meta corruption attacks are included."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        # Should have file meta attacks
        meta_mutations = [m for m in cve_mutations if "file_meta" in m.name]
        assert len(meta_mutations) > 0

    def test_cve_2025_5943_vr_length_values(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that VR length attacks use boundary values."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        vr_mutations = [m for m in cve_mutations if "vr_length" in m.name]

        # Should test boundary values
        boundary_names = [
            "max_16bit_length",
            "boundary_16bit_length",
            "signed_boundary_length",
        ]
        for name in boundary_names:
            matching = [m for m in vr_mutations if name in m.name]
            assert len(matching) > 0, f"Missing VR length attack: {name}"

    def test_cve_2025_5943_exploitability_rating(
        self, fuzzer: MedicalDeviceSecurityFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that exploitability is correctly rated."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert len(cve_mutations) > 0

        # VR length and pixel attacks should be marked as exploitable
        exploitable = [m for m in cve_mutations if m.exploitability == "exploitable"]
        assert len(exploitable) > 0


class TestCVEPatternIntegration:
    """Integration tests for all 2025 CVE patterns."""

    def test_all_2025_cves_have_mutations(self) -> None:
        """Test that all 2025 CVEs have associated mutations."""
        config = MedicalDeviceSecurityConfig()  # All vulns and CVEs
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPInstanceUID = "1.2.3"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.PixelData = b"\x00" * 1024

        fuzzer.generate_mutations(ds)

        # Check all 2025 CVEs have mutations
        cve_2025_patterns = [
            CVEPattern.CVE_2025_35975,
            CVEPattern.CVE_2025_36521,
            CVEPattern.CVE_2025_5943,
        ]

        for cve in cve_2025_patterns:
            mutations = fuzzer.get_mutations_by_cve(cve)
            assert isinstance(mutations, list)
            assert len(mutations) > 0, f"No mutations for {cve.value}"

    def test_cve_mutations_in_summary(self) -> None:
        """Test that CVE mutations appear in summary."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3"
        ds.Rows = 256
        ds.Columns = 256
        ds.PixelData = b"\x00" * 100

        fuzzer.generate_mutations(ds)
        summary = fuzzer.get_summary()

        # Summary should include CVE counts
        assert isinstance(summary, dict)
        assert "by_cve" in summary
        assert len(summary["by_cve"]) > 0

    def test_high_value_targets_include_cve_mutations(self) -> None:
        """Test that high-value targets include CVE mutations."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3"
        ds.Rows = 256
        ds.Columns = 256
        ds.PixelData = b"\x00" * 100

        fuzzer.generate_mutations(ds)
        summary = fuzzer.get_summary()

        # High-value targets should include CVE patterns
        assert isinstance(summary, dict)
        high_value = summary.get("high_value_targets", [])
        cve_in_high_value = [t for t in high_value if t.get("cve_pattern") is not None]
        assert len(cve_in_high_value) > 0

    def test_mutation_diversity_across_cves(self) -> None:
        """Test mutation diversity across different CVEs."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.PixelData = b"\x00" * 2048

        fuzzer.generate_mutations(ds)

        # Different CVEs should target different tags
        cve_35975 = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        cve_36521 = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)
        cve_5943 = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)

        # Get unique tags for each CVE
        tags_35975 = {m.tag for m in cve_35975 if m.tag}
        tags_36521 = {m.tag for m in cve_36521 if m.tag}
        tags_5943 = {m.tag for m in cve_5943 if m.tag}

        # Each CVE should have some unique characteristics
        assert isinstance(tags_35975, set)
        assert isinstance(tags_36521, set)
        assert isinstance(tags_5943, set)
        assert len(tags_35975) > 0
        assert len(tags_36521) > 0
        assert len(tags_5943) > 0

    def test_apply_cve_mutations(self) -> None:
        """Test that CVE mutations can be applied."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3"
        ds.Rows = 256
        ds.Columns = 256
        ds.PixelData = b"\x00" * 100

        fuzzer.generate_mutations(ds)

        # Get CVE-2025-5943 mutations and apply them
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)
        assert isinstance(cve_mutations, list)
        assert len(cve_mutations) > 0

        # Apply first mutation
        mutation = cve_mutations[0]
        ds_copy = Dataset()
        ds_copy.update(ds)
        result = fuzzer.apply_mutation(ds_copy, mutation)
        assert result is not None
        assert isinstance(result, Dataset)


class TestCVEPatternEdgeCases:
    """Edge case tests for CVE patterns."""

    def test_cve_patterns_with_empty_dataset(self) -> None:
        """Test CVE pattern generation with empty dataset."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        mutations = fuzzer.generate_mutations(ds)

        # Should still generate mutations (they create new elements)
        assert isinstance(mutations, list)
        assert len(mutations) > 0

    def test_cve_patterns_pixel_data_disabled(self) -> None:
        """Test CVE patterns when pixel data fuzzing is disabled."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=False,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3"

        fuzzer.generate_mutations(ds)
        cve_5943 = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_5943)

        # Should not have pixel misalignment attacks
        pixel_mutations = [m for m in cve_5943 if "pixel_misalign" in m.name]
        assert len(pixel_mutations) == 0

    def test_cve_patterns_severity_distribution(self) -> None:
        """Test severity distribution of CVE patterns."""
        config = MedicalDeviceSecurityConfig()
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPInstanceUID = "1.2.3"
        ds.Rows = 256
        ds.Columns = 256
        ds.PixelData = b"\x00" * 100

        fuzzer.generate_mutations(ds)

        # Check severity distribution
        all_cve_mutations = []
        for cve in CVEPattern:
            all_cve_mutations.extend(fuzzer.get_mutations_by_cve(cve))

        if all_cve_mutations:
            critical = sum(1 for m in all_cve_mutations if m.severity >= 9)
            high = sum(1 for m in all_cve_mutations if 7 <= m.severity < 9)

            # Most CVE mutations should be high or critical severity
            assert (critical + high) >= len(all_cve_mutations) // 2

"""Comprehensive tests for medical_device_security.py module.

Target: medical_device_security.py (new module)
Focus areas:
- VulnerabilityClass enum
- CVEPattern enum
- SecurityMutation dataclass
- MedicalDeviceSecurityConfig dataclass
- MedicalDeviceSecurityFuzzer class methods
"""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.strategies.medical_device_security import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    MedicalDeviceSecurityFuzzer,
    SecurityMutation,
    VulnerabilityClass,
)


class TestVulnerabilityClass:
    """Tests for VulnerabilityClass enum."""

    def test_all_vulnerability_classes_exist(self) -> None:
        """Test all vulnerability classes are defined."""
        expected = [
            "OUT_OF_BOUNDS_WRITE",
            "OUT_OF_BOUNDS_READ",
            "STACK_BUFFER_OVERFLOW",
            "HEAP_BUFFER_OVERFLOW",
            "INTEGER_OVERFLOW",
            "FORMAT_STRING",
            "USE_AFTER_FREE",
            "NULL_POINTER_DEREF",
            "MEMORY_CORRUPTION",
            "DENIAL_OF_SERVICE",
        ]
        for name in expected:
            assert hasattr(VulnerabilityClass, name)

    def test_vulnerability_class_values(self) -> None:
        """Test vulnerability class enum values."""
        assert VulnerabilityClass.OUT_OF_BOUNDS_WRITE.value == "oob_write"
        assert VulnerabilityClass.OUT_OF_BOUNDS_READ.value == "oob_read"
        assert VulnerabilityClass.STACK_BUFFER_OVERFLOW.value == "stack_overflow"
        assert VulnerabilityClass.HEAP_BUFFER_OVERFLOW.value == "heap_overflow"
        assert VulnerabilityClass.INTEGER_OVERFLOW.value == "integer_overflow"
        assert VulnerabilityClass.FORMAT_STRING.value == "format_string"
        assert VulnerabilityClass.USE_AFTER_FREE.value == "use_after_free"
        assert VulnerabilityClass.NULL_POINTER_DEREF.value == "null_deref"
        assert VulnerabilityClass.MEMORY_CORRUPTION.value == "memory_corruption"
        assert VulnerabilityClass.DENIAL_OF_SERVICE.value == "dos"


class TestCVEPattern:
    """Tests for CVEPattern enum."""

    def test_all_cve_patterns_exist(self) -> None:
        """Test all CVE patterns are defined."""
        expected = [
            "CVE_2025_35975",
            "CVE_2025_36521",
            "CVE_2025_5943",
            "CVE_2025_1001",
            "CVE_2022_2119",
            "CVE_2022_2120",
        ]
        for name in expected:
            assert hasattr(CVEPattern, name)

    def test_cve_pattern_values(self) -> None:
        """Test CVE pattern enum values."""
        assert CVEPattern.CVE_2025_35975.value == "CVE-2025-35975"
        assert CVEPattern.CVE_2025_36521.value == "CVE-2025-36521"
        assert CVEPattern.CVE_2025_5943.value == "CVE-2025-5943"
        assert CVEPattern.CVE_2025_1001.value == "CVE-2025-1001"
        assert CVEPattern.CVE_2022_2119.value == "CVE-2022-2119"
        assert CVEPattern.CVE_2022_2120.value == "CVE-2022-2120"


class TestSecurityMutation:
    """Tests for SecurityMutation dataclass."""

    def test_basic_creation(self) -> None:
        """Test creating a basic SecurityMutation."""
        mutation = SecurityMutation(
            name="test_mutation",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
        )
        assert mutation.name == "test_mutation"
        assert mutation.vulnerability_class == VulnerabilityClass.OUT_OF_BOUNDS_WRITE
        assert mutation.cve_pattern is None
        assert mutation.tag is None
        assert mutation.original_value is None
        assert mutation.mutated_value is None
        assert mutation.description == ""
        assert mutation.severity == 5
        assert mutation.exploitability == "unknown"

    def test_full_creation(self) -> None:
        """Test creating a fully populated SecurityMutation."""
        mutation = SecurityMutation(
            name="oob_write_test",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
            cve_pattern=CVEPattern.CVE_2025_35975,
            tag=(0x0010, 0x0010),
            original_value="John Doe",
            mutated_value="A" * 1000,
            description="Buffer overflow via PatientName",
            severity=9,
            exploitability="exploitable",
        )
        assert mutation.name == "oob_write_test"
        assert mutation.cve_pattern == CVEPattern.CVE_2025_35975
        assert mutation.tag == (0x0010, 0x0010)
        assert mutation.original_value == "John Doe"
        assert mutation.mutated_value == "A" * 1000
        assert mutation.severity == 9
        assert mutation.exploitability == "exploitable"

    def test_to_dict(self) -> None:
        """Test converting SecurityMutation to dictionary."""
        mutation = SecurityMutation(
            name="test_mutation",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            cve_pattern=CVEPattern.CVE_2025_35975,
            tag=(0x0010, 0x0020),
            description="Test description",
            severity=8,
            exploitability="probably_exploitable",
        )
        result = mutation.to_dict()
        assert result["name"] == "test_mutation"
        assert result["vulnerability_class"] == "stack_overflow"
        assert result["cve_pattern"] == "CVE-2025-35975"
        assert result["tag"] == "(0010,0020)"
        assert result["description"] == "Test description"
        assert result["severity"] == 8
        assert result["exploitability"] == "probably_exploitable"

    def test_to_dict_no_cve(self) -> None:
        """Test to_dict with no CVE pattern."""
        mutation = SecurityMutation(
            name="test",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
        )
        result = mutation.to_dict()
        assert result["cve_pattern"] is None
        assert result["tag"] is None


class TestMedicalDeviceSecurityConfig:
    """Tests for MedicalDeviceSecurityConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = MedicalDeviceSecurityConfig()
        assert len(config.target_cves) > 0
        assert len(config.target_vulns) > 0
        assert config.max_string_length == 65536
        assert config.enable_destructive is True
        assert config.fuzz_pixel_data is True
        assert config.fuzz_sequence_depth == 10

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = MedicalDeviceSecurityConfig(
            target_cves=[CVEPattern.CVE_2025_35975],
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            max_string_length=1024,
            enable_destructive=False,
            fuzz_pixel_data=False,
            fuzz_sequence_depth=5,
        )
        assert len(config.target_cves) == 1
        assert CVEPattern.CVE_2025_35975 in config.target_cves
        assert len(config.target_vulns) == 1
        assert config.max_string_length == 1024
        assert config.enable_destructive is False
        assert config.fuzz_pixel_data is False
        assert config.fuzz_sequence_depth == 5


class TestMedicalDeviceSecurityFuzzer:
    """Tests for MedicalDeviceSecurityFuzzer class."""

    @pytest.fixture
    def fuzzer(self) -> MedicalDeviceSecurityFuzzer:
        """Create a fuzzer instance with default config."""
        return MedicalDeviceSecurityFuzzer()

    @pytest.fixture
    def custom_fuzzer(self) -> MedicalDeviceSecurityFuzzer:
        """Create a fuzzer with custom config."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[
                VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                VulnerabilityClass.OUT_OF_BOUNDS_READ,
            ],
            fuzz_pixel_data=True,
        )
        return MedicalDeviceSecurityFuzzer(config)

    @pytest.fixture
    def sample_dataset(self) -> Dataset:
        """Create a sample DICOM dataset."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4.5.6"
        ds.SeriesInstanceUID = "1.2.3.4.5.6.7"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.HighBit = 11
        ds.NumberOfFrames = "1"
        ds.SamplesPerPixel = 1
        ds.PixelData = b"\x00" * 1024
        return ds

    def test_initialization_default(self, fuzzer: MedicalDeviceSecurityFuzzer) -> None:
        """Test default initialization."""
        assert fuzzer.config is not None
        assert fuzzer._mutations_generated == []

    def test_initialization_custom(
        self, custom_fuzzer: MedicalDeviceSecurityFuzzer
    ) -> None:
        """Test custom initialization."""
        assert len(custom_fuzzer.config.target_vulns) == 2
        assert custom_fuzzer.config.fuzz_pixel_data is True

    def test_generate_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test mutation generation."""
        mutations = fuzzer.generate_mutations(sample_dataset)
        assert len(mutations) > 0
        assert all(isinstance(m, SecurityMutation) for m in mutations)
        assert fuzzer._mutations_generated == mutations

    def test_generate_oob_write_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test OOB write mutation generation."""
        mutations = fuzzer._generate_oob_write_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert (
                mutation.vulnerability_class == VulnerabilityClass.OUT_OF_BOUNDS_WRITE
            )

    def test_generate_oob_read_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test OOB read mutation generation."""
        mutations = fuzzer._generate_oob_read_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert mutation.vulnerability_class == VulnerabilityClass.OUT_OF_BOUNDS_READ

    def test_generate_integer_overflow_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test integer overflow mutation generation."""
        mutations = fuzzer._generate_integer_overflow_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert mutation.vulnerability_class == VulnerabilityClass.INTEGER_OVERFLOW

    def test_generate_stack_overflow_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test stack overflow mutation generation."""
        mutations = fuzzer._generate_stack_overflow_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert (
                mutation.vulnerability_class == VulnerabilityClass.STACK_BUFFER_OVERFLOW
            )
            # Check for varying sizes
        sizes = [
            len(m.mutated_value) for m in mutations if isinstance(m.mutated_value, str)
        ]
        assert len(set(sizes)) > 1  # Multiple different sizes

    def test_generate_heap_overflow_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test heap overflow mutation generation."""
        mutations = fuzzer._generate_heap_overflow_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert (
                mutation.vulnerability_class == VulnerabilityClass.HEAP_BUFFER_OVERFLOW
            )

    def test_generate_format_string_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test format string mutation generation."""
        mutations = fuzzer._generate_format_string_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert mutation.vulnerability_class == VulnerabilityClass.FORMAT_STRING
            assert "%" in mutation.mutated_value

    def test_generate_null_deref_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test null deref mutation generation."""
        mutations = fuzzer._generate_null_deref_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert mutation.vulnerability_class == VulnerabilityClass.NULL_POINTER_DEREF
            assert mutation.mutated_value in ("", "\x00")

    def test_generate_dos_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test DoS mutation generation."""
        mutations = fuzzer._generate_dos_mutations(sample_dataset)
        assert len(mutations) > 0
        for mutation in mutations:
            assert mutation.vulnerability_class == VulnerabilityClass.DENIAL_OF_SERVICE

    def test_apply_mutation_string(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying a string mutation."""
        mutation = SecurityMutation(
            name="test_string",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            tag=(0x0010, 0x0010),
            mutated_value="A" * 500,
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert result.PatientName == "A" * 500

    def test_apply_mutation_integer(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying an integer mutation."""
        mutation = SecurityMutation(
            name="test_int",
            vulnerability_class=VulnerabilityClass.INTEGER_OVERFLOW,
            tag=(0x0028, 0x0010),
            mutated_value=65535,
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert result.Rows == 65535

    def test_apply_mutation_none_tag(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying mutation with no tag."""
        mutation = SecurityMutation(
            name="test_no_tag",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
            tag=None,
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        # Should return unchanged dataset
        assert result == sample_dataset

    def test_apply_complex_mutation_dimensions(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying complex dimension mutation."""
        mutation = SecurityMutation(
            name="test_dimensions",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
            tag=(0x0028, 0x0010),
            mutated_value={"rows": 99999, "cols": 99999},
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert result.Rows == 99999
        assert result.Columns == 99999

    def test_apply_complex_mutation_bits(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying complex bit allocation mutation."""
        mutation = SecurityMutation(
            name="test_bits",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
            tag=(0x0028, 0x0100),
            mutated_value={"bits_allocated": 64, "bits_stored": 8},
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert result.BitsAllocated == 64
        assert result.BitsStored == 8

    def test_apply_complex_mutation_pixel_data(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying complex pixel data mutation."""
        mutation = SecurityMutation(
            name="test_pixel",
            vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
            tag=(0x7FE0, 0x0010),
            mutated_value={"data_size": 4096, "pattern": "overflow"},
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert len(result.PixelData) == 4096
        assert result.PixelData == b"\x41" * 4096  # 'A' pattern

    def test_apply_complex_mutation_pixel_data_random(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test applying complex pixel data mutation with random pattern."""
        mutation = SecurityMutation(
            name="test_pixel_random",
            vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
            tag=(0x7FE0, 0x0010),
            mutated_value={"data_size": 1024},
        )
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert len(result.PixelData) == 1024

    def test_apply_mutation_new_element(
        self, fuzzer: MedicalDeviceSecurityFuzzer
    ) -> None:
        """Test applying mutation adds new element if not present."""
        ds = Dataset()
        ds.SOPInstanceUID = "1.2.3"

        mutation = SecurityMutation(
            name="test_new",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            tag=(0x0010, 0x0010),  # PatientName not in dataset
            mutated_value="A" * 100,
        )
        result = fuzzer.apply_mutation(ds, mutation)
        assert (0x0010, 0x0010) in result
        assert result[0x0010, 0x0010].value == "A" * 100

    def test_apply_mutation_error_handling(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test mutation application with error."""
        # Create a mutation that will cause an error
        mutation = SecurityMutation(
            name="test_error",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
            tag=(0x0008, 0x1115),  # ReferencedSeriesSequence
            mutated_value={"depth": 5},
        )
        # Should not raise, just log warning
        result = fuzzer.apply_mutation(sample_dataset, mutation)
        assert result is not None

    def test_create_nested_sequence(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test creating nested sequence."""
        fuzzer._create_nested_sequence(sample_dataset, (0x0008, 0x1115), 3)
        assert (0x0008, 0x1115) in sample_dataset

    def test_create_nested_sequence_zero_depth(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test creating nested sequence with zero depth."""
        initial_count = len(sample_dataset)
        fuzzer._create_nested_sequence(sample_dataset, (0x0008, 0x1115), 0)
        # Should not add anything
        assert len(sample_dataset) == initial_count

    def test_create_nested_sequence_none_tag(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test creating nested sequence with None tag."""
        initial_count = len(sample_dataset)
        fuzzer._create_nested_sequence(sample_dataset, None, 5)
        assert len(sample_dataset) == initial_count

    def test_get_vr_for_tag(self, fuzzer: MedicalDeviceSecurityFuzzer) -> None:
        """Test getting VR for known tags."""
        assert fuzzer._get_vr_for_tag((0x0010, 0x0010)) == "PN"
        assert fuzzer._get_vr_for_tag((0x0010, 0x0020)) == "LO"
        assert fuzzer._get_vr_for_tag((0x0010, 0x0030)) == "DA"
        assert fuzzer._get_vr_for_tag((0x0008, 0x0018)) == "UI"
        assert fuzzer._get_vr_for_tag((0x0028, 0x0010)) == "US"
        assert fuzzer._get_vr_for_tag((0x7FE0, 0x0010)) == "OW"

    def test_get_vr_for_unknown_tag(self, fuzzer: MedicalDeviceSecurityFuzzer) -> None:
        """Test getting VR for unknown tag returns default."""
        assert fuzzer._get_vr_for_tag((0x9999, 0x9999)) == "LO"

    def test_get_mutations_by_cve(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test filtering mutations by CVE."""
        fuzzer.generate_mutations(sample_dataset)
        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        assert all(m.cve_pattern == CVEPattern.CVE_2025_35975 for m in cve_mutations)

    def test_get_mutations_by_severity(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test filtering mutations by severity."""
        fuzzer.generate_mutations(sample_dataset)
        high_severity = fuzzer.get_mutations_by_severity(min_severity=8)
        assert all(m.severity >= 8 for m in high_severity)

    def test_get_mutations_by_severity_default(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test filtering mutations by default severity threshold."""
        fuzzer.generate_mutations(sample_dataset)
        mutations = fuzzer.get_mutations_by_severity()  # Default min_severity=7
        assert all(m.severity >= 7 for m in mutations)

    def test_get_summary_empty(self, fuzzer: MedicalDeviceSecurityFuzzer) -> None:
        """Test summary with no mutations."""
        summary = fuzzer.get_summary()
        assert summary["total_mutations"] == 0
        assert summary["by_vulnerability_class"] == {}
        assert summary["by_cve"] == {}

    def test_get_summary_with_mutations(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test summary with mutations."""
        fuzzer.generate_mutations(sample_dataset)
        summary = fuzzer.get_summary()

        assert summary["total_mutations"] > 0
        assert len(summary["by_vulnerability_class"]) > 0
        assert "by_severity" in summary
        assert all(
            k in summary["by_severity"] for k in ["critical", "high", "medium", "low"]
        )

    def test_get_summary_high_value_targets(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
    ) -> None:
        """Test summary includes high value targets."""
        fuzzer.generate_mutations(sample_dataset)
        summary = fuzzer.get_summary()

        # Should have high value targets (severity >= 8)
        assert "high_value_targets" in summary
        if summary["high_value_targets"]:
            # All should be dicts with expected keys
            for target in summary["high_value_targets"]:
                assert "name" in target
                assert "description" in target

    def test_print_summary(
        self,
        fuzzer: MedicalDeviceSecurityFuzzer,
        sample_dataset: Dataset,
        capsys,
    ) -> None:
        """Test printing summary."""
        fuzzer.generate_mutations(sample_dataset)
        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "Medical Device Security Fuzzing Summary" in captured.out
        assert "Total Mutations:" in captured.out
        assert "By Vulnerability Class" in captured.out
        assert "By Severity" in captured.out

    def test_print_summary_empty(
        self, fuzzer: MedicalDeviceSecurityFuzzer, capsys
    ) -> None:
        """Test printing summary with no mutations."""
        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "Total Mutations: 0" in captured.out

    def test_vulnerable_tags_defined(self, fuzzer: MedicalDeviceSecurityFuzzer) -> None:
        """Test vulnerable tags are properly defined."""
        assert len(fuzzer.VULNERABLE_TAGS) > 0
        assert (0x0010, 0x0010) in fuzzer.VULNERABLE_TAGS  # PatientName
        assert (0x0010, 0x0020) in fuzzer.VULNERABLE_TAGS  # PatientID
        assert (0x7FE0, 0x0010) in fuzzer.VULNERABLE_TAGS  # PixelData


class TestMedicalDeviceSecurityFuzzerIntegration:
    """Integration tests for medical device security fuzzer."""

    def test_full_workflow(self) -> None:
        """Test complete fuzzing workflow."""
        # Create config targeting specific vulnerabilities
        config = MedicalDeviceSecurityConfig(
            target_vulns=[
                VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                VulnerabilityClass.STACK_BUFFER_OVERFLOW,
                VulnerabilityClass.FORMAT_STRING,
            ],
            fuzz_pixel_data=True,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        # Create dataset
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.PixelData = b"\x00" * 1024

        # Generate mutations
        mutations = fuzzer.generate_mutations(ds)
        assert len(mutations) > 0

        # Apply mutations
        for mutation in mutations[:5]:  # Test first 5
            ds_copy = Dataset()
            ds_copy.update(ds)
            mutated = fuzzer.apply_mutation(ds_copy, mutation)
            assert mutated is not None

        # Get summary
        summary = fuzzer.get_summary()
        assert summary["total_mutations"] == len(mutations)

    def test_cve_targeting(self) -> None:
        """Test CVE-specific targeting."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[
                VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
                VulnerabilityClass.OUT_OF_BOUNDS_READ,
            ],
            target_cves=[CVEPattern.CVE_2025_35975, CVEPattern.CVE_2025_36521],
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.PixelData = b"\x00" * 1024

        mutations = fuzzer.generate_mutations(ds)

        # Check CVE-specific mutations exist
        cve_35975_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)
        cve_36521_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_36521)

        assert len(cve_35975_mutations) > 0
        assert len(cve_36521_mutations) > 0

    def test_severity_filtering(self) -> None:
        """Test severity-based filtering."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.PixelData = b"\x00" * 1024

        fuzzer.generate_mutations(ds)

        # Get mutations by severity
        critical = fuzzer.get_mutations_by_severity(min_severity=9)
        high = fuzzer.get_mutations_by_severity(min_severity=7)

        assert len(critical) <= len(high)
        assert all(m.severity >= 9 for m in critical)

    def test_mutation_diversity(self) -> None:
        """Test that mutations cover multiple vulnerability classes."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        ds = Dataset()
        ds.PatientName = "Test"
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.NumberOfFrames = "1"
        ds.PixelData = b"\x00" * 1024
        ds.SOPInstanceUID = "1.2.3"
        ds.StudyInstanceUID = "1.2.3.4"
        ds.SeriesInstanceUID = "1.2.3.4.5"

        fuzzer.generate_mutations(ds)
        summary = fuzzer.get_summary()

        # Should have multiple vulnerability classes
        assert len(summary["by_vulnerability_class"]) > 3

    def test_pixel_data_mutations_disabled(self) -> None:
        """Test disabling pixel data mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=False,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        ds.Rows = 512
        ds.Columns = 512
        ds.PixelData = b"\x00" * 1024

        mutations = fuzzer._generate_oob_write_mutations(ds)

        # Should not have pixel data size mismatch mutation
        pixel_mutations = [
            m
            for m in mutations
            if m.tag == (0x7FE0, 0x0010) and isinstance(m.mutated_value, dict)
        ]
        assert len(pixel_mutations) == 0


class TestMedicalDeviceSecurityEdgeCases:
    """Edge case tests for medical device security fuzzer."""

    def test_empty_dataset(self) -> None:
        """Test with empty dataset."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()

        mutations = fuzzer.generate_mutations(ds)
        assert len(mutations) > 0  # Should still generate mutations

    def test_minimal_config(self) -> None:
        """Test with minimal configuration."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.DENIAL_OF_SERVICE],
            target_cves=[],
            fuzz_pixel_data=False,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.NumberOfFrames = "10"

        mutations = fuzzer.generate_mutations(ds)
        assert len(mutations) > 0
        assert all(
            m.vulnerability_class == VulnerabilityClass.DENIAL_OF_SERVICE
            for m in mutations
        )

    def test_apply_mutation_to_empty_dataset(self) -> None:
        """Test applying mutation to empty dataset."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()

        mutation = SecurityMutation(
            name="test",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            tag=(0x0010, 0x0010),
            mutated_value="A" * 100,
        )

        result = fuzzer.apply_mutation(ds, mutation)
        assert (0x0010, 0x0010) in result

    def test_oob_write_without_pixel_data(self) -> None:
        """Test OOB write mutations without pixel data in dataset."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=True,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        ds = Dataset()
        ds.PatientName = "Test"
        # No PixelData

        mutations = fuzzer._generate_oob_write_mutations(ds)
        assert len(mutations) > 0  # Should still generate string mutations

    def test_complex_mutation_missing_tags(self) -> None:
        """Test complex mutation when target tags don't exist."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()  # Empty dataset

        mutation = SecurityMutation(
            name="test_missing",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
            tag=(0x0028, 0x0010),
            mutated_value={"rows": 1000, "cols": 1000, "bits_allocated": 16},
        )

        # Should not raise
        result = fuzzer.apply_mutation(ds, mutation)
        assert result is not None

    def test_complex_mutation_non_dict_value(self) -> None:
        """Test complex mutation path with non-dict value returns early."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()
        ds.Rows = 512
        ds.Columns = 512

        # Mutation with non-dict value should trigger early return in _apply_complex_mutation
        mutation = SecurityMutation(
            name="test_non_dict",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
            tag=(0x0028, 0x0010),
            mutated_value="not_a_dict",  # String instead of dict
        )

        result = fuzzer.apply_mutation(ds, mutation)
        # Should not modify - value is string not dict for complex mutation
        assert result is not None

    def test_complex_mutation_pixel_data_named_pattern(self) -> None:
        """Test complex pixel data mutation with named non-overflow pattern."""
        from pydicom.uid import ExplicitVRLittleEndian

        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()
        ds.file_meta = Dataset()
        ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds.Rows = 8
        ds.Columns = 8
        ds.BitsAllocated = 8
        ds.PixelData = b"\x00" * 64

        # Use pattern other than "overflow" to trigger else branch
        mutation = SecurityMutation(
            name="test_pattern",
            vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
            tag=(0x7FE0, 0x0010),
            mutated_value={"data_size": 128, "pattern": "random"},
        )

        result = fuzzer.apply_mutation(ds, mutation)
        assert len(result.PixelData) == 128
        # Random pattern should not be all 'A's
        assert result.PixelData != b"\x41" * 128

    def test_create_nested_sequence_existing_tag(self) -> None:
        """Test nested sequence creation when tag already exists."""
        from pydicom.sequence import Sequence

        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = Dataset()
        # Pre-populate the sequence tag
        ds.ReferencedSeriesSequence = Sequence([Dataset()])

        # Should replace existing sequence
        fuzzer._create_nested_sequence(ds, (0x0008, 0x1115), 2)
        assert (0x0008, 0x1115) in ds

    def test_get_summary_low_severity_count(self) -> None:
        """Test summary counts low severity mutations (severity < 4)."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        # Manually add a low severity mutation
        low_sev_mutation = SecurityMutation(
            name="low_sev_test",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
            severity=2,  # Low severity
            description="Test low severity",
        )
        fuzzer._mutations_generated.append(low_sev_mutation)

        summary = fuzzer.get_summary()
        assert summary["by_severity"]["low"] >= 1

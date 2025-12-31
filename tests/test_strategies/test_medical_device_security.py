"""Tests for strategies/medical_device_security.py - Medical Device Security Fuzzer.

Tests cover vulnerability classes, CVE patterns, security mutations,
and the MedicalDeviceSecurityFuzzer class.
"""

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.strategies.medical_device_security import (
    CVEPattern,
    MedicalDeviceSecurityConfig,
    MedicalDeviceSecurityFuzzer,
    SecurityMutation,
    VulnerabilityClass,
)


def create_test_dataset() -> Dataset:
    """Create a minimal test dataset for mutation testing."""
    ds = Dataset()
    ds.PatientName = "TEST^PATIENT"
    ds.PatientID = "TEST-001"
    ds.PatientBirthDate = "19900101"
    ds.SOPInstanceUID = generate_uid()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.NumberOfFrames = 1
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = bytes([0] * (512 * 512 * 2))

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = file_meta

    return ds


class TestVulnerabilityClass:
    """Test VulnerabilityClass enum."""

    def test_vulnerability_class_values(self):
        """Test all vulnerability class values are defined."""
        assert VulnerabilityClass.OUT_OF_BOUNDS_WRITE.value == "oob_write"
        assert VulnerabilityClass.OUT_OF_BOUNDS_READ.value == "oob_read"
        assert VulnerabilityClass.STACK_BUFFER_OVERFLOW.value == "stack_overflow"
        assert VulnerabilityClass.HEAP_BUFFER_OVERFLOW.value == "heap_overflow"
        assert VulnerabilityClass.INTEGER_OVERFLOW.value == "integer_overflow"
        assert VulnerabilityClass.FORMAT_STRING.value == "format_string"
        assert VulnerabilityClass.USE_AFTER_FREE.value == "use_after_free"
        assert VulnerabilityClass.NULL_POINTER_DEREF.value == "null_deref"
        assert VulnerabilityClass.DENIAL_OF_SERVICE.value == "dos"

    def test_vulnerability_class_count(self):
        """Test expected number of vulnerability classes."""
        assert len(VulnerabilityClass) == 10


class TestCVEPattern:
    """Test CVEPattern enum."""

    def test_cve_2025_patterns(self):
        """Test 2025 CVE patterns are defined."""
        assert CVEPattern.CVE_2025_35975.value == "CVE-2025-35975"
        assert CVEPattern.CVE_2025_36521.value == "CVE-2025-36521"
        assert CVEPattern.CVE_2025_5943.value == "CVE-2025-5943"
        assert CVEPattern.CVE_2025_1001.value == "CVE-2025-1001"
        assert CVEPattern.CVE_2025_1002.value == "CVE-2025-1002"

    def test_historical_cve_patterns(self):
        """Test historical CVE patterns are defined."""
        assert CVEPattern.CVE_2022_2119.value == "CVE-2022-2119"
        assert CVEPattern.CVE_2022_2120.value == "CVE-2022-2120"

    def test_cve_pattern_count(self):
        """Test expected number of CVE patterns."""
        assert len(CVEPattern) == 7


class TestSecurityMutation:
    """Test SecurityMutation dataclass."""

    def test_creation_minimal(self):
        """Test creating mutation with minimal arguments."""
        mutation = SecurityMutation(
            name="test_mutation",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_WRITE,
        )

        assert mutation.name == "test_mutation"
        assert mutation.vulnerability_class == VulnerabilityClass.OUT_OF_BOUNDS_WRITE
        assert mutation.cve_pattern is None
        assert mutation.severity == 5

    def test_creation_full(self):
        """Test creating mutation with all arguments."""
        mutation = SecurityMutation(
            name="full_mutation",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            cve_pattern=CVEPattern.CVE_2025_35975,
            tag=(0x0010, 0x0010),
            original_value="test",
            mutated_value="A" * 1000,
            description="Test overflow mutation",
            severity=9,
            exploitability="exploitable",
        )

        assert mutation.name == "full_mutation"
        assert mutation.cve_pattern == CVEPattern.CVE_2025_35975
        assert mutation.tag == (0x0010, 0x0010)
        assert mutation.severity == 9

    def test_to_dict(self):
        """Test conversion to dictionary."""
        mutation = SecurityMutation(
            name="dict_test",
            vulnerability_class=VulnerabilityClass.INTEGER_OVERFLOW,
            cve_pattern=CVEPattern.CVE_2025_36521,
            tag=(0x0028, 0x0010),
            description="Test description",
            severity=7,
            exploitability="probably_exploitable",
        )

        d = mutation.to_dict()

        assert d["name"] == "dict_test"
        assert d["vulnerability_class"] == "integer_overflow"
        assert d["cve_pattern"] == "CVE-2025-36521"
        assert d["tag"] == "(0028,0010)"
        assert d["severity"] == 7

    def test_to_dict_no_cve(self):
        """Test to_dict without CVE pattern."""
        mutation = SecurityMutation(
            name="no_cve",
            vulnerability_class=VulnerabilityClass.FORMAT_STRING,
        )

        d = mutation.to_dict()
        assert d["cve_pattern"] is None

    def test_to_dict_no_tag(self):
        """Test to_dict without tag."""
        mutation = SecurityMutation(
            name="no_tag",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
        )

        d = mutation.to_dict()
        assert d["tag"] is None


class TestMedicalDeviceSecurityConfig:
    """Test MedicalDeviceSecurityConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = MedicalDeviceSecurityConfig()

        assert config.max_string_length == 65536
        assert config.enable_destructive is True
        assert config.fuzz_pixel_data is True
        assert config.fuzz_sequence_depth == 10

    def test_custom_config(self):
        """Test custom configuration values."""
        config = MedicalDeviceSecurityConfig(
            target_cves=[CVEPattern.CVE_2025_35975],
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            max_string_length=4096,
            enable_destructive=False,
        )

        assert len(config.target_cves) == 1
        assert config.max_string_length == 4096
        assert config.enable_destructive is False


class TestMedicalDeviceSecurityFuzzerInit:
    """Test MedicalDeviceSecurityFuzzer initialization."""

    def test_init_default_config(self):
        """Test initialization with default config."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        assert fuzzer.config is not None
        assert fuzzer._mutations_generated == []

    def test_init_custom_config(self):
        """Test initialization with custom config."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.INTEGER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)

        assert fuzzer.config == config

    def test_vulnerable_tags_defined(self):
        """Test that vulnerable tags are defined."""
        assert len(MedicalDeviceSecurityFuzzer.VULNERABLE_TAGS) > 0
        assert (0x0010, 0x0010) in MedicalDeviceSecurityFuzzer.VULNERABLE_TAGS
        assert (0x7FE0, 0x0010) in MedicalDeviceSecurityFuzzer.VULNERABLE_TAGS


class TestGenerateMutations:
    """Test generate_mutations method."""

    def test_generate_all_vulns(self):
        """Test generating mutations for all vulnerability classes."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        assert len(mutations) > 0
        assert fuzzer._mutations_generated == mutations

    def test_generate_specific_vuln(self):
        """Test generating mutations for specific vulnerability."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.INTEGER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        for m in mutations:
            assert m.vulnerability_class == VulnerabilityClass.INTEGER_OVERFLOW


class TestGenerateOOBWriteMutations:
    """Test _generate_oob_write_mutations method."""

    def test_generates_string_overflow(self):
        """Test generation of string overflow mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        string_mutations = [m for m in mutations if isinstance(m.mutated_value, str)]
        assert len(string_mutations) > 0

    def test_generates_pixel_mismatch(self):
        """Test generation of pixel data mismatch mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE],
            fuzz_pixel_data=True,
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        pixel_mutations = [m for m in mutations if m.tag == (0x7FE0, 0x0010)]
        assert len(pixel_mutations) > 0

    def test_includes_cve_2025_35975(self):
        """Test includes CVE-2025-35975 pattern."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        cve_mutations = [
            m for m in mutations if m.cve_pattern == CVEPattern.CVE_2025_35975
        ]
        assert len(cve_mutations) > 0


class TestGenerateCve20255943Mutations:
    """Test _generate_cve_2025_5943_mutations method."""

    def test_generates_vr_length_attacks(self):
        """Test VR length overflow attacks are generated."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        vr_mutations = [m for m in mutations if "vr_length" in m.name]
        assert len(vr_mutations) > 0

    def test_generates_transfer_syntax_attacks(self):
        """Test transfer syntax confusion attacks are generated."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        ts_mutations = [m for m in mutations if "transfer_syntax" in m.name]
        assert len(ts_mutations) > 0

    def test_generates_file_meta_attacks(self):
        """Test file meta corruption attacks are generated."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        file_meta_mutations = [m for m in mutations if "file_meta" in m.name]
        assert len(file_meta_mutations) > 0


class TestGenerateOOBReadMutations:
    """Test _generate_oob_read_mutations method."""

    def test_generates_dimension_tests(self):
        """Test dimension overflow mutations are generated."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_READ]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        assert len(mutations) > 0
        assert any(m.cve_pattern == CVEPattern.CVE_2025_36521 for m in mutations)

    def test_generates_bits_mismatch(self):
        """Test bits allocation mismatch mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_READ]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        bits_mutations = [m for m in mutations if "bits" in m.name]
        assert len(bits_mutations) > 0


class TestGenerateIntegerOverflowMutations:
    """Test _generate_integer_overflow_mutations method."""

    def test_generates_dimension_overflow(self):
        """Test dimension multiplication overflow mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.INTEGER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        assert len(mutations) > 0
        assert any("int_overflow" in m.name for m in mutations)

    def test_generates_frame_overflow(self):
        """Test NumberOfFrames overflow mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.INTEGER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        frame_mutations = [m for m in mutations if "frames" in m.name]
        assert len(frame_mutations) > 0


class TestGenerateStackOverflowMutations:
    """Test _generate_stack_overflow_mutations method."""

    def test_generates_overflow_patterns(self):
        """Test stack overflow pattern mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.STACK_BUFFER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        assert len(mutations) > 0
        assert any("stack_overflow" in m.name for m in mutations)

    def test_generates_null_bypass(self):
        """Test null terminator bypass mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.STACK_BUFFER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        null_mutations = [m for m in mutations if "null" in m.name]
        assert len(null_mutations) > 0


class TestGenerateHeapOverflowMutations:
    """Test _generate_heap_overflow_mutations method."""

    def test_generates_large_allocations(self):
        """Test large allocation mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.HEAP_BUFFER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        heap_mutations = [m for m in mutations if "heap_overflow" in m.name]
        assert len(heap_mutations) > 0

    def test_generates_depth_exhaust(self):
        """Test sequence depth exhaustion mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.HEAP_BUFFER_OVERFLOW]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        depth_mutations = [m for m in mutations if "depth" in m.name]
        assert len(depth_mutations) > 0


class TestGenerateFormatStringMutations:
    """Test _generate_format_string_mutations method."""

    def test_generates_format_patterns(self):
        """Test format string attack patterns."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.FORMAT_STRING]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        assert len(mutations) > 0
        assert any("format_string" in m.name for m in mutations)

    def test_format_strings_contain_specifiers(self):
        """Test format strings contain format specifiers."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.FORMAT_STRING]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        for m in mutations:
            if isinstance(m.mutated_value, str):
                assert "%" in m.mutated_value


class TestGenerateNullDerefMutations:
    """Test _generate_null_deref_mutations method."""

    def test_generates_empty_values(self):
        """Test empty value mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.NULL_POINTER_DEREF]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        empty_mutations = [m for m in mutations if m.mutated_value == ""]
        assert len(empty_mutations) > 0

    def test_generates_null_bytes(self):
        """Test null byte mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.NULL_POINTER_DEREF]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        null_mutations = [m for m in mutations if m.mutated_value == "\x00"]
        assert len(null_mutations) > 0


class TestGenerateDosMutations:
    """Test _generate_dos_mutations method."""

    def test_generates_resource_exhaustion(self):
        """Test resource exhaustion mutations."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.DENIAL_OF_SERVICE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        dos_mutations = [m for m in mutations if "dos" in m.name]
        assert len(dos_mutations) > 0

    def test_generates_circular_ref(self):
        """Test circular reference mutation."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.DENIAL_OF_SERVICE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()

        mutations = fuzzer.generate_mutations(ds)

        circular_mutations = [m for m in mutations if "circular" in m.name]
        assert len(circular_mutations) > 0


class TestApplyMutation:
    """Test apply_mutation method."""

    def test_apply_string_mutation(self):
        """Test applying string mutation to dataset."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()

        mutation = SecurityMutation(
            name="test_string",
            vulnerability_class=VulnerabilityClass.STACK_BUFFER_OVERFLOW,
            tag=(0x0010, 0x0010),  # PatientName
            mutated_value="OVERFLOW" * 100,
        )

        mutated_ds = fuzzer.apply_mutation(ds, mutation)

        assert mutated_ds.PatientName == "OVERFLOW" * 100

    def test_apply_integer_mutation(self):
        """Test applying integer mutation to dataset."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()

        mutation = SecurityMutation(
            name="test_int",
            vulnerability_class=VulnerabilityClass.INTEGER_OVERFLOW,
            tag=(0x0028, 0x0008),  # NumberOfFrames
            mutated_value=0xFFFFFFFF,
        )

        mutated_ds = fuzzer.apply_mutation(ds, mutation)

        assert mutated_ds.NumberOfFrames == 0xFFFFFFFF

    def test_apply_complex_dimension_mutation(self):
        """Test applying complex dimension mutation."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()

        mutation = SecurityMutation(
            name="test_dims",
            vulnerability_class=VulnerabilityClass.OUT_OF_BOUNDS_READ,
            tag=(0x0028, 0x0010),
            mutated_value={"rows": 0xFFFF, "cols": 0xFFFF},
        )

        mutated_ds = fuzzer.apply_mutation(ds, mutation)

        assert mutated_ds.Rows == 0xFFFF
        assert mutated_ds.Columns == 0xFFFF

    def test_apply_mutation_no_tag(self):
        """Test applying mutation without tag returns unchanged dataset."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        original_name = ds.PatientName

        mutation = SecurityMutation(
            name="no_tag",
            vulnerability_class=VulnerabilityClass.DENIAL_OF_SERVICE,
            tag=None,
        )

        mutated_ds = fuzzer.apply_mutation(ds, mutation)

        assert mutated_ds.PatientName == original_name


class TestGetMutationsByFilters:
    """Test mutation filtering methods."""

    def test_get_mutations_by_cve(self):
        """Test filtering mutations by CVE."""
        config = MedicalDeviceSecurityConfig(
            target_vulns=[VulnerabilityClass.OUT_OF_BOUNDS_WRITE]
        )
        fuzzer = MedicalDeviceSecurityFuzzer(config)
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        cve_mutations = fuzzer.get_mutations_by_cve(CVEPattern.CVE_2025_35975)

        assert len(cve_mutations) > 0
        for m in cve_mutations:
            assert m.cve_pattern == CVEPattern.CVE_2025_35975

    def test_get_mutations_by_severity(self):
        """Test filtering mutations by severity."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        high_severity = fuzzer.get_mutations_by_severity(min_severity=8)

        for m in high_severity:
            assert m.severity >= 8

    def test_get_mutations_by_severity_default(self):
        """Test default severity filter (7+)."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        high_severity = fuzzer.get_mutations_by_severity()

        for m in high_severity:
            assert m.severity >= 7


class TestGetSummary:
    """Test get_summary method."""

    def test_summary_structure(self):
        """Test summary dictionary structure."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        summary = fuzzer.get_summary()

        assert "total_mutations" in summary
        assert "by_vulnerability_class" in summary
        assert "by_cve" in summary
        assert "by_severity" in summary
        assert "high_value_targets" in summary

    def test_summary_counts(self):
        """Test summary counts are accurate."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        mutations = fuzzer.generate_mutations(ds)

        summary = fuzzer.get_summary()

        assert summary["total_mutations"] == len(mutations)

    def test_summary_severity_categories(self):
        """Test severity categories in summary."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        summary = fuzzer.get_summary()

        assert "critical" in summary["by_severity"]
        assert "high" in summary["by_severity"]
        assert "medium" in summary["by_severity"]
        assert "low" in summary["by_severity"]


class TestPrintSummary:
    """Test print_summary method."""

    def test_print_summary_no_error(self, capsys):
        """Test print_summary executes without error."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "Medical Device Security Fuzzing Summary" in captured.out
        assert "Total Mutations" in captured.out

    def test_print_summary_shows_vuln_classes(self, capsys):
        """Test print_summary shows vulnerability classes."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "By Vulnerability Class" in captured.out

    def test_print_summary_shows_cves(self, capsys):
        """Test print_summary shows CVE patterns."""
        fuzzer = MedicalDeviceSecurityFuzzer()
        ds = create_test_dataset()
        fuzzer.generate_mutations(ds)

        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "By CVE Pattern" in captured.out


class TestGetVRForTag:
    """Test _get_vr_for_tag method."""

    def test_known_tags(self):
        """Test VR lookup for known tags."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        assert fuzzer._get_vr_for_tag((0x0010, 0x0010)) == "PN"
        assert fuzzer._get_vr_for_tag((0x0028, 0x0010)) == "US"
        assert fuzzer._get_vr_for_tag((0x7FE0, 0x0010)) == "OW"

    def test_unknown_tag_default(self):
        """Test default VR for unknown tags."""
        fuzzer = MedicalDeviceSecurityFuzzer()

        assert fuzzer._get_vr_for_tag((0x9999, 0x9999)) == "LO"

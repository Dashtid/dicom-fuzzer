"""
Tests for Differential Fuzzer Module.

Tests differential testing capabilities for DICOM implementations:
- Parser wrappers (PydicomParser, GDCMParser, DCMTKParser)
- Differential analysis
- Bug classification
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.differential_fuzzer import (
    BugSeverity,
    DCMTKParser,
    Difference,
    DifferenceType,
    DifferentialAnalyzer,
    DifferentialFuzzer,
    DifferentialFuzzerConfig,
    DifferentialResult,
    GDCMParser,
    ImplementationType,
    ParseResult,
    PydicomParser,
)

# ============================================================================
# Test Enums
# ============================================================================


class TestImplementationType:
    """Test ImplementationType enum."""

    def test_types_defined(self):
        """Test all implementation types are defined."""
        assert ImplementationType.PYDICOM.value == "pydicom"
        assert ImplementationType.GDCM.value == "gdcm"
        assert ImplementationType.DCMTK.value == "dcmtk"
        assert ImplementationType.PYNETDICOM.value == "pynetdicom"
        assert ImplementationType.CUSTOM.value == "custom"


class TestDifferenceType:
    """Test DifferenceType enum."""

    def test_types_defined(self):
        """Test all difference types are defined."""
        expected = [
            "PARSE_SUCCESS_FAILURE",
            "VALUE_MISMATCH",
            "VR_MISMATCH",
            "TAG_PRESENCE",
            "SEQUENCE_DEPTH",
            "ENCODING_DIFFERENCE",
            "EXCEPTION_TYPE",
            "CRASH",
            "TIMEOUT",
            "MEMORY_DIVERGENCE",
        ]
        for name in expected:
            assert hasattr(DifferenceType, name)


class TestBugSeverity:
    """Test BugSeverity enum."""

    def test_severities_defined(self):
        """Test all severity levels are defined."""
        assert BugSeverity.CRITICAL.value == "critical"
        assert BugSeverity.HIGH.value == "high"
        assert BugSeverity.MEDIUM.value == "medium"
        assert BugSeverity.LOW.value == "low"
        assert BugSeverity.INFO.value == "info"


# ============================================================================
# Test Dataclasses
# ============================================================================


class TestParseResult:
    """Test ParseResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
        )

        assert result.success is True
        assert result.error_message == ""
        assert result.parse_time_ms == 0.0
        assert result.tags_found == {}
        assert result.values == {}

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
            tags_found={"(0010,0010)": True, "(0010,0020)": True},
            values={"(0010,0010)": "Test Patient"},
            vr_types={"(0010,0010)": "PN"},
            transfer_syntax="1.2.840.10008.1.2",
        )

        d = result.to_dict()

        assert d["implementation"] == "pydicom"
        assert d["success"] is True
        assert "(0010,0010)" in d["tags_found"]
        assert d["transfer_syntax"] == "1.2.840.10008.1.2"


class TestDifference:
    """Test Difference dataclass."""

    def test_default_values(self):
        """Test default values."""
        diff = Difference(
            diff_type=DifferenceType.VALUE_MISMATCH,
            description="Test difference",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.GDCM,
        )

        assert diff.tag == ""
        assert diff.value_a is None
        assert diff.value_b is None
        assert diff.severity == BugSeverity.MEDIUM

    def test_to_dict(self):
        """Test conversion to dictionary."""
        diff = Difference(
            diff_type=DifferenceType.TAG_PRESENCE,
            description="Tag missing in gdcm",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.GDCM,
            tag="(0010,0010)",
            severity=BugSeverity.HIGH,
        )

        d = diff.to_dict()

        assert d["type"] == "tag_presence"
        assert d["implementations"] == ["pydicom", "gdcm"]
        assert d["severity"] == "high"


class TestDifferentialResult:
    """Test DifferentialResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = DifferentialResult(
            input_hash="abc123",
            input_path="/test/path.dcm",
        )

        assert result.results == {}
        assert result.differences == []
        assert result.is_interesting is False
        assert result.bug_severity == BugSeverity.INFO

    def test_timestamp_auto_set(self):
        """Test timestamp is automatically set."""
        result = DifferentialResult(
            input_hash="abc123",
            input_path="/test/path.dcm",
        )

        assert result.timestamp > 0


# ============================================================================
# Test Parsers
# ============================================================================


class TestPydicomParser:
    """Test PydicomParser class."""

    def test_implementation_type(self):
        """Test implementation type is correct."""
        parser = PydicomParser()
        assert parser.implementation_type == ImplementationType.PYDICOM

    def test_is_available(self):
        """Test pydicom is available (it's a dependency)."""
        parser = PydicomParser()
        assert parser.is_available() is True

    def test_parse_valid_dicom(self, tmp_path):
        """Test parsing a valid DICOM file."""
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian

        # Create minimal DICOM file
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = pydicom.uid.generate_uid()
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        dcm_path = tmp_path / "test.dcm"
        ds.save_as(dcm_path)

        parser = PydicomParser()
        result = parser.parse(dcm_path)

        assert result.success is True
        assert result.error_message == ""
        assert "(0010,0010)" in result.tags_found
        assert "(0010,0020)" in result.tags_found
        assert result.parse_time_ms > 0

    def test_parse_invalid_file(self, tmp_path):
        """Test parsing an invalid file."""
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"This is not DICOM data")

        parser = PydicomParser()
        result = parser.parse(invalid_file)

        # pydicom with force=True may still succeed on some invalid files
        # but should return some result
        assert result.implementation == ImplementationType.PYDICOM


class TestGDCMParser:
    """Test GDCMParser class."""

    def test_implementation_type(self):
        """Test implementation type is correct."""
        parser = GDCMParser()
        assert parser.implementation_type == ImplementationType.GDCM

    def test_is_available_without_gdcm(self):
        """Test is_available returns False when GDCM not installed."""
        parser = GDCMParser()
        # GDCM may or may not be installed
        result = parser.is_available()
        assert isinstance(result, bool)


class TestDCMTKParser:
    """Test DCMTKParser class."""

    def test_implementation_type(self):
        """Test implementation type is correct."""
        parser = DCMTKParser()
        assert parser.implementation_type == ImplementationType.DCMTK

    def test_custom_dcmdump_path(self):
        """Test custom dcmdump path."""
        parser = DCMTKParser(dcmdump_path="/custom/path/dcmdump")
        assert parser.dcmdump_path == "/custom/path/dcmdump"

    def test_is_available_not_found(self):
        """Test is_available returns False when dcmdump not found."""
        parser = DCMTKParser(dcmdump_path="/nonexistent/dcmdump")
        assert parser.is_available() is False

    @patch("subprocess.run")
    def test_is_available_with_dcmdump(self, mock_run):
        """Test is_available when dcmdump is found."""
        mock_run.return_value = Mock(returncode=0)

        parser = DCMTKParser()
        result = parser.is_available()

        assert result is True

    @patch("subprocess.run")
    def test_parse_success(self, mock_run):
        """Test parsing with dcmdump."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="(0010,0010) PN Test^Patient\n(0010,0020) LO 12345\n",
            stderr="",
        )

        parser = DCMTKParser()
        result = parser.parse("/test/file.dcm")

        assert result.success is True
        assert "(0010,0010)" in result.tags_found

    @patch("subprocess.run")
    def test_parse_failure(self, mock_run):
        """Test parsing failure with dcmdump."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error reading file",
        )

        parser = DCMTKParser()
        result = parser.parse("/test/file.dcm")

        assert result.success is False
        assert "Error" in result.error_message or "ExitCode" in result.error_type

    @patch("subprocess.run")
    def test_parse_timeout(self, mock_run):
        """Test parsing timeout with dcmdump."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("dcmdump", 30)

        parser = DCMTKParser()
        result = parser.parse("/test/file.dcm")

        assert result.success is False
        assert result.error_type == "TimeoutError"


# ============================================================================
# Test DifferentialAnalyzer
# ============================================================================


class TestDifferentialAnalyzer:
    """Test DifferentialAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return DifferentialAnalyzer()

    def test_analyze_identical_results(self, analyzer):
        """Test analyzing identical results produces no differences."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={"(0010,0010)": True},
                values={"(0010,0010)": "Test"},
                vr_types={"(0010,0010)": "PN"},
                transfer_syntax="1.2.840.10008.1.2",
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={"(0010,0010)": True},
                values={"(0010,0010)": "Test"},
                vr_types={"(0010,0010)": "PN"},
                transfer_syntax="1.2.840.10008.1.2",
            ),
        }

        differences = analyzer.analyze(results)
        assert len(differences) == 0

    def test_analyze_parse_success_failure(self, analyzer):
        """Test detecting parse success/failure divergence."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=False,
                error_message="Parse error",
            ),
        }

        differences = analyzer.analyze(results)

        assert len(differences) == 1
        assert differences[0].diff_type == DifferenceType.PARSE_SUCCESS_FAILURE

    def test_analyze_tag_presence_difference(self, analyzer):
        """Test detecting tag presence differences."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={"(0010,0010)": True, "(0010,0020)": True},
                values={"(0010,0010)": "Test", "(0010,0020)": "123"},
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={"(0010,0010)": True},
                values={"(0010,0010)": "Test"},
            ),
        }

        differences = analyzer.analyze(results)

        tag_diff = [
            d for d in differences if d.diff_type == DifferenceType.TAG_PRESENCE
        ]
        assert len(tag_diff) == 1
        assert "(0010,0020)" in tag_diff[0].description

    def test_analyze_value_mismatch(self, analyzer):
        """Test detecting value mismatches."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={"(0010,0010)": True},
                values={"(0010,0010)": "Patient A"},
                vr_types={"(0010,0010)": "PN"},
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={"(0010,0010)": True},
                values={"(0010,0010)": "Patient B"},
                vr_types={"(0010,0010)": "PN"},
            ),
        }

        differences = analyzer.analyze(results)

        value_diff = [
            d for d in differences if d.diff_type == DifferenceType.VALUE_MISMATCH
        ]
        assert len(value_diff) == 1
        assert value_diff[0].value_a == "Patient A"
        assert value_diff[0].value_b == "Patient B"

    def test_analyze_vr_mismatch(self, analyzer):
        """Test detecting VR mismatches."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={"(0008,0005)": True},
                values={"(0008,0005)": "ISO_IR 100"},
                vr_types={"(0008,0005)": "CS"},
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={"(0008,0005)": True},
                values={"(0008,0005)": "ISO_IR 100"},
                vr_types={"(0008,0005)": "LO"},
            ),
        }

        differences = analyzer.analyze(results)

        vr_diff = [d for d in differences if d.diff_type == DifferenceType.VR_MISMATCH]
        assert len(vr_diff) == 1

    def test_analyze_transfer_syntax_difference(self, analyzer):
        """Test detecting transfer syntax differences."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={},
                values={},
                transfer_syntax="1.2.840.10008.1.2",
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={},
                values={},
                transfer_syntax="1.2.840.10008.1.2.1",
            ),
        }

        differences = analyzer.analyze(results)

        enc_diff = [
            d for d in differences if d.diff_type == DifferenceType.ENCODING_DIFFERENCE
        ]
        assert len(enc_diff) == 1

    def test_security_critical_tag_high_severity(self, analyzer):
        """Test that differences in security-critical tags have high severity."""
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
                tags_found={"(0010,0010)": True},  # Patient Name - security critical
                values={"(0010,0010)": "Patient"},
            ),
            ImplementationType.GDCM: ParseResult(
                implementation=ImplementationType.GDCM,
                success=True,
                tags_found={},
                values={},
            ),
        }

        differences = analyzer.analyze(results)

        assert len(differences) == 1
        assert differences[0].severity == BugSeverity.HIGH


# ============================================================================
# Test DifferentialFuzzerConfig
# ============================================================================


class TestDifferentialFuzzerConfig:
    """Test DifferentialFuzzerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = DifferentialFuzzerConfig()

        assert config.output_dir == Path("diff_fuzzer_output")
        assert config.max_iterations == 10000
        assert config.timeout_per_test == 30.0
        assert config.save_interesting is True
        assert config.save_all_differences is False
        assert config.min_severity == BugSeverity.LOW

    def test_custom_values(self):
        """Test custom configuration."""
        config = DifferentialFuzzerConfig(
            output_dir=Path("/custom/output"),
            max_iterations=1000,
            min_severity=BugSeverity.HIGH,
        )

        assert config.output_dir == Path("/custom/output")
        assert config.max_iterations == 1000
        assert config.min_severity == BugSeverity.HIGH


# ============================================================================
# Test DifferentialFuzzer
# ============================================================================


class TestDifferentialFuzzer:
    """Test DifferentialFuzzer class."""

    @pytest.fixture
    def tmp_output(self, tmp_path):
        """Create temporary output directory."""
        return tmp_path / "diff_output"

    @pytest.fixture
    def fuzzer(self, tmp_output):
        """Create fuzzer with default config."""
        config = DifferentialFuzzerConfig(output_dir=tmp_output)
        return DifferentialFuzzer(config)

    def test_initialization(self, fuzzer, tmp_output):
        """Test fuzzer initialization."""
        assert tmp_output.exists()
        assert fuzzer.analyzer is not None
        assert fuzzer.total_tests == 0

    def test_parsers_initialized(self, fuzzer):
        """Test parsers are initialized."""
        # At minimum, pydicom should be available
        assert len(fuzzer.parsers) >= 1

        pydicom_parsers = [
            p
            for p in fuzzer.parsers
            if p.implementation_type == ImplementationType.PYDICOM
        ]
        assert len(pydicom_parsers) == 1

    def test_add_parser(self, fuzzer):
        """Test adding custom parser."""
        mock_parser = Mock()
        mock_parser.is_available.return_value = True
        mock_parser.implementation_type = ImplementationType.CUSTOM

        initial_count = len(fuzzer.parsers)
        fuzzer.add_parser(mock_parser)

        assert len(fuzzer.parsers) == initial_count + 1

    def test_add_unavailable_parser(self, fuzzer):
        """Test adding unavailable parser is skipped."""
        mock_parser = Mock()
        mock_parser.is_available.return_value = False

        initial_count = len(fuzzer.parsers)
        fuzzer.add_parser(mock_parser)

        assert len(fuzzer.parsers) == initial_count

    def test_test_file(self, fuzzer, tmp_path):
        """Test testing a single file."""
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian

        # Create test DICOM file
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"

        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = pydicom.uid.generate_uid()
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        dcm_path = tmp_path / "test.dcm"
        ds.save_as(dcm_path)

        result = fuzzer.test_file(dcm_path)

        assert result.input_hash != ""
        assert result.input_path == str(dcm_path)
        assert len(result.results) >= 1  # At least pydicom result

    def test_severity_counts_initialized(self, fuzzer):
        """Test severity counts are initialized."""
        for severity in BugSeverity:
            assert severity in fuzzer.severity_counts
            assert fuzzer.severity_counts[severity] == 0


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_single_implementation(self):
        """Test analyzer with single implementation."""
        analyzer = DifferentialAnalyzer()
        results = {
            ImplementationType.PYDICOM: ParseResult(
                implementation=ImplementationType.PYDICOM,
                success=True,
            ),
        }

        differences = analyzer.analyze(results)
        # No differences with only one implementation
        assert len(differences) == 0

    def test_analyze_empty_results(self):
        """Test analyzer with empty results."""
        analyzer = DifferentialAnalyzer()
        differences = analyzer.analyze({})
        assert len(differences) == 0

    def test_parse_result_with_all_fields(self):
        """Test ParseResult with all fields populated."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
            error_message="",
            error_type="",
            parse_time_ms=123.45,
            memory_usage_mb=10.5,
            tags_found={"(0010,0010)": True},
            values={"(0010,0010)": "Test"},
            vr_types={"(0010,0010)": "PN"},
            sequence_depths={"(0008,1115)": 2},
            file_meta={"version": "1.0"},
            transfer_syntax="1.2.840.10008.1.2",
            sop_class="1.2.840.10008.5.1.4.1.1.2",
        )

        assert result.parse_time_ms == 123.45
        assert result.memory_usage_mb == 10.5
        assert result.sop_class == "1.2.840.10008.5.1.4.1.1.2"

    def test_difference_with_all_fields(self):
        """Test Difference with all fields populated."""
        diff = Difference(
            diff_type=DifferenceType.VALUE_MISMATCH,
            description="Test mismatch",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.GDCM,
            tag="(0010,0010)",
            value_a="Value A",
            value_b="Value B",
            severity=BugSeverity.CRITICAL,
        )

        d = diff.to_dict()
        assert d["type"] == "value_mismatch"
        assert d["severity"] == "critical"

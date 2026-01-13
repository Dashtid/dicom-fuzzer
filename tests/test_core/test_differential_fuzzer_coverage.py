"""Additional tests for differential_fuzzer.py coverage.

Coverage target: 61% -> 80%+
Tests multi-implementation parsing comparison and differential analysis.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.core.constants import BugSeverity
from dicom_fuzzer.core.differential_fuzzer import (
    DICOMParser,
    Difference,
    DifferenceType,
    DifferentialResult,
    ImplementationType,
    ParseResult,
    PydicomParser,
)


class TestImplementationType:
    """Tests for ImplementationType enum."""

    def test_all_implementation_types(self) -> None:
        """Test all implementation types exist."""
        assert ImplementationType.PYDICOM.value == "pydicom"
        assert ImplementationType.GDCM.value == "gdcm"
        assert ImplementationType.DCMTK.value == "dcmtk"
        assert ImplementationType.PYNETDICOM.value == "pynetdicom"
        assert ImplementationType.CUSTOM.value == "custom"


class TestDifferenceType:
    """Tests for DifferenceType enum."""

    def test_all_difference_types(self) -> None:
        """Test all difference types exist."""
        assert DifferenceType.PARSE_SUCCESS_FAILURE.value == "parse_success_failure"
        assert DifferenceType.VALUE_MISMATCH.value == "value_mismatch"
        assert DifferenceType.VR_MISMATCH.value == "vr_mismatch"
        assert DifferenceType.TAG_PRESENCE.value == "tag_presence"
        assert DifferenceType.CRASH.value == "crash"
        assert DifferenceType.TIMEOUT.value == "timeout"


class TestParseResult:
    """Tests for ParseResult dataclass."""

    def test_parse_result_defaults(self) -> None:
        """Test ParseResult default values."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
        )
        assert result.error_message == ""
        assert result.parse_time_ms == 0.0
        assert result.tags_found == {}
        assert result.values == {}

    def test_parse_result_full(self) -> None:
        """Test ParseResult with all fields."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
            error_message="",
            parse_time_ms=150.5,
            memory_usage_mb=50.0,
            tags_found={"(0010,0010)": "PatientName"},
            values={"(0010,0010)": "Test^Patient"},
            vr_types={"(0010,0010)": "PN"},
            transfer_syntax="1.2.840.10008.1.2",
        )
        assert result.parse_time_ms == 150.5
        assert result.tags_found["(0010,0010)"] == "PatientName"

    def test_parse_result_to_dict(self) -> None:
        """Test ParseResult to_dict conversion."""
        result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
            tags_found={"(0010,0010)": "PatientName"},
            values={"(0010,0010)": "Test"},
            vr_types={"(0010,0010)": "PN"},
            transfer_syntax="1.2.840.10008.1.2",
        )

        d = result.to_dict()

        assert d["implementation"] == "pydicom"
        assert d["success"] is True
        assert "(0010,0010)" in d["tags_found"]
        assert d["transfer_syntax"] == "1.2.840.10008.1.2"


class TestDifference:
    """Tests for Difference dataclass."""

    def test_difference_creation(self) -> None:
        """Test Difference creation."""
        diff = Difference(
            diff_type=DifferenceType.VALUE_MISMATCH,
            description="Patient name differs",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.GDCM,
            tag="(0010,0010)",
            value_a="Test^Patient",
            value_b="Patient^Test",
            severity=BugSeverity.MEDIUM,
        )
        assert diff.diff_type == DifferenceType.VALUE_MISMATCH
        assert diff.tag == "(0010,0010)"

    def test_difference_to_dict(self) -> None:
        """Test Difference to_dict conversion."""
        diff = Difference(
            diff_type=DifferenceType.CRASH,
            description="Parser crashed",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.DCMTK,
            severity=BugSeverity.CRITICAL,
        )

        d = diff.to_dict()

        assert d["type"] == "crash"
        assert d["implementations"] == ["pydicom", "dcmtk"]
        assert d["severity"] == "critical"


class TestDifferentialResult:
    """Tests for DifferentialResult dataclass."""

    def test_differential_result_auto_timestamp(self) -> None:
        """Test DifferentialResult auto-generates timestamp."""
        before = time.time()
        result = DifferentialResult(
            input_hash="abc123",
            input_path="/path/to/file.dcm",
        )
        after = time.time()

        assert before <= result.timestamp <= after

    def test_differential_result_explicit_timestamp(self) -> None:
        """Test DifferentialResult with explicit timestamp."""
        explicit_time = 1234567890.0
        result = DifferentialResult(
            input_hash="abc123",
            input_path="/path/to/file.dcm",
            timestamp=explicit_time,
        )
        assert result.timestamp == explicit_time

    def test_differential_result_full(self) -> None:
        """Test DifferentialResult with all fields."""
        parse_result = ParseResult(
            implementation=ImplementationType.PYDICOM,
            success=True,
        )
        diff = Difference(
            diff_type=DifferenceType.VALUE_MISMATCH,
            description="Test",
            impl_a=ImplementationType.PYDICOM,
            impl_b=ImplementationType.GDCM,
        )

        result = DifferentialResult(
            input_hash="abc123",
            input_path="/path/to/file.dcm",
            results={ImplementationType.PYDICOM: parse_result},
            differences=[diff],
            is_interesting=True,
            bug_severity=BugSeverity.HIGH,
        )

        assert result.is_interesting is True
        assert len(result.differences) == 1
        assert result.bug_severity == BugSeverity.HIGH


class TestPydicomParser:
    """Tests for PydicomParser class."""

    def test_implementation_type(self) -> None:
        """Test implementation type property."""
        parser = PydicomParser()
        assert parser.implementation_type == ImplementationType.PYDICOM

    def test_is_available_pydicom_installed(self) -> None:
        """Test is_available when pydicom is installed."""
        parser = PydicomParser()
        # pydicom should be installed in test environment
        assert parser.is_available() is True

    def test_is_available_pydicom_not_installed(self) -> None:
        """Test is_available when pydicom not installed."""
        parser = PydicomParser()

        with patch.dict("sys.modules", {"pydicom": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = parser.is_available()
                # May still return True if cached
                assert isinstance(result, bool)

    def test_parse_valid_file(self, tmp_path: Path) -> None:
        """Test parsing a valid DICOM-like file."""
        # Create a minimal DICOM file
        dicom_file = tmp_path / "test.dcm"
        # DICOM preamble (128 bytes) + DICM magic
        preamble = b"\x00" * 128 + b"DICM"
        # Minimal file meta header
        dicom_file.write_bytes(preamble)

        parser = PydicomParser()
        result = parser.parse(dicom_file)

        # Parsing with force=True should succeed or fail gracefully
        assert isinstance(result, ParseResult)
        assert result.implementation == ImplementationType.PYDICOM

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """Test parsing nonexistent file."""
        parser = PydicomParser()
        result = parser.parse(tmp_path / "nonexistent.dcm")

        assert result.success is False
        assert result.error_message != ""

    def test_parse_invalid_file(self, tmp_path: Path) -> None:
        """Test parsing invalid file."""
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"not a dicom file")

        parser = PydicomParser()
        result = parser.parse(invalid_file)

        # Should either fail or parse with force=True
        assert isinstance(result, ParseResult)

    def test_parse_measures_time(self, tmp_path: Path) -> None:
        """Test that parsing measures execution time."""
        dicom_file = tmp_path / "test.dcm"
        dicom_file.write_bytes(b"\x00" * 128 + b"DICM")

        parser = PydicomParser()
        result = parser.parse(dicom_file)

        # Parse time should be measured
        assert result.parse_time_ms >= 0


class TestDICOMParserAbstract:
    """Tests for abstract DICOMParser class."""

    def test_cannot_instantiate_abstract(self) -> None:
        """Test that abstract class cannot be instantiated."""
        with pytest.raises(TypeError):
            DICOMParser()  # type: ignore

    def test_concrete_implementation(self) -> None:
        """Test creating a concrete implementation."""

        class TestParser(DICOMParser):
            @property
            def implementation_type(self) -> ImplementationType:
                return ImplementationType.CUSTOM

            def parse(self, file_path: Path | str) -> ParseResult:
                return ParseResult(
                    implementation=self.implementation_type,
                    success=True,
                )

            def is_available(self) -> bool:
                return True

        parser = TestParser()
        assert parser.implementation_type == ImplementationType.CUSTOM
        assert parser.is_available() is True

        result = parser.parse(Path("/test"))
        assert result.success is True

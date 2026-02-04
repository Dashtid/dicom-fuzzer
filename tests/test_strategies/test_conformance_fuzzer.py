"""Tests for conformance_fuzzer.py - DICOM Conformance and Interoperability Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.conformance_fuzzer import (
    ConformanceFuzzer,
    SOP_CLASSES,
    TRANSFER_SYNTAXES,
)


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> ConformanceFuzzer:
    """Create a ConformanceFuzzer instance."""
    return ConformanceFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with file_meta."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    ds.SOPClassUID = SOP_CLASSES["CT"]
    ds.SOPInstanceUID = generate_uid()

    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = SOP_CLASSES["CT"]
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    return ds


# =============================================================================
# ConformanceFuzzer Initialization Tests
# =============================================================================
class TestConformanceFuzzerInit:
    """Tests for ConformanceFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: ConformanceFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 10

    def test_all_strategies_callable(self, fuzzer: ConformanceFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate_conformance Tests
# =============================================================================
class TestMutateConformance:
    """Tests for mutate_conformance method."""

    def test_returns_dataset(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate_conformance returns a Dataset."""
        result = fuzzer.mutate_conformance(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: ConformanceFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate_conformance(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_sop_class Tests
# =============================================================================
class TestInvalidSopClass:
    """Tests for _invalid_sop_class method."""

    def test_completely_invalid_uid(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test completely invalid SOP Class UID."""
        with patch.object(random, "choice", side_effect=["completely_invalid", ""]):
            result = fuzzer._invalid_sop_class(sample_dataset)
        assert isinstance(result, Dataset)

    def test_unknown_but_valid_format(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test unknown but valid format SOP Class UID."""
        with patch.object(random, "choice", return_value="unknown_but_valid_format"):
            result = fuzzer._invalid_sop_class(sample_dataset)
        assert isinstance(result, Dataset)

    def test_retired_sop_class(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test retired SOP Class UID."""
        with patch.object(random, "choice", side_effect=[
            "retired_sop_class",
            "1.2.840.10008.5.1.4.1.1.5"
        ]):
            result = fuzzer._invalid_sop_class(sample_dataset)
        assert isinstance(result, Dataset)

    def test_private_sop_class(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test private SOP Class UID."""
        with patch.object(random, "choice", return_value="private_sop_class"):
            result = fuzzer._invalid_sop_class(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_transfer_syntax Tests
# =============================================================================
class TestInvalidTransferSyntax:
    """Tests for _invalid_transfer_syntax method."""

    def test_completely_invalid_ts(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test completely invalid Transfer Syntax UID."""
        with patch.object(random, "choice", side_effect=["completely_invalid", ""]):
            result = fuzzer._invalid_transfer_syntax(sample_dataset)
        assert isinstance(result, Dataset)

    def test_unknown_syntax(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test unknown Transfer Syntax UID."""
        with patch.object(random, "choice", return_value="unknown_syntax"):
            result = fuzzer._invalid_transfer_syntax(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _sop_transfer_mismatch Tests
# =============================================================================
class TestSopTransferMismatch:
    """Tests for _sop_transfer_mismatch method."""

    def test_creates_mismatch(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test creation of SOP/Transfer Syntax mismatch."""
        result = fuzzer._sop_transfer_mismatch(sample_dataset)
        assert isinstance(result, Dataset)
        assert hasattr(result, "file_meta")


# =============================================================================
# _missing_file_meta Tests
# =============================================================================
class TestMissingFileMeta:
    """Tests for _missing_file_meta method."""

    def test_remove_all(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test removal of all file_meta."""
        with patch.object(random, "choice", return_value="remove_all"):
            result = fuzzer._missing_file_meta(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.file_meta is None

    def test_remove_sop_class(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test removal of MediaStorageSOPClassUID."""
        with patch.object(random, "choice", return_value="remove_sop_class"):
            result = fuzzer._missing_file_meta(sample_dataset)
        assert isinstance(result, Dataset)

    def test_remove_transfer_syntax(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test removal of TransferSyntaxUID."""
        with patch.object(random, "choice", return_value="remove_transfer_syntax"):
            result = fuzzer._missing_file_meta(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _corrupted_file_meta Tests
# =============================================================================
class TestCorruptedFileMeta:
    """Tests for _corrupted_file_meta method."""

    def test_wrong_preamble(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test wrong preamble attack."""
        with patch.object(random, "choice", return_value="wrong_preamble"):
            result = fuzzer._corrupted_file_meta(sample_dataset)
        assert isinstance(result, Dataset)
        assert result.preamble == b"\xFF" * 128

    def test_wrong_version(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test wrong version attack."""
        with patch.object(random, "choice", return_value="wrong_version"):
            result = fuzzer._corrupted_file_meta(sample_dataset)
        assert isinstance(result, Dataset)

    def test_extra_meta_elements(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test extra meta elements attack."""
        with patch.object(random, "choice", return_value="extra_meta_elements"):
            result = fuzzer._corrupted_file_meta(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _version_mismatch Tests
# =============================================================================
class TestVersionMismatch:
    """Tests for _version_mismatch method."""

    def test_old_version(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test old version attack."""
        with patch.object(random, "choice", return_value="old_version"):
            result = fuzzer._version_mismatch(sample_dataset)
        assert isinstance(result, Dataset)

    def test_future_version(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test future version attack."""
        with patch.object(random, "choice", return_value="future_version"):
            result = fuzzer._version_mismatch(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _implementation_uid_attack Tests
# =============================================================================
class TestImplementationUidAttack:
    """Tests for _implementation_uid_attack method."""

    def test_known_vulnerable(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test known vulnerable implementation attack."""
        with patch.object(random, "choice", side_effect=[
            "known_vulnerable",
            ("1.2.276.0.7230010.3.0.3.6.0", "OFFIS_DCMTK_360")
        ]):
            result = fuzzer._implementation_uid_attack(sample_dataset)
        assert isinstance(result, Dataset)

    def test_invalid_format(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test invalid format implementation UID."""
        with patch.object(random, "choice", side_effect=["invalid_format", ""]):
            result = fuzzer._implementation_uid_attack(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _modality_sop_mismatch Tests
# =============================================================================
class TestModalitySopMismatch:
    """Tests for _modality_sop_mismatch method."""

    def test_creates_mismatch(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test creation of Modality/SOP mismatch."""
        result = fuzzer._modality_sop_mismatch(sample_dataset)
        assert isinstance(result, Dataset)
        # Modality should not match SOP Class
        assert hasattr(result, "Modality")


# =============================================================================
# _uid_format_violations Tests
# =============================================================================
class TestUidFormatViolations:
    """Tests for _uid_format_violations method."""

    def test_too_long_uid(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test too long UID attack."""
        with patch.object(random, "choice", side_effect=[
            "too_long_uid",
            (Tag(0x0008, 0x0016), "SOPClassUID")
        ]):
            result = fuzzer._uid_format_violations(sample_dataset)
        assert isinstance(result, Dataset)

    def test_non_numeric_component(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test non-numeric component in UID."""
        with patch.object(random, "choice", side_effect=[
            "non_numeric_component",
            (Tag(0x0008, 0x0018), "SOPInstanceUID")
        ]):
            result = fuzzer._uid_format_violations(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _retired_syntax_attack Tests
# =============================================================================
class TestRetiredSyntaxAttack:
    """Tests for _retired_syntax_attack method."""

    def test_retired_transfer_syntax(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test retired transfer syntax attack."""
        with patch.object(random, "choice", side_effect=[
            "retired_transfer_syntax",
            "1.2.840.10008.1.2.4.52"
        ]):
            result = fuzzer._retired_syntax_attack(sample_dataset)
        assert isinstance(result, Dataset)

    def test_explicit_vr_big_endian(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test explicit VR big endian attack."""
        with patch.object(random, "choice", return_value="explicit_vr_big_endian"):
            result = fuzzer._retired_syntax_attack(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# Integration Tests
# =============================================================================
class TestConformanceFuzzerIntegration:
    """Integration tests for ConformanceFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: ConformanceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate_conformance(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations(
        self, fuzzer: ConformanceFuzzer
    ) -> None:
        """Test multiple mutations in sequence."""
        for i in range(5):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Test"
            result = fuzzer.mutate_conformance(ds)
            assert isinstance(result, Dataset)

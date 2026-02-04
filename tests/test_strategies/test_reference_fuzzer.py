"""Tests for reference_fuzzer.py - DICOM Reference and Link Integrity Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.reference_fuzzer import ReferenceFuzzer


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> ReferenceFuzzer:
    """Create a ReferenceFuzzer instance."""
    return ReferenceFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with UIDs."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.SOPInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.FrameOfReferenceUID = generate_uid()
    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    return ds


# =============================================================================
# ReferenceFuzzer Initialization Tests
# =============================================================================
class TestReferenceFuzzerInit:
    """Tests for ReferenceFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: ReferenceFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 10

    def test_all_strategies_callable(self, fuzzer: ReferenceFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate_references Tests
# =============================================================================
class TestMutateReferences:
    """Tests for mutate_references method."""

    def test_returns_dataset(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate_references returns a Dataset."""
        result = fuzzer.mutate_references(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: ReferenceFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate_references(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _orphan_reference Tests
# =============================================================================
class TestOrphanReference:
    """Tests for _orphan_reference method."""

    def test_nonexistent_sop_instance(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test nonexistent SOP instance reference."""
        with patch.object(random, "choice", return_value="nonexistent_sop_instance"):
            result = fuzzer._orphan_reference(minimal_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1140) in result

    def test_nonexistent_series(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test nonexistent series reference."""
        with patch.object(random, "choice", return_value="nonexistent_series"):
            result = fuzzer._orphan_reference(minimal_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1115) in result

    def test_nonexistent_study(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test nonexistent study reference."""
        with patch.object(random, "choice", return_value="nonexistent_study"):
            result = fuzzer._orphan_reference(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_nonexistent_frame_of_reference(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test nonexistent frame of reference."""
        with patch.object(random, "choice", return_value="nonexistent_frame_of_reference"):
            result = fuzzer._orphan_reference(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.FrameOfReferenceUID == "1.2.3.4.5.6.7.8.9.NOFRAME"


# =============================================================================
# _circular_reference Tests
# =============================================================================
class TestCircularReference:
    """Tests for _circular_reference method."""

    def test_direct_self_ref(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test direct self-reference."""
        with patch.object(random, "choice", return_value="direct_self_ref"):
            result = fuzzer._circular_reference(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1140) in result

    def test_two_hop_cycle(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test two-hop cycle reference."""
        with patch.object(random, "choice", return_value="two_hop_cycle"):
            result = fuzzer._circular_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_reference_chain_to_self(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test long reference chain to self."""
        with patch.object(random, "choice", return_value="reference_chain_to_self"):
            result = fuzzer._circular_reference(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _self_reference Tests
# =============================================================================
class TestSelfReference:
    """Tests for _self_reference method."""

    def test_study_refs_self(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test study referencing itself."""
        with patch.object(random, "choice", return_value="study_refs_self"):
            result = fuzzer._self_reference(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1110) in result

    def test_series_refs_self(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test series referencing itself."""
        with patch.object(random, "choice", return_value="series_refs_self"):
            result = fuzzer._self_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_source_image_is_self(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test source image is self."""
        with patch.object(random, "choice", return_value="source_image_is_self"):
            result = fuzzer._self_reference(sample_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x2112) in result


# =============================================================================
# _invalid_frame_reference Tests
# =============================================================================
class TestInvalidFrameReference:
    """Tests for _invalid_frame_reference method."""

    def test_frame_beyond_count(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test reference to frame beyond count."""
        with patch.object(random, "choice", return_value="frame_beyond_count"):
            result = fuzzer._invalid_frame_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_negative_frame(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test negative frame number."""
        with patch.object(random, "choice", return_value="negative_frame"):
            result = fuzzer._invalid_frame_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_zero_frame(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test zero frame number."""
        with patch.object(random, "choice", return_value="zero_frame"):
            result = fuzzer._invalid_frame_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_massive_frame_number(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test massive frame number."""
        with patch.object(random, "choice", return_value="massive_frame_number"):
            result = fuzzer._invalid_frame_reference(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _mismatched_study_reference Tests
# =============================================================================
class TestMismatchedStudyReference:
    """Tests for _mismatched_study_reference method."""

    def test_series_different_study(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test series with different study UID."""
        with patch.object(random, "choice", return_value="series_different_study"):
            result = fuzzer._mismatched_study_reference(sample_dataset)
        assert isinstance(result, Dataset)

    def test_instance_different_series(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test instance with different series UID."""
        with patch.object(random, "choice", return_value="instance_different_series"):
            result = fuzzer._mismatched_study_reference(sample_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _broken_series_reference Tests
# =============================================================================
class TestBrokenSeriesReference:
    """Tests for _broken_series_reference method."""

    def test_creates_broken_references(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of broken series references."""
        result = fuzzer._broken_series_reference(minimal_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1115) in result


# =============================================================================
# _frame_of_reference_attack Tests
# =============================================================================
class TestFrameOfReferenceAttack:
    """Tests for _frame_of_reference_attack method."""

    def test_conflicting_for(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test conflicting Frame of Reference."""
        with patch.object(random, "choice", return_value="conflicting_for"):
            result = fuzzer._frame_of_reference_attack(sample_dataset)
        assert isinstance(result, Dataset)

    def test_missing_for_with_position(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test missing FoR with position data."""
        with patch.object(random, "choice", return_value="missing_for_with_position"):
            result = fuzzer._frame_of_reference_attack(sample_dataset)
        assert isinstance(result, Dataset)
        assert not hasattr(result, "FrameOfReferenceUID")


# =============================================================================
# _duplicate_references Tests
# =============================================================================
class TestDuplicateReferences:
    """Tests for _duplicate_references method."""

    def test_creates_duplicates(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of duplicate references."""
        result = fuzzer._duplicate_references(minimal_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1140) in result
        # Should have 10 identical items
        assert len(result[Tag(0x0008, 0x1140)].value) == 10


# =============================================================================
# _massive_reference_chain Tests
# =============================================================================
class TestMassiveReferenceChain:
    """Tests for _massive_reference_chain method."""

    def test_creates_long_chain(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of long reference chain."""
        with patch.object(random, "choice", return_value=50):  # Shorter for test
            result = fuzzer._massive_reference_chain(minimal_dataset)
        assert isinstance(result, Dataset)
        assert Tag(0x0008, 0x1140) in result


# =============================================================================
# _reference_type_mismatch Tests
# =============================================================================
class TestReferenceTypeMismatch:
    """Tests for _reference_type_mismatch method."""

    def test_creates_type_mismatch(
        self, fuzzer: ReferenceFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test creation of reference type mismatch."""
        result = fuzzer._reference_type_mismatch(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.Modality == "CT"
        assert Tag(0x0008, 0x1140) in result


# =============================================================================
# Integration Tests
# =============================================================================
class TestReferenceFuzzerIntegration:
    """Integration tests for ReferenceFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate_references(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations(
        self, fuzzer: ReferenceFuzzer
    ) -> None:
        """Test multiple mutations in sequence."""
        for i in range(5):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Test"
            result = fuzzer.mutate_references(ds)
            assert isinstance(result, Dataset)

    def test_preserves_patient_data(
        self, fuzzer: ReferenceFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that patient data is preserved."""
        original_name = sample_dataset.PatientName
        random.seed(42)
        result = fuzzer.mutate_references(sample_dataset)
        assert result.PatientName == original_name

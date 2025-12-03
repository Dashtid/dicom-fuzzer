"""Tests for grammar_fuzzer module to improve code coverage.

These tests exercise the grammar-based fuzzing code paths.
"""

import warnings

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.grammar_fuzzer import DicomGrammarRule, GrammarFuzzer


@pytest.fixture
def fuzzer():
    """Create GrammarFuzzer instance."""
    return GrammarFuzzer()


@pytest.fixture
def sample_dataset():
    """Create sample DICOM dataset for testing."""
    ds = Dataset()

    # File meta
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    # Patient info
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.PatientBirthDate = "19900101"
    ds.PatientSex = "O"
    ds.PatientAge = "035Y"

    # Study info
    ds.StudyInstanceUID = "1.2.3.4.5.6.7"
    ds.StudyDate = "20250101"
    ds.StudyTime = "120000"
    ds.StudyID = "STUDY001"
    ds.StudyDescription = "Test Study"

    # Series info
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8"
    ds.SeriesNumber = "1"
    ds.Modality = "CT"
    ds.SeriesDescription = "Test Series"

    # Image info
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.InstanceNumber = "1"
    ds.ImageType = ["ORIGINAL", "PRIMARY"]

    # Pixel info
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    # CT-specific
    ds.SliceThickness = "1.0"
    ds.KVP = "120"
    ds.DataCollectionDiameter = "500"

    return ds


class TestDicomGrammarRule:
    """Test DicomGrammarRule class."""

    def test_rule_creation(self):
        """Test creating a grammar rule."""
        rule = DicomGrammarRule(
            rule_name="test_rule",
            tags_involved=["Tag1", "Tag2"],
            rule_type="required",
            description="Test description",
        )

        assert rule.rule_name == "test_rule"
        assert rule.tags_involved == ["Tag1", "Tag2"]
        assert rule.rule_type == "required"
        assert rule.description == "Test description"

    def test_rule_with_empty_tags(self):
        """Test creating rule with empty tags list."""
        rule = DicomGrammarRule(
            rule_name="empty_tags",
            tags_involved=[],
            rule_type="conditional",
            description="Empty tags rule",
        )

        assert rule.tags_involved == []

    def test_rule_with_many_tags(self):
        """Test creating rule with many tags."""
        tags = [f"Tag{i}" for i in range(20)]
        rule = DicomGrammarRule(
            rule_name="many_tags",
            tags_involved=tags,
            rule_type="required",
            description="Many tags rule",
        )

        assert len(rule.tags_involved) == 20


class TestGrammarFuzzerInit:
    """Test GrammarFuzzer initialization."""

    def test_init_loads_rules(self, fuzzer):
        """Test that initialization loads rules."""
        assert len(fuzzer.rules) > 0

    def test_init_loads_sop_class_requirements(self, fuzzer):
        """Test that initialization loads SOP class requirements."""
        assert len(fuzzer.sop_class_requirements) > 0

    def test_rules_have_correct_structure(self, fuzzer):
        """Test that loaded rules have correct structure."""
        for rule in fuzzer.rules:
            assert isinstance(rule, DicomGrammarRule)
            assert rule.rule_name
            assert isinstance(rule.tags_involved, list)
            assert rule.rule_type in ["required", "conditional", "range"]
            assert rule.description


class TestLoadDicomRules:
    """Test _load_dicom_rules method."""

    def test_load_rules_returns_list(self, fuzzer):
        """Test that rules are returned as a list."""
        rules = fuzzer._load_dicom_rules()
        assert isinstance(rules, list)

    def test_rules_contain_patient_required(self, fuzzer):
        """Test that patient required rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "patient_required" in rule_names

    def test_rules_contain_study_required(self, fuzzer):
        """Test that study required rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "study_required" in rule_names

    def test_rules_contain_series_required(self, fuzzer):
        """Test that series required rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "series_required" in rule_names

    def test_rules_contain_image_required(self, fuzzer):
        """Test that image required rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "image_required" in rule_names

    def test_rules_contain_pixel_dependencies(self, fuzzer):
        """Test that pixel dependencies rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "pixel_dependencies" in rule_names

    def test_rules_contain_ct_specific(self, fuzzer):
        """Test that CT specific rule exists."""
        rules = fuzzer._load_dicom_rules()
        rule_names = [r.rule_name for r in rules]
        assert "ct_specific" in rule_names


class TestLoadSopClassRequirements:
    """Test _load_sop_class_requirements method."""

    def test_load_sop_requirements_returns_dict(self, fuzzer):
        """Test that SOP requirements are returned as dict."""
        reqs = fuzzer._load_sop_class_requirements()
        assert isinstance(reqs, dict)

    def test_ct_image_storage_requirements(self, fuzzer):
        """Test CT Image Storage requirements."""
        reqs = fuzzer._load_sop_class_requirements()
        ct_uid = "1.2.840.10008.5.1.4.1.1.2"
        assert ct_uid in reqs
        assert "Modality" in reqs[ct_uid]
        assert "PatientName" in reqs[ct_uid]
        assert "PixelData" in reqs[ct_uid]

    def test_mr_image_storage_requirements(self, fuzzer):
        """Test MR Image Storage requirements."""
        reqs = fuzzer._load_sop_class_requirements()
        mr_uid = "1.2.840.10008.5.1.4.1.1.4"
        assert mr_uid in reqs
        assert "Modality" in reqs[mr_uid]
        assert "ScanningSequence" in reqs[mr_uid]


class TestViolateRequiredTags:
    """Test violate_required_tags method."""

    def test_violate_required_tags_returns_dataset(self, fuzzer, sample_dataset):
        """Test that method returns a dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_required_tags(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_required_tags_multiple_times(self, fuzzer, sample_dataset):
        """Test applying violation multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(10):
                sample_dataset = fuzzer.violate_required_tags(sample_dataset)

        assert isinstance(sample_dataset, Dataset)

    def test_violate_required_tags_empty_dataset(self, fuzzer):
        """Test with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_required_tags(ds)

        assert isinstance(result, Dataset)


class TestViolateConditionalRules:
    """Test violate_conditional_rules method."""

    def test_violate_conditional_returns_dataset(self, fuzzer, sample_dataset):
        """Test that method returns a dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_conditional_with_pixel_data(self, fuzzer, sample_dataset):
        """Test conditional violation with PixelData."""
        assert hasattr(sample_dataset, "PixelData")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        # Some pixel description tag may have been removed
        assert isinstance(result, Dataset)

    def test_violate_conditional_ct_modality(self, fuzzer, sample_dataset):
        """Test conditional violation with CT modality."""
        sample_dataset.Modality = "CT"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_conditional_non_ct_modality(self, fuzzer, sample_dataset):
        """Test conditional violation with non-CT modality."""
        sample_dataset.Modality = "MR"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_conditional_no_pixel_data(self, fuzzer, sample_dataset):
        """Test conditional violation without PixelData."""
        del sample_dataset.PixelData

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_conditional_multiple_times(self, fuzzer, sample_dataset):
        """Test applying violation multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(10):
                sample_dataset = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(sample_dataset, Dataset)


class TestCreateInconsistentState:
    """Test create_inconsistent_state method."""

    def test_inconsistent_state_returns_dataset(self, fuzzer, sample_dataset):
        """Test that method returns a dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        assert isinstance(result, Dataset)

    def test_inconsistent_state_changes_dimensions(self, fuzzer, sample_dataset):
        """Test that dimensions can be changed."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        # Rows and Columns should be set to 1
        if hasattr(result, "Rows"):
            assert result.Rows == 1
        if hasattr(result, "Columns"):
            assert result.Columns == 1

    def test_inconsistent_state_future_date(self, fuzzer, sample_dataset):
        """Test that study date is set to future."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        if hasattr(result, "StudyDate"):
            # Date should be in future
            from datetime import datetime

            current_year = datetime.now().year
            study_year = int(result.StudyDate[:4])
            assert study_year > current_year

    def test_inconsistent_state_negative_series_number(self, fuzzer, sample_dataset):
        """Test that series number is set negative."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        if hasattr(result, "SeriesNumber"):
            assert result.SeriesNumber == -999

    def test_inconsistent_state_patient_age(self, fuzzer, sample_dataset):
        """Test that patient age is set to impossible value."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        if hasattr(result, "PatientAge"):
            assert "999" in str(result.PatientAge)

    def test_inconsistent_state_bits_mismatch(self, fuzzer, sample_dataset):
        """Test bits allocation mismatch."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(sample_dataset)

        if hasattr(result, "BitsAllocated") and hasattr(result, "BitsStored"):
            # Should be inconsistent
            assert result.BitsAllocated == 8
            assert result.BitsStored == 16

    def test_inconsistent_state_empty_dataset(self, fuzzer):
        """Test with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.create_inconsistent_state(ds)

        assert isinstance(result, Dataset)


class TestViolateValueConstraints:
    """Test violate_value_constraints method."""

    def test_violate_constraints_returns_dataset(self, fuzzer, sample_dataset):
        """Test that method returns a dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_value_constraints(sample_dataset)

        assert isinstance(result, Dataset)

    def test_violate_constraints_multiple_times(self, fuzzer, sample_dataset):
        """Test applying violation multiple times."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(10):
                sample_dataset = fuzzer.violate_value_constraints(sample_dataset)

        assert isinstance(sample_dataset, Dataset)

    def test_violate_constraints_empty_dataset(self, fuzzer):
        """Test with empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_value_constraints(ds)

        assert isinstance(result, Dataset)

    def test_violate_constraints_dataset_with_uid(self, fuzzer):
        """Test with dataset containing UIDs."""
        ds = Dataset()
        ds.StudyInstanceUID = "1.2.3.4.5"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_value_constraints(ds)

        assert isinstance(result, Dataset)

    def test_violate_constraints_dataset_with_series_number(self, fuzzer):
        """Test with dataset containing SeriesNumber."""
        ds = Dataset()
        ds.SeriesNumber = "1"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_value_constraints(ds)

        assert isinstance(result, Dataset)

    def test_violate_constraints_dataset_with_slice_thickness(self, fuzzer):
        """Test with dataset containing SliceThickness."""
        ds = Dataset()
        ds.SliceThickness = "1.0"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_value_constraints(ds)

        assert isinstance(result, Dataset)


class TestApplyGrammarBasedMutation:
    """Test apply_grammar_based_mutation method."""

    def test_apply_mutation_returns_dataset(self, fuzzer, sample_dataset):
        """Test that method returns a dataset."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(sample_dataset)

        assert isinstance(result, Dataset)

    def test_apply_mutation_required_tags(self, fuzzer, sample_dataset):
        """Test specific mutation type: required_tags."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="required_tags"
            )

        assert isinstance(result, Dataset)

    def test_apply_mutation_conditional_rules(self, fuzzer, sample_dataset):
        """Test specific mutation type: conditional_rules."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="conditional_rules"
            )

        assert isinstance(result, Dataset)

    def test_apply_mutation_inconsistent_state(self, fuzzer, sample_dataset):
        """Test specific mutation type: inconsistent_state."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="inconsistent_state"
            )

        assert isinstance(result, Dataset)

    def test_apply_mutation_value_constraints(self, fuzzer, sample_dataset):
        """Test specific mutation type: value_constraints."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="value_constraints"
            )

        assert isinstance(result, Dataset)

    def test_apply_mutation_unknown_type(self, fuzzer, sample_dataset):
        """Test with unknown mutation type."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="unknown_type"
            )

        # Should return copy without mutation
        assert isinstance(result, Dataset)

    def test_apply_mutation_random_type(self, fuzzer, sample_dataset):
        """Test with random mutation type (None)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _ in range(20):
                result = fuzzer.apply_grammar_based_mutation(
                    sample_dataset, mutation_type=None
                )
                assert isinstance(result, Dataset)

    def test_apply_mutation_preserves_original(self, fuzzer, sample_dataset):
        """Test that original dataset is not modified."""
        original_patient_name = sample_dataset.PatientName

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fuzzer.apply_grammar_based_mutation(
                sample_dataset, mutation_type="required_tags"
            )

        # Original should be unchanged (copy is mutated)
        assert sample_dataset.PatientName == original_patient_name


class TestGrammarFuzzerEdgeCases:
    """Test edge cases for grammar fuzzer."""

    def test_empty_dataset(self, fuzzer):
        """Test all mutations on empty dataset."""
        ds = Dataset()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fuzzer.violate_required_tags(ds)
            fuzzer.violate_conditional_rules(ds)
            fuzzer.create_inconsistent_state(ds)
            fuzzer.violate_value_constraints(ds)
            result = fuzzer.apply_grammar_based_mutation(ds)

        assert isinstance(result, Dataset)

    def test_minimal_dataset(self, fuzzer):
        """Test all mutations on minimal dataset."""
        ds = Dataset()
        ds.Modality = "CT"
        ds.PatientName = "Test"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fuzzer.violate_required_tags(ds)
            fuzzer.violate_conditional_rules(ds)
            fuzzer.create_inconsistent_state(ds)
            fuzzer.violate_value_constraints(ds)
            result = fuzzer.apply_grammar_based_mutation(ds)

        assert isinstance(result, Dataset)

    def test_dataset_without_ct_tags(self, fuzzer, sample_dataset):
        """Test conditional rules without CT-specific tags."""
        del sample_dataset.SliceThickness
        del sample_dataset.KVP
        del sample_dataset.DataCollectionDiameter

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = fuzzer.violate_conditional_rules(sample_dataset)

        assert isinstance(result, Dataset)

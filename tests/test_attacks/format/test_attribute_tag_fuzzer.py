"""Tests for attribute_tag_fuzzer.py - DICOM AT VR pointer-semantics mutations."""

from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.attacks.format.attribute_tag_fuzzer import (
    _FALLBACK_AT_TAG,
    _NONEXISTENT_TAG,
    _UNDEFINED_PRIVATE_TAG,
    AttributeTagFuzzer,
)


@pytest.fixture
def fuzzer() -> AttributeTagFuzzer:
    return AttributeTagFuzzer()


@pytest.fixture
def dataset_with_at() -> Dataset:
    """Dataset already containing two AT-typed elements."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.add_new(Tag(0x0020, 0x9165), "AT", Tag(0x0028, 0x0010))  # DimensionIndexPointer
    ds.add_new(Tag(0x0020, 0x9167), "AT", Tag(0x0028, 0x0011))  # FunctionalGroupPointer
    return ds


@pytest.fixture
def dataset_without_at() -> Dataset:
    """Dataset with no AT-typed elements."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST123"
    return ds


class TestInit:
    def test_strategy_name(self, fuzzer: AttributeTagFuzzer) -> None:
        assert fuzzer.strategy_name == "attribute_tag"

    def test_three_strategies(self, fuzzer: AttributeTagFuzzer) -> None:
        assert len(fuzzer.mutation_strategies) == 3

    def test_strategies_callable(self, fuzzer: AttributeTagFuzzer) -> None:
        for s in fuzzer.mutation_strategies:
            assert callable(s)


class TestFindAtElements:
    def test_finds_existing_at(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        tags = fuzzer._find_at_elements(dataset_with_at)
        assert Tag(0x0020, 0x9165) in tags
        assert Tag(0x0020, 0x9167) in tags
        assert len(tags) == 2

    def test_empty_when_no_at(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        assert fuzzer._find_at_elements(dataset_without_at) == []


class TestEnsureAtElement:
    def test_returns_existing_when_present(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        tag = fuzzer._ensure_at_element(dataset_with_at)
        # Should return one of the existing AT tags, not the fallback.
        assert tag in (Tag(0x0020, 0x9165), Tag(0x0020, 0x9167))

    def test_adds_fallback_when_absent(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        assert fuzzer._find_at_elements(dataset_without_at) == []
        tag = fuzzer._ensure_at_element(dataset_without_at)
        assert tag == _FALLBACK_AT_TAG
        assert _FALLBACK_AT_TAG in dataset_without_at
        assert dataset_without_at[_FALLBACK_AT_TAG].VR == "AT"


class TestAtToNonexistent:
    def test_rewrites_existing_at_values(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        result = fuzzer._at_to_nonexistent(dataset_with_at)
        assert result[Tag(0x0020, 0x9165)].value == _NONEXISTENT_TAG
        assert result[Tag(0x0020, 0x9167)].value == _NONEXISTENT_TAG

    def test_adds_at_when_dataset_has_none(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        result = fuzzer._at_to_nonexistent(dataset_without_at)
        assert _FALLBACK_AT_TAG in result
        assert result[_FALLBACK_AT_TAG].value == _NONEXISTENT_TAG

    def test_target_is_reserved_group(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        result = fuzzer._at_to_nonexistent(dataset_without_at)
        assert result[_FALLBACK_AT_TAG].value.group == 0xFFFF


class TestAtToSelf:
    def test_each_at_points_at_itself(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        result = fuzzer._at_to_self(dataset_with_at)
        for tag in (Tag(0x0020, 0x9165), Tag(0x0020, 0x9167)):
            assert result[tag].value == Tag(tag)

    def test_self_reference_holds_after_no_initial_at(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        result = fuzzer._at_to_self(dataset_without_at)
        assert result[_FALLBACK_AT_TAG].value == Tag(_FALLBACK_AT_TAG)


class TestAtToPrivate:
    def test_rewrites_to_private_tag(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        result = fuzzer._at_to_private(dataset_with_at)
        for tag in (Tag(0x0020, 0x9165), Tag(0x0020, 0x9167)):
            assert result[tag].value == _UNDEFINED_PRIVATE_TAG

    def test_private_target_has_odd_group(
        self, fuzzer: AttributeTagFuzzer, dataset_without_at: Dataset
    ) -> None:
        result = fuzzer._at_to_private(dataset_without_at)
        assert result[_FALLBACK_AT_TAG].value.group % 2 == 1


class TestMutateDispatcher:
    def test_records_last_variant(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        fuzzer.mutate(dataset_with_at)
        assert fuzzer.last_variant in {
            "_at_to_nonexistent",
            "_at_to_self",
            "_at_to_private",
        }

    def test_returns_dataset(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        result = fuzzer.mutate(dataset_with_at)
        assert isinstance(result, Dataset)

    def test_handles_strategy_exception_gracefully(
        self, fuzzer: AttributeTagFuzzer, dataset_with_at: Dataset
    ) -> None:
        def boom(_ds: Dataset) -> Dataset:
            raise RuntimeError("boom")

        boom.__name__ = "_at_to_nonexistent"  # type: ignore[attr-defined]
        with patch(
            "dicom_fuzzer.attacks.format.attribute_tag_fuzzer.random.choice",
            return_value=boom,
        ):
            # Mutator must not propagate strategy exceptions.
            result = fuzzer.mutate(dataset_with_at)
            assert isinstance(result, Dataset)


class TestRoundTripCompatibility:
    """Ensure mutated datasets remain readable by pydicom."""

    def test_each_strategy_produces_readable_dataset(
        self,
        fuzzer: AttributeTagFuzzer,
        dataset_with_at: Dataset,
    ) -> None:
        for strategy in fuzzer.mutation_strategies:
            ds = Dataset()
            ds.PatientName = "Round^Trip"
            ds.add_new(Tag(0x0020, 0x9165), "AT", Tag(0x0028, 0x0010))
            mutated = strategy(ds)
            # Touch the AT value so any lazy resolution would fire.
            assert mutated[Tag(0x0020, 0x9165)].VR == "AT"
            assert isinstance(mutated[Tag(0x0020, 0x9165)].value, type(Tag(0, 0)))

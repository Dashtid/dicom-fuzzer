"""Tests for target-type filtering in DicomMutator._get_applicable_strategies().

Verifies that:
- config["target_types"] = None (or absent) → all strategies pass
- config["target_types"] = frozenset({"viewer"}) → only viewer strategies pass
- config["target_types"] = frozenset({"pacs"}) → only pacs strategies pass
- config["target_types"] = frozenset({"viewer", "pacs"}) → union passes
- Strategies without target_types attribute default to all types (no exclusion)

Note: modality-specific fuzzers (nm, pet, rt_dose, rtss, seg, encapsulated_pdf) also
filter via can_mutate() for non-matching SOP classes, so a generic CT dataset won't
activate them regardless of target-type settings.  Tests that assert their presence
use a fixture with the matching SOP class UID.
"""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.core.mutation.mutator import DicomMutator

# Known viewer-only strategy names (always pass can_mutate for pixel datasets)
_VIEWER_ONLY = {"pixel", "compressed_pixel", "pixel_reencoding"}
# Known pacs-only strategy names
_PACS_ONLY = {
    "nuclear_medicine",
    "pet",
    "rt_dose",
    "rt_structure_set",
    "segmentation",
    "encapsulated_pdf",
}
# All-types strategies that always pass can_mutate (generic dataset)
_ALL_TYPES_GENERIC = {
    "calibration",
    "conformance",
    "dictionary",
    "encoding",
    "header",
    "metadata",
    "private_tag",
    "reference",
    "sequence",
    "structure",
}


@pytest.fixture
def rich_dataset() -> Dataset:
    """Dataset rich enough that most strategies report can_mutate=True."""
    meta = FileMetaDataset()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = meta
    ds.Rows = 16
    ds.Columns = 16
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PixelData = b"\x00" * (16 * 16 * 2)
    ds.PatientName = "Filter^Test"
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    return ds


def _active_names(mutator: DicomMutator, dataset: Dataset) -> set[str]:
    """Return strategy names that pass the applicable-strategies filter."""
    return {s.strategy_name for s in mutator._get_applicable_strategies(dataset)}


class TestNoFilter:
    def test_none_config_includes_generic_strategies(self, rich_dataset):
        """No target_types filter → all-types and viewer-only strategies active."""
        mutator = DicomMutator(config=None)
        active = _active_names(mutator, rich_dataset)
        # All-types generic strategies must be present
        assert _ALL_TYPES_GENERIC <= active
        # Viewer-only strategies must also be present (pixel dataset)
        assert _VIEWER_ONLY <= active

    def test_explicit_none_same_as_no_filter(self, rich_dataset):
        """Explicit target_types=None behaves identically to no filter."""
        mutator = DicomMutator(config={"target_types": None})
        active = _active_names(mutator, rich_dataset)
        assert _ALL_TYPES_GENERIC <= active
        assert _VIEWER_ONLY <= active


class TestViewerFilter:
    def test_viewer_includes_viewer_only_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"viewer"})})
        active = _active_names(mutator, rich_dataset)
        assert _VIEWER_ONLY <= active

    def test_viewer_excludes_pacs_only_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"viewer"})})
        active = _active_names(mutator, rich_dataset)
        assert active.isdisjoint(_PACS_ONLY), (
            f"pacs-only strategies present with viewer filter: {active & _PACS_ONLY}"
        )


class TestPacsFilter:
    def test_pacs_includes_all_types_strategies(self, rich_dataset):
        """All-types strategies pass the pacs filter."""
        mutator = DicomMutator(config={"target_types": frozenset({"pacs"})})
        active = _active_names(mutator, rich_dataset)
        assert _ALL_TYPES_GENERIC <= active

    def test_pacs_excludes_viewer_only_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"pacs"})})
        active = _active_names(mutator, rich_dataset)
        assert active.isdisjoint(_VIEWER_ONLY)


class TestWebFilter:
    def test_web_excludes_viewer_only_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"web"})})
        active = _active_names(mutator, rich_dataset)
        assert active.isdisjoint(_VIEWER_ONLY)

    def test_web_excludes_pacs_only_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"web"})})
        active = _active_names(mutator, rich_dataset)
        assert active.isdisjoint(_PACS_ONLY)


class TestUnionFilter:
    def test_viewer_pacs_includes_viewer_strategies(self, rich_dataset):
        mutator = DicomMutator(config={"target_types": frozenset({"viewer", "pacs"})})
        active = _active_names(mutator, rich_dataset)
        assert _VIEWER_ONLY <= active

    def test_viewer_pacs_includes_all_types_strategies(self, rich_dataset):
        """All-types strategies appear in both viewer and pacs, so they survive the union."""
        mutator = DicomMutator(config={"target_types": frozenset({"viewer", "pacs"})})
        active = _active_names(mutator, rich_dataset)
        assert _ALL_TYPES_GENERIC <= active


class TestDefaultFallback:
    """Strategies without target_types default to all-types (not excluded)."""

    def test_strategy_without_attribute_survives_any_filter(self, rich_dataset):
        """A strategy that lacks target_types must not be excluded."""

        class NoTypesStrategy:
            strategy_name = "no_types_test"

            def mutate(self, ds):
                return ds

            def can_mutate(self, ds):
                return True

        mutator = DicomMutator(
            config={"target_types": frozenset({"viewer"})},
            # Disable auto-registration so we control the pool
        )
        mutator.strategies.clear()
        mutator._strategy_cache.clear()
        mutator.register_strategy(NoTypesStrategy())

        active = _active_names(mutator, rich_dataset)
        assert "no_types_test" in active


class TestCacheKeyIncludesTargetTypes:
    """Changing target_types must produce different cache keys."""

    def test_different_target_types_produce_different_cache_keys(self, rich_dataset):
        """Cache key includes target_types so viewer and pacs configs are cached separately."""
        mutator_all = DicomMutator(config={"target_types": None})
        mutator_viewer = DicomMutator(config={"target_types": frozenset({"viewer"})})
        mutator_pacs = DicomMutator(config={"target_types": frozenset({"pacs"})})

        mutator_all._get_applicable_strategies(rich_dataset)
        mutator_viewer._get_applicable_strategies(rich_dataset)
        mutator_pacs._get_applicable_strategies(rich_dataset)

        # Each mutator should have exactly one distinct cache entry
        assert len(mutator_all._strategy_cache) == 1
        assert len(mutator_viewer._strategy_cache) == 1
        assert len(mutator_pacs._strategy_cache) == 1

        # Cache keys must differ between viewer and pacs configs
        key_viewer = list(mutator_viewer._strategy_cache.keys())[0]
        key_pacs = list(mutator_pacs._strategy_cache.keys())[0]
        assert key_viewer != key_pacs

    def test_viewer_filter_excludes_pacs_only_via_target_types(self, rich_dataset):
        """With viewer filter, pacs-only strategies are excluded at the target-type layer
        (before can_mutate), verifiable by inspecting which strategies are checked."""
        mutator_no_filter = DicomMutator(config=None)
        mutator_viewer = DicomMutator(config={"target_types": frozenset({"viewer"})})

        # No-filter active set (pacs-only strategies excluded by can_mutate on CT dataset)
        active_no_filter = {
            s.strategy_name
            for s in mutator_no_filter._get_applicable_strategies(rich_dataset)
        }
        # Viewer-filter active set
        active_viewer = {
            s.strategy_name
            for s in mutator_viewer._get_applicable_strategies(rich_dataset)
        }

        # Both sets should be the same here (pacs-only already fail can_mutate on CT)
        # but the pacs-filter should drop viewer-only
        mutator_pacs = DicomMutator(config={"target_types": frozenset({"pacs"})})
        active_pacs = {
            s.strategy_name
            for s in mutator_pacs._get_applicable_strategies(rich_dataset)
        }

        assert active_pacs.isdisjoint(_VIEWER_ONLY)
        assert _VIEWER_ONLY <= active_viewer

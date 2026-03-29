"""Per-fuzzer target_types assertions.

Verifies that every format fuzzer declares the expected target category set
so that --target-type filtering routes attacks to the right systems.
"""

from __future__ import annotations

import pytest

from dicom_fuzzer.attacks.format import (
    CalibrationFuzzer,
    CompressedPixelFuzzer,
    ConformanceFuzzer,
    DictionaryFuzzer,
    EncapsulatedPdfFuzzer,
    EncodingFuzzer,
    HeaderFuzzer,
    MetadataFuzzer,
    NuclearMedicineFuzzer,
    PetFuzzer,
    PixelFuzzer,
    PixelReencodingFuzzer,
    PrivateTagFuzzer,
    ReferenceFuzzer,
    RTDoseFuzzer,
    RTStructureSetFuzzer,
    SegmentationFuzzer,
    SequenceFuzzer,
    StructureFuzzer,
)

_ALL = frozenset({"viewer", "web", "pacs"})
_VIEWER = frozenset({"viewer"})
_PACS = frozenset({"pacs"})

# (fuzzer_class, expected_target_types)
_CASES = [
    (CalibrationFuzzer, _ALL),
    (CompressedPixelFuzzer, _VIEWER),
    (ConformanceFuzzer, _ALL),
    (DictionaryFuzzer, _ALL),
    (EncapsulatedPdfFuzzer, _PACS),
    (EncodingFuzzer, _ALL),
    (HeaderFuzzer, _ALL),
    (MetadataFuzzer, _ALL),
    (NuclearMedicineFuzzer, _PACS),
    (PetFuzzer, _PACS),
    (PixelFuzzer, _VIEWER),
    (PixelReencodingFuzzer, _VIEWER),
    (PrivateTagFuzzer, _ALL),
    (ReferenceFuzzer, _ALL),
    (RTDoseFuzzer, _PACS),
    (RTStructureSetFuzzer, _PACS),
    (SegmentationFuzzer, _PACS),
    (SequenceFuzzer, _ALL),
    (StructureFuzzer, _ALL),
]

_IDS = [cls.__name__ for cls, _ in _CASES]


@pytest.mark.parametrize(("fuzzer_cls", "expected"), _CASES, ids=_IDS)
def test_target_types_assignment(fuzzer_cls, expected):
    """Each fuzzer must declare the expected target_types frozenset."""
    fuzzer = fuzzer_cls()
    assert fuzzer.target_types == expected, (
        f"{fuzzer_cls.__name__}.target_types == {fuzzer.target_types!r}, "
        f"expected {expected!r}"
    )


class TestTargetTypeGroups:
    """Sanity checks on the collective groupings."""

    def test_viewer_only_fuzzers(self):
        viewer_only = [cls for cls, tt in _CASES if tt == _VIEWER]
        assert set(viewer_only) == {
            PixelFuzzer,
            CompressedPixelFuzzer,
            PixelReencodingFuzzer,
        }

    def test_pacs_only_fuzzers(self):
        pacs_only = [cls for cls, tt in _CASES if tt == _PACS]
        assert set(pacs_only) == {
            NuclearMedicineFuzzer,
            PetFuzzer,
            RTDoseFuzzer,
            RTStructureSetFuzzer,
            SegmentationFuzzer,
            EncapsulatedPdfFuzzer,
        }

    def test_all_types_fuzzers(self):
        all_types = [cls for cls, tt in _CASES if tt == _ALL]
        assert len(all_types) == 10  # 19 total - 3 viewer - 6 pacs

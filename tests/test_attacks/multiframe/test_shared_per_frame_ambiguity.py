"""Tests for SharedPerFrameAmbiguityStrategy.

PS3.3 C.7.6.16.1.1 says a functional-group macro lives in *either* the
Shared Functional Groups Sequence *or* the Per-frame Functional Groups
Sequence, never both. This strategy intentionally violates that by
duplicating macros across both. Tests assert the duplicated structure
is produced as expected and that the result still serializes (the
violation is semantic, not structural).
"""

from __future__ import annotations

import io

import pydicom
import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

import dicom_fuzzer.attacks.multiframe.shared_per_frame_ambiguity as mod
from dicom_fuzzer.attacks.multiframe.shared_per_frame_ambiguity import (
    SharedPerFrameAmbiguityStrategy,
)

_MACROS = (
    "PixelMeasuresSequence",
    "PlaneOrientationSequence",
    "PlanePositionSequence",
    "FrameVOILUTSequence",
)


@pytest.fixture
def strategy() -> SharedPerFrameAmbiguityStrategy:
    return SharedPerFrameAmbiguityStrategy()


@pytest.fixture
def multiframe_ds() -> Dataset:
    """Minimal enhanced multi-frame dataset: 4 frames, 4 per-frame items."""
    ds = Dataset()
    ds.NumberOfFrames = 4
    ds.Rows = 8
    ds.Columns = 8
    ds.BitsAllocated = 16
    ds.PerFrameFunctionalGroupsSequence = Sequence([Dataset() for _ in range(4)])
    return ds


def _force_attack(monkeypatch, attack_type: str) -> None:
    monkeypatch.setattr(
        mod.random,
        "choice",
        lambda choices: attack_type if attack_type in choices else choices[0],
    )


def _force_attack_and_macro(monkeypatch, attack_type: str, macro: str) -> None:
    """random.choice is called for attack type AND for the macro name."""

    def chooser(choices):
        if attack_type in choices:
            return attack_type
        if macro in choices:
            return macro
        return choices[0]

    monkeypatch.setattr(mod.random, "choice", chooser)


# ---------------------------------------------------------------------------
# can_mutate
# ---------------------------------------------------------------------------


class TestCanMutate:
    def test_true_for_multiframe(self, strategy, multiframe_ds):
        assert strategy.can_mutate(multiframe_ds) is True

    def test_false_for_single_frame(self, strategy):
        ds = Dataset()
        ds.NumberOfFrames = 1
        assert strategy.can_mutate(ds) is False

    def test_false_when_absent(self, strategy):
        assert strategy.can_mutate(Dataset()) is False

    def test_false_for_zero_frames(self, strategy):
        ds = Dataset()
        ds.NumberOfFrames = 0
        assert strategy.can_mutate(ds) is False


# ---------------------------------------------------------------------------
# identical_in_both
# ---------------------------------------------------------------------------


class TestIdenticalInBoth:
    def test_macro_in_shared_and_every_per_frame(
        self, strategy, multiframe_ds, monkeypatch
    ):
        _force_attack_and_macro(
            monkeypatch, "identical_in_both", "PixelMeasuresSequence"
        )
        out, records = strategy._mutate_impl(multiframe_ds, 1)
        assert records[0].details["attack_type"] == "identical_in_both"
        sfg = out.SharedFunctionalGroupsSequence[0]
        assert "PixelMeasuresSequence" in sfg
        for item in out.PerFrameFunctionalGroupsSequence:
            assert "PixelMeasuresSequence" in item

    def test_values_are_equal_across_copies(self, strategy, multiframe_ds, monkeypatch):
        _force_attack_and_macro(
            monkeypatch, "identical_in_both", "PixelMeasuresSequence"
        )
        out, _ = strategy._mutate_impl(multiframe_ds, 1)
        shared_spacing = list(
            out.SharedFunctionalGroupsSequence[0].PixelMeasuresSequence[0].PixelSpacing
        )
        for item in out.PerFrameFunctionalGroupsSequence:
            assert list(item.PixelMeasuresSequence[0].PixelSpacing) == shared_spacing


# ---------------------------------------------------------------------------
# conflicting_in_both
# ---------------------------------------------------------------------------


class TestConflictingInBoth:
    def test_shared_and_per_frame_disagree(self, strategy, multiframe_ds, monkeypatch):
        _force_attack_and_macro(
            monkeypatch, "conflicting_in_both", "PixelMeasuresSequence"
        )
        out, records = strategy._mutate_impl(multiframe_ds, 1)
        assert records[0].details["attack_type"] == "conflicting_in_both"
        shared_spacing = list(
            out.SharedFunctionalGroupsSequence[0].PixelMeasuresSequence[0].PixelSpacing
        )
        per_frame_spacing = list(
            out.PerFrameFunctionalGroupsSequence[0]
            .PixelMeasuresSequence[0]
            .PixelSpacing
        )
        assert shared_spacing != per_frame_spacing
        # Every per-frame item carries the same (conflicting) value.
        for item in out.PerFrameFunctionalGroupsSequence:
            assert list(item.PixelMeasuresSequence[0].PixelSpacing) == per_frame_spacing


# ---------------------------------------------------------------------------
# partial_per_frame
# ---------------------------------------------------------------------------


class TestPartialPerFrame:
    def test_only_first_half_of_per_frame_has_macro(
        self, strategy, multiframe_ds, monkeypatch
    ):
        _force_attack_and_macro(
            monkeypatch, "partial_per_frame", "PlanePositionSequence"
        )
        out, records = strategy._mutate_impl(multiframe_ds, 1)
        assert records[0].details["attack_type"] == "partial_per_frame"
        # 4 frames -> first 2 get the macro
        assert "PlanePositionSequence" in out.SharedFunctionalGroupsSequence[0]
        has_macro = [
            "PlanePositionSequence" in item
            for item in out.PerFrameFunctionalGroupsSequence
        ]
        assert has_macro == [True, True, False, False]

    def test_partial_count_in_record(self, strategy, multiframe_ds, monkeypatch):
        _force_attack_and_macro(
            monkeypatch, "partial_per_frame", "PlanePositionSequence"
        )
        _, records = strategy._mutate_impl(multiframe_ds, 1)
        assert records[0].details["partial_count"] == 2
        assert records[0].details["frame_count"] == 4


# ---------------------------------------------------------------------------
# all_macros_conflicting
# ---------------------------------------------------------------------------


class TestAllMacrosConflicting:
    def test_all_four_macros_in_both(self, strategy, multiframe_ds, monkeypatch):
        _force_attack(monkeypatch, "all_macros_conflicting")
        out, records = strategy._mutate_impl(multiframe_ds, 1)
        assert records[0].details["attack_type"] == "all_macros_conflicting"
        assert records[0].details["macro_count"] == 4
        sfg = out.SharedFunctionalGroupsSequence[0]
        for macro in _MACROS:
            assert macro in sfg
            for item in out.PerFrameFunctionalGroupsSequence:
                assert macro in item


# ---------------------------------------------------------------------------
# General behavior
# ---------------------------------------------------------------------------


class TestGeneralBehavior:
    def test_one_record_per_mutation_count(self, strategy, multiframe_ds, monkeypatch):
        _force_attack(monkeypatch, "all_macros_conflicting")
        _, records = strategy._mutate_impl(multiframe_ds, 5)
        assert len(records) == 5
        assert all(r.strategy == "shared_per_frame_ambiguity" for r in records)

    def test_creates_per_frame_seq_when_absent(self, strategy, monkeypatch):
        # No PerFrameFunctionalGroupsSequence to start.
        ds = Dataset()
        ds.NumberOfFrames = 3
        _force_attack_and_macro(monkeypatch, "identical_in_both", "FrameVOILUTSequence")
        out, _ = strategy._mutate_impl(ds, 1)
        assert hasattr(out, "PerFrameFunctionalGroupsSequence")
        assert len(out.PerFrameFunctionalGroupsSequence) >= 3

    def test_frame_count_capped_at_max(self, strategy, monkeypatch):
        # NumberOfFrames huge -> _get_frame_count caps at _MAX_FRAME_COUNT (100).
        ds = Dataset()
        ds.NumberOfFrames = 10_000
        _force_attack_and_macro(
            monkeypatch, "identical_in_both", "PixelMeasuresSequence"
        )
        out, _ = strategy._mutate_impl(ds, 1)
        assert len(out.PerFrameFunctionalGroupsSequence) == 100

    def test_round_trips_through_dcmwrite(self, strategy, multiframe_ds, monkeypatch):
        # The duplication is spec-illegal but structurally valid DICOM.
        _force_attack(monkeypatch, "all_macros_conflicting")
        out, _ = strategy._mutate_impl(multiframe_ds, 1)
        # Minimal fields so dcmwrite is happy.
        out.PatientID = "P"
        out.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        out.SOPClassUID = "1.2.840.10008.5.1.4.1.1.4.1"  # Enhanced MR Image
        out.is_little_endian = True
        out.is_implicit_VR = True
        buf = io.BytesIO()
        pydicom.dcmwrite(buf, out, enforce_file_format=False)
        buf.seek(0)
        rt = pydicom.dcmread(buf, force=True)
        assert "PixelMeasuresSequence" in rt.SharedFunctionalGroupsSequence[0]
        assert "PixelMeasuresSequence" in rt.PerFrameFunctionalGroupsSequence[0]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_registered_in_mutator(self):
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "shared_per_frame_ambiguity" in names

    def test_exported_from_package(self):
        from dicom_fuzzer.attacks.multiframe import (
            SharedPerFrameAmbiguityStrategy as Exported,
        )

        assert Exported is SharedPerFrameAmbiguityStrategy

"""Tests for synthetic seed generators (SEG, RTSS, Encapsulated PDF).

Verifies that:
- Each factory produces a Dataset that passes the matching fuzzer's can_mutate()
- Each dataset round-trips through pydicom serialization without error
- The save_seed() helper writes a readable DICOM file
- The seeds CLI --synthetic flag generates the expected number of files
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.attacks.format.encapsulated_pdf_fuzzer import EncapsulatedPdfFuzzer
from dicom_fuzzer.attacks.format.rtss_fuzzer import RTStructureSetFuzzer
from dicom_fuzzer.attacks.format.seg_fuzzer import SegmentationFuzzer
from dicom_fuzzer.core.corpus.synthetic_seeds import (
    SEED_FACTORIES,
    create_pdf_seed,
    create_rtss_seed,
    create_seg_seed,
    save_seed,
)

_SEG_SOP = "1.2.840.10008.5.1.4.1.1.66.4"
_RTSS_SOP = "1.2.840.10008.5.1.4.1.1.481.3"
_PDF_SOP = "1.2.840.10008.5.1.4.1.1.104.1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seg_ds() -> Dataset:
    return create_seg_seed()


@pytest.fixture
def rtss_ds() -> Dataset:
    return create_rtss_seed()


@pytest.fixture
def pdf_ds() -> Dataset:
    return create_pdf_seed()


# ---------------------------------------------------------------------------
# can_mutate integration
# ---------------------------------------------------------------------------


class TestCanMutateIntegration:
    def test_seg_seed_passes_seg_fuzzer(self, seg_ds: Dataset) -> None:
        assert SegmentationFuzzer().can_mutate(seg_ds) is True

    def test_rtss_seed_passes_rtss_fuzzer(self, rtss_ds: Dataset) -> None:
        assert RTStructureSetFuzzer().can_mutate(rtss_ds) is True

    def test_pdf_seed_passes_pdf_fuzzer(self, pdf_ds: Dataset) -> None:
        assert EncapsulatedPdfFuzzer().can_mutate(pdf_ds) is True

    def test_seg_seed_rejected_by_rtss_fuzzer(self, seg_ds: Dataset) -> None:
        assert RTStructureSetFuzzer().can_mutate(seg_ds) is False

    def test_rtss_seed_rejected_by_seg_fuzzer(self, rtss_ds: Dataset) -> None:
        assert SegmentationFuzzer().can_mutate(rtss_ds) is False

    def test_pdf_seed_rejected_by_seg_fuzzer(self, pdf_ds: Dataset) -> None:
        assert SegmentationFuzzer().can_mutate(pdf_ds) is False


# ---------------------------------------------------------------------------
# SOP class and required attributes
# ---------------------------------------------------------------------------


class TestSopClassAndAttributes:
    def test_seg_sop_class(self, seg_ds: Dataset) -> None:
        assert str(seg_ds.SOPClassUID) == _SEG_SOP

    def test_seg_modality(self, seg_ds: Dataset) -> None:
        assert seg_ds.Modality == "SEG"

    def test_seg_has_segment_sequence(self, seg_ds: Dataset) -> None:
        assert hasattr(seg_ds, "SegmentSequence")
        assert len(seg_ds.SegmentSequence) >= 1

    def test_seg_has_per_frame_functional_groups(self, seg_ds: Dataset) -> None:
        assert hasattr(seg_ds, "PerFrameFunctionalGroupsSequence")

    def test_seg_has_pixel_data(self, seg_ds: Dataset) -> None:
        assert hasattr(seg_ds, "PixelData")

    def test_rtss_sop_class(self, rtss_ds: Dataset) -> None:
        assert str(rtss_ds.SOPClassUID) == _RTSS_SOP

    def test_rtss_modality(self, rtss_ds: Dataset) -> None:
        assert rtss_ds.Modality == "RTSTRUCT"

    def test_rtss_has_roi_sequence(self, rtss_ds: Dataset) -> None:
        assert hasattr(rtss_ds, "StructureSetROISequence")
        assert len(rtss_ds.StructureSetROISequence) >= 1

    def test_rtss_has_contour_sequence(self, rtss_ds: Dataset) -> None:
        assert hasattr(rtss_ds, "ROIContourSequence")
        assert len(rtss_ds.ROIContourSequence) >= 1

    def test_rtss_has_observations_sequence(self, rtss_ds: Dataset) -> None:
        assert hasattr(rtss_ds, "RTROIObservationsSequence")

    def test_rtss_has_frame_of_reference_sequence(self, rtss_ds: Dataset) -> None:
        assert hasattr(rtss_ds, "ReferencedFrameOfReferenceSequence")

    def test_pdf_sop_class(self, pdf_ds: Dataset) -> None:
        assert str(pdf_ds.SOPClassUID) == _PDF_SOP

    def test_pdf_modality(self, pdf_ds: Dataset) -> None:
        assert pdf_ds.Modality == "DOC"

    def test_pdf_has_encapsulated_document(self, pdf_ds: Dataset) -> None:
        assert hasattr(pdf_ds, "EncapsulatedDocument")
        doc = pdf_ds.EncapsulatedDocument
        assert isinstance(doc, (bytes, bytearray))
        assert doc[:4] == b"%PDF"

    def test_pdf_has_mime_type(self, pdf_ds: Dataset) -> None:
        assert pdf_ds.MIMETypeOfEncapsulatedDocument == "application/pdf"


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_seg_round_trip(self, seg_ds: Dataset, tmp_path: Path) -> None:
        path = save_seed(seg_ds, tmp_path, "seg_test.dcm")
        assert path.exists()
        reloaded = pydicom.dcmread(str(path))
        assert str(reloaded.SOPClassUID) == _SEG_SOP

    def test_rtss_round_trip(self, rtss_ds: Dataset, tmp_path: Path) -> None:
        path = save_seed(rtss_ds, tmp_path, "rtss_test.dcm")
        assert path.exists()
        reloaded = pydicom.dcmread(str(path))
        assert str(reloaded.SOPClassUID) == _RTSS_SOP

    def test_pdf_round_trip(self, pdf_ds: Dataset, tmp_path: Path) -> None:
        path = save_seed(pdf_ds, tmp_path, "pdf_test.dcm")
        assert path.exists()
        reloaded = pydicom.dcmread(str(path))
        assert str(reloaded.SOPClassUID) == _PDF_SOP

    def test_save_seed_creates_output_dir(
        self, seg_ds: Dataset, tmp_path: Path
    ) -> None:
        nested = tmp_path / "a" / "b" / "c"
        path = save_seed(seg_ds, nested, "seg.dcm")
        assert path.exists()

    def test_reloaded_seg_can_be_mutated(self, seg_ds: Dataset, tmp_path: Path) -> None:
        path = save_seed(seg_ds, tmp_path, "seg_mut.dcm")
        reloaded = pydicom.dcmread(str(path))
        mutated = SegmentationFuzzer().mutate(reloaded)
        assert isinstance(mutated, Dataset)

    def test_reloaded_rtss_can_be_mutated(
        self, rtss_ds: Dataset, tmp_path: Path
    ) -> None:
        path = save_seed(rtss_ds, tmp_path, "rtss_mut.dcm")
        reloaded = pydicom.dcmread(str(path))
        mutated = RTStructureSetFuzzer().mutate(reloaded)
        assert isinstance(mutated, Dataset)

    def test_reloaded_pdf_can_be_mutated(self, pdf_ds: Dataset, tmp_path: Path) -> None:
        path = save_seed(pdf_ds, tmp_path, "pdf_mut.dcm")
        reloaded = pydicom.dcmread(str(path))
        mutated = EncapsulatedPdfFuzzer().mutate(reloaded)
        assert isinstance(mutated, Dataset)


# ---------------------------------------------------------------------------
# SEED_FACTORIES registry
# ---------------------------------------------------------------------------


class TestSeedFactories:
    def test_all_keys_present(self) -> None:
        assert set(SEED_FACTORIES.keys()) == {"seg", "rtss", "pdf"}

    def test_factories_are_callable(self) -> None:
        for key, factory in SEED_FACTORIES.items():
            assert callable(factory), f"SEED_FACTORIES[{key!r}] is not callable"

    def test_factories_return_datasets(self) -> None:
        for key, factory in SEED_FACTORIES.items():
            result = factory()
            assert isinstance(result, Dataset), (
                f"SEED_FACTORIES[{key!r}] did not return Dataset"
            )

    def test_each_call_produces_unique_sop_instance_uid(self) -> None:
        """Each invocation must return a fresh UID."""
        for factory in SEED_FACTORIES.values():
            ds1 = factory()
            ds2 = factory()
            assert ds1.SOPInstanceUID != ds2.SOPInstanceUID


# ---------------------------------------------------------------------------
# Seeds CLI --synthetic integration
# ---------------------------------------------------------------------------


class TestSeedsCLI:
    def test_synthetic_seg_generates_files(self, tmp_path: Path) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        args = argparse.Namespace(
            synthetic="seg",
            count=3,
            output=str(tmp_path / "seg"),
            input=None,
            seed=None,
        )
        result = SeedsCommand.execute(args)
        assert result == 0
        dcm_files = list((tmp_path / "seg").glob("*.dcm"))
        assert len(dcm_files) == 3

    def test_synthetic_rtss_generates_files(self, tmp_path: Path) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        args = argparse.Namespace(
            synthetic="rtss",
            count=2,
            output=str(tmp_path / "rtss"),
            input=None,
            seed=None,
        )
        result = SeedsCommand.execute(args)
        assert result == 0
        dcm_files = list((tmp_path / "rtss").glob("*.dcm"))
        assert len(dcm_files) == 2

    def test_synthetic_pdf_generates_files(self, tmp_path: Path) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        args = argparse.Namespace(
            synthetic="pdf",
            count=2,
            output=str(tmp_path / "pdf"),
            input=None,
            seed=None,
        )
        result = SeedsCommand.execute(args)
        assert result == 0
        dcm_files = list((tmp_path / "pdf").glob("*.dcm"))
        assert len(dcm_files) == 2

    def test_missing_input_without_synthetic_returns_error(
        self, tmp_path: Path
    ) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        args = argparse.Namespace(
            synthetic=None,
            count=5,
            output=str(tmp_path),
            input=None,
            seed=None,
        )
        result = SeedsCommand.execute(args)
        assert result != 0

    def test_nonexistent_input_returns_error(self, tmp_path: Path) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        args = argparse.Namespace(
            synthetic=None,
            count=5,
            output=str(tmp_path),
            input="/nonexistent/path.dcm",
            seed=None,
        )
        result = SeedsCommand.execute(args)
        assert result != 0

    def test_generated_files_are_valid_dicom(self, tmp_path: Path) -> None:
        from dicom_fuzzer.cli.commands.seeds import SeedsCommand

        for modality in ("seg", "rtss", "pdf"):
            out_dir = tmp_path / modality
            args = argparse.Namespace(
                synthetic=modality,
                count=1,
                output=str(out_dir),
                input=None,
                seed=None,
            )
            SeedsCommand.execute(args)
            for dcm_path in out_dir.glob("*.dcm"):
                ds = pydicom.dcmread(str(dcm_path))
                assert hasattr(ds, "SOPClassUID")

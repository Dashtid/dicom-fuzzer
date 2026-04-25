"""Tests for cli/samples.py - Samples Subcommand.

Tests cover argument parsing, listing sources, and strip pixel data.
"""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.cli.commands.samples import (
    SAMPLE_SOURCES,
    SamplesCommand,
    create_parser,
    main,
    run_list_sources,
    run_strip_pixel_data,
)


@pytest.fixture
def dicom_file_factory():
    """Factory creating minimal DICOM files with PixelData.

    Real files (not mocks) so the strip_pixel_data / optimize_corpus code
    paths under test actually run end-to-end.
    """

    def _make(path: Path) -> Path:
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(str(path), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.PatientName = "Strip^Test"
        ds.PatientID = "STRIP001"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.PixelRepresentation = 0
        ds.PhotometricInterpretation = "MONOCHROME2"
        # Real PixelData so stripping actually shaves bytes.
        ds.PixelData = b"\xff" * (64 * 64 * 2)
        ds.save_as(str(path), write_like_original=False)
        return path

    return _make


class TestSampleSources:
    """Test SAMPLE_SOURCES constant."""

    def test_sources_defined(self):
        """Test that sample sources are defined."""
        assert len(SAMPLE_SOURCES) > 0
        assert "rubo" in SAMPLE_SOURCES
        assert "osirix" in SAMPLE_SOURCES

    def test_source_structure(self):
        """Test each source has required fields."""
        for key, source in SAMPLE_SOURCES.items():
            assert "name" in source
            assert "url" in source
            assert "description" in source


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()
        assert parser is not None

    def test_list_sources_action(self):
        """Test --list-sources action."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.list_sources is True

    def test_strip_pixel_data_action(self):
        """Test --strip-pixel-data action."""
        parser = create_parser()
        args = parser.parse_args(["--strip-pixel-data", "./input", "-o", "./output"])
        assert args.strip_pixel_data == "./input"

    def test_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--list-sources", "--strip-pixel-data", "./input"])

    def test_default_output(self):
        """Test default output path."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.output == "./artifacts/samples"

    def test_verbose_flag(self):
        """Test verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources", "-v"])
        assert args.verbose is True


class TestRunListSources:
    """Test run_list_sources function."""

    def test_list_sources(self, capsys):
        """Test listing sources."""
        args = MagicMock()

        result = run_list_sources(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Public DICOM Sample Sources" in captured.out
        assert "rubo" in captured.out.lower()
        assert "osirix" in captured.out.lower()

    def test_list_sources_contains_urls(self, capsys):
        """Test listing includes URLs."""
        args = MagicMock()

        run_list_sources(args)

        captured = capsys.readouterr()
        assert "URL:" in captured.out
        assert "http" in captured.out


class TestRunStripPixelData:
    """Test run_strip_pixel_data function."""

    def test_strip_path_not_found(self, tmp_path, capsys):
        """Test stripping nonexistent path."""
        args = MagicMock()
        args.strip_pixel_data = str(tmp_path / "nonexistent")
        args.output = str(tmp_path / "output")

        result = run_strip_pixel_data(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_strip_single_file_happy_path(self, tmp_path, dicom_file_factory, capsys):
        """Single DICOM file -> stripped copy under output dir, exit 0."""
        src = dicom_file_factory(tmp_path / "input.dcm")
        out_dir = tmp_path / "out"

        args = argparse.Namespace(
            strip_pixel_data=str(src), output=str(out_dir), verbose=False
        )

        assert run_strip_pixel_data(args) == 0

        stripped = out_dir / "input.dcm"
        assert stripped.exists()
        # PixelData removal should shave bytes.
        assert stripped.stat().st_size < src.stat().st_size

        captured = capsys.readouterr().out
        assert "input.dcm" in captured
        assert "Original:" in captured
        assert "Stripped:" in captured
        assert "Saved:" in captured

    def test_strip_directory_happy_path(self, tmp_path, dicom_file_factory, capsys):
        """Directory with DICOM files -> optimize_corpus stats printed."""
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(3):
            dicom_file_factory(corpus / f"slice_{i}.dcm")
        out_dir = tmp_path / "out"

        args = argparse.Namespace(
            strip_pixel_data=str(corpus), output=str(out_dir), verbose=False
        )

        assert run_strip_pixel_data(args) == 0

        captured = capsys.readouterr().out
        assert "Files processed:" in captured
        assert "Files optimized:" in captured
        assert "Space saved:" in captured
        assert "Reduction:" in captured

    def test_strip_single_file_failure_returns_1(
        self, tmp_path, dicom_file_factory, capsys
    ):
        """If strip_pixel_data returns success=False, run returns 1."""
        src = dicom_file_factory(tmp_path / "input.dcm")
        out_dir = tmp_path / "out"

        args = argparse.Namespace(
            strip_pixel_data=str(src), output=str(out_dir), verbose=False
        )

        # Patch at the source module -- samples.py does a local import.
        with patch(
            "dicom_fuzzer.core.corpus.corpus_minimization.strip_pixel_data",
            return_value=(False, 0),
        ):
            assert run_strip_pixel_data(args) == 1

        captured = capsys.readouterr().out
        assert "Failed to process" in captured

    def test_strip_exception_non_verbose(self, tmp_path, dicom_file_factory, capsys):
        """Exception inside strip_pixel_data -> exit 1, message but no traceback."""
        src = dicom_file_factory(tmp_path / "input.dcm")
        args = argparse.Namespace(
            strip_pixel_data=str(src),
            output=str(tmp_path / "out"),
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.corpus.corpus_minimization.strip_pixel_data",
            side_effect=RuntimeError("disk gremlin"),
        ):
            assert run_strip_pixel_data(args) == 1

        captured = capsys.readouterr().out
        assert "Optimization failed: disk gremlin" in captured
        assert "Traceback" not in captured

    def test_strip_exception_verbose_prints_traceback(
        self, tmp_path, dicom_file_factory, capsys
    ):
        """With --verbose, exception path also prints the traceback."""
        src = dicom_file_factory(tmp_path / "input.dcm")
        args = argparse.Namespace(
            strip_pixel_data=str(src),
            output=str(tmp_path / "out"),
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.core.corpus.corpus_minimization.strip_pixel_data",
            side_effect=RuntimeError("disk gremlin"),
        ):
            assert run_strip_pixel_data(args) == 1

        captured = capsys.readouterr()
        assert "Optimization failed: disk gremlin" in captured.out
        assert "Traceback" in captured.err
        assert "RuntimeError" in captured.err


class TestSamplesCommandExecute:
    """Exercise SamplesCommand.execute() branching directly.

    The parser makes --list-sources and --strip-pixel-data mutually
    exclusive with required=True, so the fallback help-print branch
    isn't reachable via main() -- but execute() is a plain method that
    can be called with an arbitrary Namespace.
    """

    def test_execute_falls_back_to_help_when_nothing_set(self, capsys):
        args = argparse.Namespace(list_sources=False, strip_pixel_data=None)

        assert SamplesCommand.execute(args) == 1

        # print_help() goes to stdout by default
        assert "usage" in capsys.readouterr().out.lower()

    def test_execute_dispatches_to_strip_pixel_data(self, tmp_path):
        """execute() routes to run_strip_pixel_data when the flag is set."""
        args = argparse.Namespace(
            list_sources=False,
            strip_pixel_data=str(tmp_path / "missing"),
            output=str(tmp_path / "out"),
            verbose=False,
        )

        # Path doesn't exist -> run_strip_pixel_data returns 1, but we've
        # still covered the dispatch branch in execute().
        assert SamplesCommand.execute(args) == 1


class TestMain:
    """Test main function."""

    def test_main_list_sources(self, capsys):
        """Test main with --list-sources."""
        result = main(["--list-sources"])

        assert result == 0
        captured = capsys.readouterr()
        assert "Public DICOM Sample Sources" in captured.out

    def test_main_no_action(self, capsys):
        """Test main without any action."""
        with pytest.raises(SystemExit):
            main([])

    def test_main_help(self, capsys):
        """Test main with --help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0

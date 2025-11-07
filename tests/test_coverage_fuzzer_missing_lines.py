"""Tests for coverage_fuzzer.py missing lines to reach 100% coverage.

Targets specific uncovered lines in coverage_fuzzer.py (91% -> 100%).
Missing lines: 196-199, 204, 206-207, 211-226, 263-268
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer
from dicom_fuzzer.core.mutator import MutationSeverity


@pytest.fixture
def temp_corpus_dir():
    """Create a temporary directory for corpus storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_dataset():
    """Create a sample DICOM dataset for testing."""
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.10"

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.Modality = "CT"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.10"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    return ds


class TestCoverageGuidedFuzzerMissingLines:
    """Test CoverageGuidedFuzzer missing lines."""

    def test_fuzz_iteration_with_crash(self, temp_corpus_dir, sample_dataset):
        """Test lines 196-199, 204, 211-226: crash detection during execution.

        When target_function raises exception during execution, it should:
        - Catch the exception (lines 196-199)
        - Mark crash = True and record the crash (line 199)
        - Set is_interesting = True (line 204)
        - Add entry to corpus with crash_triggered=True (lines 211-226)
        """
        # Create a flag to control when to crash
        crash_count = [0]

        def conditional_crashing_target(ds):
            crash_count[0] += 1
            # Only crash after first call (seed addition)
            if crash_count[0] > 1:
                raise ValueError("Intentional crash for testing")
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=conditional_crashing_target,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Add seed (first call, won't crash)
        fuzzer.add_seed(sample_dataset)

        # Perform iterations until crash occurs
        result = None
        for _ in range(10):
            result = fuzzer.fuzz_iteration()
            if result and result.crash_triggered:
                break

        # Lines 196-199: Exception caught, crash recorded
        # Line 204: is_interesting = True for crash
        # Lines 211-226: Entry added to corpus with crash_triggered=True
        assert result is not None
        assert result.crash_triggered is True
        assert fuzzer.stats.unique_crashes > 0

    def test_fuzz_iteration_with_new_coverage(self, temp_corpus_dir, sample_dataset):
        """Test lines 206-207, 211-226: adding interesting input with new coverage.

        When coverage tracker finds new coverage:
        - is_interesting = True (line 206)
        - Increment interesting_inputs_found (line 207)
        - Add entry to corpus (lines 211-226)
        """

        # Create fuzzer with target function
        def simple_target(ds):
            if hasattr(ds, "PatientName"):
                return "processed"
            return "default"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Mock coverage tracker to always return True for is_interesting
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=True)

        # Add seed
        fuzzer.add_seed(sample_dataset)

        # Perform iterations until we get new coverage
        result = None
        for _ in range(10):
            result = fuzzer.fuzz_iteration()
            if result is not None:
                break

        # Lines 206-207: is_interesting = True, stats incremented
        # Lines 211-226: Entry added to corpus
        assert fuzzer.stats.interesting_inputs_found > 0

    def test_fuzz_with_stop_on_crash(self, temp_corpus_dir, sample_dataset):
        """Test lines 263-268: stop_on_crash functionality.

        When stop_on_crash=True and a crash is found:
        - Check if new_entry.crash_triggered (line 262)
        - Log warning (lines 263-266)
        - Break out of loop (line 268)
        """
        # Create a flag to control when to crash
        crash_count = [0]

        def conditional_crashing_target(ds):
            crash_count[0] += 1
            # Only crash after first call (seed addition)
            if crash_count[0] > 1:
                raise RuntimeError("Crash for stop_on_crash test")
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=conditional_crashing_target,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Add seed (first call, won't crash)
        fuzzer.add_seed(sample_dataset)

        # Run campaign with stop_on_crash=True
        stats = fuzzer.fuzz(iterations=100, show_progress=False, stop_on_crash=True)

        # Lines 262-268: Should stop early when crash found
        # If it ran all 100 iterations, stop_on_crash didn't work
        assert stats.total_iterations < 100
        assert stats.unique_crashes > 0

    def test_fuzz_iteration_uninteresting_input(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration when input is not interesting (returns None).

        This ensures lines 210-229 are tested when is_interesting = False,
        meaning the function returns None instead of adding to corpus.
        """

        # Create fuzzer with simple target
        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Mock coverage tracker to always return False (not interesting)
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=False)

        # Add seed
        fuzzer.add_seed(sample_dataset)

        # Perform iterations - should return None (not interesting)
        results = []
        for _ in range(5):
            result = fuzzer.fuzz_iteration()
            results.append(result)

        # Most/all results should be None (not interesting)
        assert results.count(None) >= 3

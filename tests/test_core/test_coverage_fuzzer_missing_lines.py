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

    def test_fuzz_iteration_none_parent_dataset(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration when parent.get_dataset() returns None (lines 188-193).

        This covers the case where lazy-loaded dataset returns None.
        """

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Add seed
        fuzzer.add_seed(sample_dataset)

        # Mock the corpus entry to return None for get_dataset
        mock_entry = MagicMock()
        mock_entry.get_dataset.return_value = None
        mock_entry.entry_id = "test_entry"
        mock_entry.generation = 0

        # Mock _select_input to return our mock entry
        fuzzer._select_input = MagicMock(return_value=mock_entry)

        # Perform iteration - should return None due to None dataset
        result = fuzzer.fuzz_iteration()

        # Lines 189-193: Should log warning and return None
        assert result is None

    def test_select_input_explore_mode_random(self, temp_corpus_dir, sample_dataset):
        """Test _select_input in explore mode (20% probability) - lines 320-331.

        When random.random() >= 0.8, should use get_random_entry().
        """
        from unittest.mock import patch

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Add multiple seeds
        for i in range(5):
            ds = sample_dataset.copy()
            ds.PatientID = f"ID{i}"
            fuzzer.add_seed(ds, seed_id=f"seed{i}")

        # Force explore mode by making random.random return > 0.8
        with patch("random.random", return_value=0.95):
            result = fuzzer._select_input()

        # Line 331: Should return random entry
        assert result is not None

    def test_select_input_exploit_empty_best(self, temp_corpus_dir, sample_dataset):
        """Test _select_input exploit mode when get_best_entries returns empty - line 327-328.

        When exploit mode (random < 0.8) but no best entries, falls through to explore.
        """
        from unittest.mock import patch

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        # Add a seed
        fuzzer.add_seed(sample_dataset)

        # Force exploit mode but mock get_best_entries to return empty
        with patch("random.random", return_value=0.5):  # exploit mode
            with patch.object(
                fuzzer.corpus_manager, "get_best_entries", return_value=[]
            ):
                result = fuzzer._select_input()

        # Lines 327-328: Empty best entries, falls through to explore mode (line 331)
        assert result is not None

    def test_execute_with_coverage_no_history(self, temp_corpus_dir, sample_dataset):
        """Test _execute_with_coverage when coverage_history is empty - lines 379-382.

        When no coverage is recorded during trace_execution, should return None.
        """
        from contextlib import contextmanager
        from unittest.mock import patch

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        # Mock trace_execution to NOT add to history (simulates no coverage recorded)
        @contextmanager
        def mock_trace_execution(test_case_id):
            # Don't add anything to coverage_history
            yield

        with patch.object(
            fuzzer.coverage_tracker, "trace_execution", mock_trace_execution
        ):
            # Clear history before test
            fuzzer.coverage_tracker.coverage_history = []
            snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case")

        # Lines 379-382: With empty history after trace_execution, returns None
        assert snapshot is None

    def test_fuzz_progress_update_every_100(self, temp_corpus_dir, sample_dataset):
        """Test fuzz() progress update at 100 iteration intervals - lines 280-290.

        When show_progress=True and (i+1) % 100 == 0, should update stats and log.
        """

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        fuzzer.add_seed(sample_dataset)

        # Run exactly 100 iterations to trigger progress update
        stats = fuzzer.fuzz(iterations=100, show_progress=True, stop_on_crash=False)

        # Lines 280-290: Progress update should have been triggered
        assert stats.total_iterations == 100

    def test_fuzz_campaign_final_statistics(self, temp_corpus_dir, sample_dataset):
        """Test fuzz() final statistics update - lines 292-304.

        After loop completes, should update final stats.
        """

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=10, show_progress=False)

        # Lines 292-304: Final statistics should be updated
        assert stats.total_iterations == 10
        assert stats.corpus_size >= 1
        assert stats.total_coverage >= 0

    def test_record_crash_details(self, temp_corpus_dir, sample_dataset):
        """Test _record_crash records all crash details - lines 399-416.

        Should record crash_id, parent_id, exception info, and timestamp.
        """
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        exception = TypeError("Test type error")
        fuzzer._record_crash("crash_123", "parent_456", sample_dataset, exception)

        # Lines 399-408: Crash record should contain all details
        assert len(fuzzer.crashes) == 1
        crash = fuzzer.crashes[0]
        assert crash["crash_id"] == "crash_123"
        assert crash["parent_id"] == "parent_456"
        assert crash["exception_type"] == "TypeError"
        assert crash["exception_message"] == "Test type error"
        assert "timestamp" in crash

        # Lines 407-416: Stats should be updated
        assert fuzzer.stats.unique_crashes == 1

    def test_get_report_full_output(self, temp_corpus_dir, sample_dataset):
        """Test get_report generates complete report - lines 418-459.

        Should generate report with all sections.
        """

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=5, show_progress=False)

        # Add a crash for completeness
        fuzzer._record_crash(
            "crash_1", "parent_1", sample_dataset, RuntimeError("Test")
        )

        report = fuzzer.get_report()

        # Lines 418-459: Report should contain all sections
        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Duration:" in report
        assert "Execution Statistics:" in report
        assert "Total Iterations:" in report
        assert "Executions/Second:" in report
        assert "Coverage Statistics:" in report
        assert "Total Lines Covered:" in report
        assert "Interesting Inputs:" in report
        assert "Coverage Efficiency:" in report
        assert "Corpus Statistics:" in report
        assert "Current Size:" in report
        assert "Max Generation:" in report
        assert "Average Fitness:" in report
        assert "Crashes Found:" in report
        assert "Unique Crashes:" in report

    def test_reset_clears_all_state(self, temp_corpus_dir, sample_dataset):
        """Test reset() clears all state - lines 461-466.

        Should reset coverage tracker, stats, and crashes.
        """

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=10, show_progress=False)
        fuzzer._record_crash(
            "crash_1", "parent_1", sample_dataset, RuntimeError("Test")
        )

        # Verify state is populated
        assert fuzzer.stats.total_iterations > 0
        assert len(fuzzer.crashes) > 0

        # Reset
        fuzzer.reset()

        # Lines 461-466: All state should be cleared
        assert fuzzer.stats.total_iterations == 0
        assert fuzzer.stats.unique_crashes == 0
        assert len(fuzzer.crashes) == 0


class TestUpdateFromCampaignEdgeCases:
    """Test FuzzingCampaignStats.update_from_campaign edge cases."""

    def test_update_with_very_short_elapsed(self, temp_corpus_dir, sample_dataset):
        """Test update_from_campaign with very short elapsed time - lines 66-72.

        Should handle division by near-zero elapsed time.
        """
        from datetime import UTC, datetime

        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)

        # Set start time to just now
        fuzzer.stats.start_time = datetime.now(UTC)
        fuzzer.stats.total_iterations = 1000

        # Update stats - should not crash
        fuzzer.stats.update_from_campaign(fuzzer)

        # Lines 66-72: Should calculate very high exec/sec
        assert fuzzer.stats.executions_per_second >= 0

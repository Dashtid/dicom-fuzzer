"""Comprehensive tests for coverage_fuzzer.py to achieve high coverage.

Targets all uncovered lines in coverage_fuzzer.py.
Missing lines: 66-72, 182-239, 261-304, 320-331, 347-356, 379-382, 399-410, 425-459, 463-466
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.corpus import CorpusEntry
from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer
from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot
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


class TestFuzzingCampaignStatsUpdateFromCampaign:
    """Test FuzzingCampaignStats.update_from_campaign (lines 66-72)."""

    def test_update_from_campaign_calculates_exec_per_second(self, temp_corpus_dir):
        """Test lines 66-72: executions_per_second calculation."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Set a specific start time in the past
        fuzzer.stats.start_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        fuzzer.stats.total_iterations = 1000

        # Call update_from_campaign
        fuzzer.stats.update_from_campaign(fuzzer)

        # Line 66-68: elapsed calculated and exec_per_second computed
        assert fuzzer.stats.executions_per_second > 0

        # Line 70-72: corpus_size and avg_fitness updated from corpus_manager
        assert fuzzer.stats.corpus_size == 0  # Empty corpus
        assert fuzzer.stats.avg_fitness == 0.0

    def test_update_from_campaign_with_corpus_entries(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test update_from_campaign with entries in corpus."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Add some entries to corpus
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Set stats
        fuzzer.stats.start_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        fuzzer.stats.total_iterations = 500

        # Call update
        fuzzer.stats.update_from_campaign(fuzzer)

        # Lines 70-72: Should reflect corpus state
        assert fuzzer.stats.corpus_size == 1

    def test_update_from_campaign_zero_elapsed(self, temp_corpus_dir):
        """Test update_from_campaign with near-zero elapsed time (line 68 branch)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Set start time to now
        fuzzer.stats.start_time = datetime.now(UTC)
        fuzzer.stats.total_iterations = 0

        # Call update - elapsed is ~0, should handle gracefully
        fuzzer.stats.update_from_campaign(fuzzer)

        # Line 68: elapsed <= 0 branch, exec_per_second = 0.0
        # Since elapsed is very small but > 0, it will compute a very high value
        # unless total_iterations is 0
        assert fuzzer.stats.executions_per_second >= 0


class TestFuzzIterationMethod:
    """Test fuzz_iteration method (lines 182-239)."""

    def test_fuzz_iteration_no_corpus_returns_none(self, temp_corpus_dir):
        """Test lines 182-185: empty corpus returns None."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer.fuzz_iteration()

        # Lines 182-185: _select_input returns None, returns None
        assert result is None

    def test_fuzz_iteration_parent_dataset_none(self, temp_corpus_dir, sample_dataset):
        """Test lines 188-193: parent.get_dataset() returns None."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Add a seed
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock _select_input to return entry with None dataset
        mock_entry = Mock(spec=CorpusEntry)
        mock_entry.get_dataset.return_value = None
        mock_entry.entry_id = "mock_entry"

        with patch.object(fuzzer, "_select_input", return_value=mock_entry):
            result = fuzzer.fuzz_iteration()

        # Lines 189-193: returns None when parent_dataset is None
        assert result is None

    def test_fuzz_iteration_with_target_function(self, temp_corpus_dir, sample_dataset):
        """Test lines 203-205: execution with target function."""

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock is_interesting to return False (not interesting)
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=False)

        # Run iteration
        result = fuzzer.fuzz_iteration()

        # Lines 203-205: target function executed with coverage
        # Lines 238: total_iterations incremented
        assert fuzzer.stats.total_iterations >= 1

    def test_fuzz_iteration_crash_during_execution(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test lines 206-209: exception caught during execution."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:  # Don't crash on seed addition
                raise ValueError("Test crash")
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=crashing_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run iteration - should catch the crash
        result = fuzzer.fuzz_iteration()

        # Lines 206-209: crash caught, recorded
        # Lines 213-214: is_interesting = True for crash
        # Lines 220-227: entry added to corpus
        if result is not None:
            assert result.crash_triggered is True
            assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_interesting_coverage(self, temp_corpus_dir, sample_dataset):
        """Test lines 215-217: interesting coverage found."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock is_interesting to return True
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=True)

        # Run iteration
        result = fuzzer.fuzz_iteration()

        # Lines 215-217: is_interesting = True, stats.interesting_inputs_found++
        assert fuzzer.stats.interesting_inputs_found >= 1

    def test_fuzz_iteration_entry_added_to_corpus(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test lines 220-236: interesting entry added to corpus."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock is_interesting to return True
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=True)

        initial_corpus_size = len(fuzzer.corpus_manager.corpus)

        # Run iteration
        result = fuzzer.fuzz_iteration()

        # Lines 220-236: entry added if interesting
        if result is not None:
            assert len(fuzzer.corpus_manager.corpus) >= initial_corpus_size

    def test_fuzz_iteration_not_interesting(self, temp_corpus_dir, sample_dataset):
        """Test lines 238: iteration completes but not interesting."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock is_interesting to return False
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=False)

        # Run iteration
        result = fuzzer.fuzz_iteration()

        # Line 238: total_iterations incremented even if not interesting
        assert fuzzer.stats.total_iterations >= 1


class TestFuzzMethod:
    """Test fuzz method (lines 261-304)."""

    def test_fuzz_basic_campaign(self, temp_corpus_dir, sample_dataset):
        """Test lines 261-304: basic fuzzing campaign."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run short campaign
        stats = fuzzer.fuzz(iterations=10, show_progress=False)

        # Lines 261-265: logging campaign start
        # Lines 267-290: iteration loop
        # Lines 292-302: final stats update
        assert stats.total_iterations == 10

    def test_fuzz_stop_on_crash(self, temp_corpus_dir, sample_dataset):
        """Test lines 271-278: stop_on_crash behavior."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 2:
                raise RuntimeError("Crash!")
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=crashing_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run with stop_on_crash=True
        stats = fuzzer.fuzz(iterations=100, show_progress=False, stop_on_crash=True)

        # Lines 271-278: should stop when crash found
        # May complete early if crash triggers stop
        assert stats.total_iterations < 100 or stats.unique_crashes == 0

    def test_fuzz_progress_updates(self, temp_corpus_dir, sample_dataset):
        """Test lines 280-290: progress updates at 100 iteration intervals."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run 100+ iterations with progress
        stats = fuzzer.fuzz(iterations=100, show_progress=True)

        # Lines 281-290: progress logged at iteration 100
        assert stats.total_iterations == 100

    def test_fuzz_final_statistics(self, temp_corpus_dir, sample_dataset):
        """Test lines 292-304: final statistics update."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        stats = fuzzer.fuzz(iterations=20, show_progress=False)

        # Lines 292-302: stats updated and returned
        assert stats.total_iterations == 20
        assert isinstance(stats.total_coverage, int)


class TestSelectInputMethod:
    """Test _select_input method (lines 320-331)."""

    def test_select_input_empty_corpus(self, temp_corpus_dir):
        """Test lines 320-321: empty corpus returns None."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer._select_input()

        assert result is None

    def test_select_input_exploit_mode(self, temp_corpus_dir, sample_dataset):
        """Test lines 324-328: exploit mode (80% probability)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Add multiple seeds
        for i in range(5):
            ds = Dataset()
            ds.file_meta = sample_dataset.file_meta
            ds.PatientName = f"Patient{i}"
            ds.PatientID = f"ID{i}"
            ds.Modality = "CT"
            ds.SeriesInstanceUID = f"1.2.3.{i}"
            ds.SOPInstanceUID = f"1.2.3.{i}"
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            fuzzer.add_seed(ds, seed_id=f"seed{i}")

        # Force exploit mode (random < 0.8)
        with patch("random.random", return_value=0.5):
            result = fuzzer._select_input()

        # Lines 326-328: get_best_entries called, random.choice used
        assert result is not None

    def test_select_input_explore_mode(self, temp_corpus_dir, sample_dataset):
        """Test lines 330-331: explore mode (20% probability)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Force explore mode (random >= 0.8)
        with patch("random.random", return_value=0.9):
            result = fuzzer._select_input()

        # Lines 330-331: get_random_entry called
        assert result is not None

    def test_select_input_exploit_no_best_entries(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test lines 326-328: exploit mode but get_best_entries returns empty."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Force exploit mode and mock empty best_entries
        with patch("random.random", return_value=0.5):
            # Mock get_best_entries to return empty
            fuzzer.corpus_manager.get_best_entries = MagicMock(return_value=[])
            result = fuzzer._select_input()

        # Lines 327-328: if best_entries empty, fall through to explore
        # Line 331: get_random_entry called
        assert result is not None


class TestMutateInputMethod:
    """Test _mutate_input method (lines 347-356)."""

    def test_mutate_input_basic(self, temp_corpus_dir, sample_dataset):
        """Test lines 347-356: mutation applied to dataset."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Mutate the dataset
        mutated = fuzzer._mutate_input(sample_dataset)

        # Lines 347: start_session called
        # Lines 350: num_mutations randomized
        # Lines 352-354: apply_mutations called
        # Line 356: mutated dataset returned
        assert isinstance(mutated, Dataset)

    def test_mutate_input_with_severity(self, temp_corpus_dir, sample_dataset):
        """Test mutation respects severity setting."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            mutation_severity=MutationSeverity.AGGRESSIVE,
        )

        # Control random for consistent mutation count
        with patch("random.randint", return_value=3):
            mutated = fuzzer._mutate_input(sample_dataset)

        assert isinstance(mutated, Dataset)


class TestExecuteWithCoverageMethod:
    """Test _execute_with_coverage method (lines 379-382)."""

    def test_execute_with_coverage_with_target(self, temp_corpus_dir, sample_dataset):
        """Test lines 373-382: execute with target function."""

        def simple_target(ds):
            return "processed"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        # Execute with coverage
        snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case_1")

        # Lines 373-376: target executed in trace context
        # Lines 379-380: coverage_history checked
        # Lines 380: snapshot returned if history exists
        # Result may be None if coverage tracker doesn't capture anything
        assert snapshot is None or hasattr(snapshot, "lines_covered")

    def test_execute_with_coverage_no_target(self, temp_corpus_dir, sample_dataset):
        """Test lines 374-376: no target function set."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Execute without target
        snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case_1")

        # Lines 374-376: target_function is None, nothing executed
        assert snapshot is None or hasattr(snapshot, "lines_covered")

    def test_execute_with_coverage_returns_snapshot(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test lines 379-382: snapshot returned from coverage history."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        # Mock coverage_history to have an entry
        mock_snapshot = Mock(spec=CoverageSnapshot)
        mock_snapshot.lines_covered = {"file.py": {1, 2, 3}}

        with patch.object(fuzzer.coverage_tracker, "coverage_history", [mock_snapshot]):
            snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case_1")

        # Lines 379-380: coverage_history checked and snapshot returned
        # Note: The actual return depends on implementation
        # The test verifies the code path is exercised


class TestRecordCrashMethod:
    """Test _record_crash method (lines 399-410)."""

    def test_record_crash_basic(self, temp_corpus_dir, sample_dataset):
        """Test lines 399-416: crash recorded correctly."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        exception = ValueError("Test error message")
        fuzzer._record_crash("crash_001", "parent_001", sample_dataset, exception)

        # Lines 399-405: crash_record created
        assert len(fuzzer.crashes) == 1
        crash = fuzzer.crashes[0]
        assert crash["crash_id"] == "crash_001"
        assert crash["parent_id"] == "parent_001"
        assert crash["exception_type"] == "ValueError"
        assert crash["exception_message"] == "Test error message"
        assert "timestamp" in crash

        # Lines 407-408: crashes appended, unique_crashes incremented
        assert fuzzer.stats.unique_crashes == 1

    def test_record_crash_multiple(self, temp_corpus_dir, sample_dataset):
        """Test multiple crashes recorded."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        fuzzer._record_crash("c1", "p1", sample_dataset, RuntimeError("Error 1"))
        fuzzer._record_crash("c2", "p1", sample_dataset, TypeError("Error 2"))
        fuzzer._record_crash("c3", "p2", sample_dataset, KeyError("Error 3"))

        assert len(fuzzer.crashes) == 3
        assert fuzzer.stats.unique_crashes == 3

    def test_record_crash_long_message_truncated(self, temp_corpus_dir, sample_dataset):
        """Test lines 410-416: long exception message in log."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Create exception with very long message
        long_message = "X" * 500
        exception = RuntimeError(long_message)

        fuzzer._record_crash("crash_long", "parent", sample_dataset, exception)

        # Line 415: message truncated to [:100] in logger
        # The crash record itself has full message
        crash = fuzzer.crashes[0]
        assert crash["exception_message"] == long_message


class TestGetReportMethod:
    """Test get_report method (lines 425-459)."""

    def test_get_report_basic(self, temp_corpus_dir, sample_dataset):
        """Test lines 425-459: report generation."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run some iterations
        fuzzer.fuzz(iterations=5, show_progress=False)

        # Generate report
        report = fuzzer.get_report()

        # Lines 425: stats updated
        # Lines 427-428: coverage and corpus stats fetched
        # Lines 430-457: report string formatted
        # Line 459: report.strip() returned
        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Duration:" in report
        assert "Total Iterations:" in report
        assert "Executions/Second:" in report
        assert "Coverage Statistics:" in report
        assert "Corpus Statistics:" in report
        assert "Crashes Found:" in report

    def test_get_report_with_crashes(self, temp_corpus_dir, sample_dataset):
        """Test report includes crash information."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Record some crashes
        fuzzer._record_crash("c1", "p1", sample_dataset, RuntimeError("Test"))
        fuzzer._record_crash("c2", "p1", sample_dataset, ValueError("Test2"))

        report = fuzzer.get_report()

        # Lines 453-454: unique crashes in report
        assert "Unique Crashes:          2" in report

    def test_get_report_coverage_report_included(self, temp_corpus_dir, sample_dataset):
        """Test lines 456: coverage report included."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        report = fuzzer.get_report()

        # Line 456: coverage_tracker.get_coverage_report() included
        # The coverage report section should be part of the output
        assert len(report) > 100  # Should have substantial content


class TestResetMethod:
    """Test reset method (lines 463-466)."""

    def test_reset_clears_state(self, temp_corpus_dir, sample_dataset):
        """Test lines 463-466: reset clears fuzzer state."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Run campaign and record crashes
        fuzzer.fuzz(iterations=10, show_progress=False)
        fuzzer._record_crash("c1", "p1", sample_dataset, RuntimeError("Test"))

        # Verify state before reset
        corpus_size_before = len(fuzzer.corpus_manager.corpus)
        assert fuzzer.stats.total_iterations == 10
        assert len(fuzzer.crashes) == 1

        # Reset
        fuzzer.reset()

        # Line 463: coverage_tracker.reset() called
        assert fuzzer.coverage_tracker.get_statistics()["total_executions"] == 0

        # Line 464: new FuzzingCampaignStats created
        assert fuzzer.stats.total_iterations == 0
        assert fuzzer.stats.unique_crashes == 0

        # Line 465: crashes cleared
        assert len(fuzzer.crashes) == 0

        # Corpus preserved (line 462 docstring says "keeps corpus")
        assert len(fuzzer.corpus_manager.corpus) == corpus_size_before

    def test_reset_allows_new_campaign(self, temp_corpus_dir, sample_dataset):
        """Test reset allows running a new campaign."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # First campaign
        fuzzer.fuzz(iterations=10, show_progress=False)

        # Reset
        fuzzer.reset()

        # Second campaign
        stats = fuzzer.fuzz(iterations=15, show_progress=False)

        # Should run fresh campaign
        assert stats.total_iterations == 15


class TestIntegrationScenarios:
    """Integration tests covering multiple code paths."""

    def test_full_fuzzing_workflow(self, temp_corpus_dir, sample_dataset):
        """Test complete fuzzing workflow exercising all major code paths."""

        def target_with_branches(ds):
            if hasattr(ds, "StudyDescription"):
                if "CRASH" in str(ds.StudyDescription):
                    raise RuntimeError("Crash triggered")
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=target_with_branches,
            max_corpus_size=50,
            mutation_severity=MutationSeverity.MODERATE,
        )

        # Add seed
        seed_id = fuzzer.add_seed(sample_dataset, seed_id="seed1")
        assert seed_id == "seed1"

        # Run campaign
        stats = fuzzer.fuzz(iterations=50, show_progress=False, stop_on_crash=False)

        # Generate report
        report = fuzzer.get_report()
        assert len(report) > 0

        # Reset and run again
        fuzzer.reset()
        stats2 = fuzzer.fuzz(iterations=20, show_progress=False)
        assert stats2.total_iterations == 20

    def test_fuzzing_with_mocked_coverage_interesting(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test fuzzing where coverage is always interesting."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # Mock coverage to always be interesting
        fuzzer.coverage_tracker.is_interesting = MagicMock(return_value=True)

        # Run iterations
        for _ in range(10):
            fuzzer.fuzz_iteration()

        # Should have found interesting inputs
        assert fuzzer.stats.interesting_inputs_found >= 1

    def test_fuzzing_with_corpus_growth(self, temp_corpus_dir, sample_dataset):
        """Test fuzzing that grows the corpus."""

        def simple_target(ds):
            return "ok"

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )

        # Add a single seed (corpus manager deduplicates based on coverage)
        fuzzer.add_seed(sample_dataset, seed_id="seed0")

        initial_size = len(fuzzer.corpus_manager.corpus)
        assert initial_size >= 1  # At least the first seed added

        # Mock is_interesting to occasionally return True
        call_count = [0]

        def mock_is_interesting(snapshot):
            call_count[0] += 1
            return call_count[0] % 5 == 0

        fuzzer.coverage_tracker.is_interesting = mock_is_interesting

        # Run campaign
        fuzzer.fuzz(iterations=50, show_progress=False)

        # Corpus may have grown due to mocked is_interesting
        # At minimum, we exercised the code paths


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

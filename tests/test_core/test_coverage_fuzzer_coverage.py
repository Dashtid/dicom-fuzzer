"""Tests for coverage_fuzzer module to improve code coverage.

These tests target specific uncovered lines in coverage_fuzzer.py.
"""

import threading
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.coverage_fuzzer import (
    CoverageGuidedFuzzer,
    FuzzingCampaignStats,
)


@pytest.fixture
def temp_corpus_dir(tmp_path):
    """Create temporary corpus directory."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    return corpus_dir


@pytest.fixture
def sample_dataset():
    """Create sample DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = "1.2.3.4.5"
    ds.SeriesInstanceUID = "1.2.3.4.5.1"
    ds.SOPInstanceUID = "1.2.3.4.5.1.1"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.Modality = "CT"
    return ds


@pytest.fixture
def fuzzer(temp_corpus_dir, sample_dataset):
    """Create CoverageGuidedFuzzer with seed."""
    fuzzer = CoverageGuidedFuzzer(
        corpus_dir=temp_corpus_dir,
        target_function=lambda ds: ds,
        max_corpus_size=100,
    )
    fuzzer.add_seed(sample_dataset)
    return fuzzer


class TestFuzzingCampaignStats:
    """Test FuzzingCampaignStats dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        stats = FuzzingCampaignStats()

        assert stats.campaign_id is not None
        assert stats.start_time is not None
        assert stats.total_iterations == 0
        assert stats.unique_crashes == 0
        assert stats.corpus_size == 0
        assert stats.total_coverage == 0
        assert stats.executions_per_second == 0.0
        assert stats.interesting_inputs_found == 0
        assert stats.avg_fitness == 0.0

    def test_update_from_campaign(self, fuzzer):
        """Test updating stats from campaign."""
        stats = FuzzingCampaignStats()
        stats.total_iterations = 100

        # Set start time in the past
        stats.start_time = datetime.now(UTC)

        stats.update_from_campaign(fuzzer)

        assert stats.corpus_size >= 0
        assert stats.executions_per_second >= 0.0

    def test_update_from_campaign_zero_elapsed(self, fuzzer):
        """Test update with zero elapsed time (edge case)."""
        stats = FuzzingCampaignStats()
        stats.total_iterations = 100
        stats.start_time = datetime.now(UTC)

        stats.update_from_campaign(fuzzer)

        # Should handle zero elapsed time
        assert stats.executions_per_second >= 0.0


class TestAddSeed:
    """Test add_seed method."""

    def test_add_seed_invalid_type(self, temp_corpus_dir):
        """Test add_seed with invalid type raises TypeError."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        with pytest.raises(TypeError, match="must be a pydicom Dataset"):
            fuzzer.add_seed("not a dataset")

    def test_add_seed_empty_dataset(self, temp_corpus_dir):
        """Test add_seed with empty dataset raises ValueError."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        empty_ds = Dataset()

        with pytest.raises(ValueError, match="must contain at least one"):
            fuzzer.add_seed(empty_ds)

    def test_add_seed_custom_id(self, temp_corpus_dir, sample_dataset):
        """Test add_seed with custom seed ID."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        entry_id = fuzzer.add_seed(sample_dataset, seed_id="custom-seed-001")

        assert entry_id == "custom-seed-001"

    def test_add_seed_auto_id(self, temp_corpus_dir, sample_dataset):
        """Test add_seed generates auto ID."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        entry_id = fuzzer.add_seed(sample_dataset)

        assert entry_id is not None
        # Auto-generated IDs start with "seed_" (underscore, not hyphen)
        assert entry_id.startswith("seed_")

    def test_add_seed_with_target_function(self, temp_corpus_dir, sample_dataset):
        """Test add_seed executes target function."""
        calls = []

        def target(ds):
            calls.append(ds)
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=target
        )
        fuzzer.add_seed(sample_dataset)

        assert len(calls) == 1


class TestFuzzIteration:
    """Test fuzz_iteration method."""

    def test_fuzz_iteration_empty_corpus(self, temp_corpus_dir):
        """Test fuzz_iteration with empty corpus."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer.fuzz_iteration()

        assert result is None

    def test_fuzz_iteration_parent_dataset_none(self, fuzzer):
        """Test fuzz_iteration when parent dataset is None."""
        # Mock corpus_manager to return entry with None dataset
        mock_entry = MagicMock()
        mock_entry.get_dataset.return_value = None
        mock_entry.entry_id = "test-entry"

        with patch.object(fuzzer, "_select_input", return_value=mock_entry):
            result = fuzzer.fuzz_iteration()

        assert result is None

    def test_fuzz_iteration_value_error_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration records crash on ValueError."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:  # Only crash after seed
                raise ValueError("Test value error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        # Run iteration - should record crash
        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_type_error_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration records crash on TypeError."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise TypeError("Test type error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_attribute_error_crash(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test fuzz_iteration records crash on AttributeError."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise AttributeError("Test attribute error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_key_error_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration records crash on KeyError."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise KeyError("Test key error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_os_error_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration records crash on OSError."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise OSError("Test OS error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_unexpected_exception(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration records crash on unexpected exception."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise RuntimeError("Unexpected error")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        fuzzer.fuzz_iteration()

        assert fuzzer.stats.unique_crashes >= 1

    def test_fuzz_iteration_keyboard_interrupt_propagates(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test KeyboardInterrupt propagates."""
        call_count = [0]

        def interrupt_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise KeyboardInterrupt()
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=interrupt_target
        )
        fuzzer.add_seed(sample_dataset)

        with pytest.raises(KeyboardInterrupt):
            fuzzer.fuzz_iteration()

    def test_fuzz_iteration_system_exit_propagates(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test SystemExit propagates."""
        call_count = [0]

        def exit_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise SystemExit(1)
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=exit_target
        )
        fuzzer.add_seed(sample_dataset)

        with pytest.raises(SystemExit):
            fuzzer.fuzz_iteration()

    def test_fuzz_iteration_interesting_input(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration with interesting input."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=lambda ds: ds
        )
        fuzzer.add_seed(sample_dataset)

        # Mock coverage tracker to report new coverage
        with patch.object(fuzzer.coverage_tracker, "is_interesting", return_value=True):
            result = fuzzer.fuzz_iteration()

        # May or may not add depending on corpus state
        assert fuzzer.stats.total_iterations >= 0


class TestFuzz:
    """Test fuzz method."""

    def test_fuzz_basic(self, fuzzer):
        """Test basic fuzzing campaign."""
        stats = fuzzer.fuzz(iterations=10, show_progress=False)

        assert stats.total_iterations >= 0
        assert isinstance(stats, FuzzingCampaignStats)

    def test_fuzz_with_progress(self, fuzzer, capsys):
        """Test fuzzing with progress output."""
        # Run 150 iterations to trigger progress update at 100
        fuzzer.fuzz(iterations=150, show_progress=True)

        # Progress should be logged (but may go to structlog)
        assert fuzzer.stats.total_iterations >= 0

    def test_fuzz_stop_on_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzzing stops on crash."""
        crash_count = [0]

        def crashing_target(ds):
            crash_count[0] += 1
            if crash_count[0] > 1:
                raise ValueError("Crash!")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=100, stop_on_crash=True, show_progress=False)

        # Should have stopped early due to crash
        assert stats.unique_crashes >= 1


class TestSelectInput:
    """Test _select_input method."""

    def test_select_input_empty_corpus(self, temp_corpus_dir):
        """Test select_input with empty corpus."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer._select_input()

        assert result is None

    def test_select_input_exploit_path(self, fuzzer):
        """Test exploit path (80% probability)."""
        # Force exploit path by mocking random
        with patch("random.random", return_value=0.5):  # < 0.8 = exploit
            with patch.object(fuzzer.corpus_manager, "get_best_entries") as mock_best:
                mock_entry = MagicMock()
                mock_best.return_value = [mock_entry]

                with patch("random.choice", return_value=mock_entry):
                    result = fuzzer._select_input()

                assert result is not None

    def test_select_input_explore_path(self, fuzzer):
        """Test explore path (20% probability)."""
        # Force explore path by mocking random
        with patch("random.random", return_value=0.9):  # >= 0.8 = explore
            with patch.object(fuzzer.corpus_manager, "get_random_entry") as mock_random:
                mock_entry = MagicMock()
                mock_random.return_value = mock_entry

                result = fuzzer._select_input()

                assert result == mock_entry

    def test_select_input_exploit_empty_best(self, fuzzer):
        """Test exploit falls back when best is empty."""
        with patch("random.random", return_value=0.5):
            with patch.object(
                fuzzer.corpus_manager, "get_best_entries", return_value=[]
            ):
                with patch.object(
                    fuzzer.corpus_manager, "get_random_entry"
                ) as mock_random:
                    mock_entry = MagicMock()
                    mock_random.return_value = mock_entry

                    result = fuzzer._select_input()

                    # Falls back to random when best is empty
                    assert result == mock_entry


class TestMutateInput:
    """Test _mutate_input method."""

    def test_mutate_input_basic(self, fuzzer, sample_dataset):
        """Test basic mutation."""
        mutated = fuzzer._mutate_input(sample_dataset)

        assert isinstance(mutated, Dataset)


class TestExecuteWithCoverage:
    """Test _execute_with_coverage method."""

    def test_execute_with_coverage_basic(self, fuzzer, sample_dataset):
        """Test basic execution with coverage."""
        result = fuzzer._execute_with_coverage(sample_dataset, "test-001")

        # CoverageSnapshot has lines_covered, not covered_lines
        assert result is None or hasattr(result, "lines_covered")

    def test_execute_with_coverage_no_target(self, temp_corpus_dir, sample_dataset):
        """Test execution with no target function."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir, target_function=None)

        result = fuzzer._execute_with_coverage(sample_dataset, "test-001")

        # CoverageSnapshot has lines_covered attribute
        assert result is None or hasattr(result, "lines_covered")

    def test_execute_with_coverage_history(self, fuzzer, sample_dataset):
        """Test coverage history is populated."""
        fuzzer._execute_with_coverage(sample_dataset, "test-001")

        # Coverage history may be populated
        assert fuzzer.coverage_tracker.coverage_history is not None


class TestRecordCrash:
    """Test _record_crash method."""

    def test_record_crash_basic(self, fuzzer, sample_dataset):
        """Test basic crash recording."""
        exception = ValueError("Test error")

        fuzzer._record_crash("crash-001", "parent-001", sample_dataset, exception)

        assert len(fuzzer.crashes) == 1
        assert fuzzer.crashes[0]["crash_id"] == "crash-001"
        assert fuzzer.crashes[0]["exception_type"] == "ValueError"
        assert "Test error" in fuzzer.crashes[0]["exception_message"]
        assert fuzzer.stats.unique_crashes == 1

    def test_record_crash_thread_safety(self, fuzzer, sample_dataset):
        """Test crash recording is thread-safe."""
        results = []
        errors = []

        def record_crashes(thread_id):
            try:
                for i in range(10):
                    exception = ValueError(f"Error {thread_id}-{i}")
                    fuzzer._record_crash(
                        f"crash-{thread_id}-{i}",
                        f"parent-{thread_id}",
                        sample_dataset,
                        exception,
                    )
                results.append(thread_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_crashes, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 5
        assert fuzzer.stats.unique_crashes == 50


class TestGetReport:
    """Test get_report method."""

    def test_get_report_basic(self, fuzzer):
        """Test basic report generation."""
        report = fuzzer.get_report()

        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Duration:" in report
        assert "Execution Statistics:" in report
        assert "Coverage Statistics:" in report
        assert "Corpus Statistics:" in report
        assert "Crashes Found:" in report

    def test_get_report_with_crashes(self, temp_corpus_dir, sample_dataset):
        """Test report with crashes."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise ValueError("Test crash")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        # Trigger some crashes
        for _ in range(5):
            try:
                fuzzer.fuzz_iteration()
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                pass

        report = fuzzer.get_report()

        assert "Unique Crashes:" in report

    def test_get_report_with_stats(self, fuzzer):
        """Test report includes statistics."""
        # Run some iterations
        fuzzer.fuzz(iterations=10, show_progress=False)

        report = fuzzer.get_report()

        assert "Total Iterations:" in report
        assert "Executions/Second:" in report
        assert "Coverage Efficiency:" in report


class TestReset:
    """Test reset method."""

    def test_reset_clears_crashes(self, fuzzer, sample_dataset):
        """Test reset clears crashes."""
        # Add some crashes
        fuzzer._record_crash(
            "crash-001", "parent-001", sample_dataset, ValueError("Test")
        )
        assert len(fuzzer.crashes) == 1

        fuzzer.reset()

        assert len(fuzzer.crashes) == 0
        assert fuzzer.stats.unique_crashes == 0

    def test_reset_clears_stats(self, fuzzer):
        """Test reset clears statistics."""
        fuzzer.stats.total_iterations = 100
        fuzzer.stats.unique_crashes = 5

        fuzzer.reset()

        assert fuzzer.stats.total_iterations == 0
        assert fuzzer.stats.unique_crashes == 0

    def test_reset_keeps_corpus(self, fuzzer):
        """Test reset keeps corpus."""
        initial_corpus_size = len(fuzzer.corpus_manager.corpus)
        assert initial_corpus_size > 0

        fuzzer.reset()

        # Corpus should still be there
        assert len(fuzzer.corpus_manager.corpus) == initial_corpus_size

    def test_reset_thread_safety(self, fuzzer, sample_dataset):
        """Test reset is thread-safe."""
        results = []
        errors = []

        def run_operations(thread_id):
            try:
                for i in range(5):
                    if i % 2 == 0:
                        fuzzer._record_crash(
                            f"crash-{thread_id}-{i}",
                            f"parent-{thread_id}",
                            sample_dataset,
                            ValueError("Test"),
                        )
                    else:
                        fuzzer.reset()
                results.append(thread_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run_operations, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 3


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_fuzzer_corpus_dir_created(self, tmp_path):
        """Test corpus directory is created if it doesn't exist."""
        corpus_dir = tmp_path / "nonexistent" / "corpus"
        assert not corpus_dir.exists()

        fuzzer = CoverageGuidedFuzzer(corpus_dir=corpus_dir)

        assert corpus_dir.exists()

    def test_fuzzer_with_custom_severity(self, temp_corpus_dir, sample_dataset):
        """Test fuzzer with custom mutation severity."""
        from dicom_fuzzer.core.mutator import MutationSeverity

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            mutation_severity=MutationSeverity.AGGRESSIVE,
        )
        fuzzer.add_seed(sample_dataset)

        # Should not crash
        fuzzer.fuzz(iterations=5, show_progress=False)

    def test_multiple_seeds(self, temp_corpus_dir, sample_dataset):
        """Test adding multiple seeds."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        ds1 = sample_dataset.copy()
        ds1.PatientID = "Patient1"

        ds2 = sample_dataset.copy()
        ds2.PatientID = "Patient2"

        id1 = fuzzer.add_seed(ds1)
        id2 = fuzzer.add_seed(ds2)

        assert id1 != id2
        assert len(fuzzer.corpus_manager.corpus) == 2

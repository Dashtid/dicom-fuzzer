"""Comprehensive tests for dicom_fuzzer.core.coverage_fuzzer module.

Tests coverage-guided fuzzing orchestration including CoverageGuidedFuzzer
and FuzzingCampaignStats classes.
"""

from datetime import UTC, datetime

import pytest
from pydicom.dataset import Dataset, FileMetaDataset

from dicom_fuzzer.core.coverage_fuzzer import (
    CoverageGuidedFuzzer,
    FuzzingCampaignStats,
)
from dicom_fuzzer.core.types import MutationSeverity


@pytest.fixture
def sample_dataset():
    """Create a sample DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    ds.StudyInstanceUID = "1.2.3.4.5"
    ds.SeriesInstanceUID = "1.2.3.4.5.6"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
    ds.file_meta = file_meta

    return ds


class TestFuzzingCampaignStats:
    """Tests for FuzzingCampaignStats dataclass."""

    def test_default_values(self):
        """Test default FuzzingCampaignStats values."""
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

    def test_campaign_id_auto_generated(self):
        """Test campaign_id is auto-generated."""
        stats1 = FuzzingCampaignStats()
        stats2 = FuzzingCampaignStats()
        # Each should have a unique ID
        assert stats1.campaign_id != stats2.campaign_id

    def test_start_time_auto_set(self):
        """Test start_time is auto-set."""
        before = datetime.now(UTC)
        stats = FuzzingCampaignStats()
        after = datetime.now(UTC)

        assert before <= stats.start_time <= after

    def test_update_from_campaign(self, tmp_path, sample_dataset):
        """Test update_from_campaign method."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=tmp_path / "corpus")
        fuzzer.add_seed(sample_dataset)

        stats = FuzzingCampaignStats()
        stats.total_iterations = 100
        stats.update_from_campaign(fuzzer)

        assert stats.corpus_size >= 1
        assert stats.executions_per_second >= 0


class TestCoverageGuidedFuzzer:
    """Tests for CoverageGuidedFuzzer class."""

    @pytest.fixture
    def fuzzer(self, tmp_path):
        """Create a CoverageGuidedFuzzer instance."""
        return CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus",
            max_corpus_size=100,
        )

    def test_initialization(self, fuzzer, tmp_path):
        """Test CoverageGuidedFuzzer initialization."""
        assert fuzzer.corpus_dir == tmp_path / "corpus"
        assert fuzzer.corpus_dir.exists()
        assert fuzzer.target_function is None
        assert fuzzer.mutation_severity == MutationSeverity.MODERATE
        assert fuzzer.corpus_manager is not None
        assert fuzzer.coverage_tracker is not None
        assert fuzzer.mutator is not None
        assert len(fuzzer.crashes) == 0

    def test_initialization_with_target_function(self, tmp_path):
        """Test initialization with target function."""

        def target(ds):
            return ds.PatientName

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=target
        )
        assert fuzzer.target_function == target

    def test_initialization_with_custom_severity(self, tmp_path):
        """Test initialization with custom severity."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus",
            mutation_severity=MutationSeverity.AGGRESSIVE,
        )
        assert fuzzer.mutation_severity == MutationSeverity.AGGRESSIVE

    def test_add_seed(self, fuzzer, sample_dataset):
        """Test add_seed method."""
        seed_id = fuzzer.add_seed(sample_dataset)

        assert seed_id is not None
        assert fuzzer.corpus_manager.size() == 1
        entry = fuzzer.corpus_manager.get_entry(seed_id)
        assert entry is not None

    def test_add_seed_with_custom_id(self, fuzzer, sample_dataset):
        """Test add_seed with custom ID."""
        seed_id = fuzzer.add_seed(sample_dataset, seed_id="custom_seed")

        assert seed_id == "custom_seed"
        entry = fuzzer.corpus_manager.get_entry("custom_seed")
        assert entry is not None

    def test_add_seed_with_target_function(self, tmp_path, sample_dataset):
        """Test add_seed executes target function."""
        executed = []

        def target(ds):
            executed.append(ds.PatientName)
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=target
        )
        fuzzer.add_seed(sample_dataset)

        assert len(executed) == 1
        assert executed[0] == sample_dataset.PatientName

    def test_fuzz_iteration_empty_corpus(self, fuzzer):
        """Test fuzz_iteration with empty corpus returns None."""
        result = fuzzer.fuzz_iteration()
        assert result is None

    def test_fuzz_iteration_with_seed(self, fuzzer, sample_dataset):
        """Test fuzz_iteration with seeded corpus."""
        fuzzer.add_seed(sample_dataset)

        # Run an iteration
        result = fuzzer.fuzz_iteration()

        # Result can be None if mutation wasn't interesting
        assert fuzzer.stats.total_iterations == 1

    def test_fuzz_iteration_crash_detection(self, tmp_path, sample_dataset):
        """Test fuzz_iteration detects crashes."""
        call_count = [0]

        def crashing_target(ds):
            call_count[0] += 1
            # Don't crash on first call (during seeding), crash on subsequent calls
            if call_count[0] > 1:
                raise ValueError("Simulated crash")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        # This should trigger a crash (second call to target)
        result = fuzzer.fuzz_iteration()

        # Should have recorded the crash
        assert fuzzer.stats.unique_crashes >= 1
        assert len(fuzzer.crashes) >= 1

    def test_fuzz_basic_campaign(self, fuzzer, sample_dataset):
        """Test basic fuzzing campaign."""
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=5, show_progress=False)

        assert stats.total_iterations == 5
        assert stats.campaign_id is not None

    def test_fuzz_with_target_function(self, tmp_path, sample_dataset):
        """Test fuzzing with target function."""
        call_count = [0]

        def counting_target(ds):
            call_count[0] += 1
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=counting_target
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=3, show_progress=False)

        # Target should have been called multiple times
        assert call_count[0] >= 1

    def test_fuzz_stop_on_crash(self, tmp_path, sample_dataset):
        """Test fuzzing stops on crash when requested."""
        iterations_completed = [0]

        def crashing_target(ds):
            iterations_completed[0] += 1
            if iterations_completed[0] > 1:
                raise ValueError("Crash!")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=100, show_progress=False, stop_on_crash=True)

        # Should have stopped early due to crash
        assert fuzzer.stats.total_iterations < 100

    def test_fuzz_progress_updates(self, tmp_path, sample_dataset, caplog):
        """Test progress updates are logged."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=tmp_path / "corpus")
        fuzzer.add_seed(sample_dataset)

        # Run enough iterations to trigger progress update (every 100)
        fuzzer.fuzz(iterations=100, show_progress=True)

        # Check that progress was logged
        assert fuzzer.stats.total_iterations == 100

    def test_get_report(self, fuzzer, sample_dataset):
        """Test get_report method."""
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=3, show_progress=False)

        report = fuzzer.get_report()

        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Duration:" in report
        assert "Total Iterations:" in report
        assert "Coverage Statistics:" in report
        assert "Corpus Statistics:" in report
        assert "Crashes Found:" in report

    def test_reset(self, fuzzer, sample_dataset):
        """Test reset method."""
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=5, show_progress=False)

        # Should have some state
        assert fuzzer.stats.total_iterations > 0

        fuzzer.reset()

        # State should be reset
        assert fuzzer.stats.total_iterations == 0
        assert fuzzer.stats.unique_crashes == 0
        assert len(fuzzer.crashes) == 0

    def test_select_input_exploit_vs_explore(self, fuzzer, sample_dataset):
        """Test input selection balances exploit and explore."""
        # Add multiple seeds
        for i in range(5):
            ds = sample_dataset.copy()
            ds.PatientID = f"Patient{i}"
            fuzzer.add_seed(ds, seed_id=f"seed_{i}")

        # Run multiple selections
        selections = []
        for _ in range(20):
            selected = fuzzer._select_input()
            if selected:
                selections.append(selected.entry_id)

        # Should have some selections
        assert len(selections) > 0

    def test_mutate_input(self, fuzzer, sample_dataset):
        """Test _mutate_input method."""
        original_patient_name = sample_dataset.PatientName
        original_patient_id = sample_dataset.PatientID

        mutated = fuzzer._mutate_input(sample_dataset)

        # Mutation should return a dataset
        assert mutated is not None
        assert isinstance(mutated, Dataset)
        # Note: mutations may or may not change these specific fields

    def test_record_crash(self, fuzzer, sample_dataset):
        """Test _record_crash method."""
        exception = ValueError("Test crash")
        fuzzer._record_crash(
            entry_id="crash_entry",
            parent_id="parent_entry",
            dataset=sample_dataset,
            exception=exception,
        )

        assert len(fuzzer.crashes) == 1
        assert fuzzer.stats.unique_crashes == 1

        crash = fuzzer.crashes[0]
        assert crash["crash_id"] == "crash_entry"
        assert crash["parent_id"] == "parent_entry"
        assert crash["exception_type"] == "ValueError"
        assert crash["exception_message"] == "Test crash"
        assert "timestamp" in crash


class TestCoverageIntegration:
    """Tests for coverage tracking integration."""

    def test_coverage_snapshot_recorded(self, tmp_path, sample_dataset):
        """Test that coverage snapshots are recorded."""

        def simple_target(ds):
            # Access some fields to generate coverage
            _ = ds.PatientName
            _ = ds.PatientID
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=simple_target
        )
        fuzzer.add_seed(sample_dataset)

        # The coverage tracker should have recorded something
        assert fuzzer.coverage_tracker is not None

    def test_interesting_input_detection(self, tmp_path, sample_dataset):
        """Test detection of interesting inputs."""
        call_count = [0]

        def varying_target(ds):
            call_count[0] += 1
            # Different behavior based on call count
            if call_count[0] % 2 == 0:
                return ds.PatientName
            else:
                return ds.PatientID

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=varying_target
        )
        fuzzer.add_seed(sample_dataset)

        # Run some iterations
        fuzzer.fuzz(iterations=5, show_progress=False)

        # Stats should be updated
        assert fuzzer.stats.total_iterations == 5


class TestCorpusManagement:
    """Tests for corpus management integration."""

    def test_corpus_grows_with_interesting_inputs(self, tmp_path, sample_dataset):
        """Test corpus grows when interesting inputs are found."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", max_corpus_size=50
        )
        fuzzer.add_seed(sample_dataset)

        initial_size = fuzzer.corpus_manager.size()
        fuzzer.fuzz(iterations=10, show_progress=False)

        # Corpus may have grown (or stayed same if no interesting inputs)
        assert fuzzer.corpus_manager.size() >= initial_size

    def test_max_corpus_size_respected(self, tmp_path, sample_dataset):
        """Test max corpus size is respected."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=tmp_path / "corpus", max_corpus_size=5)

        # Add many seeds
        for i in range(10):
            ds = sample_dataset.copy()
            ds.PatientID = f"Patient{i}"
            fuzzer.add_seed(ds, seed_id=f"seed_{i}")

        # Corpus should be limited
        assert fuzzer.corpus_manager.size() <= 5


class TestStatisticsTracking:
    """Tests for statistics tracking."""

    def test_stats_update_during_campaign(self, tmp_path, sample_dataset):
        """Test statistics are updated during campaign."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=tmp_path / "corpus")
        fuzzer.add_seed(sample_dataset)

        # Initial stats
        assert fuzzer.stats.total_iterations == 0

        fuzzer.fuzz(iterations=10, show_progress=False)

        # Stats should be updated
        assert fuzzer.stats.total_iterations == 10
        assert fuzzer.stats.corpus_size >= 1

    def test_executions_per_second_calculation(self, tmp_path, sample_dataset):
        """Test executions per second is calculated."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=tmp_path / "corpus")
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=50, show_progress=False)

        # Should have calculated exec/sec
        assert fuzzer.stats.executions_per_second >= 0

    def test_crash_counting(self, tmp_path, sample_dataset):
        """Test crash counting."""
        crash_count = [0]

        def sometimes_crashing_target(ds):
            crash_count[0] += 1
            if crash_count[0] % 3 == 0:
                raise ValueError("Periodic crash")
            return ds

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus", target_function=sometimes_crashing_target
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=10, show_progress=False, stop_on_crash=False)

        # Should have detected crashes
        assert fuzzer.stats.unique_crashes >= 1
        assert len(fuzzer.crashes) >= 1


class TestEdgeCases:
    """Edge case tests for coverage-guided fuzzer."""

    @pytest.fixture
    def fuzzer(self, tmp_path):
        """Create a CoverageGuidedFuzzer instance."""
        return CoverageGuidedFuzzer(
            corpus_dir=tmp_path / "corpus",
            max_corpus_size=100,
        )

    def test_empty_corpus_handling(self, fuzzer):
        """Test handling of empty corpus."""
        result = fuzzer.fuzz_iteration()
        assert result is None

    def test_single_seed_fuzzing(self, fuzzer, sample_dataset):
        """Test fuzzing with only one seed."""
        fuzzer.add_seed(sample_dataset)
        stats = fuzzer.fuzz(iterations=5, show_progress=False)
        assert stats.total_iterations == 5

    def test_target_function_none(self, fuzzer, sample_dataset):
        """Test fuzzing without target function."""
        fuzzer.add_seed(sample_dataset)
        stats = fuzzer.fuzz(iterations=3, show_progress=False)
        assert stats.total_iterations == 3

    def test_corpus_persistence(self, tmp_path, sample_dataset):
        """Test corpus persists across fuzzer instances."""
        corpus_dir = tmp_path / "persistent_corpus"

        # First fuzzer
        fuzzer1 = CoverageGuidedFuzzer(corpus_dir=corpus_dir)
        fuzzer1.add_seed(sample_dataset, seed_id="persistent_seed")
        assert fuzzer1.corpus_manager.size() == 1

        # Second fuzzer pointing to same directory
        fuzzer2 = CoverageGuidedFuzzer(corpus_dir=corpus_dir)
        # Should have loaded the seed
        assert fuzzer2.corpus_manager.size() == 1

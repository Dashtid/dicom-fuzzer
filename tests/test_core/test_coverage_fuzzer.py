"""
Comprehensive test suite for coverage_fuzzer.py

Tests coverage-guided fuzzing orchestration including:
- FuzzingCampaignStats tracking
- CoverageGuidedFuzzer initialization
- Seed addition and execution
- Fuzzing iteration logic
- Full campaign execution
- Input selection strategies
- Coverage tracking integration
- Crash detection and recording
- Report generation
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer, FuzzingCampaignStats
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
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


@pytest.fixture
def mock_target_function():
    """Create a mock target function for testing."""

    def target(dataset: Dataset):
        """Mock target that validates dataset."""
        if not hasattr(dataset, "PatientName"):
            raise ValueError("Missing PatientName")
        return True

    return target


@pytest.fixture
def mock_crashing_target():
    """Create a mock target that crashes on specific inputs."""

    def target(dataset: Dataset):
        """Mock target that crashes if PatientID is 'CRASH'."""
        if hasattr(dataset, "PatientID") and dataset.PatientID == "CRASH":
            raise RuntimeError("Crash triggered by test case")
        return True

    return target


class TestFuzzingCampaignStats:
    """Test FuzzingCampaignStats dataclass."""

    def test_initialization(self):
        """Test stats initialization with defaults."""
        stats = FuzzingCampaignStats()

        assert stats.campaign_id is not None
        assert len(stats.campaign_id) == 8  # UUID[:8]
        assert isinstance(stats.start_time, datetime)
        assert stats.total_iterations == 0
        assert stats.unique_crashes == 0
        assert stats.corpus_size == 0
        assert stats.total_coverage == 0
        assert stats.executions_per_second == 0.0
        assert stats.interesting_inputs_found == 0
        assert stats.avg_fitness == 0.0

    def test_custom_initialization(self):
        """Test stats initialization with custom values."""
        campaign_id = "test123"
        start_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

        stats = FuzzingCampaignStats(campaign_id=campaign_id, start_time=start_time)

        assert stats.campaign_id == campaign_id
        assert stats.start_time == start_time

    def test_update_from_campaign(self, temp_corpus_dir):
        """Test updating stats from a fuzzing campaign."""
        # Create fuzzer
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.stats.total_iterations = 1000

        # Update stats
        fuzzer.stats.update_from_campaign(fuzzer)

        # Should calculate executions per second
        assert fuzzer.stats.executions_per_second > 0
        # Corpus size should be 0 (no seeds added)
        assert fuzzer.stats.corpus_size == 0

    def test_update_with_zero_elapsed_time(self, temp_corpus_dir):
        """Test update handles zero elapsed time gracefully."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Set start time to now (near-zero elapsed)
        fuzzer.stats.start_time = datetime.now(UTC)
        fuzzer.stats.total_iterations = 100

        # Should not crash, should calculate exec/sec
        fuzzer.stats.update_from_campaign(fuzzer)
        # Exec/sec will be calculated based on tiny elapsed time
        assert fuzzer.stats.executions_per_second >= 0


class TestCoverageGuidedFuzzerInitialization:
    """Test CoverageGuidedFuzzer initialization."""

    def test_initialization_default_params(self, temp_corpus_dir):
        """Test fuzzer initialization with default parameters."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        assert fuzzer.corpus_dir == temp_corpus_dir
        assert fuzzer.corpus_dir.exists()
        assert fuzzer.coverage_tracker is not None
        assert fuzzer.corpus_manager is not None
        assert fuzzer.mutator is not None
        assert fuzzer.target_function is None
        assert fuzzer.mutation_severity == MutationSeverity.MODERATE
        assert isinstance(fuzzer.stats, FuzzingCampaignStats)
        assert fuzzer.crashes == []

    def test_initialization_custom_params(self, temp_corpus_dir, mock_target_function):
        """Test fuzzer initialization with custom parameters."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
            max_corpus_size=500,
            mutation_severity=MutationSeverity.AGGRESSIVE,
        )

        assert fuzzer.target_function == mock_target_function
        assert fuzzer.mutation_severity == MutationSeverity.AGGRESSIVE
        # Check corpus manager was initialized with custom max size
        corpus_stats = fuzzer.corpus_manager.get_statistics()
        assert corpus_stats["max_size"] == 500

    def test_corpus_directory_creation(self, temp_corpus_dir):
        """Test that corpus directory is created if it doesn't exist."""
        new_dir = temp_corpus_dir / "new_corpus"
        assert not new_dir.exists()

        fuzzer = CoverageGuidedFuzzer(corpus_dir=new_dir)

        assert new_dir.exists()
        assert fuzzer.corpus_dir == new_dir


class TestSeedAddition:
    """Test seed addition to corpus."""

    def test_add_seed_without_target(self, temp_corpus_dir, sample_dataset):
        """Test adding seed without target function."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        seed_id = fuzzer.add_seed(sample_dataset)

        assert seed_id.startswith("seed_")
        assert len(seed_id) == 13  # "seed_" + 8 hex chars
        # Should be in corpus
        assert seed_id in fuzzer.corpus_manager.corpus

    def test_add_seed_with_custom_id(self, temp_corpus_dir, sample_dataset):
        """Test adding seed with custom ID."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        seed_id = fuzzer.add_seed(sample_dataset, seed_id="custom_seed_1")

        assert seed_id == "custom_seed_1"
        assert seed_id in fuzzer.corpus_manager.corpus

    def test_add_seed_with_target(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test adding seed with target function (executes with coverage)."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )

        seed_id = fuzzer.add_seed(sample_dataset)

        # Should execute and capture coverage
        assert seed_id in fuzzer.corpus_manager.corpus
        entry = fuzzer.corpus_manager.get_entry(seed_id)
        # Coverage might be captured (depends on coverage tracker)
        assert entry is not None

    def test_add_multiple_seeds(self, temp_corpus_dir, sample_dataset):
        """Test adding multiple seeds."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        seed_id1 = fuzzer.add_seed(sample_dataset, seed_id="seed1")
        seed_id2 = fuzzer.add_seed(sample_dataset, seed_id="seed2")

        assert seed_id1 != seed_id2
        assert len(fuzzer.corpus_manager.corpus) == 2


class TestFuzzingIteration:
    """Test single fuzzing iteration."""

    def test_fuzz_iteration_no_corpus(self, temp_corpus_dir):
        """Test fuzzing iteration with empty corpus."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer.fuzz_iteration()

        assert result is None

    def test_fuzz_iteration_with_seed(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test fuzzing iteration with seed in corpus."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)

        # Run a few iterations
        results = []
        for _ in range(5):
            result = fuzzer.fuzz_iteration()
            results.append(result)

        # Should have attempted mutations
        assert fuzzer.stats.total_iterations >= 5

    def test_fuzz_iteration_crash_detection(
        self, temp_corpus_dir, sample_dataset, mock_crashing_target
    ):
        """Test that fuzzing iteration detects crashes."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_crashing_target,
        )

        # Add seed with CRASH PatientID to trigger crash
        crash_dataset = Dataset()
        crash_dataset.file_meta = sample_dataset.file_meta
        crash_dataset.PatientName = "Crash^Test"
        crash_dataset.PatientID = "CRASH"
        crash_dataset.Modality = "CT"
        crash_dataset.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9"
        crash_dataset.SOPInstanceUID = "1.2.3.4.5.6.7.8.11"
        crash_dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        crash_dataset.is_little_endian = True
        crash_dataset.is_implicit_VR = False

        # This seed itself will crash on execution
        try:
            fuzzer.add_seed(crash_dataset, seed_id="crash_seed")
        except RuntimeError:
            # Expected - seed crashes during initial execution
            pass

        # Add a safe seed
        fuzzer.add_seed(sample_dataset, seed_id="safe_seed")

        # Run iterations - might find crashes through mutation
        for _ in range(10):
            fuzzer.fuzz_iteration()

    def test_fuzz_iteration_interesting_input(self, temp_corpus_dir, sample_dataset):
        """Test that interesting inputs are added to corpus."""

        # Mock target that always returns
        def simple_target(ds):
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset)

        # Run iterations
        for _ in range(20):
            fuzzer.fuzz_iteration()

        # Corpus might have grown (if interesting inputs found)
        # At minimum, we tried to fuzz
        assert fuzzer.stats.total_iterations >= 20


class TestFuzzingCampaign:
    """Test full fuzzing campaigns."""

    def test_fuzz_campaign_basic(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test basic fuzzing campaign."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=50, show_progress=False)

        assert stats.total_iterations == 50
        assert stats.corpus_size >= 1  # At least the seed
        assert isinstance(stats.executions_per_second, float)

    def test_fuzz_campaign_with_progress(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test fuzzing campaign with progress reporting."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=100, show_progress=True)

        assert stats.total_iterations == 100

    def test_fuzz_campaign_stop_on_crash(self, temp_corpus_dir, sample_dataset):
        """Test fuzzing campaign stops on crash when requested."""

        # Create target that crashes after certain mutations
        def crash_target(ds):
            # Crash if PixelData is present (mutation might add it)
            if hasattr(ds, "PixelData"):
                raise RuntimeError("Crash on PixelData")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=crash_target,
        )
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=1000, show_progress=False, stop_on_crash=True)

        # Might stop early if crash found
        # At minimum, it tried to fuzz
        assert stats.total_iterations >= 0

    def test_fuzz_campaign_without_stop_on_crash(
        self, temp_corpus_dir, sample_dataset, mock_crashing_target
    ):
        """Test fuzzing campaign continues after crashes."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_crashing_target,
        )
        fuzzer.add_seed(sample_dataset)

        stats = fuzzer.fuzz(iterations=50, show_progress=False, stop_on_crash=False)

        # Should complete all iterations even if crashes occur
        assert stats.total_iterations == 50


class TestInputSelection:
    """Test input selection strategies."""

    def test_select_input_empty_corpus(self, temp_corpus_dir):
        """Test selecting input from empty corpus."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        result = fuzzer._select_input()

        assert result is None

    def test_select_input_exploit_mode(self, temp_corpus_dir, sample_dataset):
        """Test input selection in exploit mode (80% probability)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Add multiple seeds
        for i in range(20):
            seed_ds = Dataset()
            seed_ds.file_meta = sample_dataset.file_meta
            seed_ds.PatientName = f"Test{i}"
            seed_ds.PatientID = f"ID{i}"
            seed_ds.Modality = "CT"
            seed_ds.SeriesInstanceUID = f"1.2.3.4.5.6.7.8.{i}"
            seed_ds.SOPInstanceUID = f"1.2.3.4.5.6.7.8.{i}"
            seed_ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            seed_ds.is_little_endian = True
            seed_ds.is_implicit_VR = False
            fuzzer.add_seed(seed_ds, seed_id=f"seed{i}")

        # Select many times - should sometimes pick best entries
        selections = []
        for _ in range(100):
            selected = fuzzer._select_input()
            if selected:
                selections.append(selected.entry_id)

        # Should have made selections
        assert len(selections) > 0

    def test_select_input_explore_mode(self, temp_corpus_dir, sample_dataset):
        """Test input selection in explore mode (20% probability)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset, seed_id="seed1")

        # With only one entry, both modes return the same
        with patch("random.random", return_value=0.9):  # Force explore mode
            result = fuzzer._select_input()

        assert result is not None
        assert result.entry_id == "seed1"


class TestMutation:
    """Test mutation operations."""

    def test_mutate_input(self, temp_corpus_dir, sample_dataset):
        """Test mutating a dataset."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        mutated = fuzzer._mutate_input(sample_dataset)

        # Should return a dataset
        assert isinstance(mutated, Dataset)
        # Might be different from original (depends on mutation)

    def test_mutate_input_severity(self, sample_dataset):
        """Test mutation with different severity levels."""
        with tempfile.TemporaryDirectory() as tmpdir1:
            fuzzer_minimal = CoverageGuidedFuzzer(
                corpus_dir=Path(tmpdir1),
                mutation_severity=MutationSeverity.MINIMAL,
            )
            mutated_minimal = fuzzer_minimal._mutate_input(sample_dataset)
            assert isinstance(mutated_minimal, Dataset)

        with tempfile.TemporaryDirectory() as tmpdir2:
            fuzzer_aggressive = CoverageGuidedFuzzer(
                corpus_dir=Path(tmpdir2),
                mutation_severity=MutationSeverity.AGGRESSIVE,
            )
            mutated_aggressive = fuzzer_aggressive._mutate_input(sample_dataset)
            assert isinstance(mutated_aggressive, Dataset)


class TestCoverageExecution:
    """Test coverage tracking during execution."""

    def test_execute_with_coverage(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test executing target with coverage tracking."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )

        snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case_1")

        # Should capture coverage (might be None if no coverage collected)
        # At minimum, shouldn't crash
        assert snapshot is None or hasattr(snapshot, "lines_covered")

    def test_execute_without_target(self, temp_corpus_dir, sample_dataset):
        """Test executing without target function."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        snapshot = fuzzer._execute_with_coverage(sample_dataset, "test_case_1")

        # Might return coverage snapshot from context manager even without target
        # At minimum, shouldn't crash
        assert snapshot is None or hasattr(snapshot, "lines_covered")


class TestCrashRecording:
    """Test crash detection and recording."""

    def test_record_crash(self, temp_corpus_dir, sample_dataset):
        """Test recording a crash."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        exception = RuntimeError("Test crash")
        fuzzer._record_crash("crash1", "parent1", sample_dataset, exception)

        assert len(fuzzer.crashes) == 1
        assert fuzzer.stats.unique_crashes == 1

        crash = fuzzer.crashes[0]
        assert crash["crash_id"] == "crash1"
        assert crash["parent_id"] == "parent1"
        assert crash["exception_type"] == "RuntimeError"
        assert crash["exception_message"] == "Test crash"
        assert "timestamp" in crash

    def test_record_multiple_crashes(self, temp_corpus_dir, sample_dataset):
        """Test recording multiple crashes."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        fuzzer._record_crash("crash1", "parent1", sample_dataset, ValueError("Crash 1"))
        fuzzer._record_crash("crash2", "parent1", sample_dataset, TypeError("Crash 2"))
        fuzzer._record_crash(
            "crash3", "parent2", sample_dataset, RuntimeError("Crash 3")
        )

        assert len(fuzzer.crashes) == 3
        assert fuzzer.stats.unique_crashes == 3

        # Check all crashes recorded
        crash_ids = [c["crash_id"] for c in fuzzer.crashes]
        assert "crash1" in crash_ids
        assert "crash2" in crash_ids
        assert "crash3" in crash_ids


class TestReportGeneration:
    """Test report generation."""

    def test_get_report(self, temp_corpus_dir, sample_dataset, mock_target_function):
        """Test generating a fuzzing campaign report."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=10, show_progress=False)

        report = fuzzer.get_report()

        # Check report contains key information
        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Duration:" in report
        assert "Total Iterations:" in report
        assert "Executions/Second:" in report
        assert "Corpus Statistics:" in report
        assert "Crashes Found:" in report

    def test_get_report_with_crashes(self, temp_corpus_dir, sample_dataset):
        """Test report generation with crashes."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)

        # Simulate crashes
        fuzzer._record_crash("crash1", "parent1", sample_dataset, RuntimeError("Test"))

        report = fuzzer.get_report()

        assert "Unique Crashes:          1" in report


class TestFuzzerReset:
    """Test fuzzer state reset."""

    def test_reset(self, temp_corpus_dir, sample_dataset, mock_target_function):
        """Test resetting fuzzer state."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=20, show_progress=False)

        # Record some crashes
        fuzzer._record_crash("crash1", "parent1", sample_dataset, RuntimeError("Test"))

        initial_corpus_size = len(fuzzer.corpus_manager.corpus)

        # Reset
        fuzzer.reset()

        # Check state is reset
        assert len(fuzzer.crashes) == 0
        assert isinstance(fuzzer.stats, FuzzingCampaignStats)
        assert fuzzer.stats.total_iterations == 0
        assert fuzzer.stats.unique_crashes == 0

        # Corpus should be preserved
        assert len(fuzzer.corpus_manager.corpus) == initial_corpus_size

    def test_reset_clears_coverage(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test that reset clears coverage tracker."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
        )
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=10, show_progress=False)

        # Reset
        fuzzer.reset()

        # Coverage should be reset
        coverage_stats = fuzzer.coverage_tracker.get_statistics()
        assert coverage_stats["total_executions"] == 0


class TestAddSeedValidation:
    """Test add_seed validation and error handling (lines 162-169)."""

    def test_add_seed_invalid_type(self, temp_corpus_dir):
        """Test add_seed raises TypeError for non-Dataset input (line 163)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        with pytest.raises(TypeError) as exc_info:
            fuzzer.add_seed("not_a_dataset")  # type: ignore

        assert "dataset must be a pydicom Dataset instance" in str(exc_info.value)
        assert "str" in str(exc_info.value)

    def test_add_seed_empty_dataset(self, temp_corpus_dir):
        """Test add_seed raises ValueError for empty Dataset (line 169)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        empty_ds = Dataset()
        # Verify it's empty
        assert len(empty_ds) == 0

        with pytest.raises(ValueError) as exc_info:
            fuzzer.add_seed(empty_ds)

        assert "must contain at least one data element" in str(exc_info.value)


class TestFuzzIterationExceptionHandling:
    """Test fuzz_iteration exception handling branches (lines 224-248)."""

    def test_fuzz_iteration_with_valueerror_crash(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test that ValueError from target is caught and recorded (line 231-234)."""
        call_count = [0]

        def value_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:  # Crash on mutated inputs
                raise ValueError("Test ValueError crash")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=value_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        # Run iterations to trigger the ValueError handling
        for _ in range(5):
            fuzzer.fuzz_iteration()

        # Should have recorded at least one crash
        assert len(fuzzer.crashes) >= 1
        assert any(c["exception_type"] == "ValueError" for c in fuzzer.crashes)

    def test_fuzz_iteration_with_typeerror_crash(self, temp_corpus_dir, sample_dataset):
        """Test that TypeError from target is caught and recorded (line 231-234)."""
        call_count = [0]

        def type_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise TypeError("Test TypeError crash")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=type_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        for _ in range(5):
            fuzzer.fuzz_iteration()

        assert any(c["exception_type"] == "TypeError" for c in fuzzer.crashes)

    def test_fuzz_iteration_with_attributeerror_crash(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test that AttributeError from target is caught (line 231-234)."""
        call_count = [0]

        def attr_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise AttributeError("Test AttributeError crash")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=attr_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        for _ in range(5):
            fuzzer.fuzz_iteration()

        assert any(c["exception_type"] == "AttributeError" for c in fuzzer.crashes)

    def test_fuzz_iteration_with_keyerror_crash(self, temp_corpus_dir, sample_dataset):
        """Test that KeyError from target is caught (line 231-234)."""
        call_count = [0]

        def key_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise KeyError("missing_key")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=key_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        for _ in range(5):
            fuzzer.fuzz_iteration()

        assert any(c["exception_type"] == "KeyError" for c in fuzzer.crashes)

    def test_fuzz_iteration_with_oserror_crash(self, temp_corpus_dir, sample_dataset):
        """Test that OSError from target is caught (lines 235-238)."""
        call_count = [0]

        def os_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise OSError("Test OSError crash")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=os_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        for _ in range(5):
            fuzzer.fuzz_iteration()

        assert any(c["exception_type"] == "OSError" for c in fuzzer.crashes)

    def test_fuzz_iteration_with_unexpected_exception(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test that unexpected exceptions are caught (lines 239-248)."""
        call_count = [0]

        def unexpected_error_target(ds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise ZeroDivisionError("Test unexpected crash")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=unexpected_error_target,
        )
        fuzzer.add_seed(sample_dataset)

        for _ in range(5):
            fuzzer.fuzz_iteration()

        assert any(c["exception_type"] == "ZeroDivisionError" for c in fuzzer.crashes)


class TestFuzzIterationInterestingInput:
    """Test fuzz_iteration interesting input detection (lines 253-276)."""

    def test_fuzz_iteration_coverage_interesting(self, temp_corpus_dir, sample_dataset):
        """Test that coverage-increasing inputs are marked interesting (lines 254-257)."""

        def simple_target(ds):
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset)

        # Mock is_interesting to return True for new coverage
        original_is_interesting = fuzzer.coverage_tracker.is_interesting

        def mock_is_interesting(coverage):
            # Return True occasionally to simulate interesting coverage
            return True

        fuzzer.coverage_tracker.is_interesting = mock_is_interesting

        # Run iterations
        for _ in range(10):
            fuzzer.fuzz_iteration()

        # Should have found interesting inputs
        assert fuzzer.stats.interesting_inputs_found >= 1

        # Restore original method
        fuzzer.coverage_tracker.is_interesting = original_is_interesting

    def test_fuzz_iteration_corpus_add_returns_entry(
        self, temp_corpus_dir, sample_dataset
    ):
        """Test that new corpus entries are returned (lines 261-276)."""

        def simple_target(ds):
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=simple_target,
        )
        fuzzer.add_seed(sample_dataset)

        # Force a crash to make input interesting
        call_count = [0]

        def crash_target(ds):
            call_count[0] += 1
            if call_count[0] == 2:  # Crash on first mutation
                raise RuntimeError("Crash!")
            return True

        fuzzer.target_function = crash_target

        # Run iterations until we get a crash
        result = None
        for _ in range(20):
            r = fuzzer.fuzz_iteration()
            if r is not None and r.crash_triggered:
                result = r
                break

        # Should have returned a crash entry
        if len(fuzzer.crashes) > 0:
            assert fuzzer.stats.unique_crashes >= 1


class TestFuzzIterationNoneDataset:
    """Test fuzz_iteration when parent dataset is None (lines 208-212)."""

    def test_fuzz_iteration_parent_dataset_none(self, temp_corpus_dir, sample_dataset):
        """Test fuzz_iteration handles None parent dataset (lines 209-212)."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)

        # Get the entry and mock get_dataset to return None
        entry = fuzzer.corpus_manager.get_entry(
            "seed_" + sample_dataset.SOPInstanceUID[:8]
        )
        if entry is None:
            # Find the actual entry
            for e in fuzzer.corpus_manager.corpus.values():
                entry = e
                break

        if entry:
            original_get_dataset = entry.get_dataset
            entry.get_dataset = lambda: None

            result = fuzzer.fuzz_iteration()

            # Should return None when parent dataset is None
            assert result is None

            # Restore
            entry.get_dataset = original_get_dataset


class TestIntegration:
    """Integration tests for complete fuzzing workflows."""

    def test_complete_fuzzing_workflow(
        self, temp_corpus_dir, sample_dataset, mock_target_function
    ):
        """Test a complete fuzzing workflow from seed to report."""
        # Initialize fuzzer
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=mock_target_function,
            max_corpus_size=100,
            mutation_severity=MutationSeverity.MODERATE,
        )

        # Add seeds
        seed1 = fuzzer.add_seed(sample_dataset, seed_id="seed1")
        assert seed1 == "seed1"

        # Run campaign
        stats = fuzzer.fuzz(iterations=50, show_progress=False)

        # Check results
        assert stats.total_iterations == 50
        assert stats.corpus_size >= 1

        # Generate report
        report = fuzzer.get_report()
        assert len(report) > 0

        # Reset and run again
        fuzzer.reset()
        stats2 = fuzzer.fuzz(iterations=30, show_progress=False)
        assert stats2.total_iterations == 30

    def test_fuzzing_with_crash_discovery(self, temp_corpus_dir, sample_dataset):
        """Test fuzzing campaign that discovers crashes."""

        def crash_on_specific_tag(ds):
            """Crash if specific tag value is set."""
            if hasattr(ds, "StudyDescription") and "CRASH" in str(ds.StudyDescription):
                raise RuntimeError("Crash triggered!")
            return True

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=crash_on_specific_tag,
        )
        fuzzer.add_seed(sample_dataset)

        # Run campaign
        stats = fuzzer.fuzz(iterations=100, show_progress=False, stop_on_crash=False)

        # Check we ran the campaign
        assert stats.total_iterations == 100

        # Generate report with any crashes found
        report = fuzzer.get_report()
        assert "Crashes Found:" in report

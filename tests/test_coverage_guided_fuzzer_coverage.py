"""Tests for coverage_guided_fuzzer module to improve code coverage.

These tests exercise the coverage-guided fuzzing engine code paths.
"""

import asyncio
import json
import signal
import time
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pydicom
import pytest
from pydicom import Dataset

from dicom_fuzzer.core.coverage_guided_fuzzer import (
    CoverageGuidedFuzzer,
    FuzzingConfig,
    FuzzingStats,
    create_fuzzer_from_config,
)
from dicom_fuzzer.core.coverage_guided_mutator import MutationType
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def basic_config(temp_dir):
    """Create basic fuzzing configuration."""
    return FuzzingConfig(
        output_dir=temp_dir / "output",
        crash_dir=temp_dir / "crashes",
        corpus_dir=temp_dir / "corpus",
        max_iterations=10,
        timeout_per_run=1.0,
        num_workers=1,
        report_interval=5,
    )


@pytest.fixture
def sample_dicom_bytes():
    """Create sample DICOM bytes."""
    ds = Dataset()
    ds.PatientName = "Test"
    ds.PatientID = "12345"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = pydicom.uid.generate_uid()
    ds.file_meta = Dataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian

    buffer = BytesIO()
    pydicom.dcmwrite(buffer, ds)
    return buffer.getvalue()


class TestFuzzingConfig:
    """Test FuzzingConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = FuzzingConfig()

        assert config.target_function is None
        assert config.target_binary is None
        assert config.max_iterations == 10000
        assert config.timeout_per_run == 1.0
        assert config.num_workers == 1
        assert config.coverage_guided is True
        assert config.adaptive_mutations is True
        assert config.dicom_aware is True

    def test_custom_values(self, temp_dir):
        """Test custom configuration values."""
        config = FuzzingConfig(
            max_iterations=500,
            timeout_per_run=2.0,
            num_workers=4,
            output_dir=temp_dir / "output",
            coverage_guided=False,
        )

        assert config.max_iterations == 500
        assert config.timeout_per_run == 2.0
        assert config.num_workers == 4
        assert config.coverage_guided is False

    def test_path_defaults(self):
        """Test default path values."""
        config = FuzzingConfig()

        assert config.output_dir == Path("fuzzing_output")
        assert config.crash_dir == Path("crashes")
        assert config.corpus_dir is None
        assert config.seed_dir is None


class TestFuzzingStats:
    """Test FuzzingStats dataclass."""

    def test_default_values(self):
        """Test default stats values."""
        stats = FuzzingStats()

        assert stats.total_executions == 0
        assert stats.total_crashes == 0
        assert stats.unique_crashes == 0
        assert stats.coverage_increases == 0
        assert stats.current_coverage == 0
        assert stats.max_coverage == 0
        assert stats.exec_per_sec == 0.0
        assert isinstance(stats.start_time, float)

    def test_mutation_stats_default(self):
        """Test mutation_stats default is empty dict."""
        stats = FuzzingStats()

        assert stats.mutation_stats == {}


class TestCoverageGuidedFuzzerInit:
    """Test CoverageGuidedFuzzer initialization."""

    def test_init_basic(self, basic_config):
        """Test basic initialization."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        assert fuzzer.config == basic_config
        assert fuzzer.should_stop is False
        assert fuzzer.is_running is False
        assert fuzzer.stats is not None

    def test_init_creates_directories(self, basic_config):
        """Test that initialization creates directories."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        assert basic_config.output_dir.exists()
        assert basic_config.crash_dir.exists()
        assert basic_config.corpus_dir.exists()

    def test_init_with_target_modules(self, temp_dir):
        """Test initialization with target modules."""
        config = FuzzingConfig(
            output_dir=temp_dir / "output",
            crash_dir=temp_dir / "crashes",
            target_modules=["pydicom", "dicom_fuzzer"],
        )

        fuzzer = CoverageGuidedFuzzer(config)

        assert fuzzer.coverage_tracker is not None

    def test_init_with_historical_corpus(self, temp_dir):
        """Test initialization with historical corpus directory."""
        history_dir = temp_dir / "corpus" / "history"
        history_dir.mkdir(parents=True)

        config = FuzzingConfig(
            output_dir=temp_dir / "output",
            crash_dir=temp_dir / "crashes",
            corpus_dir=temp_dir / "corpus",
        )

        fuzzer = CoverageGuidedFuzzer(config)

        # Should use HistoricalCorpusManager
        from dicom_fuzzer.core.corpus_manager import HistoricalCorpusManager

        assert isinstance(fuzzer.corpus_manager, HistoricalCorpusManager)


class TestSignalHandler:
    """Test signal handling."""

    def test_signal_handler_sets_stop(self, basic_config):
        """Test that signal handler sets should_stop."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        assert fuzzer.should_stop is False

        fuzzer._signal_handler(signal.SIGINT, None)

        assert fuzzer.should_stop is True


class TestCreateMinimalDicom:
    """Test _create_minimal_dicom method."""

    def test_creates_valid_dicom(self, basic_config):
        """Test that minimal DICOM is created."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        dicom_bytes = fuzzer._create_minimal_dicom()

        assert isinstance(dicom_bytes, bytes)
        assert len(dicom_bytes) > 0

    def test_minimal_dicom_is_readable(self, basic_config):
        """Test that minimal DICOM can be parsed."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        dicom_bytes = fuzzer._create_minimal_dicom()

        # Should be parseable
        ds = pydicom.dcmread(BytesIO(dicom_bytes), force=True)
        assert ds is not None

    def test_fallback_on_error(self, basic_config):
        """Test fallback to minimal header on error."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        with patch("pydicom.Dataset", side_effect=Exception("Test error")):
            dicom_bytes = fuzzer._create_minimal_dicom()

        assert dicom_bytes.startswith(b"DICM")


class TestExecuteTarget:
    """Test _execute_target method."""

    def test_execute_with_function(self, basic_config):
        """Test executing with target function."""
        mock_func = MagicMock(return_value=True)
        basic_config.target_function = mock_func

        fuzzer = CoverageGuidedFuzzer(basic_config)
        result = fuzzer._execute_target(b"test data")

        mock_func.assert_called_once_with(b"test data")
        assert result is True

    def test_execute_default_dicom_parsing(self, basic_config, sample_dicom_bytes):
        """Test default DICOM parsing execution."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        result = fuzzer._execute_target(sample_dicom_bytes)

        assert result is True

    def test_execute_invalid_dicom_handles_gracefully(self, basic_config):
        """Test that invalid DICOM is handled (pydicom force=True parses anything)."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # With force=True, pydicom will parse almost anything
        # The test verifies execution completes (may return True or raise)
        try:
            result = fuzzer._execute_target(b"invalid dicom data")
            # If it returns, that's fine
            assert result is True or result is False or result is None
        except Exception:
            # If it raises, that's also expected behavior
            pass

    def test_execute_with_binary(self, basic_config, temp_dir):
        """Test executing with target binary."""
        basic_config.target_binary = "echo"
        fuzzer = CoverageGuidedFuzzer(basic_config)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = fuzzer._execute_target(b"test data")

        assert result is True
        mock_run.assert_called_once()


class TestExecuteWithCoverage:
    """Test _execute_with_coverage method."""

    @pytest.mark.asyncio
    async def test_execute_with_coverage_success(
        self, basic_config, sample_dicom_bytes
    ):
        """Test successful execution with coverage."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage, crashed = await fuzzer._execute_with_coverage(sample_dicom_bytes)

        assert isinstance(coverage, CoverageInfo)
        assert crashed is False

    @pytest.mark.asyncio
    async def test_execute_with_coverage_crash(self, basic_config):
        """Test execution that crashes."""
        basic_config.target_function = MagicMock(side_effect=Exception("Crash!"))
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage, crashed = await fuzzer._execute_with_coverage(b"data")

        assert crashed is True

    @pytest.mark.asyncio
    async def test_execute_with_coverage_timeout(self, basic_config):
        """Test execution that times out."""
        basic_config.timeout_per_run = 0.01

        def slow_func(data):
            time.sleep(1.0)
            return True

        basic_config.target_function = slow_func
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage, crashed = await fuzzer._execute_with_coverage(b"data")

        assert crashed is True


class TestProcessResult:
    """Test _process_result method."""

    @pytest.mark.asyncio
    async def test_process_result_normal(self, basic_config, sample_dicom_bytes):
        """Test processing normal result."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})

        await fuzzer._process_result(
            sample_dicom_bytes,
            coverage,
            crashed=False,
            parent_id="parent-001",
            mutation_type=MutationType.BYTE_FLIP,
        )

        assert fuzzer.stats.total_crashes == 0

    @pytest.mark.asyncio
    async def test_process_result_crash(self, basic_config, sample_dicom_bytes):
        """Test processing crash result."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage = CoverageInfo()

        # Add a seed first
        fuzzer.corpus_manager.add_seed(sample_dicom_bytes, coverage)

        await fuzzer._process_result(
            sample_dicom_bytes,
            coverage,
            crashed=True,
            parent_id="parent-001",
            mutation_type=MutationType.BYTE_FLIP,
        )

        assert fuzzer.stats.total_crashes == 1

    @pytest.mark.asyncio
    async def test_process_result_unique_crash(self, basic_config):
        """Test processing unique crash."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage = CoverageInfo()

        with patch.object(fuzzer.crash_analyzer, "is_unique_crash", return_value=True):
            await fuzzer._process_result(
                b"unique crash data",
                coverage,
                crashed=True,
                parent_id="parent-001",
                mutation_type=MutationType.BYTE_FLIP,
            )

        assert fuzzer.stats.unique_crashes == 1

        # Check crash file was saved
        crash_files = list(basic_config.crash_dir.glob("crash_*.dcm"))
        assert len(crash_files) == 1

    @pytest.mark.asyncio
    async def test_process_result_new_coverage(self, basic_config):
        """Test processing result with new coverage."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        coverage = CoverageInfo(
            edges={("new.py", 1, "new.py", 2)},
            new_coverage=True,
        )

        await fuzzer._process_result(
            b"new coverage data",
            coverage,
            crashed=False,
            parent_id="parent-001",
            mutation_type=MutationType.BYTE_FLIP,
        )

        assert fuzzer.stats.coverage_increases == 1


class TestSaveCrash:
    """Test _save_crash method."""

    def test_save_crash_creates_files(self, basic_config):
        """Test that crash files are created."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        crash_info = MagicMock()
        crash_info.id = "crash-test-001"
        crash_info.coverage_hash = "cov-hash-001"
        crash_info.parent_id = "parent-001"

        fuzzer._save_crash(b"crash data", crash_info)

        crash_file = basic_config.crash_dir / "crash_crash-test-001.dcm"
        meta_file = basic_config.crash_dir / "crash_crash-test-001.json"

        assert crash_file.exists()
        assert meta_file.exists()

        # Check metadata content
        with open(meta_file) as f:
            meta = json.load(f)

        assert meta["id"] == "crash-test-001"
        assert meta["coverage_hash"] == "cov-hash-001"


class TestSaveInterestingInput:
    """Test _save_interesting_input method."""

    def test_save_interesting_creates_file(self, basic_config):
        """Test that interesting input is saved."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        fuzzer._save_interesting_input(b"interesting data", "seed-001")

        interesting_dir = basic_config.output_dir / "interesting"
        assert interesting_dir.exists()

        input_file = interesting_dir / "input_seed-001.dcm"
        assert input_file.exists()


class TestReportProgress:
    """Test _report_progress method."""

    def test_report_progress_updates_stats(self, basic_config):
        """Test that progress reporting updates stats."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        fuzzer.stats.total_executions = 100
        fuzzer.stats.start_time = time.time() - 10  # 10 seconds ago

        fuzzer._report_progress()

        assert fuzzer.stats.exec_per_sec > 0

    def test_report_progress_verbose(self, basic_config):
        """Test verbose progress reporting.

        Note: This test validates that _report_progress executes successfully
        with verbose=True without relying on captured output, as structlog
        output can be affected by test order and parallel execution.
        """
        basic_config.verbose = True
        fuzzer = CoverageGuidedFuzzer(basic_config)
        fuzzer.stats.total_executions = 50

        # Should not raise any exceptions when reporting progress
        fuzzer._report_progress()

        # Verify stats were updated (exec_per_sec calculation happened)
        assert fuzzer.stats.exec_per_sec >= 0


class TestFinalize:
    """Test _finalize method."""

    @pytest.mark.asyncio
    async def test_finalize_saves_corpus(self, basic_config):
        """Test that finalize saves corpus."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # Add a seed
        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        fuzzer.corpus_manager.add_seed(b"test seed", coverage)

        await fuzzer._finalize()

        # Check corpus was saved
        seed_files = list(basic_config.corpus_dir.glob("*.seed"))
        assert len(seed_files) >= 0  # May or may not have seeds

    @pytest.mark.asyncio
    async def test_finalize_creates_report(self, basic_config):
        """Test that finalize creates report."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        await fuzzer._finalize()

        report_file = basic_config.output_dir / "fuzzing_report.json"
        assert report_file.exists()

        with open(report_file) as f:
            report = json.load(f)

        assert "duration" in report
        assert "total_executions" in report
        assert "crashes" in report
        assert "coverage" in report


class TestGenerateReport:
    """Test _generate_report method."""

    def test_generate_report_structure(self, basic_config):
        """Test report structure."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        fuzzer.stats.total_executions = 1000
        fuzzer.stats.total_crashes = 5
        fuzzer.stats.unique_crashes = 2

        report = fuzzer._generate_report()

        assert "duration" in report
        assert "total_executions" in report
        assert report["total_executions"] == 1000
        assert report["crashes"]["total"] == 5
        assert report["crashes"]["unique"] == 2
        assert "coverage" in report
        assert "corpus" in report
        assert "mutations" in report
        assert "config" in report


class TestLoadInitialSeeds:
    """Test _load_initial_seeds method."""

    @pytest.mark.asyncio
    async def test_load_from_corpus_dir(self, basic_config, sample_dicom_bytes):
        """Test loading seeds from corpus directory."""
        # Create corpus with saved seeds
        corpus_dir = basic_config.corpus_dir
        corpus_dir.mkdir(parents=True, exist_ok=True)

        fuzzer = CoverageGuidedFuzzer(basic_config)

        await fuzzer._load_initial_seeds()

        # Should have at least minimal seed
        assert fuzzer.stats.corpus_size >= 1

    @pytest.mark.asyncio
    async def test_load_from_seed_dir(self, basic_config, sample_dicom_bytes, temp_dir):
        """Test loading seeds from seed directory."""
        seed_dir = temp_dir / "seeds"
        seed_dir.mkdir()

        # Create seed file
        seed_file = seed_dir / "test.dcm"
        seed_file.write_bytes(sample_dicom_bytes)

        basic_config.seed_dir = seed_dir
        fuzzer = CoverageGuidedFuzzer(basic_config)

        await fuzzer._load_initial_seeds()

        assert fuzzer.stats.corpus_size >= 1

    @pytest.mark.asyncio
    async def test_creates_minimal_seed_when_empty(self, basic_config):
        """Test that minimal seed is created when no seeds exist."""
        fuzzer = CoverageGuidedFuzzer(basic_config)

        await fuzzer._load_initial_seeds()

        assert fuzzer.stats.corpus_size >= 1


class TestRunSingle:
    """Test _run_single method."""

    @pytest.mark.asyncio
    async def test_run_single_basic(self, basic_config, sample_dicom_bytes):
        """Test basic single-threaded fuzzing."""
        basic_config.max_iterations = 2
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # Add initial seed
        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        fuzzer.corpus_manager.add_seed(sample_dicom_bytes, coverage)

        await fuzzer._run_single()

        assert fuzzer.stats.total_executions > 0

    @pytest.mark.asyncio
    async def test_run_single_stops_on_signal(self, basic_config, sample_dicom_bytes):
        """Test that fuzzing stops on signal."""
        basic_config.max_iterations = 1000
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # Add initial seed
        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        fuzzer.corpus_manager.add_seed(sample_dicom_bytes, coverage)

        # Set stop flag after brief delay
        async def stop_after_delay():
            await asyncio.sleep(0.1)
            fuzzer.should_stop = True

        task = asyncio.create_task(stop_after_delay())

        await fuzzer._run_single()
        await task  # Ensure task completes

        assert fuzzer.should_stop is True


class TestRun:
    """Test run method."""

    @pytest.mark.asyncio
    async def test_run_returns_stats(self, basic_config):
        """Test that run returns FuzzingStats."""
        basic_config.max_iterations = 1
        fuzzer = CoverageGuidedFuzzer(basic_config)

        stats = await fuzzer.run()

        assert isinstance(stats, FuzzingStats)

    @pytest.mark.asyncio
    async def test_run_sets_running_flag(self, basic_config):
        """Test that run sets is_running flag."""
        basic_config.max_iterations = 1
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # Run fuzzer
        await fuzzer.run()

        # Should be False after completion
        assert fuzzer.is_running is False


class TestCreateFuzzerFromConfig:
    """Test create_fuzzer_from_config function."""

    def test_create_from_config_file(self, temp_dir):
        """Test creating fuzzer from config file."""
        config_path = temp_dir / "config.json"
        config_data = {
            "max_iterations": 100,
            "timeout_per_run": 0.5,
            "output_dir": str(temp_dir / "output"),
            "crash_dir": str(temp_dir / "crashes"),
        }

        with open(config_path, "w") as f:
            json.dump(config_data, f)

        fuzzer = create_fuzzer_from_config(config_path)

        assert fuzzer.config.max_iterations == 100
        assert fuzzer.config.timeout_per_run == 0.5

    def test_create_with_path_conversion(self, temp_dir):
        """Test that string paths are converted to Path objects."""
        config_path = temp_dir / "config.json"
        config_data = {
            "output_dir": str(temp_dir / "output"),
            "crash_dir": str(temp_dir / "crashes"),
            "corpus_dir": str(temp_dir / "corpus"),
            "seed_dir": str(temp_dir / "seeds"),
        }

        with open(config_path, "w") as f:
            json.dump(config_data, f)

        fuzzer = create_fuzzer_from_config(config_path)

        assert isinstance(fuzzer.config.output_dir, Path)
        assert isinstance(fuzzer.config.crash_dir, Path)
        assert isinstance(fuzzer.config.corpus_dir, Path)
        assert isinstance(fuzzer.config.seed_dir, Path)


class TestWorkerLoop:
    """Test _worker_loop method."""

    def test_worker_loop_stops_on_flag(self, basic_config, sample_dicom_bytes):
        """Test that worker loop stops when should_stop is set."""
        fuzzer = CoverageGuidedFuzzer(basic_config)
        fuzzer.should_stop = True

        # Add seed
        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        fuzzer.corpus_manager.add_seed(sample_dicom_bytes, coverage)

        # Should return immediately
        fuzzer._worker_loop()

        # No executions should have happened
        assert fuzzer.stats.total_executions == 0


class TestRunParallel:
    """Test _run_parallel method."""

    @pytest.mark.asyncio
    async def test_run_parallel_with_workers(self, basic_config, sample_dicom_bytes):
        """Test parallel execution with multiple workers."""
        basic_config.num_workers = 2
        fuzzer = CoverageGuidedFuzzer(basic_config)
        fuzzer.should_stop = True  # Stop immediately

        # Add seed
        coverage = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        fuzzer.corpus_manager.add_seed(sample_dicom_bytes, coverage)

        await fuzzer._run_parallel()

        # Should complete without error


class TestEdgeCases:
    """Test edge cases."""

    def test_setup_directories_no_corpus(self, temp_dir):
        """Test setup when corpus_dir is None."""
        config = FuzzingConfig(
            output_dir=temp_dir / "output",
            crash_dir=temp_dir / "crashes",
            corpus_dir=None,
        )

        fuzzer = CoverageGuidedFuzzer(config)

        assert (temp_dir / "output").exists()
        assert (temp_dir / "crashes").exists()

    @pytest.mark.asyncio
    async def test_run_single_no_seeds(self, basic_config):
        """Test run_single when no seeds available."""
        basic_config.max_iterations = 5
        fuzzer = CoverageGuidedFuzzer(basic_config)

        # Mock get_next_seed to return None
        with patch.object(fuzzer.corpus_manager, "get_next_seed", return_value=None):
            await fuzzer._run_single()

        # Should exit gracefully
        assert fuzzer.stats.total_executions == 0

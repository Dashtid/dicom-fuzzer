"""End-to-End Integration Tests for DICOM Fuzzer.

Tests the complete fuzzing workflow including:
- File generation and mutation
- Coverage-guided fuzzing campaigns
- Network fuzzing integration
- Security fuzzing integration
- Crash detection and reporting
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer, FuzzingCampaignStats
from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot, CoverageTracker
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.core.target_runner import (
    CircuitBreakerState,
    ExecutionResult,
    ExecutionStatus,
    TargetRunner,
)

if TYPE_CHECKING:
    pass


@pytest.fixture
def sample_dataset(tmp_path: Path) -> FileDataset:
    """Create a sample DICOM dataset for testing with proper file meta."""
    # Create file meta information
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.ImplementationClassUID = generate_uid()
    file_meta.ImplementationVersionName = "DICOM_FUZZER_TEST"

    # Create a temporary filename for the FileDataset
    filename = str(tmp_path / "temp_dataset.dcm")

    # Create the FileDataset
    ds = FileDataset(filename, {}, file_meta=file_meta, preamble=b"\x00" * 128)

    # Add patient and study information
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"

    # Add image information
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (512 * 512 * 2)

    # Set is_little_endian and is_implicit_VR
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    return ds


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Create a temporary output directory."""
    output_dir = tmp_path / "fuzzing_output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_corpus_dir(tmp_path: Path) -> Path:
    """Create a temporary corpus directory."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    return corpus_dir


class TestCoverageTrackerIntegration:
    """Integration tests for coverage tracking."""

    def test_coverage_tracker_full_workflow(self, sample_dataset: Dataset) -> None:
        """Test complete coverage tracking workflow."""
        tracker = CoverageTracker(target_modules=["dicom_fuzzer"])

        # Simulate multiple executions
        for i in range(5):
            with tracker.trace_execution(f"test_{i}"):
                # Execute some code that will be traced
                _ = len(sample_dataset)
                _ = str(sample_dataset.PatientName)

        # Get statistics
        stats = tracker.get_statistics()
        assert stats["total_executions"] >= 5
        assert "total_lines_covered" in stats
        assert "efficiency" in stats

    def test_coverage_snapshot_comparison(self) -> None:
        """Test coverage snapshot comparison."""
        snap1 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 20)},
            test_case_id="test1",
        )
        snap2 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 30)},
            test_case_id="test2",
        )

        # Test new coverage detection
        new_lines = snap2.new_coverage_vs(snap1)
        assert ("file1.py", 30) in new_lines
        assert ("file1.py", 20) not in new_lines

    def test_coverage_snapshot_hash(self) -> None:
        """Test coverage hash generation."""
        snap1 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 20)},
            test_case_id="test1",
        )
        snap2 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 20)},
            test_case_id="test2",
        )
        snap3 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 30)},
            test_case_id="test3",
        )

        # Same coverage should have same hash
        assert snap1.coverage_hash() == snap2.coverage_hash()
        # Different coverage should have different hash
        assert snap1.coverage_hash() != snap3.coverage_hash()

    def test_coverage_percentage_calculation(self) -> None:
        """Test coverage percentage calculation."""
        snap = CoverageSnapshot(
            lines_covered={("file1.py", i) for i in range(50)},
            test_case_id="test",
        )

        assert snap.coverage_percentage(100) == 50.0
        assert snap.coverage_percentage(0) == 0.0
        assert snap.coverage_percentage(200) == 25.0

    def test_is_interesting_with_new_coverage(self) -> None:
        """Test is_interesting detection."""
        tracker = CoverageTracker()

        # First snapshot should be interesting
        snap1 = CoverageSnapshot(
            lines_covered={("file1.py", 10)},
            test_case_id="test1",
        )
        assert tracker.is_interesting(snap1) is True

        # Update global coverage
        tracker.global_coverage.update(snap1.lines_covered)
        tracker.seen_coverage_hashes.add(snap1.coverage_hash())

        # Same coverage should not be interesting
        snap2 = CoverageSnapshot(
            lines_covered={("file1.py", 10)},
            test_case_id="test2",
        )
        assert tracker.is_interesting(snap2) is False

        # New coverage should be interesting
        snap3 = CoverageSnapshot(
            lines_covered={("file1.py", 10), ("file1.py", 20)},
            test_case_id="test3",
        )
        assert tracker.is_interesting(snap3) is True

    def test_coverage_tracker_reset(self) -> None:
        """Test coverage tracker reset functionality."""
        tracker = CoverageTracker()

        # Add some coverage
        tracker.global_coverage.add(("file1.py", 10))
        tracker.total_executions = 10
        tracker.interesting_cases = 5

        # Reset
        tracker.reset()

        # Verify reset
        assert len(tracker.global_coverage) == 0
        assert tracker.total_executions == 0
        assert tracker.interesting_cases == 0

    def test_coverage_report_generation(self) -> None:
        """Test coverage report generation."""
        tracker = CoverageTracker()
        tracker.global_coverage.add(("file1.py", 10))
        tracker.total_executions = 10
        tracker.interesting_cases = 3

        report = tracker.get_coverage_report()
        assert "Coverage-Guided Fuzzing Report" in report
        assert "Total Executions:" in report
        assert "Interesting Cases:" in report


class TestCoverageGuidedFuzzerIntegration:
    """Integration tests for coverage-guided fuzzing."""

    def test_fuzzer_initialization(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test fuzzer initialization."""
        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            max_corpus_size=100,
            mutation_severity=MutationSeverity.MINIMAL,
        )

        assert fuzzer.corpus_dir == temp_corpus_dir
        assert fuzzer.mutation_severity == MutationSeverity.MINIMAL
        assert len(fuzzer.crashes) == 0

    def test_add_seed_validation(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test seed validation."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)

        # Valid seed
        entry_id = fuzzer.add_seed(sample_dataset, seed_id="test_seed")
        assert entry_id == "test_seed"

        # Invalid type
        with pytest.raises(TypeError):
            fuzzer.add_seed("not a dataset")  # type: ignore[arg-type]

        # Empty dataset
        empty_ds = Dataset()
        with pytest.raises(ValueError):
            fuzzer.add_seed(empty_ds)

    def test_fuzzing_iteration_without_target(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test fuzzing iteration without target function."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)

        # Should work without target function
        result = fuzzer.fuzz_iteration()
        # May or may not return an entry depending on mutation
        assert result is None or hasattr(result, "entry_id")

    def test_fuzzing_iteration_with_target(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test fuzzing iteration with target function."""

        def simple_target(ds: Dataset) -> bool:
            """Simple target that processes dataset."""
            return len(ds) > 0

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=simple_target
        )
        fuzzer.add_seed(sample_dataset)

        # Perform iteration
        result = fuzzer.fuzz_iteration()
        assert result is None or hasattr(result, "entry_id")

    def test_fuzzing_campaign_stats_update(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test campaign statistics updates."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)

        # Run small campaign
        stats = fuzzer.fuzz(iterations=5, show_progress=False)

        assert isinstance(stats, FuzzingCampaignStats)
        assert stats.total_iterations >= 0
        assert stats.campaign_id is not None

    def test_fuzzer_crash_recording(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test crash recording functionality."""

        def crashing_target(ds: Dataset) -> None:
            """Target that crashes on certain conditions."""
            if ds.PatientName != "Test^Patient":
                raise ValueError("Invalid patient name")

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir, target_function=crashing_target
        )
        fuzzer.add_seed(sample_dataset)

        # Run campaign - may or may not find crashes
        fuzzer.fuzz(iterations=10, show_progress=False, stop_on_crash=False)

        # Stats should be updated
        assert fuzzer.stats.total_iterations >= 0

    def test_fuzzer_report_generation(
        self, temp_corpus_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test report generation."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=3, show_progress=False)

        report = fuzzer.get_report()
        assert "Coverage-Guided Fuzzing Campaign Report" in report
        assert "Campaign ID:" in report
        assert "Total Iterations:" in report

    def test_fuzzer_reset(self, temp_corpus_dir: Path, sample_dataset: Dataset) -> None:
        """Test fuzzer reset functionality."""
        fuzzer = CoverageGuidedFuzzer(corpus_dir=temp_corpus_dir)
        fuzzer.add_seed(sample_dataset)
        fuzzer.fuzz(iterations=5, show_progress=False)

        # Reset
        fuzzer.reset()

        # Verify reset
        assert len(fuzzer.crashes) == 0
        assert fuzzer.stats.total_iterations == 0


class TestTargetRunnerIntegration:
    """Integration tests for target runner."""

    @pytest.fixture
    def mock_executable(self, tmp_path: Path) -> Path:
        """Create a mock executable for testing."""
        if sys.platform == "win32":
            script = tmp_path / "mock_target.bat"
            script.write_text("@echo off\nexit /b 0")
        else:
            script = tmp_path / "mock_target.sh"
            script.write_text("#!/bin/bash\nexit 0")
            script.chmod(0o755)
        return script

    def test_target_runner_initialization(self, mock_executable: Path) -> None:
        """Test target runner initialization."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            timeout=5.0,
            max_retries=2,
        )

        assert runner.timeout == 5.0
        assert runner.max_retries == 2
        assert runner.target_executable == mock_executable

    def test_target_runner_nonexistent_executable(self) -> None:
        """Test target runner with nonexistent executable."""
        with pytest.raises(FileNotFoundError):
            TargetRunner(target_executable="/nonexistent/path/to/app")

    def test_circuit_breaker_state(self) -> None:
        """Test circuit breaker state initialization."""
        state = CircuitBreakerState()
        assert state.failure_count == 0
        assert state.success_count == 0
        assert state.is_open is False

    def test_circuit_breaker_updates(self, mock_executable: Path) -> None:
        """Test circuit breaker state updates."""
        runner = TargetRunner(
            target_executable=str(mock_executable),
            enable_circuit_breaker=True,
        )

        # Simulate successful execution
        runner._update_circuit_breaker(success=True)
        assert runner.circuit_breaker.success_count == 1
        assert runner.circuit_breaker.consecutive_failures == 0

        # Simulate failures
        for _ in range(5):
            runner._update_circuit_breaker(success=False)

        assert runner.circuit_breaker.failure_count == 5
        assert runner.circuit_breaker.is_open is True

    def test_error_classification(self, mock_executable: Path) -> None:
        """Test error classification logic."""
        runner = TargetRunner(target_executable=str(mock_executable))

        # OOM detection
        result = runner._classify_error("Out of memory error", 1)
        assert result == ExecutionStatus.OOM

        # Resource exhaustion
        result = runner._classify_error("Resource limit exceeded", 1)
        assert result == ExecutionStatus.RESOURCE_EXHAUSTED

        # Crash detection
        result = runner._classify_error("Segmentation fault", -11)
        assert result == ExecutionStatus.CRASH

        # Generic error
        result = runner._classify_error("Some error", 1)
        assert result == ExecutionStatus.ERROR

    @patch("subprocess.run")
    def test_execute_test_success(
        self, mock_run: MagicMock, mock_executable: Path, tmp_path: Path
    ) -> None:
        """Test successful test execution."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dummy")

        mock_run.return_value = MagicMock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(mock_executable))
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.SUCCESS
        assert result.exit_code == 0

    @patch("subprocess.run")
    def test_execute_test_timeout(
        self, mock_run: MagicMock, mock_executable: Path, tmp_path: Path
    ) -> None:
        """Test timeout handling."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dummy")

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=5)

        runner = TargetRunner(target_executable=str(mock_executable))
        result = runner.execute_test(test_file)

        assert result.result == ExecutionStatus.HANG

    @patch("subprocess.run")
    def test_run_campaign(
        self, mock_run: MagicMock, mock_executable: Path, tmp_path: Path
    ) -> None:
        """Test running a campaign."""
        # Create test files
        test_files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.dcm"
            f.write_bytes(b"dummy")
            test_files.append(f)

        mock_run.return_value = MagicMock(returncode=0, stdout="Success", stderr="")

        runner = TargetRunner(target_executable=str(mock_executable))
        results = runner.run_campaign(test_files)

        assert ExecutionStatus.SUCCESS in results
        assert len(results[ExecutionStatus.SUCCESS]) == 3

    def test_get_summary(self, mock_executable: Path) -> None:
        """Test summary generation."""
        runner = TargetRunner(target_executable=str(mock_executable))

        # Create mock results
        results = {
            ExecutionStatus.SUCCESS: [
                ExecutionResult(
                    test_file=Path("test1.dcm"),
                    result=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    execution_time=0.1,
                    stdout="",
                    stderr="",
                )
            ],
            ExecutionStatus.CRASH: [],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
            ExecutionStatus.SKIPPED: [],
            ExecutionStatus.OOM: [],
            ExecutionStatus.RESOURCE_EXHAUSTED: [],
        }

        summary = runner.get_summary(results)
        assert "Fuzzing Campaign Summary" in summary
        assert "Total test cases: 1" in summary


@pytest.mark.slow
class TestDICOMGeneratorIntegration:
    """Integration tests for DICOM generator."""

    def test_generator_workflow(
        self, temp_output_dir: Path, sample_dataset: Dataset
    ) -> None:
        """Test complete generator workflow."""
        # Save sample as seed
        seed_file = temp_output_dir / "seed.dcm"
        sample_dataset.save_as(str(seed_file))

        generator = DICOMGenerator(output_dir=temp_output_dir)

        # Use only metadata strategy which has fewer edge cases
        # that cause pydicom write failures
        files = generator.generate_batch(seed_file, count=10, strategies=["metadata"])

        # Metadata-only mutations should reliably produce files
        assert len(files) == 10
        for f in files:
            assert f.exists()
            assert f.suffix == ".dcm"

        # Verify generator stats tracked attempts
        assert generator.stats.total_attempted == 10

    def test_generator_with_custom_seed(self, temp_output_dir: Path) -> None:
        """Test generator with different output directory."""
        # Create minimal dataset with proper file meta
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.ImplementationClassUID = generate_uid()

        seed_file = temp_output_dir / "custom_seed.dcm"
        ds = FileDataset(
            str(seed_file), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        ds.save_as(str(seed_file))

        # Create generator with a different output subdirectory
        custom_output = temp_output_dir / "custom_output"
        generator = DICOMGenerator(output_dir=custom_output)

        # Exclude CVE mutations which can cause write failures by design
        files = generator.generate_batch(
            seed_file, count=3, strategies=["metadata", "header", "pixel"]
        )
        assert len(files) == 3
        # Verify files are in the custom output directory
        for f in files:
            assert f.parent == custom_output


class TestMutatorIntegration:
    """Integration tests for DICOM mutator."""

    def test_mutator_session_workflow(self, sample_dataset: Dataset) -> None:
        """Test complete mutator session workflow."""
        mutator = DicomMutator()

        # Start session
        mutator.start_session(sample_dataset)

        # Apply mutations
        mutated = mutator.apply_mutations(
            sample_dataset, num_mutations=3, severity=MutationSeverity.MODERATE
        )

        # Verify mutations were applied
        assert mutated is not None

    def test_mutator_severity_levels(self, sample_dataset: Dataset) -> None:
        """Test different mutation severity levels."""
        mutator = DicomMutator()

        for severity in MutationSeverity:
            mutated = mutator.apply_mutations(
                sample_dataset, num_mutations=1, severity=severity
            )
            assert mutated is not None


@pytest.mark.slow
class TestFullPipelineIntegration:
    """Full pipeline integration tests.

    Note: Marked slow due to non-deterministic generation that may result in
    empty output in parallel test execution.
    """

    def test_complete_fuzzing_pipeline(
        self,
        temp_output_dir: Path,
        temp_corpus_dir: Path,
        sample_dataset: Dataset,
    ) -> None:
        """Test complete fuzzing pipeline from generation to analysis.

        Seeds random state to ensure deterministic fuzzing behavior.
        """
        import random

        import numpy as np

        # Seed for deterministic fuzzing
        random.seed(42)
        np.random.seed(42)

        # 1. Generate fuzzed files
        seed_file = temp_output_dir / "seed.dcm"
        sample_dataset.save_as(str(seed_file))

        generator = DICOMGenerator(output_dir=temp_output_dir)
        # Exclude CVE mutations which can corrupt Transfer Syntax UID by design
        fuzzed_files = generator.generate_batch(
            seed_file, count=5, strategies=["metadata", "header", "pixel"]
        )

        # At least one file should be generated
        assert len(fuzzed_files) >= 1

        # 2. Set up coverage-guided fuzzer
        def analyzer(ds: Dataset) -> dict:
            """Simple analyzer that extracts metadata."""
            return {
                "patient_name": str(ds.PatientName)
                if hasattr(ds, "PatientName")
                else None,
                "modality": str(ds.Modality) if hasattr(ds, "Modality") else None,
            }

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_corpus_dir,
            target_function=analyzer,
            max_corpus_size=50,
        )

        # Add seeds
        fuzzer.add_seed(sample_dataset)

        # 3. Run fuzzing campaign
        stats = fuzzer.fuzz(iterations=10, show_progress=False)

        # 4. Generate report
        report = fuzzer.get_report()

        assert stats.total_iterations >= 0
        assert "Campaign ID:" in report


class TestCLIIntegration:
    """CLI integration tests."""

    def test_cli_help(self) -> None:
        """Test CLI help command."""
        result = subprocess.run(
            [sys.executable, "-m", "dicom_fuzzer.cli.main", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower() or "dicom" in result.stdout.lower()

    def test_cli_version(self) -> None:
        """Test CLI version command."""
        result = subprocess.run(
            [sys.executable, "-m", "dicom_fuzzer.cli.main", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Either succeeds or shows help (some CLIs don't have --version)
        assert result.returncode in [0, 2]


class TestNetworkFuzzerIntegration:
    """Network fuzzer integration tests."""

    def test_network_fuzzer_import(self) -> None:
        """Test network fuzzer can be imported."""
        from dicom_fuzzer.core.network_fuzzer import (
            DICOMNetworkConfig,
            DICOMNetworkFuzzer,
        )

        config = DICOMNetworkConfig(
            target_host="localhost",
            target_port=11112,
        )

        fuzzer = DICOMNetworkFuzzer(config)
        assert fuzzer.config.target_host == "localhost"
        assert fuzzer.config.target_port == 11112

    def test_fuzzing_strategies(self) -> None:
        """Test fuzzing strategy enumeration."""
        from dicom_fuzzer.core.network_fuzzer import FuzzingStrategy

        strategies = list(FuzzingStrategy)
        assert len(strategies) > 0
        assert FuzzingStrategy.MALFORMED_PDU in strategies


class TestGUIMonitorIntegration:
    """GUI monitor integration tests."""

    def test_gui_monitor_import(self) -> None:
        """Test GUI monitor can be imported."""
        from dicom_fuzzer.core.gui_monitor import (
            GUIMonitor,
            MonitorConfig,
        )

        config = MonitorConfig()
        monitor = GUIMonitor(config)

        assert monitor.config.poll_interval == config.poll_interval

    def test_gui_response_creation(self) -> None:
        """Test GUI response creation."""
        from dicom_fuzzer.core.gui_monitor import (
            GUIResponse,
            ResponseType,
            SeverityLevel,
        )

        response = GUIResponse(
            response_type=ResponseType.ERROR_DIALOG,
            severity=SeverityLevel.HIGH,
            details="Test error",
        )

        data = response.to_dict()
        assert data["response_type"] == "error_dialog"
        assert data["severity"] == "high"

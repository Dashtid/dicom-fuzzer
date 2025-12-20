"""
Cross-Module Integration Tests

Tests that exercise multiple modules together in realistic workflows.
This improves overall coverage by ensuring modules interact correctly.
"""

import tempfile
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.corpus import CorpusManager
from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer
from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot, CoverageTracker
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.profiler import FuzzingMetrics, PerformanceProfiler
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.core.validator import DicomValidator


class TestCrossModuleIntegration:
    """Tests that exercise multiple modules in realistic scenarios."""

    @pytest.fixture
    def sample_dataset(self):
        """Create sample DICOM dataset."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.SOPInstanceUID = "1.2.3.4.7"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.Modality = "CT"
        ds.Rows = 512
        ds.Columns = 512
        return ds

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            dirs = {
                "corpus": base / "corpus",
                "output": base / "output",
                "reports": base / "reports",
                "crashes": base / "crashes",
            }
            for d in dirs.values():
                d.mkdir(parents=True, exist_ok=True)
            yield dirs

    def test_profiler_metrics_calculations(self):
        """Test all FuzzingMetrics calculation methods."""
        metrics = FuzzingMetrics()

        metrics.files_generated = 100
        metrics.total_duration = 10.0

        # Test throughput calculation
        throughput = metrics.throughput_per_second()
        assert throughput == 10.0  # 100 files / 10 seconds

        # Test average time per file
        avg_time = metrics.avg_time_per_file()
        assert avg_time == 0.1  # 10 seconds / 100 files

        # Test estimated time remaining
        remaining = metrics.estimated_time_remaining(target=200)
        assert remaining == 10.0  # 100 more files * 0.1 seconds each

    def test_profiler_metrics_edge_cases(self):
        """Test FuzzingMetrics with edge cases."""
        metrics = FuzzingMetrics()

        # Zero duration
        metrics.files_generated = 10
        metrics.total_duration = 0.0
        assert metrics.throughput_per_second() == 0.0

        # Zero files
        metrics.files_generated = 0
        metrics.total_duration = 10.0
        assert metrics.avg_time_per_file() == 0.0

        # Target already reached
        metrics.files_generated = 100
        assert metrics.estimated_time_remaining(target=50) == 0.0

    def test_performance_profiler_with_operations(self):
        """Test PerformanceProfiler recording various operations."""
        profiler = PerformanceProfiler()

        with profiler:
            # Record various operations
            profiler.record_mutation("parse", duration=0.01)
            profiler.record_mutation("mutate", duration=0.05)
            profiler.record_mutation("validate", duration=0.02)
            profiler.record_mutation("parse", duration=0.015)  # Duplicate type

        summary = profiler.get_summary()

        assert summary["duration_seconds"] >= 0
        assert summary["mutations_applied"] == 4

    def test_corpus_manager_full_workflow(self, sample_dataset, temp_dirs):
        """Test corpus manager complete workflow."""
        manager = CorpusManager(
            corpus_dir=temp_dirs["corpus"],
            max_corpus_size=50,
        )

        # Add multiple entries
        for i in range(10):
            # Create coverage snapshot for even entries
            coverage = None
            if i % 2 == 0:
                coverage = CoverageSnapshot(
                    lines_covered={
                        (f"test_file_{i}.py", line) for line in range(10, 40)
                    },
                    test_case_id=f"entry_{i}",
                )

            manager.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dataset,
                coverage=coverage,
                crash_triggered=(i % 3 == 0),
            )

        # Test statistics
        stats = manager.get_statistics()
        assert stats["total_entries"] == 10

        # Test getting best entries
        best = manager.get_best_entries(count=5)
        assert len(best) <= 5

        # Test random entry
        random = manager.get_random_entry()
        assert random is not None

        # Test corpus size limit
        for i in range(60):  # Add more than max
            manager.add_entry(
                entry_id=f"overflow_{i}",
                dataset=sample_dataset,
                coverage=None,
                crash_triggered=False,
            )

        # Should not exceed max size
        assert len(manager.corpus) <= 50

    def test_coverage_tracker_workflow(self, temp_dirs):
        """Test coverage tracker functionality."""
        tracker = CoverageTracker(target_modules=["core"])

        # Simulate some code execution
        def dummy_function():
            x = 1 + 1
            return x * 2

        # Track execution
        with tracker.trace_execution("test_case_1"):
            result = dummy_function()
            assert result == 4

        # Check coverage history
        assert len(tracker.coverage_history) > 0

    def test_mutator_session_profiler_integration(self, sample_dataset):
        """Test mutator with profiler tracking performance."""
        profiler = PerformanceProfiler()
        mutator = DicomMutator(config={"auto_register_strategies": True})

        with profiler:
            # Start mutation session
            mutator.start_session(sample_dataset)

            # Apply mutations
            result = mutator.apply_mutations(
                sample_dataset,
                num_mutations=2,
                severity=MutationSeverity.MODERATE,
            )

            # End session
            mutator.end_session()

        # Verify both worked
        assert result is not None
        summary = profiler.get_summary()
        assert summary["duration_seconds"] >= 0

    def test_fuzzing_session_with_profiler(self, sample_dataset, temp_dirs):
        """Test fuzzing session with performance profiling."""
        profiler = PerformanceProfiler()
        session = FuzzingSession(
            session_name="profiled_session",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
            crashes_dir=str(temp_dirs["crashes"]),
        )

        with profiler:
            # Start file fuzzing
            _ = session.start_file_fuzzing(
                source_file=Path("test.dcm"),
                output_file=temp_dirs["output"] / "fuzzed.dcm",
                severity="moderate",
            )

            # Record mutation
            session.record_mutation(strategy_name="test", mutation_type="test")

            # Save file
            sample_dataset.file_meta = pydicom.dataset.FileMetaDataset()
            sample_dataset.file_meta.TransferSyntaxUID = (
                pydicom.uid.ExplicitVRLittleEndian
            )
            pydicom.dcmwrite(temp_dirs["output"] / "fuzzed.dcm", sample_dataset)

            # End file fuzzing
            session.end_file_fuzzing(temp_dirs["output"] / "fuzzed.dcm", success=True)

        # Verify
        assert session.stats["files_fuzzed"] == 1
        summary = profiler.get_summary()
        assert summary["duration_seconds"] >= 0

    def test_reporter_with_profiler_stats(self, temp_dirs):
        """Test report generation with profiler statistics."""
        profiler = PerformanceProfiler()
        reporter = ReportGenerator(output_dir=str(temp_dirs["reports"]))

        with profiler:
            # Simulate operations
            for i in range(10):
                profiler.record_mutation(f"strategy_{i % 3}", duration=0.01 * (i + 1))

        # Generate performance report with profiler stats
        summary = profiler.get_summary()
        report_path = reporter.generate_performance_html_report(
            metrics=summary,
            campaign_name="test_session",
        )

        assert report_path.exists()

    def test_corpus_with_coverage_tracking(self, sample_dataset, temp_dirs):
        """Test corpus manager with coverage tracking."""
        corpus = CorpusManager(corpus_dir=temp_dirs["corpus"])
        _ = CoverageTracker(target_modules=["core"])  # Initialize for integration test

        # Add entries with coverage data
        for i in range(5):
            # Create unique coverage for each entry
            coverage = CoverageSnapshot(
                lines_covered={
                    (f"module_{i}.py", line) for line in range(i * 10, (i + 1) * 10)
                },
                test_case_id=f"entry_{i}",
            )
            corpus.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dataset,
                coverage=coverage,
                crash_triggered=False,
            )

        # Get best entries (should prioritize coverage)
        best = corpus.get_best_entries(count=3)
        assert len(best) <= 3

    def test_coverage_fuzzer_initialization(self, temp_dirs):
        """Test coverage-guided fuzzer initialization."""

        def target(dataset):
            return hasattr(dataset, "PatientName")

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_dirs["corpus"],
            target_function=target,
            max_corpus_size=100,
        )

        assert fuzzer is not None
        assert fuzzer.corpus_manager is not None

    def test_multi_module_error_handling(self, sample_dataset):
        """Test error handling across modules."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        # Try to apply mutations without starting session
        # Should handle gracefully
        result = mutator.apply_mutations(sample_dataset)

        # Should still work even without session
        assert result is not None

    def test_validator_parser_profiler_chain(self, temp_dirs):
        """Test validator, parser, and profiler working together."""
        profiler = PerformanceProfiler()

        # Create a test DICOM file with required elements
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        ds.file_meta = pydicom.dataset.FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian

        test_file = temp_dirs["output"] / "test.dcm"
        pydicom.dcmwrite(test_file, ds)

        with profiler:
            # Parse
            parser = DicomParser(test_file)
            parsed = parser.dataset  # Use property, not method

            # Validate
            validator = DicomValidator()
            validation_result = validator.validate(parsed)

        assert parsed is not None
        assert bool(validation_result) is True  # ValidationResult evaluates to bool
        summary = profiler.get_summary()
        assert summary["duration_seconds"] >= 0

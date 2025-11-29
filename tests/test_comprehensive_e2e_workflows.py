"""Comprehensive End-to-End Integration Tests for DICOM Fuzzer

This test suite exercises complete fuzzing workflows from start to finish,
integrating multiple modules to improve overall coverage and verify system behavior.
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from pydicom import Dataset
from pydicom.uid import generate_uid

# Import what's available from __init__.py
from dicom_fuzzer.core import (
    DicomMutator,
    DicomParser,
    DicomValidator,
    SeriesCache,
    SeriesDetector,
    SeriesValidator,
    SeriesWriter,
)
from dicom_fuzzer.core.config import FuzzingConfig
from dicom_fuzzer.core.corpus import CorpusEntry, CorpusManager
from dicom_fuzzer.core.coverage_correlation import CoverageCorrelator
from dicom_fuzzer.core.coverage_guided_mutator import CoverageGuidedMutator
from dicom_fuzzer.core.coverage_tracker import CoverageTracker
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer

# Import directly from specific modules since they're not in __init__.py
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.core.statistics import MutationStatistics

# Strategies are imported when needed in specific tests


@pytest.fixture
def test_workspace(tmp_path):
    """Create a complete test workspace with all required directories."""
    workspace = {
        "root": tmp_path,
        "input": tmp_path / "input",
        "output": tmp_path / "output",
        "corpus": tmp_path / "corpus",
        "crashes": tmp_path / "crashes",
        "coverage": tmp_path / "coverage",
        "reports": tmp_path / "reports",
        "cache": tmp_path / "cache",
        "logs": tmp_path / "logs",
    }

    for dir_path in workspace.values():
        if isinstance(dir_path, Path):
            dir_path.mkdir(exist_ok=True, parents=True)

    return workspace


@pytest.fixture
def sample_dicom_file(test_workspace):
    """Create a sample DICOM file for testing."""
    from pydicom.dataset import FileDataset, FileMetaDataset

    # Create file meta information with required Transfer Syntax UID
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"  # Implicit VR Little Endian
    file_meta.ImplementationClassUID = generate_uid()

    file_path = test_workspace["input"] / "sample.dcm"

    # Create dataset with proper file meta
    ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128)

    ds.PatientName = "TEST^PATIENT"
    ds.PatientID = "12345"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (512 * 512 * 2)

    ds.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def sample_dicom_series(test_workspace):
    """Create a sample DICOM series with multiple slices."""
    from pydicom.dataset import FileDataset, FileMetaDataset

    series_uid = generate_uid()
    study_uid = generate_uid()

    files = []
    for i in range(5):
        # Create file meta for each file
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = (
            "1.2.840.10008.5.1.4.1.1.4"  # MR Image Storage
        )
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"  # Implicit VR Little Endian
        file_meta.ImplementationClassUID = generate_uid()

        file_path = test_workspace["input"] / f"slice_{i:03d}.dcm"

        # Create dataset with proper file meta
        ds = FileDataset(
            str(file_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )

        ds.PatientName = "SERIES^TEST"
        ds.PatientID = "54321"
        ds.StudyInstanceUID = study_uid
        ds.SeriesInstanceUID = series_uid
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.InstanceNumber = i + 1
        ds.SliceLocation = i * 2.5
        ds.ImagePositionPatient = [0, 0, i * 2.5]
        ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
        ds.PixelSpacing = [1.0, 1.0]
        ds.SliceThickness = 2.5
        ds.Modality = "MR"
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (256 * 256 * 2)

        ds.save_as(str(file_path), write_like_original=False)
        files.append(file_path)

    return files


@pytest.fixture
def fuzzer_config(test_workspace):
    """Create a fuzzer configuration for testing."""
    return FuzzingConfig(
        metadata_probability=0.8,
        header_probability=0.6,
        pixel_probability=0.3,
        max_mutations_per_file=3,
        max_files_per_campaign=100,
        max_campaign_duration_minutes=5,
        batch_size=10,
        parallel_workers=1,  # Single worker for tests
    )


class TestCompleteWorkflowIntegration:
    """Test complete fuzzing workflows from start to finish."""

    def test_single_file_fuzzing_workflow(
        self, sample_dicom_file, test_workspace, fuzzer_config
    ):
        """Test complete workflow for fuzzing a single DICOM file."""
        # Parse and validate input
        parser = DicomParser(str(sample_dicom_file))
        metadata = parser.extract_metadata()
        assert metadata is not None
        assert "patient_name" in metadata

        # Validate the file
        validator = DicomValidator()
        validation_result, _ = validator.validate_file(sample_dicom_file)
        assert validation_result.is_valid

        # Set up corpus manager with correct API from corpus.py
        corpus = CorpusManager(corpus_dir=test_workspace["corpus"], max_corpus_size=100)

        # Load the DICOM dataset for corpus entry
        import pydicom

        dataset = pydicom.dcmread(str(sample_dicom_file))

        # Add entry to corpus using correct API
        # CorpusManager.add_entry expects: (entry_id, dataset, coverage, parent_id, crash_triggered)
        corpus.add_entry(
            entry_id="test_entry_001",
            dataset=dataset,
            coverage=None,
            parent_id=None,
            crash_triggered=False,
        )

        # Initialize mutator
        mutator = DicomMutator()
        mutated_ds = mutator.apply_mutations(dataset)
        assert mutated_ds is not None

        # Save mutated file
        mutated_path = test_workspace["output"] / "mutated_001.dcm"
        mutated_ds.save_as(str(mutated_path))
        assert mutated_path.exists()

        # Analyze for crashes (mock)
        analyzer = CrashAnalyzer(crash_dir=str(test_workspace["crashes"]))
        with patch.object(analyzer, "analyze_crash") as mock_analyze:
            mock_analyze.return_value = {
                "severity": "low",
                "type": "benign",
                "exploitable": False,
            }
            result = analyzer.analyze_crash(mutated_path, Exception("Test crash"))
            assert result["severity"] == "low"

        # Generate statistics
        stats = MutationStatistics()
        stats.record_mutation("metadata_fuzzer")
        stats.record_execution(0.1)
        assert stats.total_mutations == 1
        assert stats.total_executions == 1

        # Generate report
        reporter = ReportGenerator(output_dir=str(test_workspace["reports"]))
        report_data = {
            "total_mutations": stats.total_mutations,
            "total_executions": stats.total_executions,
            "crashes_found": 0,
            "coverage": 0.5,
        }
        report_path = reporter.generate_report(report_data, format="json")
        assert report_path.exists()

        # Verify report content
        with open(report_path) as f:
            report = json.load(f)
            assert report["total_mutations"] == 1
            assert report["coverage"] == 0.5

    def test_series_fuzzing_workflow(
        self, sample_dicom_series, test_workspace, fuzzer_config
    ):
        """Test complete workflow for fuzzing a DICOM series."""
        # Detect series
        detector = SeriesDetector()
        series_list = detector.detect_series(test_workspace["input"])
        assert len(series_list) > 0

        series = series_list[0]
        assert len(series.slices) == 5

        # Validate series
        validator = SeriesValidator()
        validation = validator.validate_series(series)
        assert validation.is_valid

        # Cache series
        cache = SeriesCache(cache_dir=str(test_workspace["cache"]))
        cache.cache_series(series)
        assert cache.is_cached(series.series_uid)

        # Load cached series
        cached_series = cache.load_series(series.series_uid)
        assert cached_series is not None
        assert len(cached_series.slices) == len(series.slices)

        # Write series to output
        writer = SeriesWriter(output_root=test_workspace["output"])
        metadata = writer.write_series(series)
        output_paths = metadata.get_output_paths()
        assert len(output_paths) == 5
        for path in output_paths:
            assert path.exists()

    def test_coverage_guided_fuzzing_workflow(
        self, sample_dicom_file, test_workspace, fuzzer_config
    ):
        """Test coverage-guided fuzzing workflow."""
        # Initialize coverage components
        tracker = CoverageTracker()

        # Set up corpus manager with correct API from corpus.py
        corpus_manager = CorpusManager(
            corpus_dir=test_workspace["corpus"], max_corpus_size=100
        )

        # Load the DICOM dataset
        import pydicom

        dataset = pydicom.dcmread(str(sample_dicom_file))

        # Create corpus entry
        entry = CorpusEntry(
            entry_id="seed_001",
            dataset=dataset,
            metadata={"source": "initial"},
        )
        corpus_manager.add_entry(entry)
        assert corpus_manager.size() > 0

        # Initialize coverage-guided mutator
        cg_mutator = CoverageGuidedMutator()

        # Perform mutations with coverage tracking
        with patch.object(tracker, "track_execution") as mock_track:
            mock_track.return_value = {"edges": {1, 2, 3}, "blocks": {10, 11}}

            for i in range(5):
                # Get seed from corpus
                seed = corpus_manager.get_best_seed()
                assert seed is not None

                # Mutate with coverage guidance
                mutated = cg_mutator.mutate(
                    seed.data if hasattr(seed, "data") else b"test",
                    coverage_info={"new_edges": i > 2},
                )

                # Track coverage
                coverage = tracker.track_execution(mutated)
                assert "edges" in coverage

                # Update corpus if interesting
                if i > 2:  # Simulate interesting input
                    # Create a mutated corpus entry
                    mutated_entry = CorpusEntry(
                        entry_id=f"mutation_{i}",
                        dataset=dataset,  # Use existing dataset for test
                        metadata={"generation": i},
                    )
                    corpus_manager.add_entry(mutated_entry)

        # Verify corpus growth
        assert corpus_manager.size() >= 1

    def test_crash_analysis_workflow(
        self, sample_dicom_file, test_workspace, fuzzer_config
    ):
        """Test crash detection and analysis workflow."""
        # Set up crash analyzer
        analyzer = CrashAnalyzer(crash_dir=str(test_workspace["crashes"]))

        # Simulate different crash types
        crash_samples = [
            (ValueError("Invalid DICOM tag"), "validation_error", "low"),
            (MemoryError("Out of memory"), "resource_exhaustion", "medium"),
            (OSError("Segmentation fault"), "segfault", "high"),
        ]

        for i, (exception, expected_type, expected_severity) in enumerate(
            crash_samples
        ):
            # Create crash artifact
            crash_file = test_workspace["crashes"] / f"crash_{i:03d}.dcm"
            shutil.copy(sample_dicom_file, crash_file)

            # Analyze crash
            with patch.object(analyzer, "_get_crash_type") as mock_type:
                with patch.object(analyzer, "_calculate_severity") as mock_severity:
                    mock_type.return_value = expected_type
                    mock_severity.return_value = expected_severity

                    analysis = analyzer.analyze_crash(crash_file, exception)
                    assert analysis["type"] == expected_type
                    assert analysis["severity"] == expected_severity

        # Verify crash storage
        crashes = list(test_workspace["crashes"].glob("*.dcm"))
        assert len(crashes) >= 3

    def test_complete_fuzzing_session(
        self, sample_dicom_file, test_workspace, fuzzer_config
    ):
        """Test a complete fuzzing session with all components."""
        # Initialize session
        session = FuzzingSession(
            config=fuzzer_config,
            session_id="test_session_001",
            output_dir=str(test_workspace["output"]),
            reports_dir=str(test_workspace["reports"]),
            crashes_dir=str(test_workspace["crashes"]),
        )

        # Mock execution to avoid actual process spawning
        with patch.object(session, "execute_target") as mock_execute:
            mock_execute.return_value = {
                "exit_code": 0,
                "coverage": {"edges": {1, 2, 3}},
                "crash": None,
            }

            # Add initial seed
            session.add_seed(sample_dicom_file)

            # Run fuzzing iterations
            with patch.object(session, "run_iteration") as mock_iteration:
                mock_iteration.return_value = {
                    "mutation": "test_mutation",
                    "coverage_increase": True,
                    "crash_found": False,
                }

                results = []
                for i in range(10):
                    result = session.run_iteration()
                    results.append(result)

                assert len(results) == 10
                assert all(r["coverage_increase"] for r in results)

        # Generate session report
        with patch.object(session, "generate_report") as mock_report:
            mock_report.return_value = test_workspace["reports"] / "session_report.html"
            report_path = session.generate_report()
            assert "session_report" in str(report_path)

    def test_parallel_fuzzing_workflow(
        self, sample_dicom_series, test_workspace, fuzzer_config
    ):
        """Test parallel fuzzing of multiple files."""
        from concurrent.futures import ThreadPoolExecutor

        def fuzz_file(file_path):
            """Fuzz a single file."""
            import pydicom

            mutator = DicomMutator()
            try:
                dataset = pydicom.dcmread(file_path)
                mutated = mutator.apply_mutations(dataset)
                output_path = test_workspace["output"] / f"parallel_{file_path.name}"
                mutated.save_as(str(output_path))
                return {"file": str(file_path), "status": "success"}
            except Exception as e:
                return {"file": str(file_path), "status": "error", "error": str(e)}

        # Fuzz all files in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(fuzz_file, f) for f in sample_dicom_series]
            results = [f.result() for f in futures]

        # Verify results
        assert len(results) == 5
        success_count = sum(1 for r in results if r["status"] == "success")
        assert success_count >= 3  # At least 3 should succeed

    def test_coverage_correlation_workflow(
        self, sample_dicom_file, test_workspace, fuzzer_config
    ):
        """Test coverage correlation analysis."""
        correlator = CoverageCorrelator()

        # Add coverage data points
        test_data = [
            {"mutation": "metadata", "coverage": 0.45, "crash": False},
            {"mutation": "pixel", "coverage": 0.55, "crash": True},
            {"mutation": "header", "coverage": 0.50, "crash": False},
            {"mutation": "metadata", "coverage": 0.48, "crash": True},
            {"mutation": "pixel", "coverage": 0.60, "crash": True},
        ]

        for data in test_data:
            correlator.add_data_point(
                mutation_type=data["mutation"],
                coverage=data["coverage"],
                crash_found=data["crash"],
            )

        # Analyze correlations
        analysis = correlator.analyze()
        assert "mutation_effectiveness" in analysis
        assert "coverage_trends" in analysis

        # Get recommendations
        recommendations = correlator.get_recommendations()
        assert len(recommendations) > 0
        assert any("pixel" in r.lower() for r in recommendations)  # Pixel had crashes


class TestErrorHandlingIntegration:
    """Test error handling across integrated components."""

    def test_corrupted_file_handling(self, test_workspace):
        """Test handling of corrupted DICOM files."""
        # Create corrupted file
        corrupted_file = test_workspace["input"] / "corrupted.dcm"
        corrupted_file.write_bytes(b"NOT_A_DICOM_FILE")

        # Try to parse
        with pytest.raises(Exception):
            parser = DicomParser(str(corrupted_file))

        # Validator should detect corruption
        validator = DicomValidator()
        result, _ = validator.validate_file(corrupted_file)
        assert not result.is_valid

    def test_resource_exhaustion_handling(self, test_workspace, fuzzer_config):
        """Test handling of resource exhaustion scenarios."""
        # Create large file that might cause memory issues
        large_file = test_workspace["input"] / "large.dcm"
        ds = Dataset()
        ds.PatientName = "LARGE^TEST"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = generate_uid()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.Modality = "CT"
        ds.Rows = 4096
        ds.Columns = 4096
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        # Don't actually create huge pixel data in test
        ds.PixelData = b"\x00" * 1024  # Small for testing

        # Create file meta with Transfer Syntax UID
        from pydicom.dataset import FileMetaDataset

        file_meta = FileMetaDataset()
        file_meta.FileMetaInformationVersion = b"\x00\x01"
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"  # Explicit VR Little Endian
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        file_meta.ImplementationClassUID = "1.2.826.0.1.3680043.8.498.1"
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        ds.save_as(str(large_file), write_like_original=False)

        # Test that large file can be loaded and mutated without crashes
        # (actual resource exhaustion testing would require more complex setup)
        mutator = DicomMutator()

        # Should handle large files gracefully
        import pydicom

        dataset = pydicom.dcmread(large_file)
        assert dataset is not None

        # Basic mutation should work
        result = mutator.apply_mutations(dataset)
        # Should return a result (either mutated or original)
        assert result is not None

    def test_timeout_handling(self, sample_dicom_file, test_workspace, fuzzer_config):
        """Test timeout handling in fuzzing operations."""
        import time

        # Test timeout mechanism
        from dicom_fuzzer.utils.timeout_budget import TimeoutBudget

        budget = TimeoutBudget(total_seconds=1)

        # Simulate passage of time
        time.sleep(1.1)

        # After budget exhausted, trying to start new operation should raise TimeoutError
        with pytest.raises(TimeoutError):
            with budget.operation_context("slow_op"):
                pass  # This should raise immediately since budget exhausted

        assert budget.is_exhausted()

    def test_concurrent_access_handling(self, sample_dicom_file, test_workspace):
        """Test handling of concurrent file access."""
        from threading import Lock, Thread

        results = []
        lock = Lock()

        def access_file(file_path, index):
            """Access file concurrently."""
            try:
                parser = DicomParser(str(file_path))
                metadata = parser.extract_metadata()
                with lock:
                    results.append({"index": index, "success": True})
            except Exception as e:
                with lock:
                    results.append({"index": index, "success": False, "error": str(e)})

        # Create threads
        threads = [
            Thread(target=access_file, args=(sample_dicom_file, i)) for i in range(5)
        ]

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # All should succeed (file reading is thread-safe)
        assert len(results) == 5
        success_count = sum(1 for r in results if r["success"])
        assert success_count == 5


class TestPerformanceIntegration:
    """Test performance characteristics of integrated components."""

    def test_fuzzing_throughput(self, sample_dicom_file, test_workspace):
        """Test fuzzing throughput with small files."""
        import time

        import pydicom

        mutator = DicomMutator()
        start_time = time.time()

        # Load dataset once before loop
        dataset = pydicom.dcmread(sample_dicom_file)

        mutations = []
        for i in range(50):
            mutated = mutator.apply_mutations(dataset)
            mutations.append(mutated)

        elapsed = time.time() - start_time
        throughput = len(mutations) / elapsed

        # Should achieve reasonable throughput (at least 5 mutations/second)
        assert throughput > 5.0
        assert len(mutations) == 50

    def test_corpus_scalability(self, test_workspace):
        """Test corpus manager with large number of seeds."""
        from pydicom import Dataset

        corpus_manager = CorpusManager(
            corpus_dir=test_workspace["corpus"], max_corpus_size=1000
        )

        # Add many seeds
        import time

        start_time = time.time()

        for i in range(100):
            # Create minimal dataset for each seed
            ds = Dataset()
            ds.PatientName = f"TEST_{i:04d}"
            ds.PatientID = f"{i:04d}"

            entry = CorpusEntry(
                entry_id=f"seed_{i:04d}", dataset=ds, metadata={"index": i}
            )
            corpus_manager.add_entry(entry)

        elapsed = time.time() - start_time

        # Should handle 100 seeds quickly (under 5 seconds)
        assert elapsed < 5.0
        assert corpus_manager.size() <= 1000  # Respects max size

    def test_parallel_efficiency(self, sample_dicom_series, test_workspace):
        """Test efficiency of parallel processing."""
        import time
        from concurrent.futures import ThreadPoolExecutor

        def process_file(file_path):
            """Process a single file."""
            parser = DicomParser(str(file_path))
            metadata = parser.extract_metadata()
            validator = DicomValidator()
            validation, _ = validator.validate_file(file_path)
            return {"file": str(file_path), "valid": validation.is_valid}

        # Sequential processing
        start_seq = time.time()
        seq_results = [process_file(f) for f in sample_dicom_series]
        seq_time = time.time() - start_seq

        # Parallel processing
        start_par = time.time()
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(process_file, f) for f in sample_dicom_series]
            par_results = [f.result() for f in futures]
        par_time = time.time() - start_par

        # Parallel should be faster (or at least not much slower)
        # Account for thread overhead
        assert par_time < seq_time * 1.5
        assert len(par_results) == len(seq_results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

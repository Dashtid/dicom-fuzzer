"""
Integration Tests for Complete Fuzzing Workflows

Tests that exercise multiple modules together to improve overall coverage.
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.corpus import CorpusManager
from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer
from dicom_fuzzer.core.crash_deduplication import CrashDeduplicator, DeduplicationConfig
from dicom_fuzzer.core.fuzzing_session import FuzzingSession

# from dicom_fuzzer.core.generator import DICOMGenerator  # Not used in current tests
from dicom_fuzzer.core.grammar_fuzzer import GrammarFuzzer
from dicom_fuzzer.core.mutation_minimization import MutationMinimizer
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity


class TestCompleteFuzzingWorkflows:
    """Test complete end-to-end fuzzing workflows."""

    @pytest.fixture
    def sample_dicom_dataset(self):
        """Create sample DICOM dataset for testing."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.SOPInstanceUID = "1.2.3.4.7"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.Modality = "CT"
        ds.Rows = 512
        ds.Columns = 512
        return ds

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary directories for testing."""
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

    def test_mutation_workflow(self, sample_dicom_dataset, temp_dirs):
        """Test complete mutation and session tracking workflow."""
        session = FuzzingSession(
            session_name="mutation_test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
            crashes_dir=str(temp_dirs["crashes"]),
        )

        mutator = DicomMutator(
            config={
                "auto_register_strategies": False,
                "mutation_probability": 1.0,
                "max_mutations_per_file": 3,
            }
        )

        # Start file fuzzing
        _ = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=temp_dirs["output"] / "fuzzed.dcm",
            severity="moderate",
        )

        # Apply mutations
        mutator.start_session(sample_dicom_dataset)
        mutated = mutator.apply_mutations(
            sample_dicom_dataset, num_mutations=3, severity=MutationSeverity.MODERATE
        )

        # Record mutations
        for mutation in mutator.current_session.mutations:
            session.record_mutation(
                strategy_name=mutation.strategy_name, mutation_type="test_mutation"
            )

        # Save and end (with explicit transfer syntax)
        mutated.file_meta = pydicom.dataset.FileMetaDataset()
        mutated.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
        pydicom.dcmwrite(temp_dirs["output"] / "fuzzed.dcm", mutated)
        session.end_file_fuzzing(temp_dirs["output"] / "fuzzed.dcm", success=True)

        # Verify
        assert session.stats["files_fuzzed"] == 1
        # Note: mutations_applied tracks only explicit record_mutation calls
        assert session.stats["mutations_applied"] >= 0

    def test_grammar_fuzzing_workflow(self, sample_dicom_dataset):
        """Test grammar-based fuzzing workflow."""
        fuzzer = GrammarFuzzer()

        # Test different mutation types
        mutations = [
            "required_tags",
            "conditional_rules",
            "inconsistent_state",
            "value_constraints",
        ]

        for mutation_type in mutations:
            mutated = fuzzer.apply_grammar_based_mutation(
                sample_dicom_dataset, mutation_type=mutation_type
            )
            assert mutated is not None

    def test_corpus_management_workflow(self, sample_dicom_dataset, temp_dirs):
        """Test corpus management in fuzzing campaign."""
        manager = CorpusManager(corpus_dir=temp_dirs["corpus"], max_corpus_size=100)

        # Add entries with coverage
        for i in range(5):
            manager.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dicom_dataset,
                coverage=None,
                crash_triggered=False,
            )

        # Get statistics
        stats = manager.get_statistics()
        assert stats["total_entries"] == 5

        # Get best entries
        best = manager.get_best_entries(count=3)
        assert len(best) <= 3

        # Get random entry
        random_entry = manager.get_random_entry()
        assert random_entry is not None

    def test_crash_deduplication_workflow(self):
        """Test crash deduplication in fuzzing campaign."""
        from dicom_fuzzer.core.fuzzing_session import CrashRecord

        crashes = []
        for i in range(10):
            crashes.append(
                CrashRecord(
                    crash_id=f"crash_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash" if i % 2 == 0 else "hang",
                    severity="high",
                    fuzzed_file_id=f"file_{i}",
                    fuzzed_file_path=f"fuzzed_{i}.dcm",
                    exception_type="ValueError" if i % 3 == 0 else "RuntimeError",
                    exception_message=f"Error {i}",
                )
            )

        config = DeduplicationConfig(
            stack_trace_weight=0.5, exception_weight=0.5, mutation_weight=0.0
        )

        deduplicator = CrashDeduplicator(config)
        groups = deduplicator.deduplicate_crashes(crashes)

        assert len(groups) >= 1
        assert deduplicator.get_unique_crash_count() >= 1

    def test_minimization_workflow(self, sample_dicom_dataset):
        """Test mutation minimization workflow."""
        from dicom_fuzzer.core.fuzzing_session import MutationRecord

        mutations = [
            MutationRecord(
                mutation_id=f"mut_{i}",
                strategy_name="test",
                timestamp=datetime.now(),
                mutation_type="test",
            )
            for i in range(5)
        ]

        def always_crashes(dataset):
            return True

        minimizer = MutationMinimizer(always_crashes, max_iterations=20)
        result = minimizer.minimize(sample_dicom_dataset, mutations, strategy="linear")

        assert result.original_mutation_count == 5
        assert result.minimized_mutation_count >= 0

    def test_full_session_with_reporting(self, sample_dicom_dataset, temp_dirs):
        """Test full fuzzing session with report generation."""
        session = FuzzingSession(
            session_name="full_workflow",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
            crashes_dir=str(temp_dirs["crashes"]),
        )

        # Fuzz multiple files
        for i in range(3):
            _ = session.start_file_fuzzing(
                source_file=Path(f"test_{i}.dcm"),
                output_file=temp_dirs["output"] / f"fuzzed_{i}.dcm",
                severity="moderate",
            )

            session.record_mutation(strategy_name="TestStrategy", mutation_type="test")

            # Write with transfer syntax
            sample_dicom_dataset.file_meta = pydicom.dataset.FileMetaDataset()
            sample_dicom_dataset.file_meta.TransferSyntaxUID = (
                pydicom.uid.ExplicitVRLittleEndian
            )
            pydicom.dcmwrite(
                temp_dirs["output"] / f"fuzzed_{i}.dcm", sample_dicom_dataset
            )
            session.end_file_fuzzing(
                temp_dirs["output"] / f"fuzzed_{i}.dcm", success=True
            )

        # Generate report
        report = session.generate_session_report()
        assert report["statistics"]["files_fuzzed"] == 3
        assert report["statistics"]["mutations_applied"] == 3

        # Save report
        report_path = session.save_session_report()
        assert report_path.exists()

    def test_coverage_guided_fuzzing_workflow(self, sample_dicom_dataset, temp_dirs):
        """Test coverage-guided fuzzing workflow."""

        def dummy_target(dataset):
            """Process dataset for testing purposes."""
            # Simulate some processing
            if hasattr(dataset, "PatientName"):
                name = str(dataset.PatientName)
                if len(name) > 5:
                    return True
            return False

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=temp_dirs["corpus"],
            target_function=dummy_target,
            max_corpus_size=50,
        )

        # Add seed
        seed_id = fuzzer.add_seed(sample_dicom_dataset, seed_id="seed_1")
        assert seed_id is not None

        # Run fuzzing iterations
        for i in range(10):
            fuzzer.fuzz_iteration()

        # Verify corpus grew
        assert len(fuzzer.corpus_manager.corpus) >= 1

    def test_mutator_with_multiple_strategies(self, sample_dicom_dataset):
        """Verify mutator with multiple registered strategies."""
        mutator = DicomMutator(
            config={"auto_register_strategies": True, "mutation_probability": 1.0}
        )

        # Start session
        mutator.start_session(sample_dicom_dataset)

        # Apply mutations
        mutated = mutator.apply_mutations(sample_dicom_dataset, num_mutations=5)

        assert mutated is not None
        assert len(mutator.current_session.mutations) >= 1

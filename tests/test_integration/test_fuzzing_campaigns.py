"""
Fuzzing Campaign Integration Tests

Consolidated from test_end_to_end_fuzzing.py, test_end_to_end_workflows.py,
and test_integration_workflows.py.

Tests cover:
- Complete fuzzing campaigns with crash detection and analysis
- Session persistence and restoration
- Resource management and limits enforcement
- Corpus and coverage-guided fuzzing workflows
- Crash deduplication and triage pipelines
"""

from datetime import datetime
from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset

from dicom_fuzzer.core.corpus import CorpusManager
from dicom_fuzzer.core.coverage_fuzzer import CoverageGuidedFuzzer
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.crash_deduplication import CrashDeduplicator, DeduplicationConfig
from dicom_fuzzer.core.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.fuzzing_session import (
    CrashRecord,
    FuzzingSession,
    MutationRecord,
)
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.grammar_fuzzer import GrammarFuzzer
from dicom_fuzzer.core.mutation_minimization import MutationMinimizer
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.core.statistics import StatisticsCollector
from dicom_fuzzer.core.validator import DicomValidator


@pytest.fixture
def fuzzing_workspace(tmp_path):
    """Create a complete fuzzing workspace with all directories."""
    workspace = {
        "root": tmp_path,
        "inputs": tmp_path / "inputs",
        "outputs": tmp_path / "outputs",
        "crashes": tmp_path / "crashes",
        "corpus": tmp_path / "corpus",
        "reports": tmp_path / "reports",
    }
    for directory in workspace.values():
        if isinstance(directory, Path):
            directory.mkdir(parents=True, exist_ok=True)
    return workspace


@pytest.fixture
def sample_dicom_dataset():
    """Create sample DICOM dataset for testing."""
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


class TestCompleteFuzzingCampaign:
    """Test complete fuzzing campaigns from start to finish."""

    @pytest.mark.slow  # Resource-intensive test, excluded from CI
    def test_complete_fuzzing_campaign(self, fuzzing_workspace, sample_dicom_file):
        """
        Test a complete fuzzing campaign:
        1. Use seed DICOM file
        2. Mutate files
        3. Validate mutated files
        4. Track crashes
        5. Generate reports
        """
        generator = DICOMGenerator(
            output_dir=fuzzing_workspace["inputs"], skip_write_errors=True
        )

        seed_files = generator.generate_batch(
            original_file=str(sample_dicom_file), count=3
        )
        assert len(seed_files) >= 1
        assert all(f.exists() for f in seed_files)

        session = FuzzingSession(
            session_name="e2e_test_campaign",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )

        mutator = DicomMutator()
        validator = DicomValidator(strict_mode=False)
        mutated_files = []

        for seed_file in seed_files:
            parser = DicomParser(seed_file)
            dataset = parser.dataset

            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{seed_file.name}"
            file_id = session.start_file_fuzzing(
                source_file=seed_file, output_file=output_file, severity="moderate"
            )

            mutator.start_session(dataset)
            mutated_dataset = mutator.apply_mutations(
                dataset, num_mutations=5, severity="moderate"
            )
            mutation_summary = mutator.end_session()

            mutated_dataset.save_as(str(output_file), write_like_original=False)
            mutated_files.append(output_file)

            validation_result = validator.validate(mutated_dataset)

            for mutation in mutation_summary.mutations:
                session.record_mutation(
                    strategy_name=mutation.strategy_name,
                    target_tag="unknown",
                    mutation_type="unknown",
                )

            session.record_test_result(
                file_id=file_id,
                result="pass" if validation_result.is_valid else "fail",
                execution_time=0.1,
                validation_errors=len(validation_result.errors),
            )

            session.end_file_fuzzing(output_file)

        summary = session.get_session_summary()
        assert summary["total_files"] == len(seed_files)
        assert summary["total_mutations"] > 0
        assert summary["duration"] > 0

        report_path = fuzzing_workspace["reports"] / "session_report.json"
        session.save_session_report(str(report_path))
        assert report_path.exists()

        for mutated_file in mutated_files:
            assert mutated_file.exists()
            ds = pydicom.dcmread(str(mutated_file))
            assert ds is not None

    def test_multi_file_fuzzing_with_statistics(
        self, fuzzing_workspace, sample_dicom_file
    ):
        """Test fuzzing multiple files with statistics tracking."""
        generator = DICOMGenerator(
            output_dir=fuzzing_workspace["inputs"], skip_write_errors=True
        )
        seed_files = generator.generate_batch(
            original_file=str(sample_dicom_file), count=10
        )

        session = FuzzingSession(
            session_name="multi_file_test",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )
        statistics = StatisticsCollector()

        severities = ["low", "moderate", "high"]
        mutator = DicomMutator()

        for i, seed_file in enumerate(seed_files):
            severity = severities[i % len(severities)]

            parser = DicomParser(seed_file)
            dataset = parser.dataset

            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm"
            file_id = session.start_file_fuzzing(
                source_file=seed_file, output_file=output_file, severity=severity
            )

            statistics.track_iteration(
                file_path=str(output_file), mutations_applied=i + 1, severity=severity
            )

            mutator.start_session(dataset)
            mutated_dataset = mutator.apply_mutations(dataset, severity=severity)
            mutation_summary = mutator.end_session()

            mutated_dataset.save_as(str(output_file), write_like_original=False)

            for mutation in mutation_summary.mutations:
                session.record_mutation(
                    strategy_name=mutation.strategy_name,
                    target_tag="unknown",
                    mutation_type="unknown",
                )

            session.record_test_result(
                file_id=file_id, result="pass", execution_time=0.1
            )
            session.end_file_fuzzing(output_file)

        session_summary = session.get_session_summary()
        assert session_summary["total_files"] == len(seed_files)
        assert session_summary["total_mutations"] > 0
        assert session_summary["files_per_minute"] > 0

        stats_summary = statistics.get_summary()
        assert stats_summary["total_iterations"] == len(seed_files)
        assert stats_summary["executions_per_second"] >= 0
        assert len(stats_summary["severity_statistics"]) > 0


class TestCrashAnalysisPipeline:
    """Test crash detection, deduplication, and triage workflows."""

    @pytest.fixture
    def crash_workspace(self, tmp_path):
        """Create workspace for crash analysis testing."""
        workspace = {
            "input": tmp_path / "input",
            "output": tmp_path / "output",
            "crashes": tmp_path / "crashes",
            "reports": tmp_path / "reports",
        }
        for directory in workspace.values():
            directory.mkdir(parents=True, exist_ok=True)

        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.7"
        ds.Modality = "CT"

        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID

        sample_file = workspace["input"] / "sample.dcm"
        ds.save_as(sample_file, enforce_file_format=True)
        workspace["sample_file"] = sample_file

        return workspace

    def test_crash_detection_and_analysis_workflow(self, fuzzing_workspace):
        """Test crash detection and analysis."""
        session = FuzzingSession(
            session_name="crash_test",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )

        crash_analyzer = CrashAnalyzer(crash_dir=fuzzing_workspace["crashes"])

        for i in range(5):
            test_file = fuzzing_workspace["inputs"] / f"test_{i}.dcm"
            test_file.touch()

            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm"
            file_id = session.start_file_fuzzing(
                source_file=test_file, output_file=output_file, severity="moderate"
            )

            if i % 2 == 0:
                try:
                    raise ValueError(f"Simulated crash {i}")
                except ValueError as e:
                    crash_report = crash_analyzer.record_crash(
                        exception=e,
                        test_case_path=str(output_file),
                    )

                    if crash_report:
                        session.record_crash(
                            file_id=file_id,
                            crash_type="crash",
                            exception_type=type(e).__name__,
                            exception_message=str(e),
                            stack_trace=crash_report.stack_trace,
                        )
            else:
                session.record_test_result(
                    file_id=file_id, result="pass", execution_time=0.05
                )

            session.end_file_fuzzing(output_file)

        summary = session.get_session_summary()
        assert summary["crashes"] == 3
        assert summary["total_files"] == 5

        crash_summary = crash_analyzer.get_crash_summary()
        assert crash_summary["total_crashes"] >= 3
        assert crash_summary["unique_crashes"] >= 1

    def test_complete_fuzzing_to_crash_analysis_workflow(self, crash_workspace):
        """Test complete workflow: Generate fuzzed files -> Detect crashes -> Deduplicate -> Triage."""
        session = FuzzingSession(
            session_name="e2e_crash_test",
            output_dir=str(crash_workspace["output"]),
            reports_dir=str(crash_workspace["reports"]),
            crashes_dir=str(crash_workspace["crashes"]),
        )

        mutator = DicomMutator()

        fuzzed_files = []
        for i in range(10):
            ds = pydicom.dcmread(crash_workspace["sample_file"])
            output_file = crash_workspace["output"] / f"fuzzed_{i:03d}.dcm"
            file_id = session.start_file_fuzzing(
                source_file=str(crash_workspace["sample_file"]),
                output_file=str(output_file),
                severity="high",
            )

            mutator.start_session(ds)
            mutated = mutator.apply_mutations(ds, num_mutations=3)

            for mutation in mutator.current_session.mutations:
                session.record_mutation(
                    strategy_name=mutation.strategy_name,
                    mutation_type=mutation.mutation_id,
                    original_value="",
                    mutated_value=mutation.description,
                )

            try:
                mutated.save_as(output_file, enforce_file_format=True)
                fuzzed_files.append((file_id, output_file))
                session.end_file_fuzzing(str(output_file), success=True)
            except (UnicodeEncodeError, ValueError, TypeError, OSError):
                session.end_file_fuzzing(str(output_file), success=False)

            mutator.end_session()

        assert len(fuzzed_files) >= 3

        _ = CrashAnalyzer(crash_dir=str(crash_workspace["crashes"]))

        crash_types = [
            ("SIGSEGV", "SIGSEGV: Segmentation fault at 0x12345678"),
            ("SIGSEGV", "SIGSEGV: Segmentation fault at 0xABCDEF00"),
            ("SIGABRT", "SIGABRT: Assertion failed: ptr != NULL"),
            ("exception", "ValueError: Invalid DICOM tag"),
            ("exception", "ValueError: Invalid DICOM tag"),
        ]

        num_crashes = min(len(crash_types), len(fuzzed_files))
        for i, (crash_type, message) in enumerate(crash_types[:num_crashes]):
            file_id, crash_file = fuzzed_files[i]

            if crash_type == "SIGSEGV":
                session.record_crash(
                    file_id=file_id,
                    crash_type="SIGSEGV",
                    severity="critical",
                    return_code=-11,
                    exception_type="SIGSEGV",
                    exception_message=message,
                    stack_trace=f"at function_a\n  at function_b\n  at {message}",
                )
            elif crash_type == "SIGABRT":
                session.record_crash(
                    file_id=file_id,
                    crash_type="SIGABRT",
                    severity="high",
                    return_code=134,
                    exception_type="SIGABRT",
                    exception_message=message,
                    stack_trace=f"at assert_handler\n  at {message}",
                )
            else:
                session.record_crash(
                    file_id=file_id,
                    crash_type="exception",
                    severity="medium",
                    return_code=1,
                    exception_type="ValueError",
                    exception_message=message,
                    stack_trace=f"at parse_tag\n  at {message}",
                )

        crashes = session.crashes
        assert len(crashes) == num_crashes

        config = DeduplicationConfig(
            stack_trace_weight=0.5, exception_weight=0.3, mutation_weight=0.2
        )
        deduplicator = CrashDeduplicator(config)
        crash_groups = deduplicator.deduplicate_crashes(crashes)

        assert len(crash_groups) <= num_crashes
        assert len(crash_groups) >= 1

        triage_engine = CrashTriageEngine()
        triage_results = []

        for group_id, group_crashes in crash_groups.items():
            representative = group_crashes[0]
            triage = triage_engine.triage_crash(representative)
            triage_results.append(triage)

        assert len(triage_results) > 0
        assert any(t.severity.value in ["critical", "high"] for t in triage_results)

        report = session.save_session_report()
        assert report is not None

        stats = deduplicator.get_deduplication_stats()
        assert stats["total_crashes"] == num_crashes
        assert stats["unique_groups"] == len(crash_groups)

    def test_crash_deduplication_workflow(self):
        """Test crash deduplication in fuzzing campaign."""
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


class TestSessionManagement:
    """Test session persistence and restoration workflows."""

    @pytest.fixture
    def session_workspace(self, tmp_path):
        """Create workspace for session testing."""
        workspace = {
            "output": tmp_path / "output",
            "reports": tmp_path / "reports",
            "crashes": tmp_path / "crashes",
        }
        for directory in workspace.values():
            directory.mkdir(parents=True, exist_ok=True)
        return workspace

    def test_session_save_and_restore_workflow(self, session_workspace):
        """Test complete session save and restore workflow."""
        session1 = FuzzingSession(
            session_name="resumable_session",
            output_dir=str(session_workspace["output"]),
            reports_dir=str(session_workspace["reports"]),
            crashes_dir=str(session_workspace["crashes"]),
        )

        for i in range(5):
            output_file = session_workspace["output"] / f"output_{i}.dcm"
            file_id = session1.start_file_fuzzing(
                source_file="source.dcm",
                output_file=str(output_file),
                severity="moderate",
            )

            session1.record_mutation(
                strategy_name="header_fuzzer",
                mutation_type="overlong_string",
                original_value="Original",
                mutated_value="A" * 1000,
            )

            session1.end_file_fuzzing(output_file)

        report_path = session1.save_session_report()
        assert report_path is not None
        assert Path(report_path).exists()

        import json

        with open(report_path) as f:
            saved_data = json.load(f)

        assert saved_data["session_info"]["session_name"] == "resumable_session"
        assert saved_data["statistics"]["files_fuzzed"] == 5
        assert len(saved_data["fuzzed_files"]) == 5

        session2 = FuzzingSession(
            session_name="resumable_session",
            output_dir=str(session_workspace["output"]),
            reports_dir=str(session_workspace["reports"]),
            crashes_dir=str(session_workspace["crashes"]),
        )

        for i in range(5, 10):
            output_file = session_workspace["output"] / f"output_{i}.dcm"
            file_id = session2.start_file_fuzzing(
                source_file="source.dcm",
                output_file=str(output_file),
                severity="moderate",
            )
            session2.end_file_fuzzing(output_file)

        final_report_path = session2.save_session_report()
        with open(final_report_path) as f:
            final_data = json.load(f)

        assert final_data["statistics"]["files_fuzzed"] == 5

    def test_reporter_integration(self, fuzzing_workspace):
        """Test reporter integration with complete fuzzing data."""
        session = FuzzingSession(
            session_name="reporter_test",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )

        for i in range(3):
            test_file = fuzzing_workspace["inputs"] / f"test_{i}.dcm"
            test_file.touch()
            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm"

            file_id = session.start_file_fuzzing(
                source_file=test_file, output_file=output_file, severity="moderate"
            )

            session.record_mutation(
                strategy_name="TestStrategy",
                target_tag="(0010,0010)",
                mutation_type="flip_bits",
            )

            session.record_test_result(
                file_id=file_id, result="pass", execution_time=0.1
            )
            session.end_file_fuzzing(output_file)

        reporter = ReportGenerator(output_dir=str(fuzzing_workspace["reports"]))
        assert reporter.output_dir.exists()

        report_path = fuzzing_workspace["reports"] / "report.json"
        session.save_session_report(str(report_path))

        assert report_path.exists()

        import json

        with open(report_path) as f:
            report_data = json.load(f)

        assert "session_info" in report_data
        assert "statistics" in report_data
        assert "fuzzed_files" in report_data
        assert report_data["statistics"]["files_fuzzed"] == 3

    def test_full_session_with_reporting(self, sample_dicom_dataset, fuzzing_workspace):
        """Test full fuzzing session with report generation."""
        session = FuzzingSession(
            session_name="full_workflow",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )

        for i in range(3):
            _ = session.start_file_fuzzing(
                source_file=Path(f"test_{i}.dcm"),
                output_file=fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm",
                severity="moderate",
            )

            session.record_mutation(strategy_name="TestStrategy", mutation_type="test")

            sample_dicom_dataset.file_meta = pydicom.dataset.FileMetaDataset()
            sample_dicom_dataset.file_meta.TransferSyntaxUID = (
                pydicom.uid.ExplicitVRLittleEndian
            )
            pydicom.dcmwrite(
                fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm", sample_dicom_dataset
            )
            session.end_file_fuzzing(
                fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm", success=True
            )

        report = session.generate_session_report()
        assert report["statistics"]["files_fuzzed"] == 3
        assert report["statistics"]["mutations_applied"] == 3

        report_path = session.save_session_report()
        assert report_path.exists()


class TestResourceManagement:
    """Test resource management and limits enforcement."""

    def test_resource_limits_enforcement_workflow(self, tmp_path):
        """Test that resource limits are properly enforced during fuzzing."""
        limits = ResourceLimits(
            max_memory_mb=1024,
            max_cpu_seconds=60,
            min_disk_space_mb=100,
        )

        manager = ResourceManager(limits)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        has_resources = manager.check_available_resources(output_dir)
        assert isinstance(has_resources, bool)

        usage = manager.get_current_usage(output_dir)
        assert usage is not None
        assert hasattr(usage, "memory_mb")
        assert hasattr(usage, "disk_free_mb")

        can_run = manager.can_accommodate_campaign(
            num_files=10, avg_file_size_mb=1.0, output_dir=output_dir
        )
        assert isinstance(can_run, bool)


class TestMutationWorkflows:
    """Test mutation and fuzzing strategy workflows."""

    def test_mutation_workflow(self, sample_dicom_dataset, fuzzing_workspace):
        """Test complete mutation and session tracking workflow."""
        session = FuzzingSession(
            session_name="mutation_test",
            output_dir=str(fuzzing_workspace["outputs"]),
            reports_dir=str(fuzzing_workspace["reports"]),
            crashes_dir=str(fuzzing_workspace["crashes"]),
        )

        mutator = DicomMutator(
            config={
                "auto_register_strategies": False,
                "mutation_probability": 1.0,
                "max_mutations_per_file": 3,
            }
        )

        _ = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=fuzzing_workspace["outputs"] / "fuzzed.dcm",
            severity="moderate",
        )

        mutator.start_session(sample_dicom_dataset)
        mutated = mutator.apply_mutations(
            sample_dicom_dataset, num_mutations=3, severity=MutationSeverity.MODERATE
        )

        for mutation in mutator.current_session.mutations:
            session.record_mutation(
                strategy_name=mutation.strategy_name, mutation_type="test_mutation"
            )

        mutated.file_meta = pydicom.dataset.FileMetaDataset()
        mutated.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian
        pydicom.dcmwrite(fuzzing_workspace["outputs"] / "fuzzed.dcm", mutated)
        session.end_file_fuzzing(
            fuzzing_workspace["outputs"] / "fuzzed.dcm", success=True
        )

        assert session.stats["files_fuzzed"] == 1
        assert session.stats["mutations_applied"] >= 0

    def test_grammar_fuzzing_workflow(self, sample_dicom_dataset):
        """Test grammar-based fuzzing workflow."""
        fuzzer = GrammarFuzzer()

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

    def test_minimization_workflow(self, sample_dicom_dataset):
        """Test mutation minimization workflow."""
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

    def test_mutator_with_multiple_strategies(self, sample_dicom_dataset):
        """Verify mutator with multiple registered strategies."""
        mutator = DicomMutator(
            config={"auto_register_strategies": True, "mutation_probability": 1.0}
        )

        mutator.start_session(sample_dicom_dataset)
        mutated = mutator.apply_mutations(sample_dicom_dataset, num_mutations=5)

        assert mutated is not None
        assert len(mutator.current_session.mutations) >= 1


class TestCorpusAndCoverageWorkflows:
    """Test corpus management and coverage-guided fuzzing."""

    def test_corpus_management_workflow(self, sample_dicom_dataset, fuzzing_workspace):
        """Test corpus management in fuzzing campaign."""
        manager = CorpusManager(
            corpus_dir=fuzzing_workspace["corpus"], max_corpus_size=100
        )

        for i in range(5):
            manager.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dicom_dataset,
                coverage=None,
                crash_triggered=False,
            )

        stats = manager.get_statistics()
        assert stats["total_entries"] == 5

        best = manager.get_best_entries(count=3)
        assert len(best) <= 3

        random_entry = manager.get_random_entry()
        assert random_entry is not None

    def test_coverage_guided_fuzzing_workflow(
        self, sample_dicom_dataset, fuzzing_workspace
    ):
        """Test coverage-guided fuzzing workflow."""

        def dummy_target(dataset):
            if hasattr(dataset, "PatientName"):
                name = str(dataset.PatientName)
                if len(name) > 5:
                    return True
            return False

        fuzzer = CoverageGuidedFuzzer(
            corpus_dir=fuzzing_workspace["corpus"],
            target_function=dummy_target,
            max_corpus_size=50,
        )

        seed_id = fuzzer.add_seed(sample_dicom_dataset, seed_id="seed_1")
        assert seed_id is not None

        for i in range(10):
            fuzzer.fuzz_iteration()

        assert len(fuzzer.corpus_manager.corpus) >= 1


class TestValidationWorkflow:
    """Test validation workflow integration."""

    def test_batch_validation_workflow(self, tmp_path):
        """Test batch DICOM file validation workflow."""
        files = []
        for i in range(10):
            ds = Dataset()
            ds.PatientName = f"Patient{i}"
            ds.PatientID = f"ID{i:04d}"
            ds.StudyInstanceUID = f"1.2.3.4.{i}"
            ds.SeriesInstanceUID = f"1.2.3.5.{i}"
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.SOPInstanceUID = f"1.2.3.6.{i}"

            ds.file_meta = FileMetaDataset()
            ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
            ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
            ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID

            if i % 3 == 0:
                del ds.PatientName

            file_path = tmp_path / f"test_{i:03d}.dcm"
            ds.save_as(file_path, enforce_file_format=True)
            files.append(file_path)

        validator = DicomValidator(strict_mode=False)
        results = []
        invalid_files = []

        for file_path in files:
            result, _ = validator.validate_file(file_path)
            results.append((file_path, result.is_valid, result.errors))

            if not result.is_valid:
                invalid_files.append(file_path)

        assert len(results) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

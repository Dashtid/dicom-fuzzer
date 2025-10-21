"""
End-to-End Integration Tests for Complete Workflows

Tests complete workflows from start to finish, including:
- Crash analysis pipeline (fuzzing → crash → deduplication → triage)
- Resource management and recovery
- Session persistence and restoration
"""

from pathlib import Path

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.crash_deduplication import CrashDeduplicator, DeduplicationConfig
from dicom_fuzzer.core.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.core.validator import DicomValidator


class TestCompleteCrashAnalysisPipeline:
    """Test the complete crash analysis workflow from fuzzing to triage."""

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

        # Create sample DICOM file
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.7"
        ds.Modality = "CT"

        # Set file_meta for proper DICOM encoding
        from pydicom.dataset import FileMetaDataset

        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = (
            "1.2.840.10008.1.2"  # Implicit VR Little Endian
        )
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID

        sample_file = workspace["input"] / "sample.dcm"
        ds.save_as(sample_file, enforce_file_format=True)
        workspace["sample_file"] = sample_file

        return workspace

    def test_complete_fuzzing_to_crash_analysis_workflow(self, crash_workspace):
        """
        Test complete workflow: Generate fuzzed files → Detect crashes → Deduplicate → Triage.

        This tests the most common fuzzing campaign workflow.
        """
        # Step 1: Initialize fuzzing session
        session = FuzzingSession(
            session_name="e2e_crash_test",
            output_dir=str(crash_workspace["output"]),
            reports_dir=str(crash_workspace["reports"]),
        )

        # Step 2: Generate fuzzed files
        generator = DICOMGenerator(output_dir=str(crash_workspace["output"]))
        mutator = DicomMutator()

        fuzzed_files = []
        for i in range(10):
            # Load and mutate
            ds = pydicom.dcmread(crash_workspace["sample_file"])
            file_id = session.start_file_fuzzing(
                source_file=str(crash_workspace["sample_file"]),
                output_file=str(crash_workspace["output"] / f"fuzzed_{i:03d}.dcm"),
                severity="high",
            )

            mutator.start_session(ds)
            mutated = mutator.apply_mutations(ds, num_mutations=3)

            # Record mutations
            for mutation in mutator.current_session.mutations:
                session.record_mutation(
                    strategy_name=mutation.strategy_name,
                    mutation_type=mutation.mutation_type,
                    original_value=str(mutation.original_value)[:100],
                    mutated_value=str(mutation.mutated_value)[:100],
                )

            # Save
            output_file = crash_workspace["output"] / f"fuzzed_{i:03d}.dcm"
            mutated.save_as(output_file, enforce_file_format=True)
            fuzzed_files.append(output_file)
            session.end_file_fuzzing(str(output_file))

            mutator.end_session()

        # Step 3: Simulate crashes (mock target application)
        crash_analyzer = CrashAnalyzer(
            target_executable="mock_app",
            crash_dir=str(crash_workspace["crashes"]),
        )

        # Simulate different types of crashes
        crash_types = [
            ("segfault", "Segmentation fault at 0x12345678"),
            ("segfault", "Segmentation fault at 0xABCDEF00"),  # Similar crash
            ("assert", "Assertion failed: ptr != NULL"),
            ("exception", "ValueError: Invalid DICOM tag"),
            ("exception", "ValueError: Invalid DICOM tag"),  # Duplicate
        ]

        for i, (crash_type, message) in enumerate(crash_types[:5]):
            # Simulate crash for first 5 files
            crash_file = fuzzed_files[i]

            if crash_type == "segfault":
                session.record_crash(
                    fuzzed_file_path=str(crash_file),
                    crash_type="crash",
                    return_code=-11,
                    exception_type="SIGSEGV",
                    exception_message=message,
                    stack_trace=f"at function_a\n  at function_b\n  at {message}",
                )
            elif crash_type == "assert":
                session.record_crash(
                    fuzzed_file_path=str(crash_file),
                    crash_type="crash",
                    return_code=134,
                    exception_type="SIGABRT",
                    exception_message=message,
                    stack_trace=f"at assert_handler\n  at {message}",
                )
            else:  # exception
                session.record_crash(
                    fuzzed_file_path=str(crash_file),
                    crash_type="exception",
                    return_code=1,
                    exception_type="ValueError",
                    exception_message=message,
                    stack_trace=f"at parse_tag\n  at {message}",
                )

        # Step 4: Deduplicate crashes
        crashes = session.crashes
        assert len(crashes) == 5, "Should have 5 crashes"

        config = DeduplicationConfig(
            stack_trace_weight=0.5, exception_weight=0.3, mutation_weight=0.2
        )
        deduplicator = CrashDeduplicator(config)
        crash_groups = deduplicator.deduplicate_crashes(crashes)

        # Should group similar crashes together
        assert len(crash_groups) < 5, "Should have fewer groups than total crashes"
        assert len(crash_groups) >= 3, "Should have at least 3 distinct crash types"

        # Step 5: Triage crashes
        triage_engine = CrashTriageEngine()
        triage_results = []

        for group_id, group_crashes in crash_groups.items():
            # Triage representative crash from each group
            representative = group_crashes[0]
            triage = triage_engine.triage_crash(representative)
            triage_results.append(triage)

        # Verify triage identified severity levels
        assert len(triage_results) > 0, "Should have triage results"
        assert any(t.severity.value in ["CRITICAL", "HIGH"] for t in triage_results), (
            "Should identify at least one high-severity crash"
        )

        # Step 6: Generate final report
        report = session.save_session_report()
        assert report is not None, "Should generate session report"

        # Verify workflow completeness
        stats = deduplicator.get_deduplication_stats()
        assert stats["total_crashes"] == 5
        assert stats["unique_groups"] == len(crash_groups)
        assert stats["deduplication_ratio"] > 0  # Some deduplication occurred


class TestResourceManagementWorkflow:
    """Test resource management and limits enforcement."""

    def test_resource_limits_enforcement_workflow(self, tmp_path):
        """
        Test that resource limits are properly enforced during fuzzing campaign.

        Tests disk space checking and resource monitoring.
        """
        # Create resource manager with limits
        limits = ResourceLimits(
            max_memory_mb=1024,  # 1GB (soft limit)
            max_memory_hard_mb=2048,  # 2GB (hard limit)
            max_cpu_time_seconds=60,  # 1 minute
            min_disk_space_mb=100,  # 100MB minimum
        )

        manager = ResourceManager(limits)

        # Check pre-flight validation
        validation_result = manager.check_available_resources()
        assert validation_result is not None, "Should return validation result"

        # On Windows, only disk space is checked
        # On Unix/Linux, all resources are checked

        # Test disk space monitoring (works on all platforms)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        has_space = manager.check_disk_space(str(output_dir))
        assert isinstance(has_space, bool), "Should return boolean for disk space check"


class TestSessionPersistenceWorkflow:
    """Test session save/load and crash recovery workflows."""

    @pytest.fixture
    def session_workspace(self, tmp_path):
        """Create workspace for session testing."""
        workspace = {
            "output": tmp_path / "output",
            "reports": tmp_path / "reports",
        }
        for directory in workspace.values():
            directory.mkdir(parents=True, exist_ok=True)
        return workspace

    def test_session_save_and_restore_workflow(self, session_workspace):
        """
        Test complete session save and restore workflow.

        Simulates campaign interruption and resumption.
        """
        # Step 1: Create and run partial fuzzing session
        session1 = FuzzingSession(
            session_name="resumable_session",
            output_dir=str(session_workspace["output"]),
            reports_dir=str(session_workspace["reports"]),
        )

        # Simulate some fuzzing activity
        for i in range(5):
            file_id = session1.start_file_fuzzing(
                source_file="source.dcm",
                output_file=f"output_{i}.dcm",
                severity="moderate",
            )

            # Record some mutations
            session1.record_mutation(
                strategy_name="header_fuzzer",
                mutation_type="overlong_string",
                original_value="Original",
                mutated_value="A" * 1000,
            )

            session1.end_file_fuzzing(f"output_{i}.dcm")

        # Save session state
        report_path = session1.save_session_report()
        assert report_path is not None, "Should save session report"
        assert Path(report_path).exists(), "Report file should exist"

        # Step 2: Load session from saved state
        # (In real scenario, this would be after application restart)
        with open(report_path) as f:
            import json

            saved_data = json.load(f)

        # Verify saved data completeness
        assert saved_data["session_name"] == "resumable_session"
        assert saved_data["files_processed"] == 5
        assert len(saved_data["files"]) == 5
        assert all("mutations" in file_data for file_data in saved_data["files"])

        # Step 3: Resume session with new activity
        session2 = FuzzingSession(
            session_name="resumable_session",
            output_dir=str(session_workspace["output"]),
            reports_dir=str(session_workspace["reports"]),
        )

        # Continue fuzzing
        for i in range(5, 10):
            file_id = session2.start_file_fuzzing(
                source_file="source.dcm",
                output_file=f"output_{i}.dcm",
                severity="moderate",
            )
            session2.end_file_fuzzing(f"output_{i}.dcm")

        # Save final state
        final_report_path = session2.save_session_report()
        with open(final_report_path) as f:
            final_data = json.load(f)

        # Verify session continuation
        assert final_data["files_processed"] == 5, "New session has 5 more files"


class TestValidationWorkflow:
    """Test validation workflow integration."""

    def test_batch_validation_workflow(self, tmp_path):
        """
        Test batch DICOM file validation workflow.

        Generates files, validates them, and collects results.
        """
        # Create sample DICOM files
        from pydicom.dataset import FileMetaDataset

        files = []
        for i in range(10):
            ds = Dataset()
            ds.PatientName = f"Patient{i}"
            ds.PatientID = f"ID{i:04d}"
            ds.StudyInstanceUID = f"1.2.3.4.{i}"
            ds.SeriesInstanceUID = f"1.2.3.5.{i}"
            ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            ds.SOPInstanceUID = f"1.2.3.6.{i}"

            # Set file_meta for proper DICOM encoding
            ds.file_meta = FileMetaDataset()
            ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
            ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
            ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID

            # Make some files intentionally invalid
            if i % 3 == 0:
                del ds.PatientName  # Missing required field

            file_path = tmp_path / f"test_{i:03d}.dcm"
            ds.save_as(file_path, enforce_file_format=True)
            files.append(file_path)

        # Validate all files
        validator = DicomValidator(strict_mode=False)
        results = []
        invalid_files = []

        for file_path in files:
            is_valid, errors = validator.validate_file(file_path)
            results.append((file_path, is_valid, errors))

            if not is_valid:
                invalid_files.append(file_path)

        # Verify results
        assert len(results) == 10, "Should validate all files"
        assert len(invalid_files) > 0, "Should find some invalid files"
        assert len(invalid_files) < 10, "Should have some valid files"

        # Check that invalid files are those we intentionally broke
        expected_invalid_count = sum(1 for i in range(10) if i % 3 == 0)
        assert len(invalid_files) >= expected_invalid_count, (
            "Should catch missing required fields"
        )

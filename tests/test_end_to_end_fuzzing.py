"""
End-to-End Integration Tests for Complete Fuzzing Workflows

These tests exercise the entire fuzzing pipeline from start to finish,
ensuring all modules work together correctly in real-world scenarios.
"""

import shutil
from pathlib import Path

import pytest
import pydicom
from pydicom.dataset import Dataset

from core.fuzzing_session import FuzzingSession
from core.generator import DICOMGenerator
from core.mutator import DicomMutator
from core.parser import DicomParser
from core.validator import DicomValidator
from core.crash_analyzer import CrashAnalyzer
from core.reporter import ReportGenerator
from core.statistics import StatisticsCollector


class TestEndToEndFuzzingWorkflow:
    """Test complete fuzzing workflows from file generation to crash analysis."""

    @pytest.fixture
    def fuzzing_workspace(self, tmp_path):
        """Create a complete fuzzing workspace with all directories."""
        workspace = {
            "root": tmp_path,
            "inputs": tmp_path / "inputs",
            "outputs": tmp_path / "outputs",
            "crashes": tmp_path / "crashes",
            "corpus": tmp_path / "corpus",
            "reports": tmp_path / "reports",
        }

        # Create all directories
        for directory in workspace.values():
            if isinstance(directory, Path):
                directory.mkdir(parents=True, exist_ok=True)

        return workspace

    def test_complete_fuzzing_campaign(self, fuzzing_workspace):
        """
        Test a complete fuzzing campaign:
        1. Generate seed DICOM files
        2. Mutate files
        3. Validate mutated files
        4. Track crashes
        5. Generate reports
        """
        # Step 1: Generate initial seed files
        generator = DICOMGenerator(
            output_dir=fuzzing_workspace["inputs"],
            skip_write_errors=True
        )

        seed_files = generator.generate(count=3)
        assert len(seed_files) == 3
        assert all(f.exists() for f in seed_files)

        # Step 2: Start fuzzing session
        session = FuzzingSession(
            session_name="e2e_test_campaign", output_dir=str(fuzzing_workspace["outputs"])
        )

        # Step 3: Fuzz each seed file
        mutator = DicomMutator()
        validator = DicomValidator(strict_mode=False)
        mutated_files = []

        for seed_file in seed_files:
            # Parse seed file
            parser = DicomParser(seed_file)
            dataset = parser.dataset

            # Start file fuzzing
            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{seed_file.name}"
            file_id = session.start_file_fuzzing(
                source_file=seed_file, output_file=output_file, severity="moderate"
            )

            # Apply mutations
            mutator.start_session(source_file=str(seed_file), severity="moderate")
            mutated_dataset = mutator.apply_mutations(
                dataset, num_mutations=5, severity="moderate"
            )
            mutator.end_session()

            # Save mutated file
            mutated_dataset.save_as(str(output_file), write_like_original=False)
            mutated_files.append(output_file)

            # Validate mutated file
            validation_result = validator.validate_dataset(mutated_dataset)

            # Record test result
            session.record_test_result(
                file_id=file_id,
                result="pass" if validation_result.is_valid else "fail",
                execution_time=0.1,
                validation_errors=len(validation_result.errors),
            )

            # End file fuzzing
            session.end_file_fuzzing(output_file)

        # Step 4: Generate session summary
        summary = session.get_session_summary()

        assert summary["total_files"] == 3
        assert summary["total_mutations"] >= 15  # At least 5 per file
        assert summary["duration"] > 0

        # Step 5: Save report
        report_path = fuzzing_workspace["reports"] / "session_report.json"
        session.save_session_report(str(report_path))

        assert report_path.exists()

        # Verify all mutated files exist and are valid DICOM
        for mutated_file in mutated_files:
            assert mutated_file.exists()
            # Should be parseable as DICOM
            ds = pydicom.dcmread(str(mutated_file))
            assert ds is not None

    def test_crash_detection_and_analysis_workflow(self, fuzzing_workspace):
        """
        Test crash detection and analysis:
        1. Generate files
        2. Simulate crashes
        3. Analyze crashes
        4. Deduplicate crashes
        5. Generate crash reports
        """
        # Step 1: Create fuzzing session
        session = FuzzingSession(
            session_name="crash_test", output_dir=str(fuzzing_workspace["outputs"])
        )

        crash_analyzer = CrashAnalyzer(crash_dir=fuzzing_workspace["crashes"])

        # Step 2: Simulate fuzzing with crashes
        for i in range(5):
            test_file = fuzzing_workspace["inputs"] / f"test_{i}.dcm"
            test_file.touch()

            output_file = fuzzing_workspace["outputs"] / f"fuzzed_{i}.dcm"
            file_id = session.start_file_fuzzing(
                source_file=test_file, output_file=output_file, severity="moderate"
            )

            # Simulate different crash types
            if i % 2 == 0:
                # Simulate a crash
                try:
                    raise ValueError(f"Simulated crash {i}")
                except ValueError as e:
                    crash_report = crash_analyzer.analyze_exception(
                        exception=e,
                        test_case_file=str(output_file),
                        metadata={"iteration": i},
                    )

                    # Record crash in session
                    session.record_crash(
                        file_id=file_id,
                        crash_type="crash",
                        exception_type=type(e).__name__,
                        exception_message=str(e),
                        stack_trace=crash_report.stack_trace,
                    )
            else:
                # No crash
                session.record_test_result(
                    file_id=file_id, result="pass", execution_time=0.05
                )

            session.end_file_fuzzing(output_file)

        # Step 3: Verify crash detection
        summary = session.get_session_summary()
        assert summary["crashes"] == 3  # Files 0, 2, 4 crashed
        assert summary["total_files"] == 5

        # Step 4: Analyze crashes
        crash_summary = crash_analyzer.get_crash_summary()
        assert crash_summary["total_crashes"] >= 3
        assert crash_summary["unique_crashes"] >= 1

    def test_multi_file_fuzzing_with_statistics(self, fuzzing_workspace):
        """
        Test fuzzing multiple files with statistics tracking:
        1. Generate diverse seed files
        2. Fuzz with different severities
        3. Track statistics
        4. Generate comprehensive report
        """
        # Step 1: Generate diverse seed files
        generator = DICOMGenerator(output_dir=fuzzing_workspace["inputs"], skip_write_errors=True)
        seed_files = generator.generate(count=10)

        # Step 2: Create session and statistics
        session = FuzzingSession(
            session_name="multi_file_test", output_dir=str(fuzzing_workspace["outputs"])
        )
        statistics = StatisticsCollector()

        # Step 3: Fuzz with different severities
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

            # Track start time
            statistics.track_iteration(
                file_path=str(output_file), mutations_applied=i + 1, severity=severity
            )

            # Apply mutations
            mutator.start_session(source_file=str(seed_file), severity=severity)
            mutated_dataset = mutator.apply_mutations(dataset, severity=severity)
            mutation_summary = mutator.end_session()

            # Save
            mutated_dataset.save_as(str(output_file), write_like_original=False)

            # Record results
            session.record_test_result(
                file_id=file_id, result="pass", execution_time=0.1
            )
            session.end_file_fuzzing(output_file)

            # Track mutations
            for mutation in mutation_summary["mutations"]:
                session.record_mutation(
                    strategy_name=mutation.get("strategy", "unknown"),
                    target_tag=mutation.get("tag", "unknown"),
                    mutation_type=mutation.get("type", "unknown"),
                )

        # Step 4: Generate reports
        session_summary = session.get_session_summary()

        assert session_summary["total_files"] == 10
        assert session_summary["total_mutations"] > 0
        assert session_summary["files_per_minute"] > 0

        # Statistics should track all files
        stats_summary = statistics.get_summary()
        assert stats_summary["total_iterations"] == 10

    def test_reporter_integration(self, fuzzing_workspace):
        """
        Test reporter integration with complete fuzzing data:
        1. Create fuzzing data
        2. Generate text report
        3. Generate JSON report
        4. Verify report contents
        """
        # Step 1: Create session with data
        session = FuzzingSession(
            session_name="reporter_test", output_dir=str(fuzzing_workspace["outputs"])
        )

        # Add some fuzzing data
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

            session.record_test_result(file_id=file_id, result="pass", execution_time=0.1)
            session.end_file_fuzzing(output_file)

        # Step 2: Generate text report
        reporter = ReportGenerator(session_data=session.get_session_summary())
        text_report = reporter.generate_report()

        assert "Fuzzing Report" in text_report or "Session" in text_report
        assert str(3) in text_report  # Should contain the number 3

        # Step 3: Generate JSON report
        report_path = fuzzing_workspace["reports"] / "report.json"
        session.save_session_report(str(report_path))

        assert report_path.exists()

        # Step 4: Verify report contents
        import json

        with open(report_path, "r") as f:
            report_data = json.load(f)

        assert "session_info" in report_data
        assert "statistics" in report_data
        assert "fuzzed_files" in report_data
        assert report_data["statistics"]["files_fuzzed"] == 3

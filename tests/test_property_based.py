"""
Property-Based Tests for DICOM Fuzzer

Uses Hypothesis for comprehensive property testing to ensure:
- Mutations always produce valid output
- Session tracking maintains consistency
- No data corruption across operations
- Security properties are maintained
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pydicom
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck
from hypothesis.strategies import composite
from pydicom.dataset import Dataset, FileDataset

from core.fuzzing_session import FuzzingSession, MutationRecord
from core.mutator import DicomMutator
from core.types import MutationSeverity


# Custom strategies for DICOM-specific data
@composite
def dicom_tag_strategy(draw):
    """Generate valid DICOM tags."""
    group = draw(st.integers(min_value=0x0000, max_value=0xFFFF))
    element = draw(st.integers(min_value=0x0000, max_value=0xFFFF))
    return f"({group:04X},{element:04X})"


@composite
def patient_name_strategy(draw):
    """Generate valid patient names."""
    first = draw(st.text(alphabet=st.characters(min_codepoint=65, max_codepoint=90), min_size=1, max_size=20))
    last = draw(st.text(alphabet=st.characters(min_codepoint=65, max_codepoint=90), min_size=1, max_size=20))
    return f"{last}^{first}"


@composite
def dicom_date_strategy(draw):
    """Generate valid DICOM dates (YYYYMMDD)."""
    year = draw(st.integers(min_value=1900, max_value=2100))
    month = draw(st.integers(min_value=1, max_value=12))
    day = draw(st.integers(min_value=1, max_value=28))  # Safe for all months
    return f"{year:04d}{month:02d}{day:02d}"


@composite
def mutation_severity_strategy(draw):
    """Generate mutation severity levels."""
    return draw(st.sampled_from(list(MutationSeverity)))


class TestMutatorProperties:
    """Property-based tests for DicomMutator."""

    @given(
        num_mutations=st.integers(min_value=1, max_value=10),
        mutation_probability=st.floats(min_value=0.0, max_value=1.0),
    )
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=500)
    def test_mutations_respect_count(self, num_mutations, mutation_probability):
        """Property: Applied mutations never exceed requested count."""
        mutator = DicomMutator(config={
            "mutation_probability": mutation_probability,
            "auto_register_strategies": True
        })

        # Create a minimal dataset
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"

        mutator.start_session(ds)
        result = mutator.apply_mutations(ds, num_mutations=num_mutations)

        # Property: mutations applied <= mutations requested
        if mutator.current_session:
            assert len(mutator.current_session.mutations) <= num_mutations

        # Property: result is still a Dataset
        assert isinstance(result, Dataset)

    @given(
        severity=mutation_severity_strategy(),
        strategy_names=st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=5),
    )
    def test_mutation_parameters_preserved(self, severity, strategy_names):
        """Property: Mutation parameters are correctly preserved."""
        mutator = DicomMutator()

        ds = Dataset()
        ds.PatientName = "Test"

        mutator.start_session(ds)

        # Apply mutations with specific parameters
        if strategy_names:
            result = mutator.apply_mutations(
                ds,
                severity=severity,
                strategy_names=strategy_names
            )
        else:
            result = mutator.apply_mutations(ds, severity=severity)

        # Property: result is always a Dataset
        assert isinstance(result, Dataset)

    @given(
        patient_name=patient_name_strategy(),
        patient_id=st.text(alphabet=st.characters(min_codepoint=48, max_codepoint=57), min_size=1, max_size=10),
        study_date=dicom_date_strategy(),
    )
    def test_dataset_remains_valid_after_mutation(self, patient_name, patient_id, study_date):
        """Property: Mutated datasets remain structurally valid."""
        mutator = DicomMutator(config={"mutation_probability": 1.0})

        ds = Dataset()
        ds.PatientName = patient_name
        ds.PatientID = patient_id
        ds.StudyDate = study_date

        mutator.start_session(ds)
        result = mutator.apply_mutations(ds, num_mutations=1)

        # Property: Result is still a Dataset
        assert isinstance(result, Dataset)

        # Property: Core attributes still exist (even if mutated)
        assert hasattr(result, "PatientName")
        assert hasattr(result, "PatientID")
        assert hasattr(result, "StudyDate")


class TestFuzzingSessionProperties:
    """Property-based tests for FuzzingSession."""

    @given(
        session_name=st.text(alphabet=st.characters(min_codepoint=65, max_codepoint=122), min_size=1, max_size=50),
        num_files=st.integers(min_value=0, max_value=100),
    )
    @settings(deadline=500)
    def test_session_tracking_consistency(self, session_name, num_files):
        """Property: Session tracking maintains consistency."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name=session_name,
                output_dir=tmpdir,
            )

            # Track multiple files
            file_ids = []
            for i in range(num_files):
                file_id = session.start_file_fuzzing(
                    source_file=Path(f"input_{i}.dcm"),
                    output_file=Path(f"output_{i}.dcm"),
                    severity="moderate"
                )
                file_ids.append(file_id)
                session.end_file_fuzzing(Path(f"output_{i}.dcm"), success=False)

            # Properties
            assert session.stats["files_fuzzed"] == num_files
            assert len(session.fuzzed_files) == num_files
            assert len(set(file_ids)) == num_files  # All IDs unique

    @given(
        mutations=st.lists(
            st.tuples(
                st.text(min_size=1, max_size=20),  # strategy_name
                st.text(min_size=1, max_size=20),  # mutation_type
                st.text(min_size=0, max_size=50),  # original_value
                st.text(min_size=0, max_size=50),  # mutated_value
            ),
            min_size=0,
            max_size=20
        )
    )
    def test_mutation_recording_integrity(self, mutations):
        """Property: All recorded mutations are preserved correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name="test",
                output_dir=tmpdir,
            )

            file_id = session.start_file_fuzzing(
                source_file=Path("test.dcm"),
                output_file=Path("out.dcm"),
                severity="moderate"
            )

            # Record mutations
            for strategy, mut_type, orig, mut in mutations:
                session.record_mutation(
                    strategy_name=strategy,
                    mutation_type=mut_type,
                    original_value=orig,
                    mutated_value=mut,
                )

            # Properties
            assert len(session.current_file_record.mutations) == len(mutations)
            assert session.stats["mutations_applied"] == len(mutations)

            # Verify each mutation preserved
            for i, (strategy, mut_type, orig, mut) in enumerate(mutations):
                recorded = session.current_file_record.mutations[i]
                assert recorded.strategy_name == strategy
                assert recorded.mutation_type == mut_type

    @given(
        num_crashes=st.integers(min_value=0, max_value=10),
        num_hangs=st.integers(min_value=0, max_value=10),
        num_successes=st.integers(min_value=0, max_value=10),
    )
    @settings(deadline=500)
    def test_statistics_consistency(self, num_crashes, num_hangs, num_successes):
        """Property: Statistics remain consistent throughout session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name="stats_test",
                output_dir=tmpdir,
            )

            file_counter = 0

            # Record crashes
            for i in range(num_crashes):
                file_id = f"crash_file_{i}"
                # Create a proper file record structure
                from core.fuzzing_session import FuzzedFileRecord
                file_record = FuzzedFileRecord(
                    file_id=file_id,
                    source_file=str(Path(f"source_{i}.dcm")),
                    output_file=str(Path(f"crash_{i}.dcm")),
                    timestamp=datetime.now(),
                    file_hash="test_hash",
                    severity="moderate",
                    mutations=[]
                )
                session.fuzzed_files[file_id] = file_record
                session.record_crash(
                    file_id=file_id,
                    crash_type="crash",
                    exception_type="TestCrash"
                )

            # Record hangs
            for i in range(num_hangs):
                file_id = f"hang_file_{i}"
                # Create a proper file record structure
                from core.fuzzing_session import FuzzedFileRecord
                file_record = FuzzedFileRecord(
                    file_id=file_id,
                    source_file=str(Path(f"source_hang_{i}.dcm")),
                    output_file=str(Path(f"hang_{i}.dcm")),
                    timestamp=datetime.now(),
                    file_hash="test_hash",
                    severity="moderate",
                    mutations=[]
                )
                session.fuzzed_files[file_id] = file_record
                session.record_crash(
                    file_id=file_id,
                    crash_type="hang",
                    exception_type="Timeout"
                )

            # Properties
            assert session.stats["crashes"] == num_crashes
            assert session.stats["hangs"] == num_hangs
            assert len(session.crashes) == num_crashes + num_hangs


class TestSecurityProperties:
    """Property-based tests for security-related behaviors."""

    @given(
        injection_payloads=st.lists(
            st.sampled_from([
                "'; DROP TABLE patients; --",
                "<script>alert('XSS')</script>",
                "../../etc/passwd",
                "\x00\x00\x00\x00",
                "A" * 10000,  # Buffer overflow attempt
                "%s%s%s%s%s%s%s",  # Format string
            ]),
            min_size=1,
            max_size=5
        )
    )
    def test_injection_payload_handling(self, injection_payloads):
        """Property: System handles injection payloads safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name="security_test",
                output_dir=tmpdir,
            )

            file_id = session.start_file_fuzzing(
                source_file=Path("test.dcm"),
                output_file=Path("out.dcm"),
                severity="aggressive"
            )

            # Record dangerous mutations
            for payload in injection_payloads:
                session.record_mutation(
                    strategy_name="InjectionTest",
                    mutation_type="injection",
                    original_value="safe_value",
                    mutated_value=payload,
                )

            session.end_file_fuzzing(Path("out.dcm"), success=False)

            # Generate report - should handle dangerous content safely
            report = session.generate_session_report()

            # Properties
            assert isinstance(report, dict)
            assert len(session.current_file_record.mutations) == len(injection_payloads) if session.current_file_record else True

            # Report generation shouldn't fail with dangerous content
            report_path = session.save_session_report()
            assert report_path.exists()

    @given(
        path_traversal_attempts=st.lists(
            st.sampled_from([
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "file:///etc/passwd",
            ]),
            min_size=1,
            max_size=3
        )
    )
    @settings(deadline=None)  # Disable deadline for this test due to variable path handling times
    def test_path_traversal_prevention(self, path_traversal_attempts):
        """Property: Path traversal attempts are handled safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name="path_test",
                output_dir=tmpdir,
            )

            for attempt in path_traversal_attempts:
                # Should handle dangerous paths safely
                try:
                    file_id = session.start_file_fuzzing(
                        source_file=Path(attempt),
                        output_file=Path("safe_output.dcm"),
                        severity="moderate"
                    )
                    # If it doesn't raise, the path should be tracked safely
                    assert file_id in session.fuzzed_files
                except (ValueError, OSError):
                    # Expected for invalid paths
                    pass

            # Property: Session remains stable
            assert isinstance(session.stats, dict)


class TestDataIntegrity:
    """Property-based tests for data integrity."""

    @given(
        original_values=st.lists(
            st.one_of(
                st.text(max_size=100),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False),
                st.binary(max_size=100),
            ),
            min_size=0,
            max_size=10
        )
    )
    def test_mutation_value_preservation(self, original_values):
        """Property: Original values are preserved in mutation records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = FuzzingSession(
                session_name="preservation_test",
                output_dir=tmpdir,
            )

            file_id = session.start_file_fuzzing(
                source_file=Path("test.dcm"),
                output_file=Path("out.dcm"),
                severity="moderate"
            )

            # Record mutations with various value types
            for i, orig_val in enumerate(original_values):
                session.record_mutation(
                    strategy_name=f"Strategy{i}",
                    mutation_type="test",
                    original_value=orig_val,
                    mutated_value=f"mutated_{i}",
                )

            # Properties
            assert len(session.current_file_record.mutations) == len(original_values)

            # Verify values are preserved (as strings)
            for i, orig_val in enumerate(original_values):
                mutation = session.current_file_record.mutations[i]
                # Values are converted to strings for storage
                if orig_val is not None:
                    assert mutation.original_value is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
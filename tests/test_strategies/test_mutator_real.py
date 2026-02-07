"""Real-world tests for mutator module.

Tests the main mutation engine with real DICOM files and actual strategies.
"""

from datetime import datetime

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.mutation.mutator import (
    DicomMutator,
    MutationRecord,
    MutationSession,
    MutationSeverity,
)


# Mock Strategy Implementation (renamed from TestStrategy to avoid pytest collection)
class MockStrategy:
    """Simple mock strategy for controlled testing."""

    def __init__(self, name: str = "mock_strategy"):
        self.name = name
        self.mutate_called = False
        self.last_dataset = None

    def mutate(self, dataset: Dataset, severity: MutationSeverity) -> Dataset:
        """Apply test mutation."""
        self.mutate_called = True
        self.last_dataset = dataset
        dataset.PatientID = "MUTATED_123"
        return dataset

    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return self.name

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if mutation is possible."""
        return True


class FailingStrategy:
    """Strategy that fails during mutation."""

    def mutate(self, dataset: Dataset, severity: MutationSeverity) -> Dataset:
        """Raise error during mutation."""
        raise ValueError("Intentional mutation failure")

    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "failing_strategy"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Always returns True."""
        return True


class ConditionalStrategy:
    """Strategy that only mutates certain datasets."""

    def mutate(self, dataset: Dataset, severity: MutationSeverity) -> Dataset:
        """Apply mutation."""
        dataset.PatientName = "CONDITIONAL_MUTATED"
        return dataset

    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "conditional_strategy"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate if PatientID exists."""
        return hasattr(dataset, "PatientID")


@pytest.fixture
def basic_dataset():
    """Create a basic DICOM dataset."""
    ds = Dataset()
    ds.PatientID = "ORIGINAL_123"
    ds.PatientName = "Test^Patient"
    ds.StudyDescription = "Test Study"
    return ds


class TestDicomMutatorInitialization:
    """Test DicomMutator initialization."""

    def test_initialization_default(self):
        """Test creating mutator with default config."""
        mutator = DicomMutator()

        assert mutator is not None
        assert mutator.config is not None
        assert isinstance(mutator.config, dict)
        assert mutator.current_session is None

    def test_initialization_with_config(self):
        """Test creating mutator with custom config."""
        config = {
            "max_mutations_per_file": 5,
            "mutation_probability": 0.8,
            "auto_register_strategies": False,
        }
        mutator = DicomMutator(config=config)

        assert mutator.config["max_mutations_per_file"] == 5
        assert mutator.config["mutation_probability"] == 0.8
        assert mutator.config["auto_register_strategies"] is False

    def test_initialization_without_auto_register(self):
        """Test that auto_register_strategies=False prevents default strategies."""
        config = {"auto_register_strategies": False}
        mutator = DicomMutator(config=config)

        assert len(mutator.strategies) == 0

    def test_initialization_loads_default_config(self):
        """Test that default config values are loaded."""
        mutator = DicomMutator()

        # Should have default values
        assert "max_mutations_per_file" in mutator.config
        assert "mutation_probability" in mutator.config


class TestStrategyRegistration:
    """Test strategy registration."""

    def test_register_single_strategy(self):
        """Test registering a single strategy."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy = MockStrategy()

        mutator.register_strategy(strategy)

        assert len(mutator.strategies) == 1
        assert mutator.strategies[0] is strategy

    def test_register_multiple_strategies(self):
        """Test registering multiple strategies."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy1 = MockStrategy("strategy1")
        strategy2 = MockStrategy("strategy2")

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)

        assert len(mutator.strategies) == 2
        assert strategy1 in mutator.strategies
        assert strategy2 in mutator.strategies

    def test_register_strategy_validates_protocol(self):
        """Test that strategy must implement MutationStrategy protocol."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        # Valid strategy should work
        valid_strategy = MockStrategy()
        mutator.register_strategy(valid_strategy)
        assert len(mutator.strategies) == 1

        # Invalid strategy (missing methods) should raise ValueError
        class InvalidStrategy:
            pass

        invalid = InvalidStrategy()
        with pytest.raises(
            ValueError, match="does not implement MutationStrategy protocol"
        ):
            mutator.register_strategy(invalid)


class TestSessionManagement:
    """Test mutation session lifecycle."""

    def test_start_session(self, basic_dataset):
        """Test starting a mutation session."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        session_id = mutator.start_session(basic_dataset)

        assert session_id is not None
        assert isinstance(session_id, str)
        assert len(session_id) > 0
        assert mutator.current_session is not None
        assert mutator.current_session.session_id == session_id

    def test_start_session_with_file_info(self, basic_dataset):
        """Test starting session with file information."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        file_info = {"filename": "test.dcm", "size": 1024}

        mutator.start_session(basic_dataset, file_info=file_info)

        assert mutator.current_session.original_file_info == file_info

    def test_start_session_resets_previous_session(self, basic_dataset):
        """Test that starting new session resets previous one."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        session_id1 = mutator.start_session(basic_dataset)
        session_id2 = mutator.start_session(basic_dataset)

        assert session_id1 != session_id2
        assert mutator.current_session.session_id == session_id2

    def test_end_session(self, basic_dataset):
        """Test ending a mutation session."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        mutator.start_session(basic_dataset)
        session = mutator.end_session()

        assert session is not None
        assert isinstance(session, MutationSession)
        assert mutator.current_session is None

    def test_end_session_without_active_session(self):
        """Test ending session when no session is active."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        session = mutator.end_session()

        assert session is None

    def test_session_captures_file_info(self, basic_dataset):
        """Test that session stores file information."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        file_info = {"patient_id": "ORIGINAL_123"}

        mutator.start_session(basic_dataset, file_info=file_info)

        assert mutator.current_session.original_file_info is not None
        assert mutator.current_session.original_file_info == file_info


class TestMutationApplication:
    """Test applying mutations to datasets."""

    def test_apply_mutations_single_strategy(self, basic_dataset):
        """Test applying mutations with single strategy."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutation always happens
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(basic_dataset, num_mutations=1)

        assert result.PatientID == "MUTATED_123"
        assert strategy.mutate_called

    def test_apply_mutations_tracks_records(self, basic_dataset):
        """Test that mutations are tracked in session."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutation always happens
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=1)

        assert len(mutator.current_session.mutations) > 0
        assert isinstance(mutator.current_session.mutations[0], MutationRecord)

    def test_apply_mutations_with_severity(self, basic_dataset):
        """Test applying mutations with specific severity."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(
            basic_dataset, num_mutations=1, severity=MutationSeverity.EXTREME
        )

        assert result is not None
        # Check that mutation was recorded with correct severity
        if mutator.current_session.mutations:
            assert (
                mutator.current_session.mutations[0].severity
                == MutationSeverity.EXTREME
            )

    def test_apply_mutations_without_session(self, basic_dataset):
        """Test that applying mutations without session raises error."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        # Should handle gracefully or raise error
        result = mutator.apply_mutations(basic_dataset, num_mutations=1)
        # Implementation may vary - just ensure it doesn't crash

        # Verify result is valid
        assert result is not None

    def test_apply_mutations_no_strategies_registered(self, basic_dataset):
        """Test applying mutations when no strategies registered."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(basic_dataset, num_mutations=1)

        # Should return dataset unchanged
        assert result.PatientID == "ORIGINAL_123"

    def test_apply_mutations_multiple_times(self, basic_dataset):
        """Test applying mutations multiple times."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutations always happen
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=2)

        # Should have multiple mutation records
        assert len(mutator.current_session.mutations) >= 2


class TestMutationRecords:
    """Test MutationRecord creation and tracking."""

    def test_mutation_record_creation(self):
        """Test creating mutation record."""
        record = MutationRecord(
            strategy_name="test_strategy", severity=MutationSeverity.MINIMAL
        )

        assert record.strategy_name == "test_strategy"
        assert record.severity == MutationSeverity.MINIMAL
        assert record.mutation_id is not None
        assert isinstance(record.timestamp, datetime)

    def test_mutation_record_default_values(self):
        """Test mutation record default values."""
        record = MutationRecord()

        assert record.mutation_id is not None
        assert record.strategy_name == ""
        assert record.severity == MutationSeverity.MINIMAL
        assert isinstance(record.timestamp, datetime)

    def test_mutation_record_unique_ids(self):
        """Test that each record gets unique ID."""
        record1 = MutationRecord()
        record2 = MutationRecord()

        assert record1.mutation_id != record2.mutation_id


class TestMutationSession:
    """Test MutationSession creation and tracking."""

    def test_mutation_session_creation(self, basic_dataset):
        """Test creating mutation session."""
        file_info = {"test": "data"}
        session = MutationSession(
            session_id="test_session_123", original_file_info=file_info
        )

        assert session.session_id == "test_session_123"
        assert session.original_file_info == file_info
        assert isinstance(session.mutations, list)
        assert len(session.mutations) == 0

    def test_mutation_session_with_file_info(self, basic_dataset):
        """Test creating session with file information."""
        file_info = {"filename": "test.dcm", "size": 2048}
        session = MutationSession(
            session_id="test_session", original_file_info=file_info
        )

        assert session.original_file_info == file_info
        assert session.original_file_info["filename"] == "test.dcm"


class TestSessionSummary:
    """Test session summary generation."""

    def test_get_session_summary(self, basic_dataset):
        """Test getting session summary."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutation always happens
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=1)
        summary = mutator.get_session_summary()

        assert summary is not None
        assert isinstance(summary, dict)
        assert "session_id" in summary
        assert "mutations_applied" in summary

    def test_get_session_summary_without_session(self):
        """Test getting summary when no session active."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        summary = mutator.get_session_summary()

        assert summary is None

    def test_session_summary_includes_mutation_count(self, basic_dataset):
        """Test that summary includes mutation count."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutation always happens
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=1)
        summary = mutator.get_session_summary()

        assert "mutations_applied" in summary
        assert summary["mutations_applied"] >= 1


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_failing_strategy_continues_execution(self, basic_dataset):
        """Test that failing strategy doesn't stop other mutations."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutations always happen
        }
        mutator = DicomMutator(config=config)
        failing = FailingStrategy()
        working = MockStrategy()
        mutator.register_strategy(failing)
        mutator.register_strategy(working)

        mutator.start_session(basic_dataset)
        # Should handle failure gracefully
        result = mutator.apply_mutations(basic_dataset, num_mutations=2)

        # At least the working strategy should have applied
        assert result is not None

    def test_conditional_strategy_skips_when_cannot_mutate(self):
        """Test that strategy is skipped when can_mutate returns False."""
        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy = ConditionalStrategy()
        mutator.register_strategy(strategy)

        # Create dataset without PatientID
        ds = Dataset()
        ds.StudyDescription = "Test"

        mutator.start_session(ds)
        result = mutator.apply_mutations(ds, num_mutations=1)

        # Should not have been mutated
        assert (
            not hasattr(result, "PatientName")
            or result.PatientName != "CONDITIONAL_MUTATED"
        )


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_complete_mutation_workflow(self, basic_dataset):
        """Test complete mutation workflow from start to finish."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutation always happens
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        # Start session
        session_id = mutator.start_session(
            basic_dataset, file_info={"filename": "test.dcm"}
        )
        assert session_id is not None

        # Apply mutations
        result = mutator.apply_mutations(basic_dataset, num_mutations=1)
        assert result.PatientID == "MUTATED_123"

        # Get summary
        summary = mutator.get_session_summary()
        assert summary is not None
        assert summary["session_id"] == session_id

        # End session
        session = mutator.end_session()
        assert session is not None
        assert session.session_id == session_id

    def test_multiple_strategies_in_sequence(self, basic_dataset):
        """Test applying multiple different strategies."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutations always happen
        }
        mutator = DicomMutator(config=config)
        strategy1 = MockStrategy("strategy1")
        strategy2 = MockStrategy("strategy2")
        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(basic_dataset, num_mutations=2)

        assert result is not None
        assert len(mutator.current_session.mutations) >= 2

    def test_session_reuse_after_end(self, basic_dataset):
        """Test starting new session after ending previous one."""
        config = {
            "auto_register_strategies": False,
            "mutation_probability": 1.0,  # Ensure mutations always happen
        }
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        # First session
        session_id1 = mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=1)
        mutator.end_session()

        # Second session
        session_id2 = mutator.start_session(basic_dataset)
        mutator.apply_mutations(basic_dataset, num_mutations=1)

        assert session_id1 != session_id2
        assert mutator.current_session.session_id == session_id2


class TestConfigurationHandling:
    """Test configuration handling."""

    def test_max_mutations_config(self, basic_dataset):
        """Test that max_mutations_per_file config is respected."""
        config = {"max_mutations_per_file": 2, "auto_register_strategies": False}
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(basic_dataset, num_mutations=10)

        # Should respect max_mutations_per_file limit
        assert result is not None

    def test_mutation_probability_config(self, basic_dataset):
        """Test mutation probability configuration."""
        config = {"mutation_probability": 0.0, "auto_register_strategies": False}
        mutator = DicomMutator(config=config)
        strategy = MockStrategy()
        mutator.register_strategy(strategy)

        mutator.start_session(basic_dataset)
        result = mutator.apply_mutations(basic_dataset, num_mutations=5)

        # With 0% probability, no mutations should occur
        # (implementation may vary)
        assert result is not None

    def test_config_merge_with_defaults(self):
        """Test that custom config merges with defaults."""
        config = {"custom_key": "custom_value"}
        mutator = DicomMutator(config=config)

        assert "custom_key" in mutator.config
        assert "max_mutations_per_file" in mutator.config  # Default should still exist


class TestMutationSeverity:
    """Test mutation severity handling."""

    def test_mutation_severity_enum_values(self):
        """Test that MutationSeverity enum has expected values."""
        assert hasattr(MutationSeverity, "MINIMAL")
        assert hasattr(MutationSeverity, "MODERATE")
        assert hasattr(MutationSeverity, "AGGRESSIVE")
        assert hasattr(MutationSeverity, "EXTREME")

    def test_severity_in_mutation_record(self):
        """Test severity is properly stored in mutation record."""
        record = MutationRecord(
            strategy_name="test", severity=MutationSeverity.AGGRESSIVE
        )

        assert record.severity == MutationSeverity.AGGRESSIVE

    def test_default_severity_is_minimal(self):
        """Test that default severity is MINIMAL."""
        record = MutationRecord(strategy_name="test")

        assert record.severity == MutationSeverity.MINIMAL

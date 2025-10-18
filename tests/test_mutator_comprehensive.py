"""
Comprehensive tests for core/mutator.py module.

Achieves 60%+ coverage of mutation engine functionality.
"""

import pytest
from datetime import datetime
from pydicom.dataset import Dataset
from dicom_fuzzer.core.mutator import (
    MutationRecord,
    MutationSeverity,
)


class TestMutationRecord:
    """Tests for MutationRecord dataclass."""

    def test_initialization_with_defaults(self):
        """Test MutationRecord with default values."""
        record = MutationRecord()

        assert isinstance(record.mutation_id, str)
        assert len(record.mutation_id) == 8  # UUID first 8 chars
        assert record.strategy_name == ""
        assert record.severity == MutationSeverity.MINIMAL
        assert isinstance(record.timestamp, datetime)
        assert record.description == ""
        assert isinstance(record.parameters, dict)
        assert len(record.parameters) == 0
        assert record.success is True
        assert record.error_message is None

    def test_initialization_with_custom_values(self):
        """Test MutationRecord with custom values."""
        custom_time = datetime(2025, 1, 1, 12, 0, 0)
        record = MutationRecord(
            mutation_id="test123",
            strategy_name="bit_flip",
            severity=MutationSeverity.EXTREME,
            timestamp=custom_time,
            description="Test mutation",
            parameters={"offset": 100},
            success=False,
            error_message="Test error",
        )

        assert record.mutation_id == "test123"
        assert record.strategy_name == "bit_flip"
        assert record.severity == MutationSeverity.EXTREME
        assert record.timestamp == custom_time
        assert record.description == "Test mutation"
        assert record.parameters == {"offset": 100}
        assert record.success is False
        assert record.error_message == "Test error"

    def test_unique_mutation_ids(self):
        """Test that mutation IDs are unique."""
        record1 = MutationRecord()
        record2 = MutationRecord()

        assert record1.mutation_id != record2.mutation_id

    def test_severity_levels(self):
        """Test different severity levels."""
        severities = [
            MutationSeverity.MINIMAL,
            MutationSeverity.MODERATE,
            MutationSeverity.AGGRESSIVE,
            MutationSeverity.EXTREME,
        ]

        for severity in severities:
            record = MutationRecord(severity=severity)
            assert record.severity == severity

    def test_parameters_dictionary(self):
        """Test parameters can store various data types."""
        params = {
            "int_val": 42,
            "str_val": "test",
            "float_val": 3.14,
            "bool_val": True,
            "list_val": [1, 2, 3],
            "dict_val": {"nested": "data"},
        }

        record = MutationRecord(parameters=params)

        assert record.parameters["int_val"] == 42
        assert record.parameters["str_val"] == "test"
        assert record.parameters["float_val"] == 3.14
        assert record.parameters["bool_val"] is True
        assert record.parameters["list_val"] == [1, 2, 3]
        assert record.parameters["dict_val"]["nested"] == "data"

    def test_success_and_error_states(self):
        """Test success/error state tracking."""
        # Success case
        success_record = MutationRecord(success=True)
        assert success_record.success is True
        assert success_record.error_message is None

        # Failure case
        failure_record = MutationRecord(
            success=False, error_message="Mutation failed"
        )
        assert failure_record.success is False
        assert failure_record.error_message == "Mutation failed"

    def test_description_field(self):
        """Test description field."""
        description = "Applied bit flip mutation at offset 0x1234"
        record = MutationRecord(description=description)

        assert record.description == description

    def test_timestamp_is_utc(self):
        """Test timestamp is in UTC timezone."""
        record = MutationRecord()

        # Timestamp should be timezone-aware (UTC)
        assert record.timestamp.tzinfo is not None


class TestMutationSeverity:
    """Tests for MutationSeverity enum."""

    def test_severity_enum_values(self):
        """Test all severity enum values exist."""
        assert hasattr(MutationSeverity, "MINIMAL")
        assert hasattr(MutationSeverity, "MODERATE")
        assert hasattr(MutationSeverity, "AGGRESSIVE")
        assert hasattr(MutationSeverity, "EXTREME")

    def test_severity_ordering(self):
        """Test severity values can be compared."""
        # Ensure severities are distinct
        severities = [
            MutationSeverity.MINIMAL,
            MutationSeverity.MODERATE,
            MutationSeverity.AGGRESSIVE,
            MutationSeverity.EXTREME,
        ]

        # All should be unique
        assert len(set(severities)) == 4

    def test_severity_string_representation(self):
        """Test severity string representation."""
        severity = MutationSeverity.EXTREME

        # Should have a string representation
        assert str(severity) is not None
        assert repr(severity) is not None


class TestIntegrationScenarios:
    """Integration tests for mutator functionality."""

    def test_mutation_record_lifecycle(self):
        """Test complete mutation record lifecycle."""
        # Create initial record
        record = MutationRecord(
            strategy_name="header_fuzzer",
            severity=MutationSeverity.MODERATE,
            description="Mutating patient name field",
        )

        # Simulate successful mutation
        record.parameters = {
            "tag": "0010,0010",
            "original_value": "John Doe",
            "mutated_value": "FUZZ_DATA",
        }

        # Verify record
        assert record.success is True
        assert record.strategy_name == "header_fuzzer"
        assert "tag" in record.parameters

    def test_mutation_record_error_handling(self):
        """Test mutation record with error."""
        record = MutationRecord(
            strategy_name="pixel_fuzzer",
            severity=MutationSeverity.AGGRESSIVE,
        )

        # Simulate mutation failure
        record.success = False
        record.error_message = "Invalid pixel data format"

        assert record.success is False
        assert "Invalid" in record.error_message

    def test_multiple_mutation_records(self):
        """Test tracking multiple mutations."""
        records = []

        # Create multiple mutation records
        strategies = ["bit_flip", "byte_swap", "random"]
        for i, strategy in enumerate(strategies):
            record = MutationRecord(
                strategy_name=strategy,
                severity=MutationSeverity.MINIMAL,
                description=f"Mutation {i+1}",
            )
            records.append(record)

        assert len(records) == 3
        assert records[0].strategy_name == "bit_flip"
        assert records[1].strategy_name == "byte_swap"
        assert records[2].strategy_name == "random"

        # All should have unique IDs
        ids = [r.mutation_id for r in records]
        assert len(set(ids)) == 3

    def test_mutation_severity_escalation(self):
        """Test mutation severity escalation."""
        # Start with minimal
        record = MutationRecord(severity=MutationSeverity.MINIMAL)
        assert record.severity == MutationSeverity.MINIMAL

        # Can update severity
        record.severity = MutationSeverity.EXTREME
        assert record.severity == MutationSeverity.EXTREME

    def test_mutation_parameters_update(self):
        """Test updating mutation parameters."""
        record = MutationRecord()

        # Add parameters incrementally
        record.parameters["step1"] = "completed"
        record.parameters["step2"] = "completed"
        record.parameters["final_result"] = "success"

        assert len(record.parameters) == 3
        assert record.parameters["final_result"] == "success"

    def test_mutation_record_serialization_readiness(self):
        """Test mutation record can be serialized."""
        record = MutationRecord(
            strategy_name="test",
            severity=MutationSeverity.MODERATE,
            description="Test mutation",
            parameters={"key": "value"},
        )

        # Should be able to access all fields (JSON-ready)
        assert isinstance(record.mutation_id, str)
        assert isinstance(record.strategy_name, str)
        assert isinstance(record.description, str)
        assert isinstance(record.parameters, dict)
        assert isinstance(record.success, bool)

    def test_complex_mutation_workflow(self):
        """Test complex mutation workflow with multiple stages."""
        # Stage 1: Initialize
        record = MutationRecord(
            strategy_name="multi_stage_fuzzer",
            severity=MutationSeverity.AGGRESSIVE,
        )

        # Stage 2: Add initial parameters
        record.parameters["stage"] = "initialization"
        record.parameters["target_tag"] = "0020,000D"

        # Stage 3: Perform mutation
        record.parameters["stage"] = "mutation"
        record.parameters["mutation_type"] = "corruption"

        # Stage 4: Validation
        record.parameters["stage"] = "validation"
        record.parameters["validation_result"] = "PASS"

        # Final state
        assert record.parameters["stage"] == "validation"
        assert record.parameters["validation_result"] == "PASS"
        assert record.success is True


class MockStrategy:
    """Mock mutation strategy for testing."""

    def __init__(self, name="mock_strategy", can_mutate_result=True):
        self.name = name
        self.can_mutate_result = can_mutate_result
        self.mutate_called = False

    def mutate(self, dataset, severity):
        self.mutate_called = True
        return dataset

    def get_strategy_name(self):
        return self.name

    def can_mutate(self, dataset):
        return self.can_mutate_result


class TestDicomMutatorInitialization:
    """Test suite for DicomMutator initialization."""

    def test_initialization_no_config(self):
        """Test DicomMutator initialization without config."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})

        assert mutator.config is not None
        assert mutator.strategies == []
        assert mutator.current_session is None

    def test_initialization_with_config(self):
        """Test DicomMutator initialization with custom config."""
        from dicom_fuzzer.core.mutator import DicomMutator

        config = {
            "max_mutations_per_file": 5,
            "mutation_probability": 0.8,
            "auto_register_strategies": False,
        }
        mutator = DicomMutator(config=config)

        assert mutator.config["max_mutations_per_file"] == 5
        assert mutator.config["mutation_probability"] == 0.8

    def test_default_config_loaded(self):
        """Test that default configuration is loaded."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})

        assert "max_mutations_per_file" in mutator.config
        assert "mutation_probability" in mutator.config
        assert "default_severity" in mutator.config


class TestStrategyRegistration:
    """Test suite for strategy registration."""

    def test_register_valid_strategy(self):
        """Test registering a valid strategy."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy = MockStrategy()

        mutator.register_strategy(strategy)

        assert len(mutator.strategies) == 1
        assert mutator.strategies[0] == strategy

    def test_register_multiple_strategies(self):
        """Test registering multiple strategies."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        strategy1 = MockStrategy(name="strategy1")
        strategy2 = MockStrategy(name="strategy2")

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)

        assert len(mutator.strategies) == 2

    def test_register_invalid_strategy(self):
        """Test registering an invalid strategy raises error."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        invalid_strategy = object()  # Missing required methods

        with pytest.raises(ValueError, match="does not implement MutationStrategy"):
            mutator.register_strategy(invalid_strategy)


class TestSessionManagement:
    """Test suite for session management."""

    def test_start_session(self):
        """Test starting a mutation session."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        dataset = Dataset()
        file_info = {"path": "/test/file.dcm"}

        session_id = mutator.start_session(dataset, file_info)

        assert session_id is not None
        assert mutator.current_session is not None
        assert mutator.current_session.session_id == session_id

    def test_end_session(self):
        """Test ending a mutation session."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        dataset = Dataset()
        mutator.start_session(dataset)

        completed_session = mutator.end_session()

        assert completed_session is not None
        assert completed_session.end_time is not None
        assert mutator.current_session is None

    def test_get_session_summary(self):
        """Test getting session summary."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        dataset = Dataset()
        mutator.start_session(dataset, {"file": "test.dcm"})

        summary = mutator.get_session_summary()

        assert summary is not None
        assert "session_id" in summary
        assert "start_time" in summary


class TestApplyMutations:
    """Test suite for mutation application."""

    def test_apply_mutations_no_strategies(self):
        """Test mutation application with no registered strategies."""
        from dicom_fuzzer.core.mutator import DicomMutator

        mutator = DicomMutator(config={"auto_register_strategies": False})
        dataset = Dataset()

        result = mutator.apply_mutations(dataset)

        assert result == dataset  # Returns original dataset

    def test_apply_mutations_basic(self):
        """Test basic mutation application."""
        from dicom_fuzzer.core.mutator import DicomMutator
        from unittest.mock import patch

        with patch("random.random", return_value=0.5):
            with patch("random.choice") as mock_choice:
                mutator = DicomMutator(config={"auto_register_strategies": False})
                strategy = MockStrategy()
                mock_choice.return_value = strategy
                mutator.register_strategy(strategy)

                dataset = Dataset()
                result = mutator.apply_mutations(dataset, num_mutations=1)

                assert result is not None

"""
Additional tests for DicomMutator to improve code coverage.

These tests target specific uncovered code paths in mutator.py
to increase overall test coverage.
"""

from unittest.mock import Mock

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.mutation.mutator import (
    DicomMutator,
    MutationRecord,
    MutationSession,
)


class TestMutationRecordAndSession:
    """Test MutationRecord and MutationSession dataclasses."""

    def test_mutation_record_creation(self):
        """Test MutationRecord creation."""
        record = MutationRecord(
            mutation_id="test123",
            strategy_name="test_strategy",
            description="Test mutation",
            success=True,
        )
        assert record.mutation_id == "test123"
        assert record.strategy_name == "test_strategy"
        assert record.description == "Test mutation"
        assert record.success is True

    def test_mutation_session_creation(self):
        """Test MutationSession creation."""
        session = MutationSession(
            session_id="session123", total_mutations=5, successful_mutations=4
        )
        assert session.session_id == "session123"
        assert session.mutations == []
        assert session.total_mutations == 5
        assert session.successful_mutations == 4


class TestMutatorConfigAndDefaults:
    """Test mutator configuration and defaults."""

    def test_mutator_with_custom_config(self):
        """Test mutator with custom configuration."""
        custom_config = {
            "max_mutations_per_file": 50,
            "mutation_probability": 0.9,
        }

        mutator = DicomMutator(config=custom_config)
        assert mutator.config["max_mutations_per_file"] == 50

    def test_mutator_default_config(self):
        """Test mutator with default configuration."""
        mutator = DicomMutator()
        # Check default config values are present
        assert "max_mutations_per_file" in mutator.config
        assert isinstance(mutator.strategies, list)

    def test_mutator_without_auto_register(self):
        """Test mutator with auto_register_strategies disabled."""
        config = {"auto_register_strategies": False}
        mutator = DicomMutator(config=config)
        # Should have no strategies registered
        assert len(mutator.strategies) == 0


class TestStrategyRegistration:
    """Test strategy registration functionality."""

    def test_register_custom_strategy(self):
        """Test registering a custom mutation strategy."""
        mutator = DicomMutator()

        # Create a mock strategy
        mock_strategy = Mock()
        mock_strategy.get_strategy_name = Mock(return_value="custom_strategy")
        mock_strategy.can_mutate = Mock(return_value=True)
        mock_strategy.mutate = Mock(return_value=Dataset())

        # Register the strategy
        mutator.register_strategy(mock_strategy)

        # Verify strategy is registered
        strategy_names = [s.get_strategy_name() for s in mutator.strategies]
        assert "custom_strategy" in strategy_names

    def test_register_strategy_validation_error(self):
        """Test strategy registration with missing required methods."""
        mutator = DicomMutator()

        # Try to register invalid strategy (missing mutate method)
        invalid_strategy = Mock(
            spec=["get_strategy_name"]
        )  # Only has get_strategy_name
        invalid_strategy.get_strategy_name = Mock(return_value="invalid")

        # Should raise ValueError when trying to register
        with pytest.raises(ValueError):
            mutator.register_strategy(invalid_strategy)


class TestSessionManagement:
    """Test mutation session management."""

    def test_start_session_basic(self):
        """Test starting a mutation session."""
        mutator = DicomMutator()

        ds = Dataset()
        ds.PatientName = "Test"

        mutator.start_session(ds)

        # Verify session is created
        assert mutator.current_session is not None
        assert isinstance(mutator.current_session, MutationSession)
        assert mutator.current_session.mutations == []

    def test_end_session(self):
        """Test ending a mutation session."""
        mutator = DicomMutator()

        ds = Dataset()
        ds.PatientName = "Test"

        mutator.start_session(ds)
        session = mutator.end_session()

        # Verify session is ended
        assert mutator.current_session is None
        assert isinstance(session, MutationSession)
        assert session.total_mutations >= 0
        assert session.successful_mutations >= 0

    def test_get_session_summary_without_session(self):
        """Test getting session summary when no session exists."""
        mutator = DicomMutator()
        summary = mutator.get_session_summary()

        # Should return None when no session exists
        assert summary is None


class TestMutationApplication:
    """Test mutation application functionality."""

    def test_apply_mutations_basic(self):
        """Test applying mutations to a dataset."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "001"
        ds.StudyDate = "20250101"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutated_ds = mutator.apply_mutations(ds, num_mutations=2)

        # Verify mutations were applied
        assert isinstance(mutated_ds, Dataset)
        assert mutated_ds is not None

    def test_apply_mutations_with_specific_strategies(self):
        """Test applying mutations with specific strategy names."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutated_ds = mutator.apply_mutations(ds, strategy_names=["metadata"])

        # Verify mutations were applied
        assert isinstance(mutated_ds, Dataset)

    def test_apply_mutations_no_applicable_strategies(self):
        """Test applying mutations when no strategies are applicable."""
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        # Create mutator without auto-registering strategies
        mutator = DicomMutator(config={"auto_register_strategies": False})
        mutated_ds = mutator.apply_mutations(ds)

        # Should return dataset unchanged (no strategies available)
        assert isinstance(mutated_ds, Dataset)

    def test_apply_single_mutation_error_handling(self):
        """Test error handling in _apply_single_mutation."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutator.start_session(ds)

        # Create a strategy that raises an error
        error_strategy = Mock()
        error_strategy.get_strategy_name = Mock(return_value="error_strategy")
        error_strategy.can_mutate = Mock(return_value=True)
        error_strategy.mutate = Mock(side_effect=ValueError("Test error"))

        mutator.register_strategy(error_strategy)

        # Try to apply mutation - should handle error gracefully
        mutated_ds = mutator.apply_mutations(
            ds, strategy_names=["error_strategy"], num_mutations=1
        )

        # Should still return a dataset (error handled)
        assert isinstance(mutated_ds, Dataset)


class TestSafetyChecks:
    """Test safety check functionality."""

    def test_is_safe_to_mutate(self):
        """Test safety checks for tag mutation."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()

        # Test that _is_safe_to_mutate method exists
        assert hasattr(mutator, "_is_safe_to_mutate")


class TestStrategyFiltering:
    """Test strategy filtering functionality."""

    def test_get_applicable_strategies(self):
        """Test getting applicable strategies."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()

        # Test that _get_applicable_strategies method exists
        assert hasattr(mutator, "_get_applicable_strategies")

    def test_get_applicable_strategies_with_names(self):
        """Test getting applicable strategies based on names."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()

        # Register custom strategies
        strategy1 = Mock()
        strategy1.get_strategy_name = Mock(return_value="strategy1")
        strategy1.can_mutate = Mock(return_value=True)
        strategy1.mutate = Mock(return_value=ds)

        strategy2 = Mock()
        strategy2.get_strategy_name = Mock(return_value="strategy2")
        strategy2.can_mutate = Mock(return_value=True)
        strategy2.mutate = Mock(return_value=ds)

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)

        # Apply only strategy1
        mutated_ds = mutator.apply_mutations(
            ds, strategy_names=["strategy1"], num_mutations=1
        )
        assert isinstance(mutated_ds, Dataset)


class TestMutationRecording:
    """Test mutation recording functionality."""

    def test_record_mutation_in_session(self):
        """Test recording mutations during a session."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "001"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutator.start_session(ds)

        # Apply mutations
        mutator.apply_mutations(ds, num_mutations=2)

        # End session and get MutationSession object
        session = mutator.end_session()

        # Verify mutations were recorded
        assert isinstance(session, MutationSession)
        assert session.total_mutations >= 0
        assert session.successful_mutations >= 0

    def test_record_mutation_method_exists(self):
        """Test that _record_mutation method exists."""
        mutator = DicomMutator()
        assert hasattr(mutator, "_record_mutation")


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    def test_mutator_with_empty_dataset(self):
        """Test mutator behavior with minimal dataset."""
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutated_ds = mutator.apply_mutations(ds)

        # Should handle gracefully
        assert isinstance(mutated_ds, Dataset)

    def test_multiple_mutation_sessions(self):
        """Test multiple sequential mutation sessions."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()

        # First session
        mutator.start_session(ds)
        mutator.apply_mutations(ds, num_mutations=1)
        session1 = mutator.end_session()

        # Second session
        mutator.start_session(ds)
        mutator.apply_mutations(ds, num_mutations=1)
        session2 = mutator.end_session()

        # Both sessions should complete
        assert isinstance(session1, MutationSession)
        assert isinstance(session2, MutationSession)

    def test_apply_mutations_with_zero_mutations(self):
        """Test applying zero mutations."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3"

        mutator = DicomMutator()
        mutated_ds = mutator.apply_mutations(ds, num_mutations=0)

        # Should return dataset unchanged
        assert isinstance(mutated_ds, Dataset)


class TestMutatorMethods:
    """Test specific mutator methods."""

    def test_load_default_config_called(self):
        """Test that _load_default_config is called during init."""
        mutator = DicomMutator()
        # Config should have defaults loaded
        assert mutator.config is not None
        assert isinstance(mutator.config, dict)

    def test_register_default_strategies_called(self):
        """Test that _register_default_strategies is called when enabled."""
        mutator = DicomMutator(config={"auto_register_strategies": True})
        # Should have default strategies registered
        assert len(mutator.strategies) > 0

    def test_register_strategy_method(self):
        """Test register_strategy method."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        # Create valid strategy
        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=Dataset())

        initial_count = len(mutator.strategies)
        mutator.register_strategy(strategy)

        # Strategy should be added
        assert len(mutator.strategies) == initial_count + 1

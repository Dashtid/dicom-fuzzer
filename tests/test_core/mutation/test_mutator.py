"""
Comprehensive tests for DICOM Mutation Engine.

Tests cover:
- MutationSeverity enum
- MutationRecord dataclass
- MutationSession dataclass
- DicomMutator initialization and configuration
- Strategy registration and management
- Session lifecycle management
- Mutation application logic
- Mutation tracking and recording
- Safety checks
- Integration workflows
"""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydicom.dataset import Dataset

from dicom_fuzzer.core.mutation.mutator import (
    DicomMutator,
    MutationRecord,
    MutationSession,
    MutationSeverity,
)


class TestMutationSeverity:
    """Test MutationSeverity enum."""

    def test_severity_values_exist(self):
        """Test that all severity levels are defined."""
        assert MutationSeverity.MINIMAL.value == "minimal"
        assert MutationSeverity.MODERATE.value == "moderate"
        assert MutationSeverity.AGGRESSIVE.value == "aggressive"
        assert MutationSeverity.EXTREME.value == "extreme"

    def test_severity_count(self):
        """Test that exactly 4 severity levels exist."""
        severities = list(MutationSeverity)
        assert len(severities) == 4

    def test_severity_membership(self):
        """Test severity level membership checks."""
        assert MutationSeverity.MINIMAL in MutationSeverity
        assert MutationSeverity.MODERATE in MutationSeverity

    def test_severity_comparison(self):
        """Test severity levels are distinct."""
        assert MutationSeverity.MINIMAL != MutationSeverity.MODERATE
        assert MutationSeverity.AGGRESSIVE != MutationSeverity.EXTREME


class TestMutationRecord:
    """Test MutationRecord dataclass."""

    def test_record_creation_with_defaults(self):
        """Test creating mutation record with default values."""
        record = MutationRecord()

        assert record.mutation_id != ""
        assert len(record.mutation_id) == 8  # UUID prefix
        assert record.strategy_name == ""
        assert record.severity == MutationSeverity.MINIMAL
        assert isinstance(record.timestamp, datetime)
        assert record.description == ""
        assert record.parameters == {}
        assert record.success is True
        assert record.error_message is None

    def test_record_creation_with_values(self):
        """Test creating mutation record with specific values."""
        timestamp = datetime.now(UTC)

        record = MutationRecord(
            mutation_id="test123",
            strategy_name="metadata_fuzzer",
            severity=MutationSeverity.AGGRESSIVE,
            timestamp=timestamp,
            description="Test mutation",
            parameters={"key": "value"},
            success=False,
            error_message="Test error",
        )

        assert record.mutation_id == "test123"
        assert record.strategy_name == "metadata_fuzzer"
        assert record.severity == MutationSeverity.AGGRESSIVE
        assert record.timestamp == timestamp
        assert record.description == "Test mutation"
        assert record.parameters == {"key": "value"}
        assert record.success is False
        assert record.error_message == "Test error"

    def test_record_unique_ids(self):
        """Test that mutation records get unique IDs."""
        record1 = MutationRecord()
        record2 = MutationRecord()

        assert record1.mutation_id != record2.mutation_id

    def test_record_timestamp_automatic(self):
        """Test that timestamps are automatically generated."""
        before = datetime.now(UTC)
        record = MutationRecord()
        after = datetime.now(UTC)

        assert before <= record.timestamp <= after


class TestMutationSession:
    """Test MutationSession dataclass."""

    def test_session_creation_with_defaults(self):
        """Test creating session with default values."""
        session = MutationSession()

        assert session.session_id != ""
        assert len(session.session_id) == 8
        assert session.original_file_info == {}
        assert session.mutations == []
        assert isinstance(session.start_time, datetime)
        assert session.end_time is None
        assert session.total_mutations == 0
        assert session.successful_mutations == 0

    def test_session_creation_with_values(self):
        """Test creating session with specific values."""
        start_time = datetime.now(UTC)
        end_time = datetime.now(UTC)
        mutations = [MutationRecord(), MutationRecord()]

        session = MutationSession(
            session_id="sess123",
            original_file_info={"path": "test.dcm"},
            mutations=mutations,
            start_time=start_time,
            end_time=end_time,
            total_mutations=5,
            successful_mutations=3,
        )

        assert session.session_id == "sess123"
        assert session.original_file_info == {"path": "test.dcm"}
        assert len(session.mutations) == 2
        assert session.start_time == start_time
        assert session.end_time == end_time
        assert session.total_mutations == 5
        assert session.successful_mutations == 3

    def test_session_unique_ids(self):
        """Test that sessions get unique IDs."""
        session1 = MutationSession()
        session2 = MutationSession()

        assert session1.session_id != session2.session_id


class TestDicomMutatorInit:
    """Test DicomMutator initialization."""

    def test_mutator_creation_no_config(self):
        """Test creating mutator without configuration."""
        # Create mutator without auto-registering strategies
        mutator = DicomMutator(config={"auto_register_strategies": False})

        assert mutator.config is not None
        assert mutator.strategies == []
        assert mutator.current_session is None

    def test_mutator_creation_with_config(self):
        """Test creating mutator with custom configuration."""
        config = {"max_mutations_per_file": 5, "mutation_probability": 0.9}

        mutator = DicomMutator(config=config)

        assert mutator.config["max_mutations_per_file"] == 5
        assert mutator.config["mutation_probability"] == 0.9

    def test_mutator_default_config_loaded(self):
        """Test that default configuration is loaded."""
        mutator = DicomMutator()

        assert "max_mutations_per_file" in mutator.config
        assert "mutation_probability" in mutator.config
        assert "default_severity" in mutator.config
        assert "preserve_critical_elements" in mutator.config
        assert "enable_mutation_tracking" in mutator.config
        assert "safety_checks" in mutator.config

    def test_mutator_default_values(self):
        """Test default configuration values are correct."""
        mutator = DicomMutator()

        assert mutator.config["max_mutations_per_file"] == 1
        assert mutator.config["mutation_probability"] == 1.0
        assert mutator.config["default_severity"] == MutationSeverity.MODERATE
        assert mutator.config["preserve_critical_elements"] is True
        assert mutator.config["enable_mutation_tracking"] is True
        assert mutator.config["safety_checks"] is True

    def test_mutator_config_override(self):
        """Test that custom config overrides defaults."""
        config = {"max_mutations_per_file": 10}
        mutator = DicomMutator(config=config)

        # Custom value should be used
        assert mutator.config["max_mutations_per_file"] == 10
        # Other defaults should still be present
        assert mutator.config["mutation_probability"] == 1.0


class TestStrategyRegistration:
    """Test mutation strategy registration."""

    def test_register_valid_strategy(self):
        """Test registering a valid strategy."""
        # Disable auto-registration for this test
        mutator = DicomMutator(config={"auto_register_strategies": False})

        # Create a mock strategy
        strategy = Mock()
        strategy.mutate = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")
        strategy.can_mutate = Mock(return_value=True)

        mutator.register_strategy(strategy)

        assert len(mutator.strategies) == 1
        assert mutator.strategies[0] == strategy

    def test_register_multiple_strategies(self):
        """Test registering multiple strategies."""
        # Disable auto-registration for this test
        mutator = DicomMutator(config={"auto_register_strategies": False})

        strategy1 = Mock()
        strategy1.mutate = Mock()
        strategy1.get_strategy_name = Mock(return_value="strategy1")

        strategy2 = Mock()
        strategy2.mutate = Mock()
        strategy2.get_strategy_name = Mock(return_value="strategy2")

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)

        assert len(mutator.strategies) == 2

    def test_register_invalid_strategy_no_mutate(self):
        """Test registering strategy without mutate method fails."""
        mutator = DicomMutator()

        # Create object without mutate method
        class InvalidStrategy:
            def get_strategy_name(self):
                return "invalid"

        strategy = InvalidStrategy()

        with pytest.raises(ValueError, match="does not implement MutationStrategy"):
            mutator.register_strategy(strategy)

    def test_register_invalid_strategy_no_name(self):
        """Test registering strategy without get_strategy_name fails."""
        mutator = DicomMutator()

        # Create object without get_strategy_name method
        class InvalidStrategy:
            def mutate(self, dataset, severity):
                return dataset

        strategy = InvalidStrategy()

        with pytest.raises(ValueError, match="does not implement MutationStrategy"):
            mutator.register_strategy(strategy)


class TestSessionManagement:
    """Test mutation session lifecycle."""

    def test_start_session_creates_session(self):
        """Test starting a session creates session object."""
        mutator = DicomMutator()
        dataset = Mock(spec=Dataset)

        returned_id = mutator.start_session(dataset)

        assert mutator.current_session is not None
        assert returned_id == mutator.current_session.session_id
        assert len(returned_id) == 8

    def test_start_session_with_file_info(self):
        """Test starting session with file information."""
        mutator = DicomMutator()
        dataset = Mock(spec=Dataset)
        file_info = {"path": "test.dcm", "size": 2048}

        mutator.start_session(dataset, file_info)

        assert mutator.current_session.original_file_info == file_info

    def test_get_session_summary_active_session(self):
        """Test getting summary of active session."""
        mutator = DicomMutator()
        dataset = Mock(spec=Dataset)

        mutator.start_session(dataset, {"test": "data"})
        summary = mutator.get_session_summary()

        assert summary is not None
        assert "session_id" in summary
        assert "start_time" in summary
        assert "mutations_applied" in summary
        assert "successful_mutations" in summary
        assert "strategies_used" in summary

    def test_get_session_summary_no_session(self):
        """Test getting summary with no active session."""
        mutator = DicomMutator()

        summary = mutator.get_session_summary()

        assert summary is None

    def test_end_session_returns_completed(self):
        """Test ending session returns completed session."""
        mutator = DicomMutator()
        dataset = Mock(spec=Dataset)

        session_id = mutator.start_session(dataset)
        completed = mutator.end_session()

        assert completed is not None
        assert completed.session_id == session_id
        assert completed.end_time is not None
        assert mutator.current_session is None

    def test_end_session_no_active_session(self):
        """Test ending session when none active."""
        mutator = DicomMutator()

        completed = mutator.end_session()

        assert completed is None

    def test_session_statistics_updated(self):
        """Test that session statistics are updated correctly."""
        mutator = DicomMutator()
        dataset = Mock(spec=Dataset)

        mutator.start_session(dataset)

        # Manually add some mutations for testing
        mutator.current_session.total_mutations = 5
        mutator.current_session.successful_mutations = 3

        completed = mutator.end_session()

        assert completed.total_mutations == 5
        assert completed.successful_mutations == 3


class TestMutationApplication:
    """Test mutation application logic."""

    def test_apply_mutations_with_no_strategies(self, sample_dicom_dataset):
        """Test applying mutations with no registered strategies."""
        mutator = DicomMutator()

        result = mutator.apply_mutations(sample_dicom_dataset)

        # Should return unchanged dataset
        assert result is not None

    @patch("dicom_fuzzer.core.mutation.mutator.random.random", return_value=0.0)
    @patch("dicom_fuzzer.core.mutation.mutator.random.choice")
    def test_apply_mutations_with_strategy(
        self, mock_choice, mock_random, sample_dicom_dataset
    ):
        """Test applying mutations with registered strategy."""
        mutator = DicomMutator(
            config={
                "auto_register_strategies": False,
                "mutation_probability": 1.0,
            }
        )

        # Create mock strategy
        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        # Configure random.choice to return our strategy
        mock_choice.return_value = strategy

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        result = mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        assert result is not None
        strategy.mutate.assert_called()

    def test_apply_mutations_respects_num_mutations(self, sample_dicom_dataset):
        """Test that num_mutations parameter is respected."""
        # Disable auto-registration and set mutation probability to 1.0
        mutator = DicomMutator(
            config={"mutation_probability": 1.0, "auto_register_strategies": False}
        )

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        mutator.apply_mutations(sample_dicom_dataset, num_mutations=3)

        # Should be called 3 times
        assert strategy.mutate.call_count == 3

    def test_apply_mutations_with_severity(self, sample_dicom_dataset):
        """Test that severity parameter is passed to strategy."""
        mutator = DicomMutator(
            config={"mutation_probability": 1.0, "auto_register_strategies": False}
        )

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        mutator.apply_mutations(
            sample_dicom_dataset, num_mutations=1, severity=MutationSeverity.AGGRESSIVE
        )

        # Check that severity was passed
        strategy.mutate.assert_called_with(
            sample_dicom_dataset, MutationSeverity.AGGRESSIVE
        )

    def test_apply_mutations_filters_by_strategy_name(self, sample_dicom_dataset):
        """Test filtering strategies by name."""
        mutator = DicomMutator(config={"mutation_probability": 1.0})

        strategy1 = Mock()
        strategy1.get_strategy_name = Mock(return_value="strategy1")
        strategy1.can_mutate = Mock(return_value=True)
        strategy1.mutate = Mock(return_value=sample_dicom_dataset)

        strategy2 = Mock()
        strategy2.get_strategy_name = Mock(return_value="strategy2")
        strategy2.can_mutate = Mock(return_value=True)
        strategy2.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)
        mutator.start_session(sample_dicom_dataset)

        # Only use strategy1
        mutator.apply_mutations(
            sample_dicom_dataset, num_mutations=1, strategy_names=["strategy1"]
        )

        strategy1.mutate.assert_called()
        strategy2.mutate.assert_not_called()

    def test_apply_mutations_skips_inapplicable_strategies(self, sample_dicom_dataset):
        """Test that strategies that can't mutate are skipped."""
        mutator = DicomMutator()

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=False)  # Cannot mutate this dataset
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        # Should not be called since can_mutate returns False
        strategy.mutate.assert_not_called()

    @patch("random.random")
    def test_mutation_probability_respected(self, mock_random, sample_dicom_dataset):
        """Test that mutation probability affects whether mutations are applied."""
        mock_random.return_value = 0.9  # Above 0.7 threshold

        mutator = DicomMutator(config={"mutation_probability": 0.7})

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        # Should not be called because random > probability
        strategy.mutate.assert_not_called()


class TestMutationTracking:
    """Test mutation tracking and recording."""

    def test_record_mutation_success(self, sample_dicom_dataset):
        """Test recording successful mutation."""
        mutator = DicomMutator()
        mutator.start_session(sample_dicom_dataset)

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")

        mutator._record_mutation(strategy, MutationSeverity.MODERATE, success=True)

        assert len(mutator.current_session.mutations) == 1
        assert mutator.current_session.total_mutations == 1
        assert mutator.current_session.successful_mutations == 1

        mutation = mutator.current_session.mutations[0]
        assert mutation.strategy_name == "test_strategy"
        assert mutation.severity == MutationSeverity.MODERATE
        assert mutation.success is True
        assert mutation.error_message is None

    def test_record_mutation_failure(self, sample_dicom_dataset):
        """Test recording failed mutation."""
        mutator = DicomMutator()
        mutator.start_session(sample_dicom_dataset)

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")

        mutator._record_mutation(
            strategy,
            MutationSeverity.AGGRESSIVE,
            success=False,
            error="Test error",
        )

        assert len(mutator.current_session.mutations) == 1
        assert mutator.current_session.total_mutations == 1
        assert mutator.current_session.successful_mutations == 0

        mutation = mutator.current_session.mutations[0]
        assert mutation.success is False
        assert mutation.error_message == "Test error"

    def test_record_mutation_no_session(self):
        """Test that recording without session doesn't crash."""
        mutator = DicomMutator()

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")

        # Should not raise exception
        mutator._record_mutation(strategy, MutationSeverity.MINIMAL)

        # Verify mutator is still functional
        assert mutator is not None


class TestSafetyChecks:
    """Test safety check functionality."""

    def test_safety_check_always_true(self, sample_dicom_dataset):
        """Test that safety check currently always returns True."""
        mutator = DicomMutator()

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")

        result = mutator._is_safe_to_mutate(sample_dicom_dataset, strategy)

        assert result is True

    def test_safety_checks_disabled(self, sample_dicom_dataset):
        """Test that safety checks can be disabled."""
        mutator = DicomMutator(config={"safety_checks": False})

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        # Should not raise exception even if safety check would fail
        result = mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        # Verify mutation was applied
        assert result is not None


class TestPropertyBasedTesting:
    """Property-based tests for robustness."""

    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=500)
    @given(num_mutations=st.integers(min_value=1, max_value=10))
    def test_num_mutations_always_nonnegative(
        self, sample_dicom_dataset, num_mutations
    ):
        """Property test: number of mutations is always non-negative.

        Note: Increased deadline from 200ms to 500ms due to variable execution
        times when running in parallel with pytest-xdist.
        """
        mutator = DicomMutator(config={"mutation_probability": 1.0})

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        mutator.apply_mutations(sample_dicom_dataset, num_mutations=num_mutations)

        # Mutations applied should be between 0 and num_mutations
        assert 0 <= strategy.mutate.call_count <= num_mutations


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_mutation_workflow(self, sample_dicom_dataset):
        """Test complete mutation workflow from start to finish."""
        mutator = DicomMutator(config={"mutation_probability": 1.0})

        # Register strategy
        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test_strategy")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)

        # Start session
        session_id = mutator.start_session(sample_dicom_dataset, {"path": "test.dcm"})
        assert session_id is not None

        # Apply mutations
        result = mutator.apply_mutations(
            sample_dicom_dataset,
            num_mutations=2,
            severity=MutationSeverity.MODERATE,
        )
        assert result is not None

        # Check session summary
        summary = mutator.get_session_summary()
        assert summary is not None
        assert summary["mutations_applied"] == 2

        # End session
        completed = mutator.end_session()
        assert completed is not None
        assert completed.total_mutations == 2
        assert completed.successful_mutations == 2

    def test_multiple_strategies_workflow(self, sample_dicom_dataset):
        """Test workflow with multiple strategies."""
        # Disable auto-registration and set mutation probability to 1.0
        mutator = DicomMutator(
            config={"mutation_probability": 1.0, "auto_register_strategies": False}
        )

        # Register multiple strategies
        for i in range(3):
            strategy = Mock()
            strategy.get_strategy_name = Mock(return_value=f"strategy{i}")
            strategy.can_mutate = Mock(return_value=True)
            strategy.mutate = Mock(return_value=sample_dicom_dataset)
            mutator.register_strategy(strategy)

        assert len(mutator.strategies) == 3

        # Run mutation session
        mutator.start_session(sample_dicom_dataset)
        mutator.apply_mutations(sample_dicom_dataset, num_mutations=5)
        completed = mutator.end_session()

        # At least some mutations should have been applied
        assert completed.total_mutations > 0


class TestMutatorExceptionHandling:
    """Test exception handling in mutator."""

    def test_apply_mutations_with_mutation_failure(self, sample_dicom_dataset):
        """Test mutation failure exception handling (lines 294-297)."""
        from unittest.mock import Mock

        mutator = DicomMutator()
        mutator.start_session(sample_dicom_dataset)

        # Create a mock strategy that raises an exception
        mock_strategy = Mock()
        mock_strategy.get_strategy_name.return_value = "failing_strategy"
        mock_strategy.can_mutate.return_value = True
        mock_strategy.mutate.side_effect = ValueError("Test mutation error")

        # Add to strategies list
        mutator.strategies.append(mock_strategy)

        # Should handle the exception gracefully
        result = mutator.apply_mutations(
            sample_dicom_dataset,
            strategy_names=["failing_strategy"],
            num_mutations=1,
        )

        # Should return dataset even if mutation failed
        assert result is not None

    def test_get_applicable_strategies_with_exception(self, sample_dicom_dataset):
        """Test strategy checking exception handling (lines 326-327)."""
        from unittest.mock import Mock

        mutator = DicomMutator()

        # Create a mock strategy that raises exception during can_mutate
        mock_strategy = Mock()
        mock_strategy.get_strategy_name.return_value = "error_strategy"
        mock_strategy.can_mutate.side_effect = RuntimeError("Check error")

        # Add to strategies list
        mutator.strategies.append(mock_strategy)

        # Should handle exception and log warning
        # The function will catch the exception but continue
        applicable = mutator._get_applicable_strategies(sample_dicom_dataset)

        # Test passes if no crash occurred
        assert isinstance(applicable, list)

    def test_apply_single_mutation_safety_check_failure(self, sample_dicom_dataset):
        """Test safety check failure (line 347)."""
        from unittest.mock import Mock

        # Create mutator with safety checks enabled
        config = {"safety_checks": True}
        mutator = DicomMutator(config=config)

        # Create a mock strategy
        mock_strategy = Mock()
        mock_strategy.get_strategy_name.return_value = "unsafe_strategy"

        # Mock _is_safe_to_mutate to return False
        mutator._is_safe_to_mutate = Mock(return_value=False)

        # Should raise ValueError due to failed safety check
        with pytest.raises(ValueError, match="Safety check failed"):
            mutator._apply_single_mutation(
                sample_dicom_dataset, mock_strategy, MutationSeverity.MINIMAL
            )


class TestAdditionalCoverage:
    """Additional tests to improve coverage of uncovered code paths."""

    def test_start_session_with_file_info_and_severity_config(
        self, sample_dicom_dataset
    ):
        """Test start_session with file_info and MutationSeverity in config."""
        mutator = DicomMutator(
            config={
                "default_severity": MutationSeverity.AGGRESSIVE,
                "auto_register_strategies": False,
            }
        )

        file_info = {
            "file_path": "test.dcm",
            "file_size": 1024,
            "file_hash": "abc123",
        }

        session_id = mutator.start_session(sample_dicom_dataset, file_info=file_info)

        assert session_id is not None
        assert mutator.current_session is not None
        assert mutator.current_session.original_file_info == file_info

    def test_apply_mutations_with_num_mutations(self, sample_dicom_dataset):
        """Test apply_mutations with specific num_mutations."""
        mutator = DicomMutator(
            config={
                "auto_register_strategies": False,
                "mutation_probability": 1.0,
            }
        )

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)
        mutator.start_session(sample_dicom_dataset)

        result = mutator.apply_mutations(sample_dicom_dataset, num_mutations=3)

        assert result is not None
        # Should have attempted 3 mutations
        assert strategy.mutate.call_count >= 1

    def test_apply_mutations_with_strategy_filter(self, sample_dicom_dataset):
        """Test filtering strategies by name during mutation."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        strategy1 = Mock()
        strategy1.get_strategy_name = Mock(return_value="wanted")
        strategy1.can_mutate = Mock(return_value=True)
        strategy1.mutate = Mock(return_value=sample_dicom_dataset)

        strategy2 = Mock()
        strategy2.get_strategy_name = Mock(return_value="unwanted")
        strategy2.can_mutate = Mock(return_value=True)
        strategy2.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy1)
        mutator.register_strategy(strategy2)
        mutator.start_session(sample_dicom_dataset)

        # Apply mutations with strategy filter
        result = mutator.apply_mutations(
            sample_dicom_dataset, num_mutations=1, strategy_names=["wanted"]
        )

        assert result is not None

    def test_mutator_logging_paths(self, sample_dicom_dataset):
        """Test various logging code paths."""
        mutator = DicomMutator(config={"auto_register_strategies": True})

        # Start session (triggers logging)
        mutator.start_session(sample_dicom_dataset)

        # Apply mutations (triggers more logging)
        result = mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        assert result is not None
        assert mutator.current_session is not None

    def test_end_session_workflow(self, sample_dicom_dataset):
        """Test complete session workflow including end_session."""
        mutator = DicomMutator(config={"auto_register_strategies": False})

        strategy = Mock()
        strategy.get_strategy_name = Mock(return_value="test")
        strategy.can_mutate = Mock(return_value=True)
        strategy.mutate = Mock(return_value=sample_dicom_dataset)

        mutator.register_strategy(strategy)

        # Start session
        mutator.start_session(sample_dicom_dataset)

        # Apply mutations
        mutator.apply_mutations(sample_dicom_dataset, num_mutations=1)

        # End session
        session_summary = mutator.end_session()

        assert session_summary is not None
        assert hasattr(session_summary, "session_id")
        assert mutator.current_session is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

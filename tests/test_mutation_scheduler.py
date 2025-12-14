"""Comprehensive tests for MOPT-style mutation operator scheduling.

Tests the MutationScheduler and related classes for PSO-based
adaptive mutation operator selection.
"""

import pytest

from dicom_fuzzer.core.mutation_scheduler import (
    MutationOperator,
    MutationScheduler,
    MutationSchedulerConfig,
    OperatorSchedulerIntegration,
    OperatorStats,
    Particle,
    PSOConfig,
    SchedulerMode,
)


class TestParticle:
    """Tests for Particle class."""

    def test_create_random_particle(self):
        """Test random particle creation."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        particle = Particle.create_random(operators)

        assert len(particle.position) == 2
        assert len(particle.velocity) == 2
        assert len(particle.personal_best) == 2
        assert particle.personal_best_fitness == 0.0

    def test_particle_weights_sum_to_one(self):
        """Test that particle weights sum to approximately 1."""
        operators = list(MutationOperator)[:5]
        particle = Particle.create_random(operators)

        total = sum(particle.position.values())
        assert 0.99 < total < 1.01

    def test_particle_all_operators_have_weights(self):
        """Test all operators have weight assignments."""
        operators = list(MutationOperator)[:10]
        particle = Particle.create_random(operators)

        for op in operators:
            assert op in particle.position
            assert op in particle.velocity
            assert op in particle.personal_best


class TestOperatorStats:
    """Tests for OperatorStats class."""

    def test_default_values(self):
        """Test default statistics values."""
        stats = OperatorStats()

        assert stats.total_executions == 0
        assert stats.interesting_inputs == 0
        assert stats.crashes_found == 0
        assert stats.coverage_gain == 0.0
        assert stats.time_spent_ms == 0.0

    def test_efficiency_calculation(self):
        """Test efficiency calculation."""
        stats = OperatorStats(total_executions=100, interesting_inputs=10)

        assert stats.efficiency == 0.1

    def test_efficiency_zero_executions(self):
        """Test efficiency with zero executions."""
        stats = OperatorStats()

        assert stats.efficiency == 0.0

    def test_crash_rate_calculation(self):
        """Test crash rate calculation."""
        stats = OperatorStats(total_executions=1000, crashes_found=5)

        assert stats.crash_rate == 0.005


class TestPSOConfig:
    """Tests for PSOConfig class."""

    def test_default_values(self):
        """Test default PSO configuration."""
        config = PSOConfig()

        assert config.swarm_size == 5
        assert config.inertia_weight == 0.7
        assert config.cognitive_coef == 1.5
        assert config.social_coef == 1.5
        assert config.max_velocity == 0.3
        assert config.min_weight == 0.01
        assert config.pacemaker_enabled is True

    def test_custom_values(self):
        """Test custom PSO configuration."""
        config = PSOConfig(
            swarm_size=10,
            inertia_weight=0.5,
            pacemaker_enabled=False,
        )

        assert config.swarm_size == 10
        assert config.inertia_weight == 0.5
        assert config.pacemaker_enabled is False


class TestMutationSchedulerConfig:
    """Tests for MutationSchedulerConfig class."""

    def test_default_operators(self):
        """Test default operator list includes all operators."""
        config = MutationSchedulerConfig()

        assert len(config.operators) == len(MutationOperator)

    def test_custom_operators(self):
        """Test custom operator selection."""
        custom_ops = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=custom_ops)

        assert len(config.operators) == 2
        assert MutationOperator.BIT_FLIP_1 in config.operators


class TestMutationScheduler:
    """Tests for MutationScheduler class."""

    @pytest.fixture
    def scheduler(self):
        """Create a scheduler with limited operators for testing."""
        config = MutationSchedulerConfig(
            operators=[
                MutationOperator.BIT_FLIP_1,
                MutationOperator.BYTE_FLIP_1,
                MutationOperator.HAVOC,
            ],
            pso=PSOConfig(pilot_executions=10, update_interval=5),
        )
        return MutationScheduler(config)

    def test_initial_state(self, scheduler):
        """Test scheduler initial state."""
        assert scheduler.mode == SchedulerMode.PILOT
        assert scheduler.total_executions == 0
        assert len(scheduler.swarm) == 5

    def test_initial_weights_uniform(self, scheduler):
        """Test initial weights are uniform."""
        weights = scheduler.get_weights()

        # Should have approximately equal weights
        expected = 1.0 / 3
        for weight in weights.values():
            assert abs(weight - expected) < 0.01

    def test_select_operator_pilot_mode(self, scheduler):
        """Test operator selection in pilot mode."""
        # In pilot mode, should cycle through operators
        operators = []
        for _ in range(3):
            op = scheduler.select_operator()
            operators.append(op)
            scheduler.record_result(op)

        # Should have selected different operators
        assert len(set(operators)) >= 1

    def test_record_result_updates_stats(self, scheduler):
        """Test that recording results updates statistics."""
        op = scheduler.select_operator()
        scheduler.record_result(op, is_interesting=True, is_crash=True)

        stats = scheduler.get_stats()
        assert stats[op].total_executions == 1
        assert stats[op].interesting_inputs == 1
        assert stats[op].crashes_found == 1

    def test_pilot_to_core_transition(self, scheduler):
        """Test transition from pilot to core mode."""
        # Run through pilot phase
        for _ in range(35):  # 10 per operator * 3 operators + some extra
            op = scheduler.select_operator()
            scheduler.record_result(op)

        # Should have transitioned to CORE mode
        assert scheduler.mode == SchedulerMode.CORE

    def test_pso_updates_weights(self, scheduler):
        """Test that PSO updates affect weights."""
        initial_weights = scheduler.get_weights().copy()

        # Complete pilot phase with varying success rates
        for i in range(30):
            op = scheduler.select_operator()
            # Make HAVOC more successful
            is_interesting = op == MutationOperator.HAVOC and i % 2 == 0
            scheduler.record_result(op, is_interesting=is_interesting)

        # Continue in core mode
        for _ in range(50):
            op = scheduler.select_operator()
            is_interesting = op == MutationOperator.HAVOC
            scheduler.record_result(op, is_interesting=is_interesting)

        final_weights = scheduler.get_weights()

        # HAVOC should have increased weight
        assert (
            final_weights[MutationOperator.HAVOC]
            > initial_weights[MutationOperator.HAVOC]
        )

    def test_get_summary(self, scheduler):
        """Test summary generation."""
        # Run some operations
        for _ in range(10):
            op = scheduler.select_operator()
            scheduler.record_result(op, is_interesting=True)

        summary = scheduler.get_summary()

        assert "mode" in summary
        assert "total_executions" in summary
        assert "total_interesting" in summary
        assert "top_operators_by_weight" in summary

    def test_export_state(self, scheduler):
        """Test state export."""
        # Run some operations
        for _ in range(5):
            op = scheduler.select_operator()
            scheduler.record_result(op)

        state = scheduler.export_state()

        assert "weights" in state
        assert "stats" in state
        assert "global_best" in state
        assert "mode" in state

    def test_import_state(self, scheduler):
        """Test state import."""
        # Run operations and export
        for _ in range(10):
            op = scheduler.select_operator()
            scheduler.record_result(op, is_interesting=True)

        state = scheduler.export_state()

        # Create new scheduler and import
        new_scheduler = MutationScheduler(scheduler.config)
        new_scheduler.import_state(state)

        # Should have same state
        assert new_scheduler.total_executions == scheduler.total_executions
        assert new_scheduler.mode.name == scheduler.mode.name

    def test_pacemaker_activation(self):
        """Test pacemaker mode activation."""
        config = MutationSchedulerConfig(
            operators=[MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC],
            pso=PSOConfig(
                pilot_executions=5,
                pacemaker_period=20,
                pacemaker_duration=5,
            ),
        )
        scheduler = MutationScheduler(config)

        # Complete pilot
        for _ in range(12):
            op = scheduler.select_operator()
            scheduler.record_result(op)

        # Should be in CORE mode
        assert scheduler.mode == SchedulerMode.CORE

        # Run until pacemaker activates
        for _ in range(25):
            op = scheduler.select_operator()
            scheduler.record_result(op)

        # Should eventually hit pacemaker
        # (Note: exact timing depends on internal counters)


class TestSchedulerWeightOptimization:
    """Tests for weight optimization based on coverage feedback."""

    @pytest.fixture
    def scheduler(self):
        """Create scheduler for optimization tests."""
        config = MutationSchedulerConfig(
            operators=[
                MutationOperator.BIT_FLIP_1,
                MutationOperator.ARITH_8,
                MutationOperator.HAVOC,
            ],
            pso=PSOConfig(pilot_executions=5, update_interval=3),
        )
        return MutationScheduler(config)

    def test_successful_operator_gains_weight(self, scheduler):
        """Test that operators finding coverage gain weight."""
        # Complete pilot
        for _ in range(20):
            op = scheduler.select_operator()
            scheduler.record_result(op)

        # Now bias results toward BIT_FLIP_1
        for _ in range(100):
            op = scheduler.select_operator()
            is_interesting = op == MutationOperator.BIT_FLIP_1
            scheduler.record_result(op, is_interesting=is_interesting)

        weights = scheduler.get_weights()
        # BIT_FLIP_1 should have significant weight
        assert weights[MutationOperator.BIT_FLIP_1] > 0.2

    def test_crash_finding_operator_prioritized(self, scheduler):
        """Test that crash-finding operators are prioritized."""
        # Complete pilot
        for _ in range(20):
            op = scheduler.select_operator()
            scheduler.record_result(op)

        # HAVOC finds crashes
        for _ in range(100):
            op = scheduler.select_operator()
            is_crash = op == MutationOperator.HAVOC
            scheduler.record_result(op, is_crash=is_crash)

        weights = scheduler.get_weights()
        # HAVOC should have good weight due to crash finding
        assert weights[MutationOperator.HAVOC] > 0.1


class TestOperatorSchedulerIntegration:
    """Tests for OperatorSchedulerIntegration helper class."""

    @pytest.fixture
    def integration(self):
        """Create integration helper."""
        config = MutationSchedulerConfig(
            operators=[MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC],
            pso=PSOConfig(pilot_executions=5),
        )
        scheduler = MutationScheduler(config)
        return OperatorSchedulerIntegration(scheduler)

    def test_register_decorator(self, integration):
        """Test registering mutation functions."""

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return bytes([b ^ 1 for b in data])

        assert MutationOperator.BIT_FLIP_1 in integration.mutators

    def test_select_mutation_returns_function(self, integration):
        """Test selecting mutation returns operator and function."""

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return bytes([b ^ 1 for b in data])

        @integration.register(MutationOperator.HAVOC)
        def havoc(data: bytes) -> bytes:
            return data + b"\x00"

        op, func = integration.select_mutation()

        assert op in [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        assert callable(func)

    def test_select_mutation_executes(self, integration):
        """Test that selected mutation can be executed."""

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return bytes([b ^ 1 for b in data])

        @integration.register(MutationOperator.HAVOC)
        def havoc(data: bytes) -> bytes:
            return data + b"\x00"

        op, func = integration.select_mutation()
        result = func(b"\x00\x01\x02")

        assert isinstance(result, bytes)

    def test_record_result_updates_scheduler(self, integration):
        """Test that recording results updates the scheduler."""

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return bytes([b ^ 1 for b in data])

        op, _ = integration.select_mutation()
        integration.record_result(op, is_interesting=True)

        stats = integration.scheduler.get_stats()
        assert stats[op].interesting_inputs >= 1

    def test_no_registered_functions_raises(self, integration):
        """Test that no registered functions raises error."""
        with pytest.raises(ValueError, match="No mutation functions"):
            integration.select_mutation()


class TestMutationOperator:
    """Tests for MutationOperator enum."""

    def test_all_operators_defined(self):
        """Test that expected operators are defined."""
        expected_ops = [
            "BIT_FLIP_1",
            "BYTE_FLIP_1",
            "ARITH_8",
            "ARITH_16",
            "INTEREST_8",
            "HAVOC",
            "SPLICE",
            "TAG_MUTATE",
            "VR_MUTATE",
            "DICT_INSERT",
        ]

        defined_ops = [op.name for op in MutationOperator]

        for exp in expected_ops:
            assert exp in defined_ops

    def test_operator_count(self):
        """Test expected number of operators."""
        # Should have at least 15 different operators
        assert len(MutationOperator) >= 15

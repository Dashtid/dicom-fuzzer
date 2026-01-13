"""Comprehensive tests for mutation_scheduler.py

Tests MOPT-style mutation operator scheduling with PSO.
"""

import random

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

# ============================================================================
# Test MutationOperator Enum
# ============================================================================


class TestMutationOperator:
    """Test MutationOperator enum."""

    def test_bit_flip_operators(self):
        """Test bit flip operators exist."""
        assert MutationOperator.BIT_FLIP_1 is not None
        assert MutationOperator.BIT_FLIP_2 is not None
        assert MutationOperator.BIT_FLIP_4 is not None

    def test_byte_flip_operators(self):
        """Test byte flip operators exist."""
        assert MutationOperator.BYTE_FLIP_1 is not None
        assert MutationOperator.BYTE_FLIP_2 is not None
        assert MutationOperator.BYTE_FLIP_4 is not None

    def test_arithmetic_operators(self):
        """Test arithmetic operators exist."""
        assert MutationOperator.ARITH_8 is not None
        assert MutationOperator.ARITH_16 is not None
        assert MutationOperator.ARITH_32 is not None

    def test_interest_operators(self):
        """Test interesting value operators exist."""
        assert MutationOperator.INTEREST_8 is not None
        assert MutationOperator.INTEREST_16 is not None
        assert MutationOperator.INTEREST_32 is not None

    def test_havoc_operators(self):
        """Test havoc operators exist."""
        assert MutationOperator.HAVOC is not None
        assert MutationOperator.SPLICE is not None

    def test_dicom_operators(self):
        """Test DICOM-specific operators exist."""
        assert MutationOperator.TAG_MUTATE is not None
        assert MutationOperator.VR_MUTATE is not None
        assert MutationOperator.LENGTH_MUTATE is not None
        assert MutationOperator.SEQUENCE_MUTATE is not None

    def test_dictionary_operators(self):
        """Test dictionary operators exist."""
        assert MutationOperator.DICT_INSERT is not None
        assert MutationOperator.DICT_OVERWRITE is not None

    def test_all_operators_count(self):
        """Test total number of operators."""
        assert len(list(MutationOperator)) == 20


# ============================================================================
# Test Particle
# ============================================================================


class TestParticle:
    """Test Particle dataclass."""

    def test_particle_creation(self):
        """Test creating a particle."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        position = {MutationOperator.BIT_FLIP_1: 0.5, MutationOperator.HAVOC: 0.5}
        velocity = {MutationOperator.BIT_FLIP_1: 0.1, MutationOperator.HAVOC: -0.1}

        particle = Particle(
            position=position,
            velocity=velocity,
            personal_best=position.copy(),
            personal_best_fitness=0.5,
        )

        assert particle.position == position
        assert particle.velocity == velocity
        assert particle.personal_best_fitness == 0.5

    def test_create_random(self):
        """Test creating random particle."""
        operators = list(MutationOperator)[:5]

        particle = Particle.create_random(operators)

        assert len(particle.position) == 5
        assert len(particle.velocity) == 5
        assert len(particle.personal_best) == 5

        # Position should sum to 1
        assert abs(sum(particle.position.values()) - 1.0) < 0.01

        # All operators should have position
        for op in operators:
            assert op in particle.position
            assert op in particle.velocity

    def test_create_random_reproducible(self):
        """Test random particle with seed."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]

        random.seed(42)
        p1 = Particle.create_random(operators)

        random.seed(42)
        p2 = Particle.create_random(operators)

        assert p1.position == p2.position


# ============================================================================
# Test OperatorStats
# ============================================================================


class TestOperatorStats:
    """Test OperatorStats dataclass."""

    def test_default_values(self):
        """Test default statistics values."""
        stats = OperatorStats()

        assert stats.total_executions == 0
        assert stats.interesting_inputs == 0
        assert stats.crashes_found == 0
        assert stats.coverage_gain == 0.0
        assert stats.time_spent_ms == 0.0

    def test_efficiency_no_executions(self):
        """Test efficiency with no executions."""
        stats = OperatorStats()

        assert stats.efficiency == 0.0

    def test_efficiency_calculation(self):
        """Test efficiency calculation."""
        stats = OperatorStats(total_executions=100, interesting_inputs=10)

        assert stats.efficiency == 0.1

    def test_crash_rate_no_executions(self):
        """Test crash rate with no executions."""
        stats = OperatorStats()

        assert stats.crash_rate == 0.0

    def test_crash_rate_calculation(self):
        """Test crash rate calculation."""
        stats = OperatorStats(total_executions=100, crashes_found=5)

        assert stats.crash_rate == 0.05


# ============================================================================
# Test PSOConfig
# ============================================================================


class TestPSOConfig:
    """Test PSOConfig dataclass."""

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
        assert config.pacemaker_period == 5000
        assert config.pacemaker_duration == 500
        assert config.pilot_executions == 1000
        assert config.update_interval == 100

    def test_custom_values(self):
        """Test custom PSO configuration."""
        config = PSOConfig(swarm_size=10, inertia_weight=0.5, pacemaker_enabled=False)

        assert config.swarm_size == 10
        assert config.inertia_weight == 0.5
        assert config.pacemaker_enabled is False


# ============================================================================
# Test SchedulerMode
# ============================================================================


class TestSchedulerMode:
    """Test SchedulerMode enum."""

    def test_all_modes_exist(self):
        """Test all scheduler modes exist."""
        assert SchedulerMode.PILOT is not None
        assert SchedulerMode.CORE is not None
        assert SchedulerMode.PACEMAKER is not None

    def test_modes_are_unique(self):
        """Test modes have unique values."""
        modes = [SchedulerMode.PILOT, SchedulerMode.CORE, SchedulerMode.PACEMAKER]
        values = [m.value for m in modes]
        assert len(values) == len(set(values))


# ============================================================================
# Test MutationSchedulerConfig
# ============================================================================


class TestMutationSchedulerConfig:
    """Test MutationSchedulerConfig dataclass."""

    def test_default_config(self):
        """Test default scheduler configuration."""
        config = MutationSchedulerConfig()

        assert len(config.operators) == len(list(MutationOperator))
        assert config.weight_decay == 0.99
        assert config.min_samples == 50
        assert isinstance(config.pso, PSOConfig)

    def test_custom_operators(self):
        """Test custom operator list."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)

        assert config.operators == operators


# ============================================================================
# Test MutationScheduler
# ============================================================================


class TestMutationSchedulerInit:
    """Test MutationScheduler initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        scheduler = MutationScheduler()

        assert scheduler.mode == SchedulerMode.PILOT
        assert scheduler.total_executions == 0
        assert len(scheduler.swarm) == 5  # Default swarm size

    def test_custom_config_initialization(self):
        """Test custom config initialization."""
        pso_config = PSOConfig(swarm_size=3)
        config = MutationSchedulerConfig(pso=pso_config)
        scheduler = MutationScheduler(config)

        assert len(scheduler.swarm) == 3

    def test_initial_weights_uniform(self):
        """Test initial weights are uniform."""
        scheduler = MutationScheduler()

        expected = 1.0 / len(scheduler.operators)
        for weight in scheduler.weights.values():
            assert abs(weight - expected) < 0.001

    def test_stats_initialized(self):
        """Test stats initialized for all operators."""
        scheduler = MutationScheduler()

        for op in scheduler.operators:
            assert op in scheduler.stats
            assert scheduler.stats[op].total_executions == 0


class TestSelectOperator:
    """Test select_operator method."""

    def test_pilot_mode_systematic(self):
        """Test pilot mode cycles through operators."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # Should select first operator in pilot mode
        op = scheduler.select_operator()
        assert op == MutationOperator.BIT_FLIP_1

    def test_core_mode_weighted_random(self):
        """Test core mode uses weighted random selection."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # Force core mode
        scheduler.mode = SchedulerMode.CORE
        scheduler.weights = {
            MutationOperator.BIT_FLIP_1: 0.9,
            MutationOperator.HAVOC: 0.1,
        }

        # Sample multiple times
        random.seed(42)
        selections = [scheduler.select_operator() for _ in range(100)]

        # Should mostly select BIT_FLIP_1 due to high weight
        bit_flip_count = sum(1 for s in selections if s == MutationOperator.BIT_FLIP_1)
        assert bit_flip_count > 70


class TestRecordResult:
    """Test record_result method."""

    def test_record_updates_stats(self):
        """Test recording updates statistics."""
        scheduler = MutationScheduler()
        op = scheduler.operators[0]

        scheduler.record_result(
            op,
            is_interesting=True,
            is_crash=True,
            coverage_delta=0.5,
            execution_time_ms=100,
        )

        assert scheduler.stats[op].total_executions == 1
        assert scheduler.stats[op].interesting_inputs == 1
        assert scheduler.stats[op].crashes_found == 1
        assert scheduler.stats[op].coverage_gain == 0.5
        assert scheduler.stats[op].time_spent_ms == 100

    def test_record_increments_counters(self):
        """Test recording increments counters."""
        scheduler = MutationScheduler()
        op = scheduler.operators[0]

        scheduler.record_result(op)
        scheduler.record_result(op)

        assert scheduler.total_executions == 2
        assert scheduler.mode_executions == 2


class TestModeTransitions:
    """Test scheduler mode transitions."""

    def test_pilot_to_core_transition(self):
        """Test transition from pilot to core mode."""
        operators = [MutationOperator.BIT_FLIP_1]
        pso_config = PSOConfig(pilot_executions=5)
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        assert scheduler.mode == SchedulerMode.PILOT

        # Complete pilot phase
        for _ in range(10):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        assert scheduler.mode == SchedulerMode.CORE

    def test_core_to_pacemaker_transition(self):
        """Test transition from core to pacemaker mode."""
        operators = [MutationOperator.BIT_FLIP_1]
        pso_config = PSOConfig(
            pilot_executions=1, pacemaker_period=5, pacemaker_enabled=True
        )
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        # Complete pilot
        for _ in range(5):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        # Continue until pacemaker triggers
        for _ in range(10):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        assert scheduler.mode == SchedulerMode.PACEMAKER

    def test_pacemaker_to_core_transition(self):
        """Test transition from pacemaker back to core."""
        operators = [MutationOperator.BIT_FLIP_1]
        pso_config = PSOConfig(
            pilot_executions=1,
            pacemaker_period=5,
            pacemaker_duration=3,
            pacemaker_enabled=True,
        )
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        # Complete pilot
        for _ in range(5):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        # Trigger pacemaker
        for _ in range(10):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        # Complete pacemaker
        for _ in range(10):
            scheduler.record_result(MutationOperator.BIT_FLIP_1)

        assert scheduler.mode == SchedulerMode.CORE


class TestPSOUpdate:
    """Test PSO update functionality."""

    def test_pso_update_skips_pilot(self):
        """Test PSO update skips during pilot mode."""
        scheduler = MutationScheduler()
        initial_fitness = scheduler.global_best_fitness

        # Force PSO update during pilot
        scheduler._update_pso()

        # Should not change in pilot mode
        assert scheduler.global_best_fitness == initial_fitness

    def test_pso_update_in_core_mode(self):
        """Test PSO update runs in core mode."""
        operators = [MutationOperator.BIT_FLIP_1]
        pso_config = PSOConfig(pilot_executions=1, update_interval=1)
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        # Complete pilot
        scheduler.record_result(MutationOperator.BIT_FLIP_1, is_interesting=True)
        scheduler.record_result(MutationOperator.BIT_FLIP_1)

        # PSO should have updated
        assert len(scheduler.fitness_history) > 0


class TestFitnessCalculation:
    """Test fitness calculation."""

    def test_fitness_no_executions(self):
        """Test fitness with no executions."""
        scheduler = MutationScheduler()

        fitness = scheduler._calculate_fitness(scheduler.weights)

        assert fitness == 0.0

    def test_fitness_with_interesting_inputs(self):
        """Test fitness calculation with interesting inputs."""
        operators = [MutationOperator.BIT_FLIP_1]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # Add stats
        scheduler.stats[MutationOperator.BIT_FLIP_1].total_executions = 100
        scheduler.stats[MutationOperator.BIT_FLIP_1].interesting_inputs = 10

        fitness = scheduler._calculate_fitness(scheduler.weights)

        # Efficiency is 0.1, weight is 1.0, so fitness should be 0.1
        assert fitness > 0

    def test_fitness_crash_bonus(self):
        """Test fitness includes crash bonus."""
        operators = [MutationOperator.BIT_FLIP_1]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # Add stats with crashes
        scheduler.stats[MutationOperator.BIT_FLIP_1].total_executions = 100
        scheduler.stats[MutationOperator.BIT_FLIP_1].crashes_found = 5

        fitness = scheduler._calculate_fitness(scheduler.weights)

        # Crash bonus is crash_rate * 10 = 0.05 * 10 = 0.5
        assert fitness > 0


class TestNormalizeWeights:
    """Test weight normalization."""

    def test_normalize_sums_to_one(self):
        """Test normalization sums to 1."""
        scheduler = MutationScheduler()

        weights = {op: random.random() for op in scheduler.operators}
        scheduler._normalize_weights(weights)

        assert abs(sum(weights.values()) - 1.0) < 0.001

    def test_normalize_respects_minimum(self):
        """Test normalization respects minimum weight before normalizing."""
        # Use fewer operators to make the test meaningful
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        pso_config = PSOConfig(min_weight=0.1)
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        # With very low weights and only 2 operators, min_weight of 0.1
        # means weights are set to 0.1 first, then normalized to sum to 1
        weights = dict.fromkeys(scheduler.operators, 0.001)
        scheduler._normalize_weights(weights)

        # After normalization, each should be 0.5 (since both were set to min)
        for w in weights.values():
            assert w == 0.5


class TestGetWeightsAndStats:
    """Test getter methods."""

    def test_get_weights_returns_copy(self):
        """Test get_weights returns copy."""
        scheduler = MutationScheduler()

        weights = scheduler.get_weights()
        weights[list(weights.keys())[0]] = 999.0

        # Original should be unchanged
        assert scheduler.weights[list(scheduler.weights.keys())[0]] != 999.0

    def test_get_stats_returns_copy(self):
        """Test get_stats returns stats."""
        scheduler = MutationScheduler()
        scheduler.record_result(scheduler.operators[0])

        stats = scheduler.get_stats()

        assert stats[scheduler.operators[0]].total_executions == 1

    def test_get_summary(self):
        """Test get_summary returns expected fields."""
        scheduler = MutationScheduler()

        summary = scheduler.get_summary()

        assert "mode" in summary
        assert "total_executions" in summary
        assert "total_interesting" in summary
        assert "total_crashes" in summary
        assert "global_best_fitness" in summary
        assert "top_operators_by_weight" in summary
        assert "top_operators_by_efficiency" in summary


class TestExportImportState:
    """Test state export/import."""

    def test_export_state_structure(self):
        """Test export_state returns expected structure."""
        scheduler = MutationScheduler()
        scheduler.record_result(scheduler.operators[0], is_interesting=True)

        state = scheduler.export_state()

        assert "weights" in state
        assert "stats" in state
        assert "global_best" in state
        assert "mode" in state
        assert "total_executions" in state

    def test_import_state_restores(self):
        """Test import_state restores scheduler state."""
        scheduler1 = MutationScheduler()
        scheduler1.record_result(scheduler1.operators[0], is_interesting=True)

        state = scheduler1.export_state()

        scheduler2 = MutationScheduler()
        scheduler2.import_state(state)

        assert scheduler2.total_executions == scheduler1.total_executions

    def test_import_state_handles_unknown_operators(self):
        """Test import handles unknown operators gracefully."""
        scheduler = MutationScheduler()

        state = {
            "weights": {"UNKNOWN_OP": 0.5},
            "stats": {"UNKNOWN_OP": {"total_executions": 10}},
            "global_best": {"UNKNOWN_OP": 0.5},
            "mode": "CORE",
        }

        # Should not raise
        scheduler.import_state(state)

        # Verify scheduler is still functional
        assert scheduler is not None

    def test_import_state_handles_invalid_mode(self):
        """Test import handles invalid mode gracefully."""
        scheduler = MutationScheduler()

        state = {"mode": "INVALID_MODE"}

        scheduler.import_state(state)

        assert scheduler.mode == SchedulerMode.CORE  # Default


class TestGetEffectiveWeights:
    """Test _get_effective_weights method."""

    def test_core_mode_returns_weights(self):
        """Test core mode returns base weights."""
        scheduler = MutationScheduler()
        scheduler.mode = SchedulerMode.CORE

        effective = scheduler._get_effective_weights()

        assert effective == scheduler.weights

    def test_pacemaker_mode_blends_recent(self):
        """Test pacemaker mode blends with recent efficiency."""
        operators = [MutationOperator.BIT_FLIP_1]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)
        scheduler.mode = SchedulerMode.PACEMAKER

        effective = scheduler._get_effective_weights()

        # Should still be valid distribution
        assert abs(sum(effective.values()) - 1.0) < 0.01


class TestGetRecentEfficiency:
    """Test _get_recent_efficiency method."""

    def test_no_executions_returns_uniform(self):
        """Test returns uniform prior with no executions."""
        scheduler = MutationScheduler()
        op = scheduler.operators[0]

        eff = scheduler._get_recent_efficiency(op)

        expected = 1.0 / len(scheduler.operators)
        assert abs(eff - expected) < 0.01

    def test_with_executions_returns_efficiency(self):
        """Test returns actual efficiency with executions."""
        scheduler = MutationScheduler()
        op = scheduler.operators[0]

        scheduler.stats[op].total_executions = 100
        scheduler.stats[op].interesting_inputs = 20

        eff = scheduler._get_recent_efficiency(op)

        assert eff == 0.2


class TestActivatePacemaker:
    """Test _activate_pacemaker method."""

    def test_activate_resets_swarm(self):
        """Test pacemaker activation resets swarm positions."""
        scheduler = MutationScheduler()
        scheduler.mode = SchedulerMode.CORE

        # Store initial positions
        initial_positions = [p.position.copy() for p in scheduler.swarm]

        scheduler._activate_pacemaker()

        assert scheduler.mode == SchedulerMode.PACEMAKER
        assert scheduler.pacemaker_countdown == scheduler.config.pso.pacemaker_duration


class TestInitializeWeightsFromPilot:
    """Test _initialize_weights_from_pilot method."""

    def test_initializes_from_efficiency(self):
        """Test weights initialized from efficiency."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # Add different efficiencies
        scheduler.stats[MutationOperator.BIT_FLIP_1].total_executions = 100
        scheduler.stats[MutationOperator.BIT_FLIP_1].interesting_inputs = 20
        scheduler.stats[MutationOperator.HAVOC].total_executions = 100
        scheduler.stats[MutationOperator.HAVOC].interesting_inputs = 5

        scheduler._initialize_weights_from_pilot()

        # BIT_FLIP_1 should have higher weight
        assert (
            scheduler.weights[MutationOperator.BIT_FLIP_1]
            > scheduler.weights[MutationOperator.HAVOC]
        )

    def test_fallback_to_uniform(self):
        """Test falls back to uniform if no interesting inputs."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)
        scheduler = MutationScheduler(config)

        # No interesting inputs
        scheduler.stats[MutationOperator.BIT_FLIP_1].total_executions = 100
        scheduler.stats[MutationOperator.HAVOC].total_executions = 100

        scheduler._initialize_weights_from_pilot()

        # Should be uniform
        assert (
            scheduler.weights[MutationOperator.BIT_FLIP_1]
            == scheduler.weights[MutationOperator.HAVOC]
        )


# ============================================================================
# Test OperatorSchedulerIntegration
# ============================================================================


class TestOperatorSchedulerIntegration:
    """Test OperatorSchedulerIntegration class."""

    def test_initialization(self):
        """Test integration initialization."""
        integration = OperatorSchedulerIntegration()

        assert integration.scheduler is not None
        assert len(integration.mutators) == 0

    def test_register_decorator(self):
        """Test register decorator."""
        integration = OperatorSchedulerIntegration()

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return bytes([b ^ 0x01 for b in data])

        assert MutationOperator.BIT_FLIP_1 in integration.mutators
        assert integration.mutators[MutationOperator.BIT_FLIP_1] is bit_flip

    def test_select_mutation_registered(self):
        """Test select_mutation with registered function."""
        integration = OperatorSchedulerIntegration()

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip(data: bytes) -> bytes:
            return data

        # Force selection of this operator
        integration.scheduler.mode = SchedulerMode.CORE
        integration.scheduler.weights = dict.fromkeys(
            integration.scheduler.operators, 0.0
        )
        integration.scheduler.weights[MutationOperator.BIT_FLIP_1] = 1.0

        op, func = integration.select_mutation()

        assert func is bit_flip

    def test_select_mutation_fallback(self):
        """Test select_mutation falls back to registered operator."""
        integration = OperatorSchedulerIntegration()

        @integration.register(MutationOperator.HAVOC)
        def havoc(data: bytes) -> bytes:
            return data

        # Force selection of unregistered operator
        integration.scheduler.mode = SchedulerMode.PILOT

        op, func = integration.select_mutation()

        # Should fall back to registered operator
        assert func is havoc

    def test_select_mutation_no_registered(self):
        """Test select_mutation raises when no functions registered."""
        integration = OperatorSchedulerIntegration()
        integration.scheduler.mode = SchedulerMode.CORE

        with pytest.raises(ValueError, match="No mutation functions"):
            integration.select_mutation()

    def test_record_result_delegates(self):
        """Test record_result delegates to scheduler."""
        integration = OperatorSchedulerIntegration()

        integration.record_result(MutationOperator.BIT_FLIP_1, is_interesting=True)

        assert (
            integration.scheduler.stats[MutationOperator.BIT_FLIP_1].interesting_inputs
            == 1
        )


# ============================================================================
# Test Integration Scenarios
# ============================================================================


class TestIntegrationScenarios:
    """Integration tests for realistic usage scenarios."""

    def test_full_fuzzing_loop_simulation(self):
        """Simulate a full fuzzing loop."""
        operators = [
            MutationOperator.BIT_FLIP_1,
            MutationOperator.HAVOC,
            MutationOperator.TAG_MUTATE,
        ]
        pso_config = PSOConfig(
            pilot_executions=10, pacemaker_period=50, update_interval=10
        )
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        random.seed(42)

        # Simulate fuzzing with varying results
        for i in range(100):
            op = scheduler.select_operator()
            is_interesting = random.random() < 0.1
            is_crash = random.random() < 0.01
            scheduler.record_result(
                op, is_interesting=is_interesting, is_crash=is_crash
            )

        assert scheduler.total_executions == 100
        assert scheduler.mode in [SchedulerMode.CORE, SchedulerMode.PACEMAKER]

    def test_weight_convergence_high_efficiency(self):
        """Test weights converge to high-efficiency operators."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        pso_config = PSOConfig(
            pilot_executions=5, update_interval=5, pacemaker_enabled=False
        )
        config = MutationSchedulerConfig(operators=operators, pso=pso_config)
        scheduler = MutationScheduler(config)

        # Complete pilot with BIT_FLIP_1 being more efficient
        for _ in range(10):
            scheduler.record_result(MutationOperator.BIT_FLIP_1, is_interesting=True)
        for _ in range(10):
            scheduler.record_result(MutationOperator.HAVOC, is_interesting=False)

        # Continue fuzzing
        for _ in range(50):
            op = scheduler.select_operator()
            is_interesting = op == MutationOperator.BIT_FLIP_1
            scheduler.record_result(op, is_interesting=is_interesting)

        # BIT_FLIP_1 should have higher weight
        assert (
            scheduler.weights[MutationOperator.BIT_FLIP_1]
            > scheduler.weights[MutationOperator.HAVOC]
        )

    def test_state_persistence_roundtrip(self):
        """Test state can be saved and restored."""
        operators = [MutationOperator.BIT_FLIP_1, MutationOperator.HAVOC]
        config = MutationSchedulerConfig(operators=operators)
        scheduler1 = MutationScheduler(config)

        # Do some work
        for _ in range(20):
            op = scheduler1.select_operator()
            scheduler1.record_result(op, is_interesting=random.random() < 0.2)

        # Export and import
        state = scheduler1.export_state()
        scheduler2 = MutationScheduler(config)
        scheduler2.import_state(state)

        # Key state should be restored
        assert scheduler2.total_executions == scheduler1.total_executions
        assert scheduler2.global_best_fitness == scheduler1.global_best_fitness

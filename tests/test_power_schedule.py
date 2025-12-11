"""Comprehensive tests for power schedule implementations.

Tests the various power schedule algorithms used for coverage-guided
fuzzing seed prioritization.
"""

import time

import pytest

from dicom_fuzzer.core.power_schedule import (
    AdaptiveSchedule,
    COESchedule,
    EXPLOITSchedule,
    EXPLORESchedule,
    FASTSchedule,
    LINEARSchedule,
    MMOPTSchedule,
    PowerScheduleManager,
    QUADSchedule,
    RARESchedule,
    ScheduleConfig,
    ScheduleType,
    SeedMetrics,
    create_schedule,
)


class TestScheduleConfig:
    """Tests for ScheduleConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ScheduleConfig()

        assert config.base_energy == 1.0
        assert config.max_energy == 100.0
        assert config.min_energy == 0.01
        assert config.coe_exponent == 2.0
        assert config.enable_time_decay is True
        assert config.rare_threshold == 0.1

    def test_custom_config(self):
        """Test custom configuration."""
        config = ScheduleConfig(
            base_energy=2.0,
            max_energy=50.0,
            coe_exponent=3.0,
        )

        assert config.base_energy == 2.0
        assert config.max_energy == 50.0
        assert config.coe_exponent == 3.0


class TestSeedMetrics:
    """Tests for SeedMetrics dataclass."""

    def test_default_metrics(self):
        """Test default metric values."""
        metrics = SeedMetrics()

        assert metrics.executions == 0
        assert metrics.discoveries == 0
        assert metrics.crashes == 0
        assert metrics.edges_covered == 0
        assert metrics.path_frequency == 1.0
        assert metrics.depth == 0

    def test_custom_metrics(self):
        """Test custom metrics."""
        metrics = SeedMetrics(
            executions=100,
            discoveries=5,
            crashes=2,
            edges_covered=50,
            unique_edges=3,
            rare_edges=1,
        )

        assert metrics.executions == 100
        assert metrics.discoveries == 5
        assert metrics.crashes == 2
        assert metrics.edges_covered == 50
        assert metrics.unique_edges == 3
        assert metrics.rare_edges == 1

    def test_creation_time_default(self):
        """Test creation time defaults to current time."""
        before = time.time()
        metrics = SeedMetrics()
        after = time.time()

        assert before <= metrics.creation_time <= after


class TestFASTSchedule:
    """Tests for FAST power schedule."""

    @pytest.fixture
    def schedule(self):
        """Create a FAST schedule."""
        return FASTSchedule()

    def test_new_seed_gets_base_energy(self, schedule):
        """Test new seed gets approximately base energy."""
        metrics = SeedMetrics()
        energy = schedule.calculate_energy(metrics)

        # New seed should get close to base energy (with some modifier)
        assert energy > 0
        assert energy <= schedule.config.max_energy

    def test_discovery_boosts_energy(self, schedule):
        """Test that discoveries boost energy."""
        base_metrics = SeedMetrics(executions=10)
        discovery_metrics = SeedMetrics(executions=10, discoveries=5)

        base_energy = schedule.calculate_energy(base_metrics)
        discovery_energy = schedule.calculate_energy(discovery_metrics)

        assert discovery_energy > base_energy

    def test_high_execution_reduces_energy(self, schedule):
        """Test that high execution count reduces energy."""
        low_exec = SeedMetrics(executions=1)
        high_exec = SeedMetrics(executions=1000)

        low_energy = schedule.calculate_energy(low_exec)
        high_energy = schedule.calculate_energy(high_exec)

        assert high_energy < low_energy


class TestCOESchedule:
    """Tests for Cut-Off Exponential schedule."""

    @pytest.fixture
    def schedule(self):
        """Create a COE schedule."""
        return COESchedule()

    def test_rare_path_gets_boost(self, schedule):
        """Test rare paths get boosted energy."""
        common_metrics = SeedMetrics(path_frequency=100)
        rare_metrics = SeedMetrics(path_frequency=2)

        common_energy = schedule.calculate_energy(common_metrics)
        rare_energy = schedule.calculate_energy(rare_metrics)

        assert rare_energy > common_energy

    def test_cutoff_behavior(self, schedule):
        """Test cutoff threshold behavior."""
        below_cutoff = SeedMetrics(path_frequency=8)
        above_cutoff = SeedMetrics(path_frequency=32)

        below_energy = schedule.calculate_energy(below_cutoff)
        above_energy = schedule.calculate_energy(above_cutoff)

        assert below_energy > above_energy


class TestEXPLORESchedule:
    """Tests for exploration-focused schedule."""

    @pytest.fixture
    def schedule(self):
        """Create an EXPLORE schedule."""
        return EXPLORESchedule()

    def test_low_execution_gets_high_energy(self, schedule):
        """Test low-execution seeds get high energy."""
        low_exec = SeedMetrics(executions=5)
        high_exec = SeedMetrics(executions=200)

        low_energy = schedule.calculate_energy(low_exec)
        high_energy = schedule.calculate_energy(high_exec)

        assert low_energy > high_energy

    def test_unique_edges_boost(self, schedule):
        """Test unique edges provide boost."""
        no_unique = SeedMetrics(executions=50)
        has_unique = SeedMetrics(executions=50, unique_edges=10)

        base_energy = schedule.calculate_energy(no_unique)
        boosted_energy = schedule.calculate_energy(has_unique)

        assert boosted_energy > base_energy

    def test_over_executed_penalty(self, schedule):
        """Test over-executed seeds get penalty."""
        normal = SeedMetrics(executions=100)
        over_executed = SeedMetrics(executions=1500)

        normal_energy = schedule.calculate_energy(normal)
        penalized_energy = schedule.calculate_energy(over_executed)

        assert penalized_energy < normal_energy


class TestEXPLOITSchedule:
    """Tests for exploitation-focused schedule."""

    @pytest.fixture
    def schedule(self):
        """Create an EXPLOIT schedule."""
        return EXPLOITSchedule()

    def test_productive_seeds_get_boost(self, schedule):
        """Test productive seeds get boosted."""
        unproductive = SeedMetrics(executions=100, discoveries=0)
        productive = SeedMetrics(executions=100, discoveries=10)

        unproductive_energy = schedule.calculate_energy(unproductive)
        productive_energy = schedule.calculate_energy(productive)

        assert productive_energy > unproductive_energy

    def test_crash_finding_boost(self, schedule):
        """Test crash-finding seeds get boost."""
        no_crashes = SeedMetrics(executions=50)
        has_crashes = SeedMetrics(executions=50, crashes=3)

        base_energy = schedule.calculate_energy(no_crashes)
        crash_energy = schedule.calculate_energy(has_crashes)

        assert crash_energy > base_energy

    def test_unproductive_penalty(self, schedule):
        """Test unproductive seeds get penalty."""
        new_seed = SeedMetrics(executions=10)
        unproductive = SeedMetrics(executions=200, discoveries=0)

        new_energy = schedule.calculate_energy(new_seed)
        unproductive_energy = schedule.calculate_energy(unproductive)

        assert unproductive_energy < new_energy


class TestQUADSchedule:
    """Tests for quadratic schedule."""

    @pytest.fixture
    def schedule(self):
        """Create a QUAD schedule."""
        return QUADSchedule()

    def test_discovery_quadratic_boost(self, schedule):
        """Test discoveries provide quadratic boost."""
        metrics_1 = SeedMetrics(discoveries=1)
        metrics_2 = SeedMetrics(discoveries=2)
        metrics_3 = SeedMetrics(discoveries=3)

        energy_1 = schedule.calculate_energy(metrics_1)
        energy_2 = schedule.calculate_energy(metrics_2)
        energy_3 = schedule.calculate_energy(metrics_3)

        # Energy should grow faster than linear
        ratio_1_2 = energy_2 / energy_1
        ratio_2_3 = energy_3 / energy_2

        assert ratio_1_2 > 1.5  # More than linear growth
        assert ratio_2_3 > 1.3

    def test_execution_decay(self, schedule):
        """Test execution count causes decay."""
        low_exec = SeedMetrics(executions=10)
        high_exec = SeedMetrics(executions=100)

        low_energy = schedule.calculate_energy(low_exec)
        high_energy = schedule.calculate_energy(high_exec)

        assert high_energy < low_energy


class TestLINEARSchedule:
    """Tests for linear schedule."""

    @pytest.fixture
    def schedule(self):
        """Create a LINEAR schedule."""
        return LINEARSchedule()

    def test_linear_discovery_boost(self, schedule):
        """Test discoveries provide linear boost."""
        metrics_1 = SeedMetrics(discoveries=1)
        metrics_2 = SeedMetrics(discoveries=2)

        energy_1 = schedule.calculate_energy(metrics_1)
        energy_2 = schedule.calculate_energy(metrics_2)

        # Should be approximately linear difference
        diff = energy_2 - energy_1
        assert 0.3 < diff < 0.7  # Roughly 0.5 per discovery


class TestMMOPTSchedule:
    """Tests for multi-objective optimization schedule."""

    @pytest.fixture
    def schedule(self):
        """Create an MMOPT schedule."""
        return MMOPTSchedule()

    def test_weights_sum_to_one(self, schedule):
        """Test that objective weights sum to 1."""
        total = sum(schedule.weights.values())
        assert abs(total - 1.0) < 0.01

    def test_coverage_contribution(self, schedule):
        """Test coverage contributes to energy."""
        no_coverage = SeedMetrics(edges_covered=0)
        has_coverage = SeedMetrics(edges_covered=100)

        base_energy = schedule.calculate_energy(no_coverage)
        coverage_energy = schedule.calculate_energy(has_coverage)

        assert coverage_energy > base_energy

    def test_crash_contribution(self, schedule):
        """Test crashes contribute to energy."""
        no_crashes = SeedMetrics()
        has_crashes = SeedMetrics(crashes=5)

        base_energy = schedule.calculate_energy(no_crashes)
        crash_energy = schedule.calculate_energy(has_crashes)

        assert crash_energy > base_energy


class TestRARESchedule:
    """Tests for rare edge focused schedule."""

    @pytest.fixture
    def schedule(self):
        """Create a RARE schedule."""
        return RARESchedule()

    def test_rare_edges_massive_boost(self, schedule):
        """Test rare edges get massive boost."""
        no_rare = SeedMetrics()
        has_rare = SeedMetrics(rare_edges=3)

        base_energy = schedule.calculate_energy(no_rare)
        rare_energy = schedule.calculate_energy(has_rare)

        assert rare_energy > base_energy * 4  # Should be significant boost

    def test_unique_edges_moderate_boost(self, schedule):
        """Test unique edges get moderate boost."""
        no_unique = SeedMetrics()
        has_unique = SeedMetrics(unique_edges=5)

        base_energy = schedule.calculate_energy(no_unique)
        unique_energy = schedule.calculate_energy(has_unique)

        assert unique_energy > base_energy

    def test_no_rare_edges_penalty(self, schedule):
        """Test seeds without rare edges may get penalty."""
        new_seed = SeedMetrics(executions=10)
        explored_no_rare = SeedMetrics(executions=100, rare_edges=0, unique_edges=0)

        new_energy = schedule.calculate_energy(new_seed)
        explored_energy = schedule.calculate_energy(explored_no_rare)

        assert explored_energy < new_energy


class TestAdaptiveSchedule:
    """Tests for adaptive schedule."""

    @pytest.fixture
    def schedule(self):
        """Create an adaptive schedule."""
        return AdaptiveSchedule()

    def test_starts_in_explore_phase(self, schedule):
        """Test starts in explore phase."""
        assert schedule.current_phase == "explore"

    def test_has_all_sub_schedules(self, schedule):
        """Test has all required sub-schedules."""
        assert "explore" in schedule.schedules
        assert "exploit" in schedule.schedules
        assert "rare" in schedule.schedules
        assert "fast" in schedule.schedules

    def test_report_coverage_increase(self, schedule):
        """Test reporting coverage increase."""
        before = schedule.last_coverage_increase
        time.sleep(0.01)  # Small delay
        schedule.report_coverage_increase()

        assert schedule.last_coverage_increase > before


class TestPowerScheduleManager:
    """Tests for PowerScheduleManager."""

    @pytest.fixture
    def manager(self):
        """Create a schedule manager."""
        return PowerScheduleManager()

    def test_default_schedule_is_fast(self, manager):
        """Test default schedule is FAST."""
        assert manager._schedule_type == ScheduleType.FAST

    def test_set_schedule(self, manager):
        """Test changing schedule type."""
        manager.set_schedule(ScheduleType.COE)
        assert manager._schedule_type == ScheduleType.COE

    def test_enable_adaptive(self, manager):
        """Test enabling adaptive mode."""
        manager.enable_adaptive()
        assert manager._adaptive_schedule is not None

    def test_disable_adaptive(self, manager):
        """Test disabling adaptive mode."""
        manager.enable_adaptive()
        manager.disable_adaptive()
        assert manager._adaptive_schedule is None

    def test_calculate_energy_from_metrics(self, manager):
        """Test calculating energy from metrics."""
        metrics = SeedMetrics(executions=10, discoveries=2)
        energy = manager.calculate_energy_from_metrics(metrics)

        assert energy > 0
        assert energy <= manager.config.max_energy

    def test_update_stats(self, manager):
        """Test updating global stats."""
        manager.update_stats(
            total_executions=1000,
            total_discoveries=50,
            edge_frequency={(1, 2): 10, (2, 3): 5},
            corpus_size=100,
        )

        # Should not raise
        assert True

    def test_get_schedule_info(self, manager):
        """Test getting schedule info."""
        info = manager.get_schedule_info()

        assert "schedule_type" in info
        assert "adaptive_enabled" in info
        assert "config" in info

    def test_report_coverage_increase(self, manager):
        """Test reporting coverage increase."""
        manager.enable_adaptive()
        before = manager._adaptive_schedule.last_coverage_increase

        time.sleep(0.01)
        manager.report_coverage_increase()

        assert manager._adaptive_schedule.last_coverage_increase > before


class TestCreateScheduleHelper:
    """Tests for create_schedule helper function."""

    def test_create_fast(self):
        """Test creating FAST schedule."""
        schedule = create_schedule("fast")
        assert isinstance(schedule, FASTSchedule)

    def test_create_coe(self):
        """Test creating COE schedule."""
        schedule = create_schedule("coe")
        assert isinstance(schedule, COESchedule)

    def test_create_explore(self):
        """Test creating EXPLORE schedule."""
        schedule = create_schedule("explore")
        assert isinstance(schedule, EXPLORESchedule)

    def test_create_exploit(self):
        """Test creating EXPLOIT schedule."""
        schedule = create_schedule("exploit")
        assert isinstance(schedule, EXPLOITSchedule)

    def test_create_with_custom_config(self):
        """Test creating schedule with custom config."""
        config = ScheduleConfig(base_energy=5.0)
        schedule = create_schedule("fast", config)

        assert schedule.config.base_energy == 5.0

    def test_unknown_falls_back_to_fast(self):
        """Test unknown name falls back to FAST."""
        schedule = create_schedule("unknown_schedule")
        assert isinstance(schedule, FASTSchedule)


class TestScheduleTypeEnum:
    """Tests for ScheduleType enum."""

    def test_all_schedule_types_exist(self):
        """Test all expected schedule types exist."""
        expected = [
            "FAST",
            "COE",
            "EXPLORE",
            "EXPLOIT",
            "QUAD",
            "LINEAR",
            "MMOPT",
            "RARE",
        ]

        for name in expected:
            assert hasattr(ScheduleType, name)


class TestEnergyClamping:
    """Tests for energy clamping behavior."""

    def test_energy_never_exceeds_max(self):
        """Test energy never exceeds maximum."""
        config = ScheduleConfig(max_energy=10.0)
        schedule = FASTSchedule(config)

        # Create metrics that should produce very high energy
        metrics = SeedMetrics(discoveries=1000)
        energy = schedule.calculate_energy(metrics)

        assert energy <= 10.0

    def test_energy_never_below_min(self):
        """Test energy never goes below minimum."""
        config = ScheduleConfig(min_energy=0.5)
        schedule = FASTSchedule(config)

        # Create metrics that should produce very low energy
        metrics = SeedMetrics(executions=100000, discoveries=0)
        energy = schedule.calculate_energy(metrics)

        assert energy >= 0.5


class TestTimeDependentBehavior:
    """Tests for time-dependent schedule behavior."""

    def test_time_decay_enabled(self):
        """Test time decay when enabled."""
        config = ScheduleConfig(
            enable_time_decay=True,
            time_decay_factor=0.9,
            time_decay_interval=0.1,  # Short interval for testing
        )
        schedule = FASTSchedule(config)

        # Create metrics with old last_executed
        old_metrics = SeedMetrics(last_executed=time.time() - 1.0)
        recent_metrics = SeedMetrics(last_executed=time.time())

        old_energy = schedule.calculate_energy(old_metrics)
        recent_energy = schedule.calculate_energy(recent_metrics)

        assert old_energy < recent_energy

    def test_time_decay_disabled(self):
        """Test no time decay when disabled."""
        config = ScheduleConfig(enable_time_decay=False)
        schedule = FASTSchedule(config)

        # Create metrics with different ages
        old_metrics = SeedMetrics(last_executed=time.time() - 1000)
        recent_metrics = SeedMetrics(last_executed=time.time())

        old_energy = schedule.calculate_energy(old_metrics)
        recent_energy = schedule.calculate_energy(recent_metrics)

        # Without decay, they should be equal
        assert abs(old_energy - recent_energy) < 0.01

"""Power Schedule Implementations for Coverage-Guided Fuzzing.

Power schedules determine how much "energy" (mutation cycles) to allocate
to each seed in the corpus. Different schedules optimize for different
objectives: exploration, exploitation, or balanced approaches.

Implemented Schedules (based on AFL/AFL++ research):
- FAST: AFL default, balanced exploration
- COE: Cut-Off Exponential, penalizes high-frequency paths
- EXPLORE: Favors less-explored seeds
- EXPLOIT: Focuses on seeds that found new coverage
- QUAD: Quadratic schedule based on performance
- LINEAR: Simple linear schedule
- MMOPT: Multi-objective optimization (coverage + crashes)
- RARE: Prioritizes seeds covering rare edges

References:
- "Not All Bytes Are Equal" (AFLFast paper)
- AFL++ power schedules: https://aflplus.plus/docs/power_schedules/
- "FairFuzz: A Targeted Mutation Strategy" (ICSE 2018)

"""

from __future__ import annotations

import math
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from dicom_fuzzer.utils.logger import get_logger

if TYPE_CHECKING:
    from .corpus_manager import Seed

logger = get_logger(__name__)


class ScheduleType(Enum):
    """Available power schedule types."""

    FAST = auto()  # AFL default
    COE = auto()  # Cut-Off Exponential
    EXPLORE = auto()  # Exploration focused
    EXPLOIT = auto()  # Exploitation focused
    QUAD = auto()  # Quadratic
    LINEAR = auto()  # Linear
    MMOPT = auto()  # Multi-objective
    RARE = auto()  # Rare edge focused


@dataclass
class ScheduleConfig:
    """Configuration for power schedules."""

    # Base energy multiplier
    base_energy: float = 1.0

    # Maximum energy cap (prevents runaway)
    max_energy: float = 100.0

    # Minimum energy floor
    min_energy: float = 0.01

    # FAST schedule parameters
    fast_factor: float = 1.0

    # COE parameters
    coe_exponent: float = 2.0
    coe_cutoff: int = 16

    # EXPLORE parameters
    explore_factor: float = 2.0

    # EXPLOIT parameters
    exploit_boost: float = 4.0

    # RARE parameters
    rare_threshold: float = 0.1  # Edges hit by <10% of corpus

    # Time-based decay
    enable_time_decay: bool = True
    time_decay_factor: float = 0.9
    time_decay_interval: float = 300.0  # 5 minutes


@dataclass
class SeedMetrics:
    """Metrics used for power schedule calculations."""

    # Execution statistics
    executions: int = 0
    discoveries: int = 0  # New coverage found
    crashes: int = 0

    # Coverage metrics
    edges_covered: int = 0
    unique_edges: int = 0  # Edges only this seed covers
    rare_edges: int = 0  # Edges covered by few seeds

    # Path frequency (how common is this path)
    path_frequency: float = 1.0

    # Age and recency
    creation_time: float = field(default_factory=time.time)
    last_executed: float = field(default_factory=time.time)

    # Performance
    avg_exec_time: float = 0.0
    discovery_rate: float = 0.0  # discoveries / executions

    # Genealogy
    depth: int = 0  # Mutation depth from initial seed
    children: int = 0  # How many seeds derived from this one


class PowerSchedule(ABC):
    """Abstract base class for power schedules."""

    def __init__(self, config: ScheduleConfig | None = None):
        """Initialize power schedule.

        Args:
            config: Schedule configuration

        """
        self.config = config or ScheduleConfig()
        self._global_stats: dict[str, Any] = {
            "total_executions": 0,
            "total_discoveries": 0,
            "edge_frequency": {},  # edge -> hit count
            "corpus_size": 0,
        }

    @abstractmethod
    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate energy for a seed based on its metrics.

        Args:
            metrics: Seed performance metrics

        Returns:
            Energy value (higher = more mutations)

        """
        raise NotImplementedError("Subclasses must implement calculate_energy()")

    def update_global_stats(
        self,
        total_executions: int,
        total_discoveries: int,
        edge_frequency: dict[tuple[str, int, str, int], int],
        corpus_size: int,
    ) -> None:
        """Update global statistics used in calculations.

        Args:
            total_executions: Total executions across all seeds
            total_discoveries: Total new coverage discoveries
            edge_frequency: Map of edge -> number of seeds covering it
            corpus_size: Current corpus size

        """
        self._global_stats.update(
            {
                "total_executions": total_executions,
                "total_discoveries": total_discoveries,
                "edge_frequency": edge_frequency,
                "corpus_size": corpus_size,
            }
        )

    def _clamp_energy(self, energy: float) -> float:
        """Clamp energy to configured bounds."""
        return max(self.config.min_energy, min(self.config.max_energy, energy))

    def _apply_time_decay(self, energy: float, last_executed: float) -> float:
        """Apply time-based decay to energy."""
        if not self.config.enable_time_decay:
            return energy

        time_since = time.time() - last_executed
        decay_periods = time_since / self.config.time_decay_interval

        if decay_periods > 0:
            energy *= self.config.time_decay_factor**decay_periods

        return energy


class FASTSchedule(PowerSchedule):
    """AFL's default FAST power schedule.

    Balanced approach that considers execution count and discovery rate.
    Seeds that found coverage get more energy, but diminishing returns
    for over-executed seeds.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate FAST schedule energy."""
        base = self.config.base_energy * self.config.fast_factor

        # Boost for discoveries
        if metrics.discoveries > 0:
            discovery_boost = 1 + math.log2(1 + metrics.discoveries)
            base *= discovery_boost

        # Penalty for high execution count (diminishing returns)
        if metrics.executions > 0:
            exec_factor = 1 / math.log2(2 + metrics.executions)
            base *= exec_factor

        # Apply time decay
        base = self._apply_time_decay(base, metrics.last_executed)

        return self._clamp_energy(base)


class COESchedule(PowerSchedule):
    """Cut-Off Exponential schedule (AFLFast).

    Penalizes seeds on high-frequency paths. Seeds covering
    rare paths get exponentially more energy.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate COE schedule energy."""
        base = self.config.base_energy

        # Penalize high-frequency paths
        if metrics.path_frequency > self.config.coe_cutoff:
            # Exponential penalty for common paths
            penalty = (metrics.path_frequency / self.config.coe_cutoff) ** (
                self.config.coe_exponent
            )
            base /= penalty
        else:
            # Boost for rare paths
            boost = self.config.coe_cutoff / max(1, metrics.path_frequency)
            base *= math.log2(1 + boost)

        # Discovery bonus
        if metrics.discoveries > 0:
            base *= 1 + metrics.discoveries * 0.5

        return self._clamp_energy(base)


class EXPLORESchedule(PowerSchedule):
    """Exploration-focused schedule.

    Heavily favors seeds that haven't been explored much yet.
    Good for early-stage fuzzing to maximize coverage quickly.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate EXPLORE schedule energy."""
        base = self.config.base_energy * self.config.explore_factor

        # Huge boost for low-execution seeds
        if metrics.executions < 10:
            base *= 4.0
        elif metrics.executions < 50:
            base *= 2.0
        elif metrics.executions < 100:
            base *= 1.5

        # Boost for seeds with unique edges
        if metrics.unique_edges > 0:
            base *= 1 + metrics.unique_edges * 0.2

        # Penalty for over-executed seeds
        if metrics.executions > 1000:
            base *= 0.1

        return self._clamp_energy(base)


class EXPLOITSchedule(PowerSchedule):
    """Exploitation-focused schedule.

    Focuses energy on seeds that have proven productive.
    Good for late-stage fuzzing to go deep on promising areas.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate EXPLOIT schedule energy."""
        base = self.config.base_energy

        # Heavy focus on discovery rate
        if metrics.executions > 0:
            discovery_rate = metrics.discoveries / metrics.executions
            if discovery_rate > 0.01:  # >1% discovery rate
                base *= self.config.exploit_boost
            elif discovery_rate > 0.001:  # >0.1% discovery rate
                base *= self.config.exploit_boost / 2

        # Boost for crash-finding seeds
        if metrics.crashes > 0:
            base *= 1 + metrics.crashes

        # Heavy penalty for unproductive seeds
        if metrics.executions > 100 and metrics.discoveries == 0:
            base *= 0.1

        return self._clamp_energy(base)


class QUADSchedule(PowerSchedule):
    """Quadratic power schedule.

    Energy grows quadratically with discoveries but
    diminishes quadratically with executions.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate QUAD schedule energy."""
        base = self.config.base_energy

        # Quadratic boost for discoveries
        if metrics.discoveries > 0:
            base *= (1 + metrics.discoveries) ** 2

        # Quadratic decay for executions
        if metrics.executions > 0:
            decay = 1 / (1 + math.sqrt(metrics.executions))
            base *= decay

        return self._clamp_energy(base)


class LINEARSchedule(PowerSchedule):
    """Simple linear power schedule.

    Linear relationship between metrics and energy.
    Good baseline for comparison.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate LINEAR schedule energy."""
        base = self.config.base_energy

        # Linear boost for discoveries
        base += metrics.discoveries * 0.5

        # Linear decay for executions
        if metrics.executions > 0:
            base -= min(base * 0.8, metrics.executions * 0.01)

        return self._clamp_energy(base)


class MMOPTSchedule(PowerSchedule):
    """Multi-objective optimization schedule.

    Balances multiple objectives: coverage, crashes, and efficiency.
    Uses weighted combination of factors.
    """

    def __init__(self, config: ScheduleConfig | None = None):
        """Initialize MMOPT schedule with objective weights."""
        super().__init__(config)
        self.weights = {
            "coverage": 0.4,
            "crashes": 0.3,
            "efficiency": 0.2,
            "novelty": 0.1,
        }

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate MMOPT schedule energy."""
        scores = {}

        # Coverage score
        if metrics.edges_covered > 0:
            scores["coverage"] = math.log2(1 + metrics.edges_covered)
        else:
            scores["coverage"] = 0

        # Crash score
        scores["crashes"] = metrics.crashes * 2

        # Efficiency score (discoveries per execution)
        if metrics.executions > 0:
            scores["efficiency"] = (metrics.discoveries / metrics.executions) * 100
        else:
            scores["efficiency"] = 1.0  # Default for new seeds

        # Novelty score (unique edges)
        scores["novelty"] = metrics.unique_edges

        # Weighted combination
        energy = self.config.base_energy
        for objective, weight in self.weights.items():
            energy += scores.get(objective, 0) * weight

        return self._clamp_energy(energy)


class RARESchedule(PowerSchedule):
    """Rare edge focused schedule (FairFuzz-inspired).

    Prioritizes seeds that cover edges hit by few other seeds.
    Helps explore underrepresented paths.
    """

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate RARE schedule energy."""
        base = self.config.base_energy

        # Massive boost for rare edges
        if metrics.rare_edges > 0:
            rare_boost = 2 ** min(metrics.rare_edges, 10)
            base *= rare_boost

        # Moderate boost for unique edges
        if metrics.unique_edges > 0:
            base *= 1 + metrics.unique_edges

        # Standard discovery bonus
        if metrics.discoveries > 0:
            base *= 1 + math.log2(1 + metrics.discoveries)

        # Penalty for seeds with only common edges
        if metrics.rare_edges == 0 and metrics.unique_edges == 0:
            if metrics.executions > 50:
                base *= 0.5

        return self._clamp_energy(base)


class AdaptiveSchedule(PowerSchedule):
    """Adaptive schedule that switches strategies based on progress.

    Starts with EXPLORE, transitions to EXPLOIT as coverage plateaus,
    then uses RARE to break out of plateaus.
    """

    def __init__(self, config: ScheduleConfig | None = None):
        """Initialize adaptive schedule."""
        super().__init__(config)
        self.schedules = {
            "explore": EXPLORESchedule(config),
            "exploit": EXPLOITSchedule(config),
            "rare": RARESchedule(config),
            "fast": FASTSchedule(config),
        }
        self.current_phase = "explore"
        self.phase_start_time = time.time()
        self.last_coverage_increase = time.time()
        self.coverage_at_phase_start = 0

    def calculate_energy(self, metrics: SeedMetrics) -> float:
        """Calculate adaptive energy based on current phase."""
        self._update_phase()
        return self.schedules[self.current_phase].calculate_energy(metrics)

    # Phase transition rules: (condition_func, next_phase)
    # Each rule takes (time_in_phase, time_since_coverage) and returns bool
    _PHASE_TRANSITIONS: dict[str, list[tuple[Callable[[float, float], bool], str]]] = {
        "explore": [
            (lambda tip, tsc: tip > 300 or tsc > 120, "exploit"),
        ],
        "exploit": [
            (lambda tip, tsc: tsc > 180, "rare"),
            (lambda tip, tsc: tsc < 30, "fast"),
        ],
        "rare": [
            (lambda tip, tsc: tsc < 60, "explore"),
            (lambda tip, tsc: tip > 120, "fast"),
        ],
        "fast": [
            (lambda tip, tsc: tsc > 120, "rare"),
        ],
    }

    def _update_phase(self) -> None:
        """Update the current scheduling phase based on progress."""
        time_in_phase = time.time() - self.phase_start_time
        time_since_coverage = time.time() - self.last_coverage_increase

        for condition, next_phase in self._PHASE_TRANSITIONS.get(
            self.current_phase, []
        ):
            if condition(time_in_phase, time_since_coverage):
                self._switch_phase(next_phase)
                break

    def _switch_phase(self, new_phase: str) -> None:
        """Switch to a new scheduling phase."""
        if new_phase != self.current_phase:
            logger.info(f"Adaptive schedule: {self.current_phase} -> {new_phase}")
            self.current_phase = new_phase
            self.phase_start_time = time.time()

    def report_coverage_increase(self) -> None:
        """Report that new coverage was found."""
        self.last_coverage_increase = time.time()


class PowerScheduleManager:
    """Manages power schedule selection and application.

    Provides a unified interface for different power schedules
    and handles schedule switching and configuration.
    """

    SCHEDULE_CLASSES: dict[ScheduleType, type[PowerSchedule]] = {
        ScheduleType.FAST: FASTSchedule,
        ScheduleType.COE: COESchedule,
        ScheduleType.EXPLORE: EXPLORESchedule,
        ScheduleType.EXPLOIT: EXPLOITSchedule,
        ScheduleType.QUAD: QUADSchedule,
        ScheduleType.LINEAR: LINEARSchedule,
        ScheduleType.MMOPT: MMOPTSchedule,
        ScheduleType.RARE: RARESchedule,
    }

    def __init__(
        self,
        schedule_type: ScheduleType = ScheduleType.FAST,
        config: ScheduleConfig | None = None,
    ):
        """Initialize power schedule manager.

        Args:
            schedule_type: Type of schedule to use
            config: Schedule configuration

        """
        self.config = config or ScheduleConfig()
        self._schedule_type = schedule_type
        self._schedule = self._create_schedule(schedule_type)
        self._adaptive_schedule: AdaptiveSchedule | None = None

        logger.info(f"PowerScheduleManager initialized with {schedule_type.name}")

    def _create_schedule(self, schedule_type: ScheduleType) -> PowerSchedule:
        """Create a schedule instance."""
        schedule_class = self.SCHEDULE_CLASSES.get(schedule_type, FASTSchedule)
        return schedule_class(self.config)

    def set_schedule(self, schedule_type: ScheduleType) -> None:
        """Change the active schedule.

        Args:
            schedule_type: New schedule type

        """
        self._schedule_type = schedule_type
        self._schedule = self._create_schedule(schedule_type)
        logger.info(f"Schedule changed to {schedule_type.name}")

    def enable_adaptive(self) -> None:
        """Enable adaptive schedule mode."""
        self._adaptive_schedule = AdaptiveSchedule(self.config)
        logger.info("Adaptive scheduling enabled")

    def disable_adaptive(self) -> None:
        """Disable adaptive schedule mode."""
        self._adaptive_schedule = None
        logger.info("Adaptive scheduling disabled")

    def calculate_energy(self, seed: Seed) -> float:
        """Calculate energy for a seed.

        Args:
            seed: Seed to calculate energy for

        Returns:
            Energy value

        """
        # Build metrics from seed
        metrics = SeedMetrics(
            executions=seed.executions,
            discoveries=seed.discoveries,
            crashes=seed.crashes,
            edges_covered=len(seed.coverage.edges) if seed.coverage else 0,
            creation_time=seed.creation_time,
            last_executed=seed.last_executed,
        )

        # Use adaptive if enabled, otherwise standard schedule
        if self._adaptive_schedule:
            return self._adaptive_schedule.calculate_energy(metrics)

        return self._schedule.calculate_energy(metrics)

    def calculate_energy_from_metrics(self, metrics: SeedMetrics) -> float:
        """Calculate energy from raw metrics.

        Args:
            metrics: Seed metrics

        Returns:
            Energy value

        """
        if self._adaptive_schedule:
            return self._adaptive_schedule.calculate_energy(metrics)

        return self._schedule.calculate_energy(metrics)

    def update_stats(
        self,
        total_executions: int,
        total_discoveries: int,
        edge_frequency: dict[tuple[str, int, str, int], int],
        corpus_size: int,
    ) -> None:
        """Update global statistics for schedule calculations."""
        self._schedule.update_global_stats(
            total_executions, total_discoveries, edge_frequency, corpus_size
        )
        if self._adaptive_schedule:
            self._adaptive_schedule.update_global_stats(
                total_executions, total_discoveries, edge_frequency, corpus_size
            )

    def report_coverage_increase(self) -> None:
        """Report that new coverage was found (for adaptive mode)."""
        if self._adaptive_schedule:
            self._adaptive_schedule.report_coverage_increase()

    def get_schedule_info(self) -> dict[str, Any]:
        """Get information about current schedule configuration."""
        info = {
            "schedule_type": self._schedule_type.name,
            "adaptive_enabled": self._adaptive_schedule is not None,
            "config": {
                "base_energy": self.config.base_energy,
                "max_energy": self.config.max_energy,
                "min_energy": self.config.min_energy,
            },
        }

        if self._adaptive_schedule:
            info["adaptive_phase"] = self._adaptive_schedule.current_phase

        return info


# Convenience functions
def create_schedule(
    schedule_name: str, config: ScheduleConfig | None = None
) -> PowerSchedule:
    """Create a power schedule by name.

    Args:
        schedule_name: Name of schedule (fast, coe, explore, etc.)
        config: Optional configuration

    Returns:
        PowerSchedule instance

    """
    name_to_type = {
        "fast": ScheduleType.FAST,
        "coe": ScheduleType.COE,
        "explore": ScheduleType.EXPLORE,
        "exploit": ScheduleType.EXPLOIT,
        "quad": ScheduleType.QUAD,
        "linear": ScheduleType.LINEAR,
        "mmopt": ScheduleType.MMOPT,
        "rare": ScheduleType.RARE,
    }

    schedule_type = name_to_type.get(schedule_name.lower(), ScheduleType.FAST)
    manager = PowerScheduleManager(schedule_type, config)
    return manager._schedule

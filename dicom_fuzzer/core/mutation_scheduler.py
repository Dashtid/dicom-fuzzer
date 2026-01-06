"""MOPT-Style Mutation Operator Scheduling with Particle Swarm Optimization.

This module implements adaptive mutation operator selection using PSO,
inspired by the MOPT paper (https://www.usenix.org/conference/usenixsecurity19/presentation/lyu).

MOPT achieves 170% more unique vulnerabilities than AFL by optimizing
mutation operator selection probabilities based on coverage feedback.

Key concepts:
- Each mutation operator has a probability weight
- PSO optimizes weights based on "interesting" inputs found
- Pacemaker mode accelerates convergence by periodically resetting
- Pilot fuzzing phase explores operator effectiveness
"""

import logging
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)


class MutationOperator(Enum):
    """Standard mutation operators available in the fuzzer."""

    # Bit-level mutations
    BIT_FLIP_1 = auto()  # Flip 1 bit
    BIT_FLIP_2 = auto()  # Flip 2 consecutive bits
    BIT_FLIP_4 = auto()  # Flip 4 consecutive bits
    BYTE_FLIP_1 = auto()  # Flip 1 byte
    BYTE_FLIP_2 = auto()  # Flip 2 consecutive bytes
    BYTE_FLIP_4 = auto()  # Flip 4 consecutive bytes

    # Arithmetic mutations
    ARITH_8 = auto()  # 8-bit arithmetic
    ARITH_16 = auto()  # 16-bit arithmetic
    ARITH_32 = auto()  # 32-bit arithmetic

    # Interesting value mutations
    INTEREST_8 = auto()  # Replace with interesting 8-bit values
    INTEREST_16 = auto()  # Replace with interesting 16-bit values
    INTEREST_32 = auto()  # Replace with interesting 32-bit values

    # Havoc mutations (random combinations)
    HAVOC = auto()  # Random mutation combination
    SPLICE = auto()  # Splice two inputs together

    # Structure-aware mutations (DICOM-specific)
    TAG_MUTATE = auto()  # Mutate DICOM tag values
    VR_MUTATE = auto()  # Mutate Value Representation
    LENGTH_MUTATE = auto()  # Mutate length fields
    SEQUENCE_MUTATE = auto()  # Mutate nested sequences

    # Dictionary-based mutations
    DICT_INSERT = auto()  # Insert dictionary token
    DICT_OVERWRITE = auto()  # Overwrite with dictionary token


@dataclass
class Particle:
    """A particle in the PSO swarm representing operator weights.

    Each particle maintains:
    - position: current weight distribution
    - velocity: rate of change for each weight
    - personal_best: best position this particle has found
    - personal_best_fitness: fitness at personal best
    """

    position: dict[MutationOperator, float]
    velocity: dict[MutationOperator, float]
    personal_best: dict[MutationOperator, float]
    personal_best_fitness: float = 0.0

    @classmethod
    def create_random(cls, operators: list[MutationOperator]) -> "Particle":
        """Create a particle with random initial position."""
        # Random initial weights that sum to 1
        raw_weights = {op: random.random() for op in operators}
        total = sum(raw_weights.values())
        position = {op: w / total for op, w in raw_weights.items()}

        # Small random initial velocities
        velocity = {op: (random.random() - 0.5) * 0.1 for op in operators}

        return cls(
            position=position,
            velocity=velocity,
            personal_best=position.copy(),
            personal_best_fitness=0.0,
        )


@dataclass
class OperatorStats:
    """Statistics for a single mutation operator."""

    total_executions: int = 0
    interesting_inputs: int = 0
    crashes_found: int = 0
    coverage_gain: float = 0.0
    time_spent_ms: float = 0.0

    @property
    def efficiency(self) -> float:
        """Calculate operator efficiency (interesting per execution)."""
        if self.total_executions == 0:
            return 0.0
        return self.interesting_inputs / self.total_executions

    @property
    def crash_rate(self) -> float:
        """Calculate crash discovery rate."""
        if self.total_executions == 0:
            return 0.0
        return self.crashes_found / self.total_executions


@dataclass
class PSOConfig:
    """Configuration for Particle Swarm Optimization."""

    # Swarm parameters
    swarm_size: int = 5

    # PSO coefficients
    inertia_weight: float = 0.7  # w: momentum from previous velocity
    cognitive_coef: float = 1.5  # c1: attraction to personal best
    social_coef: float = 1.5  # c2: attraction to global best

    # Convergence parameters
    max_velocity: float = 0.3  # Maximum velocity magnitude
    min_weight: float = 0.01  # Minimum operator weight

    # Pacemaker mode parameters
    pacemaker_enabled: bool = True
    pacemaker_period: int = 5000  # Executions between pacemaker activations
    pacemaker_duration: int = 500  # Executions in pacemaker mode

    # Pilot fuzzing parameters
    pilot_executions: int = 1000  # Initial pilot phase per operator

    # Update frequency
    update_interval: int = 100  # Executions between PSO updates


class SchedulerMode(Enum):
    """Operating mode for the mutation scheduler."""

    PILOT = auto()  # Initial exploration phase
    CORE = auto()  # Normal PSO-guided operation
    PACEMAKER = auto()  # Convergence acceleration phase


@dataclass
class MutationSchedulerConfig:
    """Configuration for the mutation scheduler."""

    # Enabled operators
    operators: list[MutationOperator] = field(
        default_factory=lambda: list(MutationOperator)
    )

    # PSO configuration
    pso: PSOConfig = field(default_factory=PSOConfig)

    # Weight decay for temporal adaptation
    weight_decay: float = 0.99

    # Minimum samples before adjusting weights
    min_samples: int = 50


class MutationScheduler:
    """MOPT-style mutation operator scheduler using PSO.

    This scheduler dynamically adjusts mutation operator probabilities
    based on their effectiveness at finding interesting inputs. It uses
    Particle Swarm Optimization to search for optimal weight distributions.

    Example usage:
        scheduler = MutationScheduler()

        # During fuzzing loop
        operator = scheduler.select_operator()
        result = apply_mutation(input_data, operator)
        scheduler.record_result(operator, is_interesting=result.is_new_coverage)
    """

    def __init__(self, config: MutationSchedulerConfig | None = None):
        """Initialize the mutation scheduler.

        Args:
            config: Scheduler configuration. Uses defaults if not provided.

        """
        self.config = config or MutationSchedulerConfig()
        self.operators = self.config.operators

        # Initialize operator statistics
        self.stats: dict[MutationOperator, OperatorStats] = {
            op: OperatorStats() for op in self.operators
        }

        # Initialize weights uniformly
        initial_weight = 1.0 / len(self.operators)
        self.weights: dict[MutationOperator, float] = dict.fromkeys(
            self.operators, initial_weight
        )

        # Initialize PSO swarm
        self.swarm: list[Particle] = [
            Particle.create_random(self.operators)
            for _ in range(self.config.pso.swarm_size)
        ]

        # Global best tracking
        self.global_best: dict[MutationOperator, float] = self.weights.copy()
        self.global_best_fitness: float = 0.0

        # Mode and counters
        self.mode = SchedulerMode.PILOT
        self.total_executions = 0
        self.mode_executions = 0
        self.pilot_index = 0  # Current operator being explored in pilot mode

        # Pacemaker state
        self.pacemaker_countdown = 0
        self.last_pacemaker_fitness = 0.0

        # Performance tracking
        self.fitness_history: list[float] = []
        self.weight_history: list[dict[MutationOperator, float]] = []

    def select_operator(self) -> MutationOperator:
        """Select a mutation operator based on current weights.

        In pilot mode, cycles through operators systematically.
        In core/pacemaker mode, uses weighted random selection.

        Returns:
            The selected mutation operator.

        """
        if self.mode == SchedulerMode.PILOT:
            # Systematic exploration in pilot mode
            operator = self.operators[self.pilot_index]
            return operator

        # Weighted random selection for core/pacemaker modes
        weights = self._get_effective_weights()
        operators = list(weights.keys())
        probabilities = list(weights.values())

        return random.choices(operators, weights=probabilities, k=1)[0]

    def record_result(
        self,
        operator: MutationOperator,
        is_interesting: bool = False,
        is_crash: bool = False,
        coverage_delta: float = 0.0,
        execution_time_ms: float = 0.0,
    ) -> None:
        """Record the result of applying a mutation operator.

        Args:
            operator: The operator that was used.
            is_interesting: Whether the mutation produced interesting input.
            is_crash: Whether the mutation caused a crash.
            coverage_delta: Change in coverage (if tracked).
            execution_time_ms: Time spent on this mutation.

        """
        # Update operator statistics
        stats = self.stats[operator]
        stats.total_executions += 1
        if is_interesting:
            stats.interesting_inputs += 1
        if is_crash:
            stats.crashes_found += 1
        stats.coverage_gain += coverage_delta
        stats.time_spent_ms += execution_time_ms

        # Update counters
        self.total_executions += 1
        self.mode_executions += 1

        # Check for mode transitions
        self._update_mode()

        # Periodic PSO update
        if self.total_executions % self.config.pso.update_interval == 0:
            self._update_pso()

    def _update_mode(self) -> None:
        """Update the scheduler operating mode."""
        pso_config = self.config.pso

        if self.mode == SchedulerMode.PILOT:
            # Check if pilot phase for current operator is complete
            op = self.operators[self.pilot_index]
            if self.stats[op].total_executions >= pso_config.pilot_executions:
                self.pilot_index += 1
                if self.pilot_index >= len(self.operators):
                    # Pilot phase complete, move to core mode
                    self.mode = SchedulerMode.CORE
                    self.mode_executions = 0
                    self._initialize_weights_from_pilot()

        elif self.mode == SchedulerMode.CORE:
            # Check for pacemaker activation
            if pso_config.pacemaker_enabled:
                if self.mode_executions >= pso_config.pacemaker_period:
                    self._activate_pacemaker()

        elif self.mode == SchedulerMode.PACEMAKER:
            # Check for pacemaker completion
            self.pacemaker_countdown -= 1
            if self.pacemaker_countdown <= 0:
                self.mode = SchedulerMode.CORE
                self.mode_executions = 0

    def _activate_pacemaker(self) -> None:
        """Activate pacemaker mode to accelerate convergence."""
        self.mode = SchedulerMode.PACEMAKER
        self.pacemaker_countdown = self.config.pso.pacemaker_duration
        self.last_pacemaker_fitness = self._calculate_fitness(self.weights)

        # Reset swarm positions around current best
        for particle in self.swarm:
            # Partially reset to global best with noise
            for op in self.operators:
                noise = (random.random() - 0.5) * 0.2
                particle.position[op] = self.global_best[op] + noise

            # Normalize to valid probability distribution
            self._normalize_weights(particle.position)

            # Reset velocity
            particle.velocity = {
                op: (random.random() - 0.5) * 0.05 for op in self.operators
            }

    def _initialize_weights_from_pilot(self) -> None:
        """Initialize weights based on pilot phase results."""
        # Calculate initial weights based on operator efficiency
        efficiencies = {op: self.stats[op].efficiency for op in self.operators}
        total_eff = sum(efficiencies.values())

        if total_eff > 0:
            self.weights = {
                op: max(eff / total_eff, self.config.pso.min_weight)
                for op, eff in efficiencies.items()
            }
        else:
            # Fall back to uniform if no interesting inputs found
            uniform = 1.0 / len(self.operators)
            self.weights = dict.fromkeys(self.operators, uniform)

        self._normalize_weights(self.weights)

        # Initialize swarm around these weights
        for particle in self.swarm:
            for op in self.operators:
                noise = (random.random() - 0.5) * 0.1
                particle.position[op] = self.weights[op] + noise
            self._normalize_weights(particle.position)
            particle.personal_best = particle.position.copy()

        self.global_best = self.weights.copy()
        self.global_best_fitness = self._calculate_fitness(self.weights)

    def _update_pso(self) -> None:
        """Perform one PSO update iteration."""
        if self.mode == SchedulerMode.PILOT:
            return  # No PSO updates during pilot phase

        pso = self.config.pso

        # Calculate fitness for each particle
        for particle in self.swarm:
            fitness = self._calculate_fitness(particle.position)

            # Update personal best
            if fitness > particle.personal_best_fitness:
                particle.personal_best = particle.position.copy()
                particle.personal_best_fitness = fitness

            # Update global best
            if fitness > self.global_best_fitness:
                self.global_best = particle.position.copy()
                self.global_best_fitness = fitness

        # Update particle velocities and positions
        for particle in self.swarm:
            for op in self.operators:
                # Random coefficients for this dimension
                r1, r2 = random.random(), random.random()

                # PSO velocity update equation
                cognitive = (
                    pso.cognitive_coef
                    * r1
                    * (particle.personal_best[op] - particle.position[op])
                )
                social = (
                    pso.social_coef
                    * r2
                    * (self.global_best[op] - particle.position[op])
                )

                new_velocity = (
                    pso.inertia_weight * particle.velocity[op] + cognitive + social
                )

                # Clamp velocity
                particle.velocity[op] = max(
                    -pso.max_velocity, min(pso.max_velocity, new_velocity)
                )

                # Update position
                particle.position[op] += particle.velocity[op]

            # Normalize to valid probability distribution
            self._normalize_weights(particle.position)

        # Update main weights to global best
        self.weights = self.global_best.copy()

        # Record history
        self.fitness_history.append(self.global_best_fitness)
        self.weight_history.append(self.weights.copy())

    def _calculate_fitness(self, weights: dict[MutationOperator, float]) -> float:
        """Calculate fitness score for a weight distribution.

        Fitness is based on the expected number of interesting inputs
        per execution using the given weights.

        Args:
            weights: Weight distribution to evaluate.

        Returns:
            Fitness score (higher is better).

        """
        expected_interesting = 0.0

        for op, weight in weights.items():
            stats = self.stats[op]
            if stats.total_executions > 0:
                # Expected interesting inputs per execution
                efficiency = stats.efficiency

                # Bonus for crash discovery
                crash_bonus = stats.crash_rate * 10.0

                expected_interesting += weight * (efficiency + crash_bonus)

        return expected_interesting

    def _normalize_weights(self, weights: dict[MutationOperator, float]) -> None:
        """Normalize weights to valid probability distribution.

        Ensures all weights are positive, above minimum, and sum to 1.

        Args:
            weights: Weight dictionary to normalize in place.

        """
        min_weight = self.config.pso.min_weight

        # Ensure minimum weight
        for op in weights:
            weights[op] = max(weights[op], min_weight)

        # Normalize to sum to 1
        total = sum(weights.values())
        for op in weights:
            weights[op] /= total

    def _get_effective_weights(self) -> dict[MutationOperator, float]:
        """Get effective weights for operator selection.

        In pacemaker mode, uses a modified distribution that favors
        operators that have recently shown improvement.

        Returns:
            Weight distribution for selection.

        """
        if self.mode == SchedulerMode.PACEMAKER:
            # In pacemaker mode, boost operators with recent success
            recent_weights = {}
            for op in self.operators:
                base_weight = self.weights[op]
                recent_eff = self._get_recent_efficiency(op)
                # Blend base weight with recent efficiency
                recent_weights[op] = 0.5 * base_weight + 0.5 * recent_eff

            self._normalize_weights(recent_weights)
            return recent_weights

        return self.weights.copy()

    def _get_recent_efficiency(
        self,
        operator: MutationOperator,
        window: int = 100,
    ) -> float:
        """Calculate recent efficiency for an operator.

        This is a simplified approximation since we don't track
        per-execution history. Uses current efficiency with decay.

        Args:
            operator: The operator to check.
            window: Not used in this implementation.

        Returns:
            Estimated recent efficiency.

        """
        stats = self.stats[operator]
        if stats.total_executions == 0:
            return 1.0 / len(self.operators)  # Uniform prior

        return stats.efficiency

    def get_weights(self) -> dict[MutationOperator, float]:
        """Get current operator weights.

        Returns:
            Dictionary mapping operators to their selection probabilities.

        """
        return self.weights.copy()

    def get_stats(self) -> dict[MutationOperator, OperatorStats]:
        """Get operator statistics.

        Returns:
            Dictionary mapping operators to their statistics.

        """
        return {
            op: OperatorStats(
                total_executions=s.total_executions,
                interesting_inputs=s.interesting_inputs,
                crashes_found=s.crashes_found,
                coverage_gain=s.coverage_gain,
                time_spent_ms=s.time_spent_ms,
            )
            for op, s in self.stats.items()
        }

    def get_summary(self) -> dict:
        """Get summary of scheduler state.

        Returns:
            Dictionary with scheduler statistics and state.

        """
        total_interesting = sum(s.interesting_inputs for s in self.stats.values())
        total_crashes = sum(s.crashes_found for s in self.stats.values())

        # Find top operators
        top_by_weight = sorted(
            self.weights.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        top_by_efficiency = sorted(
            [(op, s.efficiency) for op, s in self.stats.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        return {
            "mode": self.mode.name,
            "total_executions": self.total_executions,
            "total_interesting": total_interesting,
            "total_crashes": total_crashes,
            "global_best_fitness": self.global_best_fitness,
            "top_operators_by_weight": [
                (op.name, weight) for op, weight in top_by_weight
            ],
            "top_operators_by_efficiency": [
                (op.name, eff) for op, eff in top_by_efficiency
            ],
        }

    def export_state(self) -> dict:
        """Export scheduler state for persistence.

        Returns:
            Dictionary containing full scheduler state.

        """
        return {
            "weights": {op.name: w for op, w in self.weights.items()},
            "stats": {
                op.name: {
                    "total_executions": s.total_executions,
                    "interesting_inputs": s.interesting_inputs,
                    "crashes_found": s.crashes_found,
                    "coverage_gain": s.coverage_gain,
                    "time_spent_ms": s.time_spent_ms,
                }
                for op, s in self.stats.items()
            },
            "global_best": {op.name: w for op, w in self.global_best.items()},
            "global_best_fitness": self.global_best_fitness,
            "mode": self.mode.name,
            "total_executions": self.total_executions,
            "fitness_history": self.fitness_history[-100:],  # Last 100 entries
        }

    def _restore_operator_dict(
        self,
        state: dict,
        key: str,
        target: dict,
        value_transform: Callable | None = None,
    ) -> None:
        """Restore an operator dictionary from state.

        Args:
            state: State dictionary containing saved data.
            key: Key in state dict to restore from.
            target: Target dictionary to update.
            value_transform: Optional transform for values (e.g., OperatorStats).

        """
        for op_name, value in state.get(key, {}).items():
            try:
                op = MutationOperator[op_name]
                if op in target:
                    target[op] = value_transform(value) if value_transform else value
            except KeyError:
                logger.debug("Skipping unknown operator in %s: %s", key, op_name)

    def import_state(self, state: dict) -> None:
        """Import scheduler state from persistence.

        Args:
            state: Previously exported state dictionary.

        """
        self._restore_operator_dict(state, "weights", self.weights)
        self._restore_operator_dict(
            state, "stats", self.stats, lambda d: OperatorStats(**d)
        )
        self._restore_operator_dict(state, "global_best", self.global_best)

        self.global_best_fitness = state.get("global_best_fitness", 0.0)
        self.total_executions = state.get("total_executions", 0)
        self.fitness_history = state.get("fitness_history", [])

        mode_name = state.get("mode", "CORE")
        try:
            self.mode = SchedulerMode[mode_name]
        except KeyError:
            self.mode = SchedulerMode.CORE


class OperatorSchedulerIntegration:
    """Integration helper for using MutationScheduler with mutation functions.

    This class provides a convenient way to register mutation functions
    and have them automatically selected based on the scheduler's weights.

    Example:
        integration = OperatorSchedulerIntegration()

        @integration.register(MutationOperator.BIT_FLIP_1)
        def bit_flip_1(data: bytes) -> bytes:
            # Implementation
            return mutated_data

        # During fuzzing
        operator, mutator = integration.select_mutation()
        mutated = mutator(input_data)
        integration.record_result(operator, is_interesting=check_coverage(mutated))

    """

    def __init__(self, scheduler: MutationScheduler | None = None):
        """Initialize the integration helper.

        Args:
            scheduler: Mutation scheduler to use. Creates new one if not provided.

        """
        self.scheduler = scheduler or MutationScheduler()
        self.mutators: dict[MutationOperator, Callable[[bytes], bytes]] = {}

    def register(
        self,
        operator: MutationOperator,
    ) -> Callable[[Callable[[bytes], bytes]], Callable[[bytes], bytes]]:
        """Decorator to register a mutation function for an operator.

        Args:
            operator: The operator this function implements.

        Returns:
            Decorator function.

        """

        def decorator(func: Callable[[bytes], bytes]) -> Callable[[bytes], bytes]:
            self.mutators[operator] = func
            return func

        return decorator

    def select_mutation(self) -> tuple[MutationOperator, Callable[[bytes], bytes]]:
        """Select a mutation operator and return it with its function.

        Returns:
            Tuple of (operator, mutation_function).

        Raises:
            ValueError: If selected operator has no registered function.

        """
        operator = self.scheduler.select_operator()

        if operator not in self.mutators:
            # Fall back to a registered operator
            available = list(self.mutators.keys())
            if not available:
                raise ValueError("No mutation functions registered")
            operator = random.choice(available)

        return operator, self.mutators[operator]

    def record_result(
        self,
        operator: MutationOperator,
        is_interesting: bool = False,
        is_crash: bool = False,
        **kwargs: bool,
    ) -> None:
        """Record mutation result in the scheduler.

        Args:
            operator: The operator that was used.
            is_interesting: Whether mutation found new coverage.
            is_crash: Whether mutation caused a crash.
            **kwargs: Additional arguments passed to scheduler.

        """
        self.scheduler.record_result(
            operator,
            is_interesting=is_interesting,
            is_crash=is_crash,
            **kwargs,
        )

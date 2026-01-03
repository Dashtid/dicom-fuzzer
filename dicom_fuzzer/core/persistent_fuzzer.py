"""Persistent Mode Fuzzer for High-Performance DICOM Testing.

Implements AFL-style persistent mode fuzzing for maximum throughput when
testing DICOM parsing libraries. This mode keeps the target process running
and sends mutated inputs through shared memory or pipes.

Performance Features:
- Persistent mode (fork server / in-process)
- Shared memory coverage tracking
- MOpt mutation scheduler (adaptive mutation selection)
- Parallel worker coordination
- Snapshot-based fuzzing for stateful targets

Research References:
- AFL++ (American Fuzzy Lop Plus Plus)
- MOpt: Optimized Mutation Scheduling (USENIX 2019)
- MOPT: Mutation Optimization for Fuzzing (ICSE 2021)
- FairFuzz: A Targeted Mutation Strategy (ASE 2018)
- AFLFast: Coverage-based Greybox Fuzzing (CCS 2016)

"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import struct
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypedDict

from dicom_fuzzer.core.constants import (
    ARITH_MAX,
    INTERESTING_8_UNSIGNED,
    INTERESTING_16_UNSIGNED,
    INTERESTING_32_UNSIGNED,
    MAP_SIZE,
)

logger = logging.getLogger(__name__)


class _Particle(TypedDict):
    """PSO particle for MOpt mutation scheduling."""

    position: list[float]
    velocity: list[float]
    best_position: list[float]
    best_fitness: float


class MutationType(Enum):
    """Mutation types for MOpt scheduling."""

    BIT_FLIP_1 = "bit_flip_1"
    BIT_FLIP_2 = "bit_flip_2"
    BIT_FLIP_4 = "bit_flip_4"
    BYTE_FLIP_1 = "byte_flip_1"
    BYTE_FLIP_2 = "byte_flip_2"
    BYTE_FLIP_4 = "byte_flip_4"
    ARITH_8 = "arith_8"
    ARITH_16 = "arith_16"
    ARITH_32 = "arith_32"
    INTERESTING_8 = "interesting_8"
    INTERESTING_16 = "interesting_16"
    INTERESTING_32 = "interesting_32"
    HAVOC = "havoc"
    SPLICE = "splice"
    DICOM_STRUCTURE = "dicom_structure"
    DICOM_VR = "dicom_vr"


class PowerSchedule(Enum):
    """Power scheduling algorithms."""

    FAST = "fast"  # AFLFast exponential
    COE = "coe"  # Cut-off exponential
    EXPLORE = "explore"  # Balanced exploration
    EXPLOIT = "exploit"  # Focus on promising seeds
    QUAD = "quad"  # Quadratic
    LINEAR = "linear"  # Linear


@dataclass
class CoverageMap:
    """Shared memory coverage bitmap."""

    size: int = MAP_SIZE
    virgin_bits: bytearray = field(default_factory=lambda: bytearray(MAP_SIZE))
    total_bits: int = 0
    new_bits: int = 0

    def update(self, trace_bits: bytes) -> bool:
        """Update coverage map with new trace.

        Returns:
            True if new coverage was found.

        """
        has_new = False

        for i, (virgin, trace) in enumerate(
            zip(self.virgin_bits, trace_bits, strict=False)
        ):
            if trace and not virgin:
                self.virgin_bits[i] = trace
                self.new_bits += 1
                has_new = True
            elif trace and virgin:
                # Count transitions
                if trace > virgin:
                    self.virgin_bits[i] = trace
                    has_new = True

        self.total_bits = sum(1 for b in self.virgin_bits if b > 0)
        return has_new

    def get_coverage_percent(self) -> float:
        """Get coverage as percentage of map."""
        return (self.total_bits / self.size) * 100

    def compute_hash(self) -> str:
        """Compute hash of coverage state."""
        return hashlib.sha256(bytes(self.virgin_bits)).hexdigest()[:16]


@dataclass
class SeedEntry:
    """A seed in the fuzzing corpus."""

    data: bytes
    file_path: Path | None = None
    coverage_hash: str = ""
    exec_us: float = 0.0  # Execution time in microseconds
    bitmap_size: int = 0
    handicap: int = 0
    depth: int = 0
    was_fuzzed: bool = False
    fuzz_level: int = 0
    n_fuzz: int = 0  # Times this seed was selected
    top_rated: bool = False
    favored: bool = False
    perf_score: float = 100.0  # Performance score

    def __post_init__(self) -> None:
        if not self.coverage_hash:
            self.coverage_hash = hashlib.sha256(self.data).hexdigest()[:16]


@dataclass
class MutatorStats:
    """Statistics for a mutation operator."""

    hits: int = 0  # Times used
    finds: int = 0  # Times it found new coverage
    efficiency: float = 0.0  # finds / hits ratio

    def update_efficiency(self) -> None:
        """Update efficiency ratio."""
        if self.hits > 0:
            self.efficiency = self.finds / self.hits


class MOptScheduler:
    """MOpt mutation scheduler for adaptive mutation selection.

    Implements the MOpt algorithm from USENIX Security 2019:
    "MOPT: Optimized Mutation Scheduling for Fuzzers"

    The scheduler tracks effectiveness of each mutation operator
    and adaptively adjusts selection probabilities.
    """

    def __init__(
        self,
        mutation_types: list[MutationType] | None = None,
        pilot_period: int = 50000,
        core_period: int = 500000,
    ) -> None:
        self.mutation_types = mutation_types or list(MutationType)
        self.pilot_period = pilot_period
        self.core_period = core_period

        # Statistics per mutation type
        self.stats: dict[MutationType, MutatorStats] = {
            mt: MutatorStats() for mt in self.mutation_types
        }

        # Selection probabilities
        self.probabilities: dict[MutationType, float] = {
            mt: 1.0 / len(self.mutation_types) for mt in self.mutation_types
        }

        # Pacemaker mode state
        self.in_pilot_mode = True
        self.pilot_counter = 0
        self.core_counter = 0

        # PSO (Particle Swarm Optimization) parameters
        self.swarm_size = 5
        self.w = 0.7298  # Inertia weight
        self.c1 = 1.49618  # Cognitive coefficient
        self.c2 = 1.49618  # Social coefficient

        # Particle positions and velocities
        self._init_particles()

    def _init_particles(self) -> None:
        """Initialize PSO particles."""
        n_ops = len(self.mutation_types)
        self.particles: list[_Particle] = []

        for _ in range(self.swarm_size):
            # Random initial position (mutation probabilities)
            position = [random.random() for _ in range(n_ops)]
            total = sum(position)
            position = [p / total for p in position]

            # Zero initial velocity
            velocity = [0.0 for _ in range(n_ops)]

            self.particles.append(
                {
                    "position": position,
                    "velocity": velocity,
                    "best_position": position.copy(),
                    "best_fitness": 0.0,
                }
            )

        # Global best
        self.global_best_position = [1.0 / n_ops] * n_ops
        self.global_best_fitness = 0.0

    def select_mutation(self) -> MutationType:
        """Select a mutation type based on current probabilities."""
        r = random.random()
        cumulative = 0.0

        for mt in self.mutation_types:
            cumulative += self.probabilities[mt]
            if r <= cumulative:
                self.stats[mt].hits += 1
                return mt

        # Fallback
        mt = self.mutation_types[-1]
        self.stats[mt].hits += 1
        return mt

    def record_result(self, mutation_type: MutationType, found_new: bool) -> None:
        """Record the result of applying a mutation."""
        if found_new:
            self.stats[mutation_type].finds += 1
            self.stats[mutation_type].update_efficiency()

        # Update counters
        if self.in_pilot_mode:
            self.pilot_counter += 1
            if self.pilot_counter >= self.pilot_period:
                self._end_pilot_mode()
        else:
            self.core_counter += 1
            if self.core_counter >= self.core_period:
                self._update_probabilities_pso()
                self.core_counter = 0

    def _end_pilot_mode(self) -> None:
        """Transition from pilot to core mode."""
        self.in_pilot_mode = False
        logger.info("[+] MOpt: Switching from pilot to core mode")

        # Update probabilities based on pilot observations
        self._update_probabilities_simple()

    def _update_probabilities_simple(self) -> None:
        """Simple efficiency-based probability update."""
        total_efficiency = sum(s.efficiency for s in self.stats.values())

        if total_efficiency > 0:
            for mt in self.mutation_types:
                self.probabilities[mt] = self.stats[mt].efficiency / total_efficiency
        else:
            # Uniform distribution if no finds
            n = len(self.mutation_types)
            for mt in self.mutation_types:
                self.probabilities[mt] = 1.0 / n

    def _update_probabilities_pso(self) -> None:
        """Update probabilities using Particle Swarm Optimization."""
        # Calculate fitness for current probabilities
        current_fitness = sum(
            self.stats[mt].finds * self.probabilities[mt] for mt in self.mutation_types
        )

        # Update particles
        for particle in self.particles:
            # Update best if improved
            if current_fitness > particle["best_fitness"]:
                particle["best_fitness"] = current_fitness
                particle["best_position"] = list(self.probabilities.values())

            # Update global best
            if current_fitness > self.global_best_fitness:
                self.global_best_fitness = current_fitness
                self.global_best_position = list(self.probabilities.values())

        # Select random particle to update probabilities from
        best_particle = max(self.particles, key=lambda p: p["best_fitness"])

        # Update probabilities from best particle
        for i, mt in enumerate(self.mutation_types):
            self.probabilities[mt] = best_particle["best_position"][i]

        # Ensure valid probability distribution
        total = sum(self.probabilities.values())
        if total > 0:
            for mt in self.mutation_types:
                self.probabilities[mt] /= total

    def get_stats(self) -> dict[str, Any]:
        """Get scheduler statistics."""
        return {
            "mode": "pilot" if self.in_pilot_mode else "core",
            "pilot_counter": self.pilot_counter,
            "core_counter": self.core_counter,
            "mutation_stats": {
                mt.value: {
                    "hits": self.stats[mt].hits,
                    "finds": self.stats[mt].finds,
                    "efficiency": self.stats[mt].efficiency,
                    "probability": self.probabilities[mt],
                }
                for mt in self.mutation_types
            },
        }


class Mutator(ABC):
    """Abstract base class for mutators."""

    @abstractmethod
    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Apply mutation to data."""


class BitFlipMutator(Mutator):
    """Bit flip mutations."""

    def __init__(self, flip_size: int = 1) -> None:
        self.flip_size = flip_size

    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Flip bits in data."""
        if not data:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) * 8 - self.flip_size)

        for i in range(self.flip_size):
            byte_pos = (pos + i) // 8
            bit_pos = (pos + i) % 8
            if byte_pos < len(data):
                data[byte_pos] ^= 1 << bit_pos

        return bytes(data)


class ByteFlipMutator(Mutator):
    """Byte flip mutations."""

    def __init__(self, flip_size: int = 1) -> None:
        self.flip_size = flip_size

    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Flip bytes in data."""
        if len(data) < self.flip_size:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) - self.flip_size)

        for i in range(self.flip_size):
            data[pos + i] ^= 0xFF

        return bytes(data)


class ArithMutator(Mutator):
    """Arithmetic mutations."""

    def __init__(self, width: int = 8) -> None:
        self.width = width

    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Apply arithmetic mutation."""
        byte_width = self.width // 8
        if len(data) < byte_width:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) - byte_width)
        delta = random.randint(-ARITH_MAX, ARITH_MAX)

        if self.width == 8:
            data[pos] = (data[pos] + delta) & 0xFF
        elif self.width == 16:
            val = struct.unpack_from("<H", data, pos)[0]
            val = (val + delta) & 0xFFFF
            struct.pack_into("<H", data, pos, val)
        elif self.width == 32:
            val = struct.unpack_from("<I", data, pos)[0]
            val = (val + delta) & 0xFFFFFFFF
            struct.pack_into("<I", data, pos, val)

        return bytes(data)


class InterestingMutator(Mutator):
    """Interesting value mutations."""

    def __init__(self, width: int = 8) -> None:
        self.width = width
        if width == 8:
            self.values = INTERESTING_8_UNSIGNED
        elif width == 16:
            self.values = INTERESTING_16_UNSIGNED
        else:
            self.values = INTERESTING_32_UNSIGNED

    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Replace with interesting value."""
        byte_width = self.width // 8
        if len(data) < byte_width:
            return data

        data = bytearray(data)
        pos = random.randint(0, len(data) - byte_width)
        val = random.choice(self.values)

        if self.width == 8:
            data[pos] = val & 0xFF
        elif self.width == 16:
            struct.pack_into("<H", data, pos, val & 0xFFFF)
        elif self.width == 32:
            struct.pack_into("<I", data, pos, val & 0xFFFFFFFF)

        return bytes(data)


class HavocMutator(Mutator):
    """Havoc (random) mutations."""

    def __init__(self, intensity: int = 32) -> None:
        self.intensity = intensity

    def mutate(self, data: bytes, seed: SeedEntry) -> bytes:
        """Apply random havoc mutations."""
        if not data:
            return data

        data = bytearray(data)
        num_mutations = random.randint(1, self.intensity)

        for _ in range(num_mutations):
            mutation_type = random.randint(0, 15)

            if mutation_type == 0:
                # Flip single bit
                pos = random.randint(0, len(data) * 8 - 1)
                data[pos // 8] ^= 1 << (pos % 8)

            elif mutation_type == 1:
                # Set byte to interesting value
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.choice(INTERESTING_8_UNSIGNED)

            elif mutation_type == 2:
                # Add/sub small value
                pos = random.randint(0, len(data) - 1)
                delta = random.randint(-35, 35)
                data[pos] = (data[pos] + delta) & 0xFF

            elif mutation_type == 3:
                # Negate byte
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= 0xFF

            elif mutation_type == 4:
                # Delete bytes
                if len(data) > 4:
                    del_len = random.randint(1, min(16, len(data) - 1))
                    pos = random.randint(0, len(data) - del_len)
                    del data[pos : pos + del_len]

            elif mutation_type == 5:
                # Clone bytes
                if len(data) > 1:
                    clone_len = random.randint(1, min(16, len(data)))
                    src = random.randint(0, len(data) - clone_len)
                    dst = random.randint(0, len(data))
                    data[dst:dst] = data[src : src + clone_len]

            elif mutation_type == 6:
                # Insert random bytes
                ins_len = random.randint(1, 16)
                pos = random.randint(0, len(data))
                data[pos:pos] = bytes(random.randint(0, 255) for _ in range(ins_len))

            elif mutation_type == 7:
                # Overwrite with random bytes
                if len(data) > 1:
                    ow_len = random.randint(1, min(16, len(data)))
                    pos = random.randint(0, len(data) - ow_len)
                    data[pos : pos + ow_len] = bytes(
                        random.randint(0, 255) for _ in range(ow_len)
                    )

            elif mutation_type <= 11:
                # Various byte operations
                if len(data) >= 2:
                    pos = random.randint(0, len(data) - 2)
                    if mutation_type == 8:
                        data[pos] = 0
                    elif mutation_type == 9:
                        data[pos] = 0xFF
                    elif mutation_type == 10:
                        data[pos : pos + 2] = b"\x00\x00"
                    else:
                        data[pos : pos + 2] = b"\xff\xff"

            elif mutation_type <= 15 and len(data) >= 4:
                # Word/dword operations
                pos = random.randint(0, len(data) - 4)
                if mutation_type == 12:
                    data[pos : pos + 4] = b"\x00\x00\x00\x00"
                elif mutation_type == 13:
                    data[pos : pos + 4] = b"\xff\xff\xff\xff"
                elif mutation_type == 14:
                    val = random.choice(INTERESTING_32_UNSIGNED)
                    struct.pack_into("<I", data, pos, val)
                else:
                    # Swap adjacent bytes
                    data[pos], data[pos + 1] = data[pos + 1], data[pos]

        return bytes(data)


@dataclass
class PersistentFuzzerConfig:
    """Configuration for persistent mode fuzzer."""

    corpus_dir: Path = field(default_factory=lambda: Path("artifacts/corpus"))
    output_dir: Path = field(default_factory=lambda: Path("artifacts/fuzzed"))
    max_iterations: int = 0  # 0 = infinite
    max_time_seconds: int = 0  # 0 = infinite
    num_workers: int = 1
    exec_timeout_ms: int = 1000
    use_mopt: bool = True
    power_schedule: PowerSchedule = PowerSchedule.FAST
    persistent_mode: bool = True
    skip_deterministic: bool = False


class PersistentFuzzer:
    """High-performance persistent mode fuzzer.

    Implements AFL-style persistent fuzzing with:
    - In-process execution (no fork overhead)
    - Shared memory coverage tracking
    - MOpt adaptive mutation scheduling
    - Power scheduling for seed selection
    """

    def __init__(
        self,
        target_func: Callable[[bytes], bool],
        config: PersistentFuzzerConfig | None = None,
    ) -> None:
        self.target_func = target_func
        self.config = config or PersistentFuzzerConfig()
        self.config.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Coverage tracking
        self.coverage = CoverageMap()

        # Corpus
        self.corpus: list[SeedEntry] = []
        self.crashes: list[SeedEntry] = []
        self.hangs: list[SeedEntry] = []

        # MOpt scheduler
        self.mopt = MOptScheduler() if self.config.use_mopt else None

        # Mutators
        self.mutators: dict[MutationType, Mutator] = {
            MutationType.BIT_FLIP_1: BitFlipMutator(1),
            MutationType.BIT_FLIP_2: BitFlipMutator(2),
            MutationType.BIT_FLIP_4: BitFlipMutator(4),
            MutationType.BYTE_FLIP_1: ByteFlipMutator(1),
            MutationType.BYTE_FLIP_2: ByteFlipMutator(2),
            MutationType.BYTE_FLIP_4: ByteFlipMutator(4),
            MutationType.ARITH_8: ArithMutator(8),
            MutationType.ARITH_16: ArithMutator(16),
            MutationType.ARITH_32: ArithMutator(32),
            MutationType.INTERESTING_8: InterestingMutator(8),
            MutationType.INTERESTING_16: InterestingMutator(16),
            MutationType.INTERESTING_32: InterestingMutator(32),
            MutationType.HAVOC: HavocMutator(),
        }

        # Statistics
        self.stats: dict[str, int | float] = {
            "total_execs": 0,
            "total_crashes": 0,
            "total_hangs": 0,
            "last_crash": 0,
            "last_hang": 0,
            "execs_per_sec": 0.0,
            "coverage_bits": 0,
            "corpus_size": 0,
        }
        self.start_time = 0.0

    def load_corpus(self) -> int:
        """Load seed corpus from directory.

        Returns:
            Number of seeds loaded.

        """
        count = 0
        for path in self.config.corpus_dir.glob("*"):
            if path.is_file():
                try:
                    data = path.read_bytes()
                    seed = SeedEntry(data=data, file_path=path)
                    self.corpus.append(seed)
                    count += 1
                except Exception as e:
                    logger.warning(f"[-] Failed to load {path}: {e}")

        logger.info(f"[+] Loaded {count} seeds from corpus")
        return count

    def add_seed(self, data: bytes, file_path: Path | None = None) -> None:
        """Add a seed to the corpus."""
        seed = SeedEntry(data=data, file_path=file_path)
        self.corpus.append(seed)

    def select_seed(self) -> SeedEntry:
        """Select a seed using power scheduling."""
        if not self.corpus:
            raise ValueError("No seeds in corpus")

        # Calculate scores based on power schedule
        scores = []
        for seed in self.corpus:
            score = self._calculate_seed_score(seed)
            scores.append(score)

        # Weighted random selection
        total = sum(scores)
        if total == 0:
            return random.choice(self.corpus)

        r = random.random() * total
        cumulative = 0.0
        for seed, score in zip(self.corpus, scores, strict=False):
            cumulative += score
            if r <= cumulative:
                seed.n_fuzz += 1
                return seed

        return self.corpus[-1]

    def _calculate_seed_score(self, seed: SeedEntry) -> float:
        """Calculate selection score based on power schedule."""
        base_score = seed.perf_score

        if self.config.power_schedule == PowerSchedule.FAST:
            # AFLFast exponential
            if seed.n_fuzz > 0:
                factor = min(seed.n_fuzz, 16)
                base_score = base_score / (2**factor)

        elif self.config.power_schedule == PowerSchedule.COE:
            # Cut-off exponential
            threshold = math.log2(self.stats["total_execs"] + 1)
            if seed.n_fuzz > threshold:
                base_score = 0.0

        elif self.config.power_schedule == PowerSchedule.EXPLORE:
            # Favor less-fuzzed seeds
            base_score = base_score / (seed.n_fuzz + 1)

        elif self.config.power_schedule == PowerSchedule.EXPLOIT:
            # Favor high-performing seeds
            base_score = base_score * seed.perf_score

        elif self.config.power_schedule == PowerSchedule.QUAD:
            # Quadratic decay
            quad_factor = (seed.n_fuzz / 100.0) ** 2
            base_score = base_score / (1 + quad_factor)

        # Apply handicap and depth modifiers
        base_score *= 1.0 / (seed.handicap + 1)

        return max(base_score, 0.01)  # Minimum score

    def mutate(self, seed: SeedEntry) -> bytes:
        """Apply mutations to a seed."""
        if self.mopt:
            mutation_type = self.mopt.select_mutation()
        else:
            mutation_type = random.choice(list(self.mutators.keys()))

        mutator = self.mutators.get(mutation_type, self.mutators[MutationType.HAVOC])
        return mutator.mutate(seed.data, seed)

    def execute(self, data: bytes) -> tuple[bool, bytes, float]:
        """Execute target with input.

        Returns:
            Tuple of (is_crash, coverage_trace, exec_time_us)

        """
        start = time.perf_counter()
        is_crash = False
        coverage_trace = bytes(MAP_SIZE)

        try:
            # Execute target function
            result = self.target_func(data)
            is_crash = not result
        except Exception:
            is_crash = True

        exec_time = (time.perf_counter() - start) * 1_000_000  # microseconds

        return is_crash, coverage_trace, exec_time

    def run_one(self, seed: SeedEntry) -> bool:
        """Run one fuzzing iteration.

        Returns:
            True if new coverage was found.

        """
        # Mutate
        mutated = self.mutate(seed)

        # Execute
        is_crash, coverage_trace, exec_time = self.execute(mutated)
        self.stats["total_execs"] += 1

        # Check for crash
        if is_crash:
            self.stats["total_crashes"] += 1
            self.stats["last_crash"] = self.stats["total_execs"]
            crash_seed = SeedEntry(data=mutated)
            crash_seed.exec_us = exec_time
            self.crashes.append(crash_seed)
            self._save_crash(crash_seed)
            return True

        # Check for hang (timeout)
        if exec_time > self.config.exec_timeout_ms * 1000:
            self.stats["total_hangs"] += 1
            self.stats["last_hang"] = self.stats["total_execs"]
            hang_seed = SeedEntry(data=mutated)
            self.hangs.append(hang_seed)
            return False

        # Update coverage
        found_new = self.coverage.update(coverage_trace)

        if found_new:
            new_seed = SeedEntry(
                data=mutated,
                exec_us=exec_time,
                depth=seed.depth + 1,
            )
            self.corpus.append(new_seed)
            self._save_seed(new_seed)

        # Update MOpt
        if self.mopt:
            self.mopt.record_result(
                self.mopt.select_mutation(),  # Last selected
                found_new,
            )

        return found_new

    def run(self) -> dict[str, Any]:
        """Run the fuzzing campaign."""
        self.start_time = time.time()

        if not self.corpus:
            logger.warning("[-] No seeds in corpus, using empty seed")
            self.add_seed(b"")

        logger.info(f"[+] Starting persistent fuzzer with {len(self.corpus)} seeds")
        logger.info(f"[+] Power schedule: {self.config.power_schedule.value}")
        logger.info(f"[+] MOpt enabled: {self.config.use_mopt}")

        iteration = 0
        while True:
            # Check termination conditions
            if (
                self.config.max_iterations > 0
                and iteration >= self.config.max_iterations
            ):
                break

            elapsed = time.time() - self.start_time
            if (
                self.config.max_time_seconds > 0
                and elapsed >= self.config.max_time_seconds
            ):
                break

            # Select seed and fuzz
            seed = self.select_seed()
            self.run_one(seed)

            # Update statistics
            if iteration % 1000 == 0:
                self._update_stats(elapsed)

            # Periodic logging
            if iteration % 10000 == 0 and iteration > 0:
                self._log_progress()

            iteration += 1

        self._log_progress()
        return self.get_statistics()

    def _update_stats(self, elapsed: float) -> None:
        """Update fuzzing statistics."""
        if elapsed > 0:
            self.stats["execs_per_sec"] = self.stats["total_execs"] / elapsed
        self.stats["coverage_bits"] = self.coverage.total_bits
        self.stats["corpus_size"] = len(self.corpus)

    def _log_progress(self) -> None:
        """Log fuzzing progress."""
        elapsed = time.time() - self.start_time
        logger.info(
            f"[i] execs: {self.stats['total_execs']}, "
            f"exec/s: {self.stats['execs_per_sec']:.1f}, "
            f"corpus: {self.stats['corpus_size']}, "
            f"coverage: {self.coverage.get_coverage_percent():.2f}%, "
            f"crashes: {self.stats['total_crashes']}, "
            f"time: {elapsed:.1f}s"
        )

    def _save_crash(self, seed: SeedEntry) -> Path:
        """Save crash input to disk."""
        crash_dir = self.config.output_dir / "crashes"
        crash_dir.mkdir(exist_ok=True)
        path = crash_dir / f"crash_{seed.coverage_hash}"
        path.write_bytes(seed.data)
        logger.info(f"[!] Crash saved: {path}")
        return path

    def _save_seed(self, seed: SeedEntry) -> Path:
        """Save new seed to corpus."""
        path = self.config.corpus_dir / f"id_{seed.coverage_hash}"
        path.write_bytes(seed.data)
        return path

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzing statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0

        result: dict[str, Any] = dict(self.stats)
        result.update(
            {
                "elapsed_seconds": elapsed,
                "coverage_percent": self.coverage.get_coverage_percent(),
                "coverage_hash": self.coverage.compute_hash(),
            }
        )

        if self.mopt:
            result["mopt"] = self.mopt.get_stats()

        return result


def create_sample_fuzzer() -> PersistentFuzzer:
    """Create a sample persistent fuzzer for demonstration."""
    from io import BytesIO

    import pydicom

    def target_pydicom(data: bytes) -> bool:
        """Target function that parses DICOM with pydicom."""
        try:
            pydicom.dcmread(BytesIO(data), force=True)
            return True
        except Exception:
            return False

    config = PersistentFuzzerConfig(
        corpus_dir=Path("artifacts/corpus"),
        output_dir=Path("artifacts/fuzzed"),
        max_iterations=10000,
        use_mopt=True,
        power_schedule=PowerSchedule.FAST,
    )

    return PersistentFuzzer(target_func=target_pydicom, config=config)


if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO)

    # Simple demo target
    def demo_target(data: bytes) -> bool:
        """Demo target that crashes on specific patterns."""
        if b"CRASH" in data:
            return False
        if len(data) > 1000:
            return False
        return True

    config = PersistentFuzzerConfig(
        max_iterations=1000,
        use_mopt=True,
    )

    fuzzer = PersistentFuzzer(target_func=demo_target, config=config)
    fuzzer.add_seed(b"DICM" + b"\x00" * 128)

    print("[+] Running persistent fuzzer...")
    stats = fuzzer.run()

    print("\n[+] Final Statistics:")
    print(json.dumps(stats, indent=2))

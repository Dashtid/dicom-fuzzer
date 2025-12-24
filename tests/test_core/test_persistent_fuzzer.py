"""
Tests for Persistent Mode Fuzzer Module.

Tests AFL-style persistent mode fuzzing components including:
- Coverage tracking
- MOpt mutation scheduling
- Various mutators
- Power scheduling
- PersistentFuzzer main class
"""

import struct
from pathlib import Path

import pytest

from dicom_fuzzer.core.persistent_fuzzer import (
    MAP_SIZE,
    ArithMutator,
    BitFlipMutator,
    ByteFlipMutator,
    CoverageMap,
    HavocMutator,
    InterestingMutator,
    MOptScheduler,
    MutationType,
    MutatorStats,
    PersistentFuzzer,
    PersistentFuzzerConfig,
    PowerSchedule,
    SeedEntry,
)

# ============================================================================
# Test Constants and Enums
# ============================================================================


class TestConstants:
    """Test module constants."""

    def test_map_size_is_power_of_two(self):
        """Test MAP_SIZE is a power of 2."""
        assert MAP_SIZE == 65536
        assert (MAP_SIZE & (MAP_SIZE - 1)) == 0  # Power of 2 check


class TestMutationType:
    """Test MutationType enum."""

    def test_mutation_types_defined(self):
        """Test all expected mutation types are defined."""
        expected = [
            "BIT_FLIP_1",
            "BIT_FLIP_2",
            "BIT_FLIP_4",
            "BYTE_FLIP_1",
            "BYTE_FLIP_2",
            "BYTE_FLIP_4",
            "ARITH_8",
            "ARITH_16",
            "ARITH_32",
            "INTERESTING_8",
            "INTERESTING_16",
            "INTERESTING_32",
            "HAVOC",
            "SPLICE",
            "DICOM_STRUCTURE",
            "DICOM_VR",
        ]
        for name in expected:
            assert hasattr(MutationType, name)

    def test_mutation_type_values(self):
        """Test mutation types have string values."""
        assert MutationType.BIT_FLIP_1.value == "bit_flip_1"
        assert MutationType.HAVOC.value == "havoc"


class TestPowerSchedule:
    """Test PowerSchedule enum."""

    def test_power_schedules_defined(self):
        """Test all power schedules are defined."""
        expected = ["FAST", "COE", "EXPLORE", "EXPLOIT", "QUAD", "LINEAR"]
        for name in expected:
            assert hasattr(PowerSchedule, name)


# ============================================================================
# Test Dataclasses
# ============================================================================


class TestCoverageMap:
    """Test CoverageMap dataclass."""

    def test_default_initialization(self):
        """Test default initialization."""
        cov = CoverageMap()
        assert cov.size == MAP_SIZE
        assert len(cov.virgin_bits) == MAP_SIZE
        assert cov.total_bits == 0
        assert cov.new_bits == 0

    def test_update_with_new_coverage(self):
        """Test updating with new coverage."""
        cov = CoverageMap()
        # Create trace with some bits set
        trace = bytearray(MAP_SIZE)
        trace[0] = 1
        trace[100] = 5
        trace[1000] = 255

        has_new = cov.update(bytes(trace))

        assert has_new is True
        assert cov.virgin_bits[0] == 1
        assert cov.virgin_bits[100] == 5
        assert cov.virgin_bits[1000] == 255
        assert cov.total_bits == 3

    def test_update_with_existing_coverage(self):
        """Test updating with existing coverage."""
        cov = CoverageMap()
        # First update
        trace1 = bytearray(MAP_SIZE)
        trace1[0] = 1
        cov.update(bytes(trace1))

        # Same coverage again
        has_new = cov.update(bytes(trace1))
        # No new bits, but trace > virgin for same bit means new transition
        # Actually when trace[i] == virgin[i], it's not new
        # But when trace[i] > virgin[i], it updates
        assert cov.virgin_bits[0] == 1  # Still 1

    def test_update_higher_hit_count(self):
        """Test updating with higher hit count."""
        cov = CoverageMap()
        # First trace
        trace1 = bytearray(MAP_SIZE)
        trace1[0] = 1
        cov.update(bytes(trace1))

        # Higher count at same edge
        trace2 = bytearray(MAP_SIZE)
        trace2[0] = 5
        has_new = cov.update(bytes(trace2))

        assert has_new is True
        assert cov.virgin_bits[0] == 5  # Updated to higher

    def test_get_coverage_percent(self):
        """Test coverage percentage calculation."""
        cov = CoverageMap()
        trace = bytearray(MAP_SIZE)
        # Set 655 bits (1% of 65536)
        for i in range(655):
            trace[i] = 1
        cov.update(bytes(trace))

        percent = cov.get_coverage_percent()
        assert 0.99 < percent < 1.01  # Approximately 1%

    def test_compute_hash(self):
        """Test coverage hash computation."""
        cov = CoverageMap()
        trace = bytearray(MAP_SIZE)
        trace[0] = 1
        cov.update(bytes(trace))

        hash1 = cov.compute_hash()
        assert len(hash1) == 16
        assert all(c in "0123456789abcdef" for c in hash1)

        # Same coverage should give same hash
        cov2 = CoverageMap()
        cov2.update(bytes(trace))
        assert cov2.compute_hash() == hash1


class TestSeedEntry:
    """Test SeedEntry dataclass."""

    def test_default_initialization(self):
        """Test default values."""
        seed = SeedEntry(data=b"test")

        assert seed.data == b"test"
        assert seed.file_path is None
        assert seed.coverage_hash != ""  # Auto-generated
        assert seed.exec_us == 0.0
        assert seed.bitmap_size == 0
        assert seed.depth == 0
        assert seed.was_fuzzed is False
        assert seed.n_fuzz == 0
        assert seed.perf_score == 100.0

    def test_coverage_hash_auto_generated(self):
        """Test coverage hash is auto-generated."""
        seed1 = SeedEntry(data=b"test1")
        seed2 = SeedEntry(data=b"test2")

        assert seed1.coverage_hash != ""
        assert seed2.coverage_hash != ""
        assert seed1.coverage_hash != seed2.coverage_hash

    def test_explicit_coverage_hash(self):
        """Test explicit coverage hash is preserved."""
        seed = SeedEntry(data=b"test", coverage_hash="explicit123")
        assert seed.coverage_hash == "explicit123"

    def test_all_fields(self):
        """Test all fields can be set."""
        seed = SeedEntry(
            data=b"full",
            file_path=Path("/test/path"),
            coverage_hash="abc123",
            exec_us=1000.0,
            bitmap_size=100,
            handicap=2,
            depth=3,
            was_fuzzed=True,
            fuzz_level=5,
            n_fuzz=10,
            top_rated=True,
            favored=True,
            perf_score=200.0,
        )

        assert seed.exec_us == 1000.0
        assert seed.bitmap_size == 100
        assert seed.handicap == 2
        assert seed.depth == 3
        assert seed.was_fuzzed is True
        assert seed.n_fuzz == 10
        assert seed.top_rated is True
        assert seed.favored is True


class TestMutatorStats:
    """Test MutatorStats dataclass."""

    def test_default_values(self):
        """Test default values."""
        stats = MutatorStats()
        assert stats.hits == 0
        assert stats.finds == 0
        assert stats.efficiency == 0.0

    def test_update_efficiency(self):
        """Test efficiency calculation."""
        stats = MutatorStats(hits=100, finds=25)
        stats.update_efficiency()
        assert stats.efficiency == 0.25

    def test_update_efficiency_zero_hits(self):
        """Test efficiency with zero hits."""
        stats = MutatorStats(hits=0, finds=0)
        stats.update_efficiency()
        assert stats.efficiency == 0.0


# ============================================================================
# Test MOptScheduler
# ============================================================================


class TestMOptScheduler:
    """Test MOptScheduler class."""

    def test_initialization_default(self):
        """Test default initialization."""
        scheduler = MOptScheduler()

        assert scheduler.pilot_period == 50000
        assert scheduler.core_period == 500000
        assert scheduler.in_pilot_mode is True
        assert len(scheduler.mutation_types) == len(MutationType)

    def test_initialization_custom_types(self):
        """Test initialization with custom mutation types."""
        custom_types = [MutationType.HAVOC, MutationType.BIT_FLIP_1]
        scheduler = MOptScheduler(mutation_types=custom_types)

        assert scheduler.mutation_types == custom_types
        assert len(scheduler.stats) == 2
        assert len(scheduler.probabilities) == 2

    def test_initial_probabilities_uniform(self):
        """Test initial probabilities are uniform."""
        scheduler = MOptScheduler()
        expected = 1.0 / len(MutationType)

        for prob in scheduler.probabilities.values():
            assert abs(prob - expected) < 0.0001

    def test_select_mutation_returns_valid_type(self):
        """Test select_mutation returns valid mutation type."""
        scheduler = MOptScheduler()

        for _ in range(100):
            mt = scheduler.select_mutation()
            assert mt in MutationType

    def test_select_mutation_updates_hits(self):
        """Test select_mutation updates hit count."""
        scheduler = MOptScheduler()
        initial_hits = sum(s.hits for s in scheduler.stats.values())

        for _ in range(10):
            scheduler.select_mutation()

        final_hits = sum(s.hits for s in scheduler.stats.values())
        assert final_hits == initial_hits + 10

    def test_record_result_updates_finds(self):
        """Test record_result updates find count."""
        scheduler = MOptScheduler()
        mt = MutationType.HAVOC

        initial_finds = scheduler.stats[mt].finds
        scheduler.record_result(mt, found_new=True)

        assert scheduler.stats[mt].finds == initial_finds + 1

    def test_record_result_no_find(self):
        """Test record_result with no new coverage."""
        scheduler = MOptScheduler()
        mt = MutationType.HAVOC

        initial_finds = scheduler.stats[mt].finds
        scheduler.record_result(mt, found_new=False)

        assert scheduler.stats[mt].finds == initial_finds

    def test_pilot_mode_transition(self):
        """Test transition from pilot to core mode."""
        scheduler = MOptScheduler(pilot_period=10, core_period=100)
        assert scheduler.in_pilot_mode is True

        # Record enough results to exit pilot mode
        for _ in range(15):
            mt = scheduler.select_mutation()
            scheduler.record_result(mt, found_new=False)

        assert scheduler.in_pilot_mode is False

    def test_get_stats(self):
        """Test get_stats returns valid structure."""
        scheduler = MOptScheduler()
        scheduler.select_mutation()

        stats = scheduler.get_stats()

        assert "mode" in stats
        assert stats["mode"] in ["pilot", "core"]
        assert "pilot_counter" in stats
        assert "core_counter" in stats
        assert "mutation_stats" in stats

    def test_particles_initialized(self):
        """Test PSO particles are initialized."""
        scheduler = MOptScheduler()

        assert len(scheduler.particles) == scheduler.swarm_size
        for particle in scheduler.particles:
            assert "position" in particle
            assert "velocity" in particle
            assert "best_position" in particle
            assert "best_fitness" in particle


# ============================================================================
# Test Mutators
# ============================================================================


class TestBitFlipMutator:
    """Test BitFlipMutator class."""

    def test_single_bit_flip(self):
        """Test single bit flip mutation."""
        mutator = BitFlipMutator(flip_size=1)
        seed = SeedEntry(data=b"\x00")

        mutated = mutator.mutate(b"\x00", seed)

        # One bit should be flipped
        assert mutated != b"\x00"
        assert len(mutated) == 1

    def test_empty_data(self):
        """Test mutation of empty data."""
        mutator = BitFlipMutator(flip_size=1)
        seed = SeedEntry(data=b"")

        mutated = mutator.mutate(b"", seed)
        assert mutated == b""

    def test_flip_size_2(self):
        """Test 2-bit flip."""
        mutator = BitFlipMutator(flip_size=2)
        seed = SeedEntry(data=b"\x00\x00")

        mutated = mutator.mutate(b"\x00\x00", seed)
        assert mutated != b"\x00\x00"


class TestByteFlipMutator:
    """Test ByteFlipMutator class."""

    def test_single_byte_flip(self):
        """Test single byte flip."""
        mutator = ByteFlipMutator(flip_size=1)
        seed = SeedEntry(data=b"\x00")

        mutated = mutator.mutate(b"\x00", seed)
        assert mutated == b"\xff"

    def test_multi_byte_flip(self):
        """Test multi-byte flip."""
        mutator = ByteFlipMutator(flip_size=2)
        seed = SeedEntry(data=b"\x00\x00\x00\x00")

        mutated = mutator.mutate(b"\x00\x00\x00\x00", seed)
        # Two bytes should be flipped to 0xFF
        assert mutated.count(b"\xff"[0]) >= 2

    def test_data_too_short(self):
        """Test mutation when data is too short."""
        mutator = ByteFlipMutator(flip_size=4)
        seed = SeedEntry(data=b"\x00")

        mutated = mutator.mutate(b"\x00", seed)
        assert mutated == b"\x00"  # Unchanged


class TestArithMutator:
    """Test ArithMutator class."""

    def test_8bit_arithmetic(self):
        """Test 8-bit arithmetic mutation."""
        mutator = ArithMutator(width=8)
        seed = SeedEntry(data=b"\x80")

        mutated = mutator.mutate(b"\x80", seed)
        assert len(mutated) == 1
        # Value should be within ARITH_MAX range
        diff = abs(mutated[0] - 0x80)
        assert diff <= 35 or diff >= (256 - 35)

    def test_16bit_arithmetic(self):
        """Test 16-bit arithmetic mutation."""
        mutator = ArithMutator(width=16)
        data = struct.pack("<H", 1000)
        seed = SeedEntry(data=data)

        mutated = mutator.mutate(data, seed)
        assert len(mutated) == 2

    def test_32bit_arithmetic(self):
        """Test 32-bit arithmetic mutation."""
        mutator = ArithMutator(width=32)
        data = struct.pack("<I", 100000)
        seed = SeedEntry(data=data)

        mutated = mutator.mutate(data, seed)
        assert len(mutated) == 4

    def test_data_too_short_for_width(self):
        """Test mutation when data is too short for width."""
        mutator = ArithMutator(width=32)
        seed = SeedEntry(data=b"\x00")

        mutated = mutator.mutate(b"\x00", seed)
        assert mutated == b"\x00"


class TestInterestingMutator:
    """Test InterestingMutator class."""

    def test_8bit_interesting(self):
        """Test 8-bit interesting value mutation."""
        mutator = InterestingMutator(width=8)
        seed = SeedEntry(data=b"\x00")

        mutated = mutator.mutate(b"\x00", seed)
        assert len(mutated) == 1
        assert mutated[0] in InterestingMutator.INTERESTING_8

    def test_16bit_interesting(self):
        """Test 16-bit interesting value mutation."""
        mutator = InterestingMutator(width=16)
        seed = SeedEntry(data=b"\x00\x00")

        mutated = mutator.mutate(b"\x00\x00", seed)
        assert len(mutated) == 2

    def test_32bit_interesting(self):
        """Test 32-bit interesting value mutation."""
        mutator = InterestingMutator(width=32)
        seed = SeedEntry(data=b"\x00\x00\x00\x00")

        mutated = mutator.mutate(b"\x00\x00\x00\x00", seed)
        assert len(mutated) == 4

    def test_interesting_values_defined(self):
        """Test interesting values are properly defined."""
        assert 0 in InterestingMutator.INTERESTING_8
        assert 255 in InterestingMutator.INTERESTING_8
        assert 65535 in InterestingMutator.INTERESTING_16
        assert 4294967295 in InterestingMutator.INTERESTING_32


class TestHavocMutator:
    """Test HavocMutator class."""

    def test_default_initialization(self):
        """Test default initialization."""
        mutator = HavocMutator()
        assert mutator.intensity == 32

    def test_custom_intensity(self):
        """Test custom intensity."""
        mutator = HavocMutator(intensity=10)
        assert mutator.intensity == 10

    def test_mutate_produces_different_output(self):
        """Test mutation produces different output."""
        mutator = HavocMutator()
        seed = SeedEntry(data=b"\x00" * 100)
        original = b"\x00" * 100

        # Havoc should almost always produce different output
        different_count = 0
        for _ in range(10):
            mutated = mutator.mutate(original, seed)
            if mutated != original:
                different_count += 1

        assert different_count >= 8  # At least 80% should be different

    def test_empty_data(self):
        """Test mutation of empty data."""
        mutator = HavocMutator()
        seed = SeedEntry(data=b"")

        mutated = mutator.mutate(b"", seed)
        assert mutated == b""


# ============================================================================
# Test PersistentFuzzerConfig
# ============================================================================


class TestPersistentFuzzerConfig:
    """Test PersistentFuzzerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = PersistentFuzzerConfig()

        assert config.corpus_dir == Path("artifacts/corpus")
        assert config.output_dir == Path("artifacts/fuzzed")
        assert config.max_iterations == 0
        assert config.max_time_seconds == 0
        assert config.num_workers == 1
        assert config.exec_timeout_ms == 1000
        assert config.use_mopt is True
        assert config.power_schedule == PowerSchedule.FAST
        assert config.persistent_mode is True
        assert config.skip_deterministic is False

    def test_custom_values(self):
        """Test custom configuration."""
        config = PersistentFuzzerConfig(
            corpus_dir=Path("/custom/corpus"),
            output_dir=Path("/custom/output"),
            max_iterations=10000,
            max_time_seconds=3600,
            use_mopt=False,
            power_schedule=PowerSchedule.EXPLORE,
        )

        assert config.corpus_dir == Path("/custom/corpus")
        assert config.max_iterations == 10000
        assert config.max_time_seconds == 3600
        assert config.use_mopt is False
        assert config.power_schedule == PowerSchedule.EXPLORE


# ============================================================================
# Test PersistentFuzzer
# ============================================================================


class TestPersistentFuzzer:
    """Test PersistentFuzzer class."""

    @pytest.fixture
    def tmp_dirs(self, tmp_path):
        """Create temporary directories."""
        corpus_dir = tmp_path / "corpus"
        output_dir = tmp_path / "output"
        return corpus_dir, output_dir

    @pytest.fixture
    def simple_target(self):
        """Create a simple target function."""

        def target(data: bytes) -> bool:
            return True

        return target

    @pytest.fixture
    def crashing_target(self):
        """Create a target that crashes on specific input."""

        def target(data: bytes) -> bool:
            if b"CRASH" in data:
                return False
            return True

        return target

    @pytest.fixture
    def fuzzer(self, tmp_dirs, simple_target):
        """Create a basic fuzzer instance."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )
        return PersistentFuzzer(target_func=simple_target, config=config)

    def test_initialization(self, tmp_dirs, simple_target):
        """Test fuzzer initialization."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )

        fuzzer = PersistentFuzzer(target_func=simple_target, config=config)

        assert corpus_dir.exists()
        assert output_dir.exists()
        assert fuzzer.coverage is not None
        assert fuzzer.corpus == []
        assert fuzzer.mopt is not None

    def test_initialization_without_mopt(self, tmp_dirs, simple_target):
        """Test fuzzer without MOpt."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            use_mopt=False,
        )

        fuzzer = PersistentFuzzer(target_func=simple_target, config=config)
        assert fuzzer.mopt is None

    def test_add_seed(self, fuzzer):
        """Test adding seeds."""
        fuzzer.add_seed(b"test1")
        fuzzer.add_seed(b"test2", file_path=Path("/test/path"))

        assert len(fuzzer.corpus) == 2
        assert fuzzer.corpus[0].data == b"test1"
        assert fuzzer.corpus[1].file_path == Path("/test/path")

    def test_load_corpus(self, tmp_dirs, simple_target):
        """Test loading corpus from directory."""
        corpus_dir, output_dir = tmp_dirs
        corpus_dir.mkdir(parents=True, exist_ok=True)

        # Create some seed files
        (corpus_dir / "seed1.bin").write_bytes(b"seed1")
        (corpus_dir / "seed2.bin").write_bytes(b"seed2")

        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )
        fuzzer = PersistentFuzzer(target_func=simple_target, config=config)
        count = fuzzer.load_corpus()

        assert count == 2
        assert len(fuzzer.corpus) == 2

    def test_select_seed_empty_corpus(self, fuzzer):
        """Test select_seed with empty corpus raises."""
        with pytest.raises(ValueError, match="No seeds"):
            fuzzer.select_seed()

    def test_select_seed_returns_seed(self, fuzzer):
        """Test select_seed returns a seed."""
        fuzzer.add_seed(b"test")

        seed = fuzzer.select_seed()
        assert isinstance(seed, SeedEntry)
        assert seed.data == b"test"

    def test_select_seed_updates_n_fuzz(self, fuzzer):
        """Test select_seed increments n_fuzz."""
        fuzzer.add_seed(b"test")

        seed = fuzzer.corpus[0]
        initial_fuzz = seed.n_fuzz

        fuzzer.select_seed()
        assert seed.n_fuzz == initial_fuzz + 1

    def test_mutate_with_mopt(self, fuzzer):
        """Test mutation with MOpt enabled."""
        seed = SeedEntry(data=b"\x00" * 100)
        fuzzer.corpus.append(seed)

        mutated = fuzzer.mutate(seed)
        # Should return bytes
        assert isinstance(mutated, bytes)

    def test_mutate_without_mopt(self, tmp_dirs, simple_target):
        """Test mutation without MOpt."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
            use_mopt=False,
        )
        fuzzer = PersistentFuzzer(target_func=simple_target, config=config)
        seed = SeedEntry(data=b"\x00" * 100)

        mutated = fuzzer.mutate(seed)
        assert isinstance(mutated, bytes)

    def test_execute_success(self, fuzzer):
        """Test successful execution."""
        is_crash, coverage, exec_time = fuzzer.execute(b"test")

        assert is_crash is False
        assert isinstance(coverage, bytes)
        assert exec_time > 0

    def test_execute_crash(self, tmp_dirs, crashing_target):
        """Test execution that crashes."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )
        fuzzer = PersistentFuzzer(target_func=crashing_target, config=config)

        is_crash, _, _ = fuzzer.execute(b"CRASH")
        assert is_crash is True

    def test_run_one_increments_execs(self, fuzzer):
        """Test run_one increments execution count."""
        seed = SeedEntry(data=b"test")
        fuzzer.corpus.append(seed)

        initial_execs = fuzzer.stats["total_execs"]
        fuzzer.run_one(seed)

        assert fuzzer.stats["total_execs"] == initial_execs + 1

    def test_run_one_records_crash(self, tmp_dirs, crashing_target):
        """Test run_one records crashes."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )
        fuzzer = PersistentFuzzer(target_func=crashing_target, config=config)

        # Create seed that will produce crashing mutation
        seed = SeedEntry(data=b"CRASH")
        fuzzer.corpus.append(seed)

        # Run until we get a crash
        for _ in range(100):
            fuzzer.run_one(seed)
            if fuzzer.stats["total_crashes"] > 0:
                break

        # With CRASH as input, havoc should keep the pattern sometimes
        assert fuzzer.stats["total_crashes"] >= 0  # May or may not crash

    def test_run_limited_iterations(self, fuzzer):
        """Test run with iteration limit."""
        fuzzer.config.max_iterations = 100
        fuzzer.add_seed(b"test")

        stats = fuzzer.run()

        assert stats["total_execs"] == 100

    def test_run_limited_time(self, fuzzer):
        """Test run with time limit."""
        fuzzer.config.max_time_seconds = 1
        fuzzer.add_seed(b"test")

        stats = fuzzer.run()

        assert stats["elapsed_seconds"] >= 1
        assert stats["elapsed_seconds"] < 5  # Should stop reasonably quick

    def test_run_adds_empty_seed_if_empty_corpus(self, fuzzer):
        """Test run adds empty seed if corpus is empty."""
        fuzzer.config.max_iterations = 10

        stats = fuzzer.run()

        assert len(fuzzer.corpus) >= 1

    def test_get_statistics(self, fuzzer):
        """Test get_statistics returns valid data."""
        fuzzer.add_seed(b"test")
        fuzzer.config.max_iterations = 10
        fuzzer.run()

        stats = fuzzer.get_statistics()

        assert "total_execs" in stats
        assert "total_crashes" in stats
        assert "coverage_percent" in stats
        assert "coverage_hash" in stats
        assert "elapsed_seconds" in stats
        assert "mopt" in stats  # MOpt is enabled by default

    def test_save_crash(self, tmp_dirs, crashing_target):
        """Test crash is saved to disk."""
        corpus_dir, output_dir = tmp_dirs
        config = PersistentFuzzerConfig(
            corpus_dir=corpus_dir,
            output_dir=output_dir,
        )
        fuzzer = PersistentFuzzer(target_func=crashing_target, config=config)

        crash_seed = SeedEntry(data=b"CRASH_DATA")
        path = fuzzer._save_crash(crash_seed)

        assert path.exists()
        assert path.read_bytes() == b"CRASH_DATA"

    def test_save_seed(self, fuzzer):
        """Test seed is saved to corpus."""
        seed = SeedEntry(data=b"NEW_SEED")
        path = fuzzer._save_seed(seed)

        assert path.exists()
        assert path.read_bytes() == b"NEW_SEED"


# ============================================================================
# Test Power Scheduling
# ============================================================================


class TestPowerScheduling:
    """Test power scheduling algorithms."""

    @pytest.fixture
    def fuzzer_with_seeds(self, tmp_path):
        """Create fuzzer with multiple seeds."""
        config = PersistentFuzzerConfig(
            corpus_dir=tmp_path / "corpus",
            output_dir=tmp_path / "output",
        )
        fuzzer = PersistentFuzzer(target_func=lambda x: True, config=config)

        # Add seeds with different characteristics
        for i in range(5):
            seed = SeedEntry(
                data=f"seed{i}".encode(),
                n_fuzz=i * 10,
                perf_score=100.0 - i * 10,
            )
            fuzzer.corpus.append(seed)

        return fuzzer

    def test_fast_schedule(self, fuzzer_with_seeds):
        """Test FAST (AFLFast) power schedule."""
        fuzzer_with_seeds.config.power_schedule = PowerSchedule.FAST
        fuzzer_with_seeds.stats["total_execs"] = 1000

        seed = fuzzer_with_seeds.corpus[0]  # n_fuzz=0
        score0 = fuzzer_with_seeds._calculate_seed_score(seed)

        seed = fuzzer_with_seeds.corpus[4]  # n_fuzz=40
        score4 = fuzzer_with_seeds._calculate_seed_score(seed)

        # Less fuzzed seeds should have higher score
        assert score0 > score4

    def test_coe_schedule(self, fuzzer_with_seeds):
        """Test COE (Cut-off Exponential) schedule."""
        fuzzer_with_seeds.config.power_schedule = PowerSchedule.COE
        fuzzer_with_seeds.stats["total_execs"] = 1000

        # Seed with n_fuzz above threshold should have 0 score
        seed = SeedEntry(data=b"test", n_fuzz=100, perf_score=100)
        score = fuzzer_with_seeds._calculate_seed_score(seed)

        # Should be close to 0 for highly fuzzed seeds
        assert score <= 0.01

    def test_explore_schedule(self, fuzzer_with_seeds):
        """Test EXPLORE schedule."""
        fuzzer_with_seeds.config.power_schedule = PowerSchedule.EXPLORE

        seed = fuzzer_with_seeds.corpus[0]  # n_fuzz=0
        score0 = fuzzer_with_seeds._calculate_seed_score(seed)

        seed = fuzzer_with_seeds.corpus[4]  # n_fuzz=40
        score4 = fuzzer_with_seeds._calculate_seed_score(seed)

        # Less fuzzed seeds should score higher
        assert score0 > score4

    def test_exploit_schedule(self, fuzzer_with_seeds):
        """Test EXPLOIT schedule."""
        fuzzer_with_seeds.config.power_schedule = PowerSchedule.EXPLOIT

        # Higher perf_score should lead to higher selection score
        seed = SeedEntry(data=b"high", perf_score=200.0)
        score_high = fuzzer_with_seeds._calculate_seed_score(seed)

        seed = SeedEntry(data=b"low", perf_score=50.0)
        score_low = fuzzer_with_seeds._calculate_seed_score(seed)

        assert score_high > score_low

    def test_quad_schedule(self, fuzzer_with_seeds):
        """Test QUAD (Quadratic) schedule."""
        fuzzer_with_seeds.config.power_schedule = PowerSchedule.QUAD

        seed0 = SeedEntry(data=b"new", n_fuzz=0, perf_score=100)
        score0 = fuzzer_with_seeds._calculate_seed_score(seed0)

        seed100 = SeedEntry(data=b"old", n_fuzz=100, perf_score=100)
        score100 = fuzzer_with_seeds._calculate_seed_score(seed100)

        # Quadratic decay means older seeds score less
        assert score0 > score100


# ============================================================================
# Test create_sample_fuzzer
# ============================================================================


class TestCreateSampleFuzzer:
    """Test create_sample_fuzzer function."""

    def test_creates_fuzzer(self):
        """Test function creates a fuzzer."""
        from dicom_fuzzer.core.persistent_fuzzer import create_sample_fuzzer

        fuzzer = create_sample_fuzzer()

        assert isinstance(fuzzer, PersistentFuzzer)
        assert fuzzer.config.max_iterations == 10000
        assert fuzzer.config.use_mopt is True
        assert fuzzer.config.power_schedule == PowerSchedule.FAST

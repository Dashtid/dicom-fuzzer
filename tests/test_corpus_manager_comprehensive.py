"""Comprehensive tests for corpus_manager module.

Tests seed management, prioritization, and corpus evolution.
"""

import time
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.corpus_manager import (
    CorpusManager,
    CorpusStats,
    Seed,
    SeedPriority,
)


class TestSeedPriority:
    """Test SeedPriority enum."""

    def test_all_priorities_defined(self):
        """Test all priority levels are defined."""
        assert SeedPriority.CRITICAL
        assert SeedPriority.HIGH
        assert SeedPriority.NORMAL
        assert SeedPriority.LOW
        assert SeedPriority.MINIMAL

    def test_priority_values(self):
        """Test priority values are correct."""
        assert SeedPriority.CRITICAL.value == 1
        assert SeedPriority.HIGH.value == 2
        assert SeedPriority.NORMAL.value == 3
        assert SeedPriority.LOW.value == 4
        assert SeedPriority.MINIMAL.value == 5

    def test_priority_ordering(self):
        """Test priorities are ordered correctly."""
        assert SeedPriority.CRITICAL.value < SeedPriority.HIGH.value
        assert SeedPriority.HIGH.value < SeedPriority.NORMAL.value
        assert SeedPriority.NORMAL.value < SeedPriority.LOW.value


class TestSeed:
    """Test Seed dataclass."""

    def test_initialization_required_fields(self):
        """Test seed initialization with required fields."""
        seed = Seed(
            id="seed-001",
            data=b"test data",
            coverage=set(),
        )

        assert seed.id == "seed-001"
        assert seed.data == b"test data"
        assert seed.coverage == set()

    def test_initialization_defaults(self):
        """Test seed initialization with default values."""
        seed = Seed(id="seed-002", data=b"data", coverage=set())

        assert seed.priority == SeedPriority.NORMAL
        assert seed.energy == 1.0
        assert seed.executions == 0
        assert seed.discoveries == 0
        assert seed.crashes == 0

    def test_seed_hash_calculation(self):
        """Test seed hash calculation."""
        seed = Seed(id="seed-003", data=b"test data", coverage=set())

        hash_value = seed.calculate_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) == 16

    def test_same_data_same_hash(self):
        """Test identical data produces same hash."""
        seed1 = Seed(id="seed-1", data=b"same data", coverage=set())
        seed2 = Seed(id="seed-2", data=b"same data", coverage=set())

        assert seed1.calculate_hash() == seed2.calculate_hash()

    def test_different_data_different_hash(self):
        """Test different data produces different hash."""
        seed1 = Seed(id="seed-1", data=b"data 1", coverage=set())
        seed2 = Seed(id="seed-2", data=b"data 2", coverage=set())

        assert seed1.calculate_hash() != seed2.calculate_hash()

    def test_seed_comparison_by_priority(self):
        """Test seeds are compared by priority."""
        critical = Seed(id="1", data=b"a", coverage=set(), priority=SeedPriority.CRITICAL)
        normal = Seed(id="2", data=b"b", coverage=set(), priority=SeedPriority.NORMAL)

        assert critical < normal

    def test_seed_comparison_by_energy(self):
        """Test seeds with same priority compared by energy."""
        high_energy = Seed(id="1", data=b"a", coverage=set(), energy=10.0)
        low_energy = Seed(id="2", data=b"b", coverage=set(), energy=1.0)

        # Higher energy is "less than" (higher priority)
        assert high_energy < low_energy

    def test_update_priority_with_coverage_gain(self):
        """Test priority update when coverage gained."""
        seed = Seed(id="seed", data=b"data", coverage=set())
        initial_energy = seed.energy

        seed.update_priority(coverage_gain=True)

        assert seed.priority == SeedPriority.CRITICAL
        assert seed.discoveries == 1
        assert seed.energy == initial_energy * 2

    def test_update_priority_after_many_executions(self):
        """Test priority downgrade after many executions."""
        seed = Seed(id="seed", data=b"data", coverage=set())
        seed.executions = 150
        seed.discoveries = 0

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.LOW
        assert seed.energy < 1.0


class TestCorpusStats:
    """Test CorpusStats dataclass."""

    def test_initialization_defaults(self):
        """Test stats initialize with zero values."""
        stats = CorpusStats()

        assert stats.total_seeds == 0

    def test_stats_tracking(self):
        """Test updating stats."""
        stats = CorpusStats()
        stats.total_seeds = 100

        assert stats.total_seeds == 100


class TestCorpusManagerInitialization:
    """Test CorpusManager initialization."""

    def test_default_initialization(self):
        """Test manager with default parameters."""
        manager = CorpusManager()

        assert isinstance(manager.stats, CorpusStats)
        assert len(manager.seeds) == 0

    def test_custom_max_corpus_size(self):
        """Test manager with custom max size."""
        manager = CorpusManager(max_corpus_size=500)

        assert manager.max_corpus_size == 500


class TestSeedAddition:
    """Test adding seeds to corpus."""

    def test_add_seed(self):
        """Test adding a seed to corpus."""
        manager = CorpusManager()
        seed = Seed(id="seed-001", data=b"test", coverage=set())

        manager.add_seed(seed)

        assert len(manager.seeds) == 1
        assert "seed-001" in manager.seeds

    def test_add_multiple_seeds(self):
        """Test adding multiple seeds."""
        manager = CorpusManager()

        for i in range(5):
            seed = Seed(id=f"seed-{i}", data=f"data{i}".encode(), coverage=set())
            manager.add_seed(seed)

        assert len(manager.seeds) == 5

    def test_duplicate_seed_handling(self):
        """Test handling duplicate seed IDs."""
        manager = CorpusManager()
        seed1 = Seed(id="seed-001", data=b"data1", coverage=set())
        seed2 = Seed(id="seed-001", data=b"data2", coverage=set())

        manager.add_seed(seed1)
        manager.add_seed(seed2)

        # Should only have one seed (latest overwrites)
        assert len(manager.seeds) == 1


class TestSeedRetrieval:
    """Test retrieving seeds from corpus."""

    def test_get_seed_by_id(self):
        """Test retrieving seed by ID."""
        manager = CorpusManager()
        seed = Seed(id="target", data=b"data", coverage=set())
        manager.add_seed(seed)

        retrieved = manager.get_seed("target")

        assert retrieved is not None
        assert retrieved.id == "target"

    def test_get_nonexistent_seed(self):
        """Test retrieving nonexistent seed."""
        manager = CorpusManager()

        retrieved = manager.get_seed("nonexistent")

        assert retrieved is None

    def test_get_all_seeds(self):
        """Test getting all seeds."""
        manager = CorpusManager()

        for i in range(3):
            seed = Seed(id=f"seed-{i}", data=b"data", coverage=set())
            manager.add_seed(seed)

        all_seeds = manager.get_all_seeds()

        assert len(all_seeds) == 3


class TestSeedSelection:
    """Test seed selection strategies."""

    def test_select_next_seed(self):
        """Test selecting next seed for fuzzing."""
        manager = CorpusManager()

        # Add seeds with different priorities
        critical = Seed(id="critical", data=b"a", coverage=set(), priority=SeedPriority.CRITICAL)
        normal = Seed(id="normal", data=b"b", coverage=set(), priority=SeedPriority.NORMAL)

        manager.add_seed(normal)
        manager.add_seed(critical)

        selected = manager.select_next_seed()

        # Should select critical priority first
        assert selected.priority == SeedPriority.CRITICAL

    def test_select_seed_empty_corpus(self):
        """Test selecting from empty corpus."""
        manager = CorpusManager()

        selected = manager.select_next_seed()

        assert selected is None


class TestCorpusStatistics:
    """Test corpus statistics."""

    def test_get_corpus_size(self):
        """Test getting corpus size."""
        manager = CorpusManager()

        for i in range(10):
            seed = Seed(id=f"seed-{i}", data=b"data", coverage=set())
            manager.add_seed(seed)

        size = manager.get_corpus_size()

        assert size == 10

    def test_update_stats(self):
        """Test updating corpus stats."""
        manager = CorpusManager()

        for i in range(5):
            seed = Seed(id=f"seed-{i}", data=b"data", coverage=set())
            manager.add_seed(seed)

        manager.update_stats()

        assert manager.stats.total_seeds == 5


class TestIntegrationScenarios:
    """Test integration scenarios."""

    def test_complete_corpus_workflow(self):
        """Test complete corpus management workflow."""
        manager = CorpusManager(max_corpus_size=100)

        # Add initial seeds
        for i in range(10):
            seed = Seed(
                id=f"seed-{i}",
                data=f"data{i}".encode(),
                coverage={i},
                priority=SeedPriority.NORMAL,
            )
            manager.add_seed(seed)

        # Verify seeds added
        assert manager.get_corpus_size() == 10

        # Select and update seed
        selected = manager.select_next_seed()
        if selected:
            selected.update_priority(coverage_gain=True)
            assert selected.priority == SeedPriority.CRITICAL

    def test_priority_based_scheduling(self):
        """Test seeds are scheduled by priority."""
        manager = CorpusManager()

        # Add seeds with different priorities
        priorities = [
            SeedPriority.LOW,
            SeedPriority.CRITICAL,
            SeedPriority.NORMAL,
            SeedPriority.HIGH,
        ]

        for i, priority in enumerate(priorities):
            seed = Seed(id=f"seed-{i}", data=b"data", coverage=set(), priority=priority)
            manager.add_seed(seed)

        # First selection should be CRITICAL
        first = manager.select_next_seed()
        assert first.priority == SeedPriority.CRITICAL

    def test_seed_lifecycle(self):
        """Test complete seed lifecycle."""
        manager = CorpusManager()

        # Create seed
        seed = Seed(
            id="lifecycle-test",
            data=b"test data",
            coverage={1, 2, 3},
            priority=SeedPriority.NORMAL,
            energy=1.0,
        )

        # Add to corpus
        manager.add_seed(seed)

        # Execute and update
        seed.executions += 1
        seed.update_priority(coverage_gain=True)

        # Verify updates
        assert seed.priority == SeedPriority.CRITICAL
        assert seed.discoveries == 1
        assert seed.energy > 1.0

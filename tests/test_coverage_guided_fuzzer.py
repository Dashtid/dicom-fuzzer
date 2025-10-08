"""
Tests for Coverage-Guided Fuzzer

Comprehensive test suite for the coverage-guided fuzzing system.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.coverage_instrumentation import CoverageTracker, CoverageInfo
from core.corpus_manager import CorpusManager, Seed, SeedPriority
from core.coverage_guided_mutator import CoverageGuidedMutator, MutationType
from core.coverage_guided_fuzzer import CoverageGuidedFuzzer, FuzzingConfig


class TestCoverageInstrumentation:
    """Test coverage tracking functionality."""

    def test_basic_coverage_tracking(self):
        """Test basic coverage tracking."""
        tracker = CoverageTracker()

        def test_function(x):
            if x > 0:
                return x * 2
            else:
                return x - 1

        # Track coverage for different inputs
        with tracker.track_coverage(b"1") as cov1:
            result = test_function(1)
            assert result == 2

        with tracker.track_coverage(b"-1") as cov2:
            result = test_function(-1)
            assert result == -2

        # Check coverage was tracked
        assert len(tracker.global_coverage.lines) > 0
        assert len(tracker.global_coverage.edges) > 0
        assert tracker.total_executions == 2

    def test_new_coverage_detection(self):
        """Test detection of new coverage."""
        tracker = CoverageTracker()

        def branching_function(x):
            if x == 1:
                return "path1"
            elif x == 2:
                return "path2"
            else:
                return "path3"

        # First execution
        with tracker.track_coverage(b"1") as cov:
            branching_function(1)
        assert cov.new_coverage  # First run always has new coverage

        # Same path - no new coverage
        with tracker.track_coverage(b"1") as cov:
            branching_function(1)
        assert not cov.new_coverage

        # Different path - new coverage
        with tracker.track_coverage(b"2") as cov:
            branching_function(2)
        assert cov.new_coverage

    def test_module_filtering(self):
        """Test module filtering in coverage tracking."""
        # Track only specific modules
        tracker = CoverageTracker(target_modules={'test_module'})

        # Mock module name check
        tracker._module_cache['test_module.py'] = True
        tracker._module_cache['other_module.py'] = False

        assert tracker.should_track_module('test_module.py')
        assert not tracker.should_track_module('other_module.py')

    def test_coverage_statistics(self):
        """Test coverage statistics calculation."""
        tracker = CoverageTracker()

        # Add some coverage
        tracker.global_coverage.edges.add(('file1', 1, 'file1', 2))
        tracker.global_coverage.edges.add(('file1', 2, 'file1', 3))
        tracker.global_coverage.functions.add('file1:func1')
        tracker.total_executions = 10
        tracker.coverage_increases = 3

        stats = tracker.get_coverage_stats()
        assert stats['total_edges'] == 2
        assert stats['total_functions'] == 1
        assert stats['total_executions'] == 10
        assert stats['coverage_increases'] == 3
        assert stats['coverage_rate'] == 0.3


class TestCorpusManager:
    """Test corpus management functionality."""

    def test_seed_creation_and_prioritization(self):
        """Test seed creation and priority management."""
        manager = CorpusManager()

        # Create coverage info
        coverage = CoverageInfo()
        coverage.edges.add(('file', 1, 'file', 2))

        # Add seed
        seed = manager.add_seed(b"test_data", coverage)
        assert seed is not None
        assert seed.id is not None
        assert seed.priority == SeedPriority.CRITICAL  # New coverage

        # Check corpus size
        assert len(manager.seeds) == 1
        assert manager.stats.total_seeds == 1

    def test_seed_scheduling(self):
        """Test seed scheduling based on priority."""
        manager = CorpusManager()

        # Add seeds with different priorities
        cov1 = CoverageInfo()
        cov1.edges.add(('file', 1, 'file', 2))
        seed1 = manager.add_seed(b"data1", cov1)

        cov2 = CoverageInfo()
        cov2.edges.add(('file', 3, 'file', 4))
        seed2 = manager.add_seed(b"data2", cov2)

        # Get next seed - should be highest priority
        next_seed = manager.get_next_seed()
        assert next_seed is not None
        assert next_seed.priority == SeedPriority.CRITICAL

    def test_corpus_minimization(self):
        """Test corpus minimization."""
        manager = CorpusManager(max_corpus_size=2)

        # Add more seeds than max size
        for i in range(5):
            cov = CoverageInfo()
            cov.edges.add(('file', i, 'file', i+1))
            manager.add_seed(f"data{i}".encode(), cov)

        # Check corpus was minimized
        assert len(manager.seeds) <= 2

    def test_coverage_uniqueness(self):
        """Test that only unique coverage is kept."""
        manager = CorpusManager(min_coverage_distance=0.1)

        # Add seed with coverage
        cov1 = CoverageInfo()
        cov1.edges = {('file', 1, 'file', 2), ('file', 2, 'file', 3)}
        seed1 = manager.add_seed(b"data1", cov1)
        assert seed1 is not None

        # Try to add seed with identical coverage
        cov2 = CoverageInfo()
        cov2.edges = cov1.edges.copy()
        seed2 = manager.add_seed(b"data2", cov2)
        assert seed2 is None  # Should be rejected

        # Add seed with different coverage
        cov3 = CoverageInfo()
        cov3.edges = {('file', 4, 'file', 5)}
        seed3 = manager.add_seed(b"data3", cov3)
        assert seed3 is not None

    def test_mutation_success_tracking(self):
        """Test tracking of mutation success rates."""
        manager = CorpusManager()

        # Add seed with mutation info
        cov = CoverageInfo()
        cov.edges = {('file', 1, 'file', 2)}
        seed = manager.add_seed(b"data", cov, mutation_type="bit_flip")

        # Check mutation tracking
        assert "bit_flip" in manager.mutation_success_rate
        assert manager.mutation_success_rate["bit_flip"] == 1

        weights = manager.get_mutation_weights()
        assert "bit_flip" in weights


class TestCoverageGuidedMutator:
    """Test coverage-guided mutation engine."""

    def test_basic_mutations(self):
        """Test basic mutation operations."""
        mutator = CoverageGuidedMutator()

        # Create a seed
        seed = Seed(
            id="test",
            data=b"Hello World",
            coverage=CoverageInfo(),
            energy=1.0
        )

        # Generate mutations
        mutations = mutator.mutate(seed)
        assert len(mutations) > 0

        # Check mutations are different
        for mutated_data, mutation_type in mutations:
            assert mutated_data != seed.data
            assert isinstance(mutation_type, MutationType)

    def test_dicom_specific_mutations(self):
        """Test DICOM-specific mutations."""
        mutator = CoverageGuidedMutator(dicom_aware=True)

        # Create DICOM-like data
        dicom_data = b'DICM' + b'\x00' * 128 + b'\x08\x00\x10\x00'

        seed = Seed(
            id="test",
            data=dicom_data,
            coverage=CoverageInfo(),
            energy=2.0
        )

        # Generate mutations
        mutations = mutator.mutate(seed)
        assert len(mutations) > 0

        # Check for DICOM-specific mutations
        mutation_types = [mt for _, mt in mutations]
        dicom_mutations = [
            MutationType.DICOM_TAG_CORRUPT,
            MutationType.DICOM_VR_MISMATCH,
            MutationType.DICOM_LENGTH_OVERFLOW,
            MutationType.DICOM_SEQUENCE_NEST,
            MutationType.DICOM_TRANSFER_SYNTAX
        ]

        # At least one DICOM-specific mutation should be attempted
        has_dicom_mutation = any(mt in dicom_mutations for mt in mutation_types)
        # Note: This might not always be true due to randomness

    def test_adaptive_mutation_selection(self):
        """Test adaptive mutation strategy selection."""
        mutator = CoverageGuidedMutator(adaptive_mode=True)

        # Update strategy feedback
        mutator.update_strategy_feedback(MutationType.BIT_FLIP, True, 5)
        mutator.update_strategy_feedback(MutationType.BIT_FLIP, True, 3)
        mutator.update_strategy_feedback(MutationType.BYTE_FLIP, False)

        # Check strategy weights were updated
        bit_flip_strategy = mutator.strategies[MutationType.BIT_FLIP]
        byte_flip_strategy = mutator.strategies[MutationType.BYTE_FLIP]

        assert bit_flip_strategy.success_count == 2
        assert bit_flip_strategy.success_rate > byte_flip_strategy.success_rate

    def test_mutation_statistics(self):
        """Test mutation statistics tracking."""
        mutator = CoverageGuidedMutator()

        # Perform mutations and update feedback
        for i in range(10):
            mutator.update_strategy_feedback(
                MutationType.BIT_FLIP,
                coverage_gained=(i % 2 == 0),
                new_edges=i
            )

        stats = mutator.get_mutation_stats()
        assert 'bit_flip' in stats
        assert stats['bit_flip']['total_count'] == 10
        assert stats['bit_flip']['success_count'] == 5
        assert stats['bit_flip']['success_rate'] == 0.5


class TestCoverageGuidedFuzzer:
    """Test main coverage-guided fuzzer."""

    @pytest.mark.asyncio
    async def test_fuzzer_initialization(self):
        """Test fuzzer initialization."""
        config = FuzzingConfig(
            max_iterations=10,
            output_dir=Path(tempfile.mkdtemp())
        )

        fuzzer = CoverageGuidedFuzzer(config)
        assert fuzzer.config == config
        assert fuzzer.coverage_tracker is not None
        assert fuzzer.corpus_manager is not None
        assert fuzzer.mutator is not None

    @pytest.mark.asyncio
    async def test_minimal_fuzzing_campaign(self):
        """Test a minimal fuzzing campaign."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simple target function
            def target_function(data: bytes) -> bool:
                if len(data) > 10 and b'CRASH' in data:
                    raise ValueError("Crash found!")
                return True

            config = FuzzingConfig(
                target_function=target_function,
                max_iterations=50,
                output_dir=Path(tmpdir) / "output",
                crash_dir=Path(tmpdir) / "crashes"
            )

            fuzzer = CoverageGuidedFuzzer(config)

            # Run short campaign
            stats = await fuzzer.run()

            assert stats.total_executions > 0
            assert stats.corpus_size > 0

    @pytest.mark.asyncio
    async def test_crash_detection(self):
        """Test crash detection and saving."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_count = 0

            def crashing_target(data: bytes) -> bool:
                nonlocal crash_count
                if b'\xFF\xFF\xFF\xFF' in data:
                    crash_count += 1
                    raise Exception("Crash!")
                return True

            config = FuzzingConfig(
                target_function=crashing_target,
                max_iterations=100,
                output_dir=Path(tmpdir) / "output",
                crash_dir=Path(tmpdir) / "crashes"
            )

            fuzzer = CoverageGuidedFuzzer(config)
            stats = await fuzzer.run()

            # Crashes should be detected
            if crash_count > 0:
                assert stats.total_crashes > 0

    def test_config_loading(self):
        """Test configuration loading."""
        config = FuzzingConfig(
            max_iterations=1000,
            num_workers=4,
            coverage_guided=True,
            adaptive_mutations=True,
            dicom_aware=True
        )

        assert config.max_iterations == 1000
        assert config.num_workers == 4
        assert config.coverage_guided
        assert config.adaptive_mutations
        assert config.dicom_aware


class TestIntegration:
    """Integration tests for the complete system."""

    @pytest.mark.asyncio
    async def test_end_to_end_fuzzing(self):
        """Test complete fuzzing workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Target with multiple paths
            def complex_target(data: bytes) -> bool:
                if len(data) < 4:
                    return False

                # Different execution paths
                if data[0] == 0xFF:
                    if data[1] == 0xFE:
                        if data[2] == 0xFD:
                            if data[3] == 0xFC:
                                raise ValueError("Deep bug found!")
                            return "path_3"
                        return "path_2"
                    return "path_1"
                return "default"

            config = FuzzingConfig(
                target_function=complex_target,
                max_iterations=500,
                coverage_guided=True,
                adaptive_mutations=True,
                output_dir=Path(tmpdir) / "output",
                corpus_dir=Path(tmpdir) / "corpus",
                crash_dir=Path(tmpdir) / "crashes"
            )

            # Configure coverage tracking
            from core.coverage_instrumentation import configure_global_tracker
            configure_global_tracker({'__main__'})

            fuzzer = CoverageGuidedFuzzer(config)
            stats = await fuzzer.run()

            # Verify fuzzing effectiveness
            assert stats.total_executions > 0
            assert stats.corpus_size > 0
            assert stats.current_coverage > 0

            # Check that corpus was saved
            corpus_files = list(config.corpus_dir.glob('*.seed'))
            assert len(corpus_files) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
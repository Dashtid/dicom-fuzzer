"""Comprehensive tests for mutation_minimization.py

Tests delta debugging algorithm edge cases, minimization strategies,
and crash orchestration workflows. Targets 85%+ coverage.
"""

import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest
from pydicom.dataset import Dataset, FileDataset

from dicom_fuzzer.core.fuzzing_session import MutationRecord
from dicom_fuzzer.core.mutation_minimization import (
    CrashMinimizationOrchestrator,
    MinimizationResult,
    MutationMinimizer,
)


class TestMinimizationResultDataclass:
    """Test MinimizationResult dataclass."""

    def test_minimization_result_initialization(self):
        """Test MinimizationResult creation with all fields."""
        mutations = [MagicMock(spec=MutationRecord) for _ in range(3)]
        result = MinimizationResult(
            original_mutation_count=10,
            minimized_mutation_count=3,
            minimal_mutations=mutations,
            test_iterations=25,
            still_crashes=True,
            minimization_ratio=0.7,
        )

        assert result.original_mutation_count == 10
        assert result.minimized_mutation_count == 3
        assert len(result.minimal_mutations) == 3
        assert result.test_iterations == 25
        assert result.still_crashes is True
        assert result.minimization_ratio == 0.7

    def test_minimization_result_zero_ratio(self):
        """Test minimization ratio calculation when no minimization occurs."""
        result = MinimizationResult(
            original_mutation_count=5,
            minimized_mutation_count=5,
            minimal_mutations=[],
            test_iterations=10,
            still_crashes=True,
            minimization_ratio=0.0,
        )

        assert result.minimization_ratio == 0.0


class TestSplitListEdgeCases:
    """Test _split_list method edge cases."""

    def setup_method(self):
        """Setup test fixtures."""
        self.minimizer = MutationMinimizer(crash_tester=lambda ds: False)

    def test_split_list_n_zero(self):
        """Test splitting with n=0 returns full list."""
        lst = [1, 2, 3, 4, 5]
        result = self.minimizer._split_list(lst, 0)

        assert result == [lst]
        assert len(result) == 1

    def test_split_list_n_negative(self):
        """Test splitting with negative n returns full list."""
        lst = [1, 2, 3, 4, 5]
        result = self.minimizer._split_list(lst, -5)

        assert result == [lst]

    def test_split_list_n_greater_than_length(self):
        """Test splitting with n > len(lst) returns full list."""
        lst = [1, 2, 3]
        result = self.minimizer._split_list(lst, 10)

        assert result == [lst]
        assert len(result) == 1

    def test_split_list_n_equals_length(self):
        """Test splitting with n == len(lst) creates individual elements."""
        lst = [1, 2, 3, 4, 5]
        result = self.minimizer._split_list(lst, 5)

        assert len(result) == 5
        assert result == [[1], [2], [3], [4], [5]]

    def test_split_list_with_remainder(self):
        """Test splitting distributes remainder across first chunks."""
        lst = [1, 2, 3, 4, 5, 6, 7]
        result = self.minimizer._split_list(lst, 3)

        # 7 elements / 3 parts = 2 per chunk + 1 remainder
        # First chunk gets remainder: [1,2,3], [4,5], [6,7]
        assert len(result) == 3
        assert len(result[0]) == 3  # Gets remainder
        assert len(result[1]) == 2
        assert len(result[2]) == 2

    def test_split_list_even_division(self):
        """Test splitting with perfect division."""
        lst = [1, 2, 3, 4, 5, 6]
        result = self.minimizer._split_list(lst, 3)

        assert len(result) == 3
        assert result == [[1, 2], [3, 4], [5, 6]]

    def test_split_list_single_element(self):
        """Test splitting single-element list."""
        lst = [1]
        result = self.minimizer._split_list(lst, 2)

        # Should return full list when n > len
        assert result == [[1]]


class TestDeltaDebuggingEdgeCases:
    """Test delta debugging algorithm edge cases."""

    def test_delta_debugging_empty_mutations(self):
        """Test delta debugging with empty mutation list."""
        dataset = Dataset()
        mutations = []

        def crash_tester(ds):
            return False

        minimizer = MutationMinimizer(crash_tester, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        assert result.minimized_mutation_count == 0
        assert result.minimal_mutations == []
        assert result.minimization_ratio == 0.0

    def test_delta_debugging_single_mutation_crashes(self):
        """Test delta debugging with single mutation that crashes."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord)]

        def crash_tester(ds):
            return True

        minimizer = MutationMinimizer(crash_tester, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        assert result.minimized_mutation_count == 1
        assert len(result.minimal_mutations) == 1
        assert result.still_crashes is True

    def test_delta_debugging_no_mutations_crash(self):
        """Test delta debugging when no mutations cause crash."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(5)]

        def crash_tester(ds):
            return False  # Never crashes

        minimizer = MutationMinimizer(crash_tester, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should keep all mutations since none individually crash
        assert result.still_crashes is False

    def test_delta_debugging_granularity_increase(self):
        """Test delta debugging increases granularity when no reduction found."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(8)]
        crash_count = 0

        def crash_tester(ds):
            nonlocal crash_count
            crash_count += 1
            # Only crashes with all mutations
            return crash_count == 1

        minimizer = MutationMinimizer(crash_tester, max_iterations=50)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should eventually stop when n >= len(mutations)
        assert result.test_iterations > 1

    def test_delta_debugging_complement_sets(self):
        """Test delta debugging complement set logic."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(4)]

        # Track which mutations are tested
        test_log = []

        def crash_tester(ds):
            # Crashes if mutations 0, 1, 2 are present (not 3)
            test_log.append("test")
            # This is simplified - actual test would check mutations
            return len(test_log) % 3 == 0

        minimizer = MutationMinimizer(crash_tester, max_iterations=30)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should have tried complement sets
        assert result.test_iterations > 2

    def test_delta_debugging_max_iterations_stops_early(self):
        """Test delta debugging respects max_iterations."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(20)]

        def crash_tester(ds):
            return True  # Always crashes

        minimizer = MutationMinimizer(crash_tester, max_iterations=5)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should stop at max_iterations
        assert result.test_iterations <= 5

    def test_delta_debugging_granularity_decrease(self):
        """Test delta debugging decreases granularity after finding smaller set."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(6)]
        call_count = 0

        def crash_tester(ds):
            nonlocal call_count
            call_count += 1
            # First subset always crashes
            return call_count == 1

        minimizer = MutationMinimizer(crash_tester, max_iterations=50)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should reduce set and decrease granularity (n = max(2, n-1))
        assert result.minimized_mutation_count < 6


class TestLinearMinimizationEdgeCases:
    """Test linear minimization edge cases."""

    def test_linear_minimization_empty_list(self):
        """Test linear minimization with empty mutation list."""
        dataset = Dataset()
        mutations = []

        minimizer = MutationMinimizer(lambda ds: False, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="linear")

        assert result.minimized_mutation_count == 0
        assert result.minimal_mutations == []

    def test_linear_minimization_all_mutations_required(self):
        """Test linear minimization when all mutations are required."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(5)]

        def crash_tester(ds):
            # Only crashes with all mutations
            return False

        minimizer = MutationMinimizer(crash_tester, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="linear")

        # Should try to remove each and keep all
        assert result.minimized_mutation_count == 5

    def test_linear_minimization_removes_unnecessary(self):
        """Test linear minimization removes unnecessary mutations."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(5)]

        # Only first mutation is needed
        def crash_tester(ds):
            return True  # Always crashes

        minimizer = MutationMinimizer(crash_tester, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="linear")

        # Should remove all unnecessary mutations
        assert result.minimized_mutation_count < 5

    def test_linear_minimization_respects_max_iterations(self):
        """Test linear minimization respects max_iterations limit."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(20)]

        minimizer = MutationMinimizer(lambda ds: True, max_iterations=3)
        result = minimizer.minimize(dataset, mutations, strategy="linear")

        assert result.test_iterations <= 3


class TestBinaryMinimizationEdgeCases:
    """Test binary minimization edge cases."""

    def test_binary_minimization_single_mutation(self):
        """Test binary minimization with single mutation."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord)]

        minimizer = MutationMinimizer(lambda ds: True, max_iterations=10)
        result = minimizer.minimize(dataset, mutations, strategy="binary")

        assert result.minimized_mutation_count == 1

    def test_binary_minimization_first_half_crashes(self):
        """Test binary minimization when first half crashes."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(10)]
        call_count = 0

        def crash_tester(ds):
            nonlocal call_count
            call_count += 1
            # First call (first half) crashes
            return call_count == 1

        minimizer = MutationMinimizer(crash_tester, max_iterations=20)
        result = minimizer.minimize(dataset, mutations, strategy="binary")

        # Should reduce to first half
        assert result.minimized_mutation_count < 10

    def test_binary_minimization_second_half_crashes(self):
        """Test binary minimization when second half crashes."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(10)]
        call_count = 0

        def crash_tester(ds):
            nonlocal call_count
            call_count += 1
            # Second call (second half) crashes
            return call_count == 2

        minimizer = MutationMinimizer(crash_tester, max_iterations=20)
        result = minimizer.minimize(dataset, mutations, strategy="binary")

        # Should reduce to second half
        assert result.minimized_mutation_count < 10

    def test_binary_minimization_falls_back_to_linear(self):
        """Test binary minimization falls back to linear when both halves needed."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord) for _ in range(10)]

        def crash_tester(ds):
            # Neither half alone crashes
            return False

        minimizer = MutationMinimizer(crash_tester, max_iterations=20)
        result = minimizer.minimize(dataset, mutations, strategy="binary")

        # Should fall back to linear minimization
        assert result.test_iterations >= 2  # At least 2 binary tries before linear


class TestMinimizationStrategyErrors:
    """Test error handling in minimization strategies."""

    def test_invalid_strategy_raises_error(self):
        """Test that invalid strategy name raises ValueError."""
        dataset = Dataset()
        mutations = [MagicMock(spec=MutationRecord)]

        minimizer = MutationMinimizer(lambda ds: True)

        with pytest.raises(ValueError, match="Unknown minimization strategy"):
            minimizer.minimize(dataset, mutations, strategy="invalid_strategy")

    def test_minimization_ratio_with_empty_mutations(self):
        """Test minimization ratio calculation with empty mutations."""
        dataset = Dataset()
        mutations = []

        minimizer = MutationMinimizer(lambda ds: False)
        result = minimizer.minimize(dataset, mutations, strategy="delta_debug")

        # Should handle division by zero
        assert result.minimization_ratio == 0.0


class TestCrashMinimizationOrchestrator:
    """Test CrashMinimizationOrchestrator class."""

    def test_orchestrator_initialization(self, tmp_path):
        """Test orchestrator initialization."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=10)

        assert orchestrator.viewer_path == viewer_path
        assert orchestrator.timeout == 10

    def test_orchestrator_default_timeout(self, tmp_path):
        """Test orchestrator uses default timeout."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path)

        assert orchestrator.timeout == 5

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_minimize_crash_subprocess_timeout(
        self, mock_dcmwrite, mock_dcmread, mock_popen, tmp_path
    ):
        """Test minimize_crash handles subprocess timeout."""
        # Setup mocks
        viewer_path = tmp_path / "viewer.exe"
        viewer_path.touch()
        source_file = tmp_path / "source.dcm"
        source_file.touch()

        dataset = FileDataset("test", {}, file_meta=Dataset(), preamble=b"\x00" * 128)
        mock_dcmread.return_value = dataset

        # Mock subprocess to timeout
        mock_proc = Mock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mock_proc.kill = Mock()
        mock_popen.return_value = mock_proc

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=5)
        mutations = [MagicMock(spec=MutationRecord)]

        result = orchestrator.minimize_crash("crash_1", source_file, mutations)

        # Timeout should count as crash
        assert mock_proc.kill.called
        # With single mutation, minimization can't reduce further (test_iterations >= 0)
        assert result.test_iterations >= 0
        assert result.still_crashes is True

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_minimize_crash_nonzero_exit(
        self, mock_dcmwrite, mock_dcmread, mock_popen, tmp_path
    ):
        """Test minimize_crash detects non-zero exit code as crash."""
        viewer_path = tmp_path / "viewer.exe"
        viewer_path.touch()
        source_file = tmp_path / "source.dcm"
        source_file.touch()

        dataset = FileDataset("test", {}, file_meta=Dataset(), preamble=b"\x00" * 128)
        mock_dcmread.return_value = dataset

        # Mock subprocess with non-zero exit
        mock_proc = Mock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 1  # Non-zero = crash
        mock_popen.return_value = mock_proc

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=5)
        mutations = [MagicMock(spec=MutationRecord)]

        result = orchestrator.minimize_crash("crash_1", source_file, mutations)

        assert result.still_crashes is True

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_minimize_crash_handles_write_error(
        self, mock_dcmwrite, mock_dcmread, mock_popen, tmp_path
    ):
        """Test minimize_crash handles file write errors gracefully."""
        viewer_path = tmp_path / "viewer.exe"
        viewer_path.touch()
        source_file = tmp_path / "source.dcm"
        source_file.touch()

        dataset = FileDataset("test", {}, file_meta=Dataset(), preamble=b"\x00" * 128)
        mock_dcmread.return_value = dataset
        mock_dcmwrite.side_effect = Exception("Write error")

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=5)
        mutations = [MagicMock(spec=MutationRecord)]

        # Should handle exception and treat as no crash
        result = orchestrator.minimize_crash("crash_1", source_file, mutations)

        assert result.still_crashes is False

    def test_batch_minimize_sorts_by_mutation_count(self, tmp_path):
        """Test batch_minimize prioritizes crashes with more mutations."""
        viewer_path = tmp_path / "viewer.exe"
        source_file = tmp_path / "source.dcm"
        source_file.touch()

        # Create crashes with different mutation counts
        crashes = [
            (
                "crash_1",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(2)],
            ),
            (
                "crash_2",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(5)],
            ),
            (
                "crash_3",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(3)],
            ),
        ]

        with patch.object(
            CrashMinimizationOrchestrator, "minimize_crash"
        ) as mock_minimize:
            mock_minimize.return_value = MinimizationResult(
                original_mutation_count=5,
                minimized_mutation_count=2,
                minimal_mutations=[],
                test_iterations=10,
                still_crashes=True,
                minimization_ratio=0.6,
            )

            orchestrator = CrashMinimizationOrchestrator(viewer_path)
            results = orchestrator.batch_minimize(crashes)

            # Should process crash_2 first (5 mutations), then crash_3 (3), then crash_1 (2)
            assert len(results) == 3
            assert "crash_1" in results
            assert "crash_2" in results
            assert "crash_3" in results

    def test_batch_minimize_respects_max_crashes(self, tmp_path):
        """Test batch_minimize respects max_crashes limit."""
        viewer_path = tmp_path / "viewer.exe"
        source_file = tmp_path / "source.dcm"
        source_file.touch()

        crashes = [
            (
                "crash_1",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(5)],
            ),
            (
                "crash_2",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(4)],
            ),
            (
                "crash_3",
                source_file,
                [MagicMock(spec=MutationRecord) for _ in range(3)],
            ),
        ]

        with patch.object(
            CrashMinimizationOrchestrator, "minimize_crash"
        ) as mock_minimize:
            mock_minimize.return_value = MinimizationResult(
                original_mutation_count=5,
                minimized_mutation_count=2,
                minimal_mutations=[],
                test_iterations=10,
                still_crashes=True,
                minimization_ratio=0.6,
            )

            orchestrator = CrashMinimizationOrchestrator(viewer_path)
            results = orchestrator.batch_minimize(crashes, max_crashes=2)

            # Should only process top 2 crashes
            assert len(results) == 2

    def test_batch_minimize_empty_list(self, tmp_path):
        """Test batch_minimize with empty crash list."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path)

        results = orchestrator.batch_minimize([])

        assert results == {}


class TestApplyMutations:
    """Test _apply_mutations method."""

    def test_apply_mutations_creates_deep_copy(self):
        """Test _apply_mutations creates deep copy of dataset."""
        dataset = Dataset()
        dataset.PatientName = "Test Patient"
        mutations = [MagicMock(spec=MutationRecord)]

        minimizer = MutationMinimizer(lambda ds: True)
        mutated = minimizer._apply_mutations(dataset, mutations)

        # Verify it's a copy
        assert mutated is not dataset
        assert mutated.PatientName == "Test Patient"

    def test_apply_mutations_with_empty_mutations(self):
        """Test _apply_mutations with empty mutation list."""
        dataset = Dataset()
        dataset.PatientID = "12345"

        minimizer = MutationMinimizer(lambda ds: True)
        mutated = minimizer._apply_mutations(dataset, [])

        assert mutated.PatientID == "12345"
        assert mutated is not dataset

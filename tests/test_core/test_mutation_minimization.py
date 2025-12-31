"""Tests for mutation minimization module.

Tests the delta debugging algorithms, mutation application,
and crash minimization orchestration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.mutation_minimization import (
    CrashMinimizationOrchestrator,
    MinimizationResult,
    MutationMinimizer,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class MockMutationRecord:
    """Mock MutationRecord for testing."""

    mutation_id: str
    strategy_name: str = "test_strategy"
    timestamp: datetime = None
    target_tag: str | None = None
    target_element: str | None = None
    mutation_type: str = "modify"
    original_value: str | None = None
    mutated_value: str | None = None
    parameters: dict = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.parameters is None:
            self.parameters = {}


@pytest.fixture
def mock_mutations():
    """Create a list of mock mutation records."""
    return [
        MockMutationRecord(
            mutation_id=f"mut_{i}",
            target_tag=f"(0010,00{i}0)",
            mutation_type="modify",
            mutated_value=f"value_{i}",
        )
        for i in range(5)
    ]


@pytest.fixture
def mock_dataset():
    """Create a mock pydicom Dataset."""
    ds = MagicMock()
    ds.copy.return_value = MagicMock()
    return ds


def make_crash_tester(crash_on_indices: set[int]):
    """Create a crash tester that crashes when specific mutation indices are present.

    Args:
        crash_on_indices: Set of mutation indices that trigger crash

    Returns:
        Tuple of (crash_tester function, call_count list)
    """
    call_count = [0]

    def crash_tester(dataset: MagicMock) -> bool:
        call_count[0] += 1
        # Check if dataset has markers for crash-triggering mutations
        # For simplicity, use dataset._crash_indices attribute
        if hasattr(dataset, "_crash_indices"):
            return bool(dataset._crash_indices & crash_on_indices)
        return False

    return crash_tester, call_count


# =============================================================================
# Phase 1: Dataclass & Helper Tests
# =============================================================================


class TestMinimizationResult:
    """Tests for MinimizationResult dataclass."""

    def test_minimization_result_creation(self):
        """Test MinimizationResult creation with all fields."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(3)]
        result = MinimizationResult(
            original_mutation_count=10,
            minimized_mutation_count=3,
            minimal_mutations=mutations,
            test_iterations=15,
            still_crashes=True,
            minimization_ratio=0.7,
        )

        assert result.original_mutation_count == 10
        assert result.minimized_mutation_count == 3
        assert len(result.minimal_mutations) == 3
        assert result.test_iterations == 15
        assert result.still_crashes is True
        assert result.minimization_ratio == 0.7

    def test_minimization_result_zero_mutations(self):
        """Test MinimizationResult with zero original mutations."""
        result = MinimizationResult(
            original_mutation_count=0,
            minimized_mutation_count=0,
            minimal_mutations=[],
            test_iterations=0,
            still_crashes=False,
            minimization_ratio=0.0,
        )

        assert result.original_mutation_count == 0
        assert result.minimization_ratio == 0.0


class TestSplitList:
    """Tests for _split_list helper method."""

    @pytest.fixture
    def minimizer(self):
        """Create a minimizer for testing split_list."""
        return MutationMinimizer(lambda ds: False)

    def test_split_list_even_split(self, minimizer):
        """Test splitting list into equal parts."""
        items = [1, 2, 3, 4, 5, 6]
        chunks = minimizer._split_list(items, 2)

        assert len(chunks) == 2
        assert chunks[0] == [1, 2, 3]
        assert chunks[1] == [4, 5, 6]

    def test_split_list_with_remainder(self, minimizer):
        """Test splitting list with remainder."""
        items = [1, 2, 3, 4, 5]
        chunks = minimizer._split_list(items, 2)

        assert len(chunks) == 2
        # First chunk gets the remainder
        assert chunks[0] == [1, 2, 3]
        assert chunks[1] == [4, 5]

    def test_split_list_n_zero(self, minimizer):
        """Test splitting with n=0 returns original list."""
        items = [1, 2, 3]
        chunks = minimizer._split_list(items, 0)

        assert chunks == [[1, 2, 3]]

    def test_split_list_n_greater_than_length(self, minimizer):
        """Test splitting with n > list length returns original."""
        items = [1, 2]
        chunks = minimizer._split_list(items, 5)

        assert chunks == [[1, 2]]

    def test_split_list_into_singletons(self, minimizer):
        """Test splitting list into single-element chunks."""
        items = [1, 2, 3]
        chunks = minimizer._split_list(items, 3)

        assert len(chunks) == 3
        assert chunks[0] == [1]
        assert chunks[1] == [2]
        assert chunks[2] == [3]


# =============================================================================
# Phase 2: MutationMinimizer Core Tests
# =============================================================================


class TestMutationMinimizer:
    """Tests for MutationMinimizer class."""

    def test_minimizer_initialization(self):
        """Test minimizer initialization with custom max_iterations."""

        def crash_tester(ds):
            return False

        minimizer = MutationMinimizer(crash_tester, max_iterations=100)

        assert minimizer.max_iterations == 100
        assert minimizer.test_count == 0

    def test_minimize_unknown_strategy_raises(self, mock_dataset, mock_mutations):
        """Test that unknown strategy raises ValueError."""
        minimizer = MutationMinimizer(lambda ds: True)

        with pytest.raises(ValueError, match="Unknown minimization strategy"):
            minimizer.minimize(mock_dataset, mock_mutations, strategy="unknown")

    def test_minimize_empty_mutations(self, mock_dataset):
        """Test minimization with empty mutation list."""
        minimizer = MutationMinimizer(lambda ds: True)
        result = minimizer.minimize(mock_dataset, [], strategy="delta_debug")

        assert result.original_mutation_count == 0
        assert result.minimized_mutation_count == 0
        assert result.minimization_ratio == 0.0

    def test_minimize_single_mutation(self, mock_dataset):
        """Test minimization with single mutation."""
        mutations = [MockMutationRecord(mutation_id="m1")]
        minimizer = MutationMinimizer(lambda ds: True)
        result = minimizer.minimize(mock_dataset, mutations, strategy="delta_debug")

        assert result.original_mutation_count == 1
        assert result.minimized_mutation_count == 1


class TestDeltaDebugging:
    """Tests for delta debugging algorithm."""

    def test_delta_debugging_finds_single_crash_mutation(self, mock_dataset):
        """Test that delta debugging isolates single crash-causing mutation."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(4)]

        # Create crash tester that only crashes when mutation 2 is present
        def crash_on_m2(dataset):
            # Simulate: check if mutation 2's effect is applied
            # For this test, we track which mutations are in the current subset
            return getattr(dataset, "_has_m2", False)

        # Custom apply_mutations that marks dataset
        minimizer = MutationMinimizer(crash_on_m2, max_iterations=50)

        # Patch _apply_mutations to mark dataset based on mutations
        original_apply = minimizer._apply_mutations

        def patched_apply(ds, muts):
            result = original_apply(ds, muts)
            result._has_m2 = any(m.mutation_id == "m2" for m in muts)
            return result

        minimizer._apply_mutations = patched_apply

        result = minimizer.minimize(mock_dataset, mutations, strategy="delta_debug")

        # Should find m2 as the minimal set
        assert result.minimized_mutation_count <= 2  # Delta debugging should reduce
        assert result.still_crashes is True

    def test_delta_debugging_respects_max_iterations(self, mock_dataset):
        """Test that delta debugging stops at max_iterations."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(10)]

        minimizer = MutationMinimizer(lambda ds: True, max_iterations=3)
        result = minimizer.minimize(mock_dataset, mutations, strategy="delta_debug")

        # Should have stopped early
        assert minimizer.test_count <= 5  # Some overhead for final verification


class TestLinearMinimization:
    """Tests for linear minimization strategy."""

    def test_linear_minimization_removes_unnecessary(self, mock_dataset):
        """Test linear minimization removes non-essential mutations."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(4)]

        # Crash tester: only needs mutation 1
        def needs_m1(dataset):
            return getattr(dataset, "_has_m1", False)

        minimizer = MutationMinimizer(needs_m1, max_iterations=50)

        original_apply = minimizer._apply_mutations

        def patched_apply(ds, muts):
            result = original_apply(ds, muts)
            result._has_m1 = any(m.mutation_id == "m1" for m in muts)
            return result

        minimizer._apply_mutations = patched_apply

        result = minimizer.minimize(mock_dataset, mutations, strategy="linear")

        # Should have found that only m1 is needed
        assert result.minimized_mutation_count == 1
        assert result.minimal_mutations[0].mutation_id == "m1"

    def test_linear_minimization_all_required(self, mock_dataset):
        """Test linear minimization when all mutations required."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(3)]

        # Crash tester: needs ALL mutations
        def needs_all(dataset):
            return getattr(dataset, "_mutation_count", 0) == 3

        minimizer = MutationMinimizer(needs_all, max_iterations=50)

        original_apply = minimizer._apply_mutations

        def patched_apply(ds, muts):
            result = original_apply(ds, muts)
            result._mutation_count = len(muts)
            return result

        minimizer._apply_mutations = patched_apply

        result = minimizer.minimize(mock_dataset, mutations, strategy="linear")

        # Should keep all mutations
        assert result.minimized_mutation_count == 3


class TestBinaryMinimization:
    """Tests for binary minimization strategy."""

    def test_binary_minimization_first_half_crashes(self, mock_dataset):
        """Test binary minimization when crash is in first half."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(4)]

        # Crash if any mutation from first half (m0, m1) is present
        def crash_first_half(dataset):
            return getattr(dataset, "_has_first_half", False)

        minimizer = MutationMinimizer(crash_first_half, max_iterations=50)

        original_apply = minimizer._apply_mutations

        def patched_apply(ds, muts):
            result = original_apply(ds, muts)
            result._has_first_half = any(m.mutation_id in ("m0", "m1") for m in muts)
            return result

        minimizer._apply_mutations = patched_apply

        result = minimizer.minimize(mock_dataset, mutations, strategy="binary")

        # Should narrow down to first half
        assert result.minimized_mutation_count <= 2
        assert result.still_crashes is True

    def test_binary_minimization_second_half_crashes(self, mock_dataset):
        """Test binary minimization when crash is in second half."""
        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(4)]

        # Crash if any mutation from second half (m2, m3) is present
        def crash_second_half(dataset):
            return getattr(dataset, "_has_second_half", False)

        minimizer = MutationMinimizer(crash_second_half, max_iterations=50)

        original_apply = minimizer._apply_mutations

        def patched_apply(ds, muts):
            result = original_apply(ds, muts)
            result._has_second_half = any(m.mutation_id in ("m2", "m3") for m in muts)
            return result

        minimizer._apply_mutations = patched_apply

        result = minimizer.minimize(mock_dataset, mutations, strategy="binary")

        # Should narrow down to second half
        assert result.minimized_mutation_count <= 2
        assert result.still_crashes is True


# =============================================================================
# Phase 3: Mutation Application Tests
# =============================================================================


class TestApplyMutations:
    """Tests for mutation application logic."""

    def test_apply_mutations_uses_dataset_copy(self, mock_dataset):
        """Test that _apply_mutations uses dataset.copy() when available."""
        minimizer = MutationMinimizer(lambda ds: False)
        mutations = [MockMutationRecord(mutation_id="m1", target_tag=None)]

        result = minimizer._apply_mutations(mock_dataset, mutations)

        mock_dataset.copy.assert_called_once()

    def test_apply_mutations_fallback_deepcopy(self):
        """Test fallback to deepcopy when copy() not available."""
        dataset = MagicMock()
        del dataset.copy  # Remove copy method

        minimizer = MutationMinimizer(lambda ds: False)
        mutations = [MockMutationRecord(mutation_id="m1", target_tag=None)]

        with patch("copy.deepcopy") as mock_deepcopy:
            mock_deepcopy.return_value = MagicMock()
            minimizer._apply_mutations(dataset, mutations)
            mock_deepcopy.assert_called_once()

    def test_apply_mutations_handles_exceptions(self, mock_dataset):
        """Test that exceptions during mutation application are logged and skipped."""
        minimizer = MutationMinimizer(lambda ds: False)

        # Mutation with invalid tag that will fail parsing
        mutations = [MockMutationRecord(mutation_id="m1", target_tag="invalid")]

        # Should not raise, just log and continue
        result = minimizer._apply_mutations(mock_dataset, mutations)
        assert result is not None

    def test_apply_single_mutation_delete(self):
        """Test applying delete mutation."""

        dataset = MagicMock()
        dataset.__contains__ = lambda self, tag: True
        dataset.__delitem__ = MagicMock()

        mutation = MockMutationRecord(
            mutation_id="m1",
            target_tag="(0010,0010)",
            mutation_type="delete",
        )

        minimizer = MutationMinimizer(lambda ds: False)
        minimizer._apply_single_mutation(dataset, mutation)

        # Should have tried to delete the tag
        dataset.__delitem__.assert_called()

    def test_apply_single_mutation_modify(self):
        """Test applying modify mutation."""
        dataset = MagicMock()
        dataset.__contains__ = lambda self, tag: True

        # Create mock element that can be modified
        mock_element = MagicMock()
        dataset.__getitem__ = lambda self, tag: mock_element

        mutation = MockMutationRecord(
            mutation_id="m1",
            target_tag="(0010,0010)",
            mutation_type="modify",
            mutated_value="NEW_VALUE",
        )

        minimizer = MutationMinimizer(lambda ds: False)
        minimizer._apply_single_mutation(dataset, mutation)

        # Should have set the value
        assert mock_element.value == "NEW_VALUE"

    def test_apply_single_mutation_no_target_tag(self):
        """Test that mutation without target_tag is skipped."""
        dataset = MagicMock()
        mutation = MockMutationRecord(
            mutation_id="m1",
            target_tag=None,  # No target
            mutation_type="modify",
        )

        minimizer = MutationMinimizer(lambda ds: False)
        # Should not raise, just return early
        minimizer._apply_single_mutation(dataset, mutation)

    def test_apply_single_mutation_corrupt(self):
        """Test applying corrupt mutation."""
        dataset = MagicMock()
        dataset.__contains__ = lambda self, tag: True

        mock_element = MagicMock()
        dataset.__getitem__ = lambda self, tag: mock_element

        mutation = MockMutationRecord(
            mutation_id="m1",
            target_tag="(0010,0010)",
            mutation_type="corrupt",
            mutated_value=b"\x00\x00",
        )

        minimizer = MutationMinimizer(lambda ds: False)
        minimizer._apply_single_mutation(dataset, mutation)

        # Should have set the corrupted value
        assert mock_element.value == b"\x00\x00"


# =============================================================================
# Phase 4: Orchestrator Tests
# =============================================================================


class TestCrashMinimizationOrchestrator:
    """Tests for CrashMinimizationOrchestrator class."""

    def test_orchestrator_initialization(self, tmp_path):
        """Test orchestrator initialization."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=10)

        assert orchestrator.viewer_path == viewer_path
        assert orchestrator.timeout == 10

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_orchestrator_minimize_crash(
        self, mock_write, mock_read, mock_popen, tmp_path
    ):
        """Test minimize_crash full workflow."""
        # Setup mocks
        mock_dataset = MagicMock()
        mock_dataset.copy.return_value = MagicMock()
        mock_read.return_value = mock_dataset

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 1  # Crash
        mock_popen.return_value = mock_proc

        # Create temp source file
        source_file = tmp_path / "test.dcm"
        source_file.touch()

        viewer_path = tmp_path / "viewer.exe"
        viewer_path.touch()

        mutations = [MockMutationRecord(mutation_id=f"m{i}") for i in range(3)]

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=5)
        result = orchestrator.minimize_crash(
            crash_id="crash_001",
            source_file=source_file,
            mutations=mutations,
            strategy="delta_debug",
        )

        assert isinstance(result, MinimizationResult)
        mock_read.assert_called_once()

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_orchestrator_crash_tester_timeout(
        self, mock_write, mock_read, mock_popen, tmp_path
    ):
        """Test that timeout is treated as crash."""
        import subprocess

        mock_dataset = MagicMock()
        mock_dataset.copy.return_value = MagicMock()
        mock_read.return_value = mock_dataset

        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mock_proc.kill = MagicMock()
        mock_popen.return_value = mock_proc

        source_file = tmp_path / "test.dcm"
        source_file.touch()
        viewer_path = tmp_path / "viewer.exe"

        mutations = [MockMutationRecord(mutation_id="m1")]

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=1)
        result = orchestrator.minimize_crash(
            crash_id="crash_001",
            source_file=source_file,
            mutations=mutations,
        )

        # Timeout should be treated as crash
        assert result.still_crashes is True

    @patch("subprocess.Popen")
    @patch("pydicom.dcmread")
    @patch("pydicom.dcmwrite")
    def test_orchestrator_crash_tester_error_handling(
        self, mock_write, mock_read, mock_popen, tmp_path
    ):
        """Test error handling in crash tester."""
        mock_dataset = MagicMock()
        mock_dataset.copy.return_value = MagicMock()
        mock_read.return_value = mock_dataset

        # dcmwrite raises error
        mock_write.side_effect = Exception("Write error")

        source_file = tmp_path / "test.dcm"
        source_file.touch()
        viewer_path = tmp_path / "viewer.exe"

        mutations = [MockMutationRecord(mutation_id="m1")]

        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=1)
        result = orchestrator.minimize_crash(
            crash_id="crash_001",
            source_file=source_file,
            mutations=mutations,
        )

        # Error should be handled gracefully
        assert isinstance(result, MinimizationResult)

    def test_batch_minimize_ordering(self, tmp_path):
        """Test that batch_minimize prioritizes by mutation count."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=1)

        # Mock minimize_crash to track call order
        call_order = []

        def mock_minimize(crash_id, source_file, mutations, strategy):
            call_order.append((crash_id, len(mutations)))
            return MinimizationResult(
                original_mutation_count=len(mutations),
                minimized_mutation_count=1,
                minimal_mutations=mutations[:1],
                test_iterations=1,
                still_crashes=True,
                minimization_ratio=0.9,
            )

        orchestrator.minimize_crash = mock_minimize

        # Create crashes with different mutation counts
        source = tmp_path / "test.dcm"
        source.touch()

        crashes = [
            ("c1", source, [MockMutationRecord(mutation_id=f"m{i}") for i in range(2)]),
            ("c2", source, [MockMutationRecord(mutation_id=f"m{i}") for i in range(5)]),
            ("c3", source, [MockMutationRecord(mutation_id=f"m{i}") for i in range(3)]),
        ]

        results = orchestrator.batch_minimize(crashes)

        # Should be ordered by mutation count (descending)
        assert call_order[0][0] == "c2"  # 5 mutations first
        assert call_order[1][0] == "c3"  # 3 mutations second
        assert call_order[2][0] == "c1"  # 2 mutations last

    def test_batch_minimize_max_crashes(self, tmp_path):
        """Test that batch_minimize respects max_crashes limit."""
        viewer_path = tmp_path / "viewer.exe"
        orchestrator = CrashMinimizationOrchestrator(viewer_path, timeout=1)

        call_count = [0]

        def mock_minimize(crash_id, source_file, mutations, strategy):
            call_count[0] += 1
            return MinimizationResult(
                original_mutation_count=len(mutations),
                minimized_mutation_count=1,
                minimal_mutations=mutations[:1],
                test_iterations=1,
                still_crashes=True,
                minimization_ratio=0.9,
            )

        orchestrator.minimize_crash = mock_minimize

        source = tmp_path / "test.dcm"
        source.touch()

        crashes = [
            ("c1", source, [MockMutationRecord(mutation_id="m1")]),
            ("c2", source, [MockMutationRecord(mutation_id="m1")]),
            ("c3", source, [MockMutationRecord(mutation_id="m1")]),
            ("c4", source, [MockMutationRecord(mutation_id="m1")]),
        ]

        results = orchestrator.batch_minimize(crashes, max_crashes=2)

        assert call_count[0] == 2
        assert len(results) == 2

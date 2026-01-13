"""Tests for Study Minimizer Module.

Tests cover:
- MinimizedStudy dataclass
- MinimizationConfig dataclass
- StudyMinimizer class (delta debugging, reduction, trigger finding)
- Factory functions
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.study_minimizer import (
    MinimizationConfig,
    MinimizedStudy,
    StudyMinimizer,
    create_crash_test_from_runner,
)


class TestMinimizedStudy:
    """Test MinimizedStudy dataclass."""

    def test_creation_basic(self, tmp_path):
        """Test creating MinimizedStudy with basic fields."""
        original = tmp_path / "original"
        minimized = tmp_path / "minimized"

        result = MinimizedStudy(
            original_study=original,
            minimized_study=minimized,
            original_slice_count=100,
            minimal_slice_count=5,
            trigger_slice=None,
            reduction_ratio=0.05,
            minimization_time_seconds=10.5,
            iterations=25,
            crash_reproducible=True,
        )

        assert result.original_slice_count == 100
        assert result.minimal_slice_count == 5
        assert result.reduction_ratio == 0.05
        assert result.iterations == 25
        assert result.crash_reproducible is True
        assert result.notes == []

    def test_creation_with_trigger_slice(self, tmp_path):
        """Test creating MinimizedStudy with trigger slice."""
        trigger = tmp_path / "trigger.dcm"
        trigger.touch()

        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=1,
            trigger_slice=trigger,
            reduction_ratio=0.01,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
        )

        assert result.trigger_slice == trigger

    def test_is_single_slice_bug_true(self, tmp_path):
        """Test is_single_slice_bug property when True."""
        trigger = tmp_path / "trigger.dcm"
        trigger.touch()

        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=1,
            trigger_slice=trigger,
            reduction_ratio=0.01,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
        )

        assert result.is_single_slice_bug is True

    def test_is_single_slice_bug_false(self, tmp_path):
        """Test is_single_slice_bug property when False."""
        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=5,
            trigger_slice=None,
            reduction_ratio=0.05,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
        )

        assert result.is_single_slice_bug is False

    def test_is_multi_slice_bug_true(self, tmp_path):
        """Test is_multi_slice_bug property when True."""
        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=3,
            trigger_slice=None,
            reduction_ratio=0.03,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
        )

        assert result.is_multi_slice_bug is True

    def test_is_multi_slice_bug_false_single(self, tmp_path):
        """Test is_multi_slice_bug property when single slice."""
        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=1,
            trigger_slice=None,
            reduction_ratio=0.01,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
        )

        assert result.is_multi_slice_bug is False

    def test_notes_field(self, tmp_path):
        """Test notes field."""
        result = MinimizedStudy(
            original_study=tmp_path,
            minimized_study=tmp_path,
            original_slice_count=100,
            minimal_slice_count=5,
            trigger_slice=None,
            reduction_ratio=0.05,
            minimization_time_seconds=5.0,
            iterations=10,
            crash_reproducible=True,
            notes=["First note", "Second note"],
        )

        assert len(result.notes) == 2
        assert "First note" in result.notes


class TestMinimizationConfig:
    """Test MinimizationConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MinimizationConfig()

        assert config.max_iterations == 100
        assert config.timeout_per_test == 30.0
        assert config.preserve_series_structure is True
        assert config.verify_final_result is True
        assert config.cleanup_temp_dirs is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = MinimizationConfig(
            max_iterations=50,
            timeout_per_test=60.0,
            preserve_series_structure=False,
            verify_final_result=False,
            cleanup_temp_dirs=False,
        )

        assert config.max_iterations == 50
        assert config.timeout_per_test == 60.0
        assert config.preserve_series_structure is False
        assert config.verify_final_result is False
        assert config.cleanup_temp_dirs is False


class TestStudyMinimizerInit:
    """Test StudyMinimizer initialization."""

    def test_init_default_config(self):
        """Test initialization with default config."""

        def crash_func(x):
            return True

        minimizer = StudyMinimizer(crash_func)

        assert minimizer.crash_test_func is crash_func
        assert minimizer.config is not None
        assert minimizer.config.max_iterations == 100

    def test_init_custom_config(self):
        """Test initialization with custom config."""

        def crash_func(x):
            return True

        config = MinimizationConfig(max_iterations=50)
        minimizer = StudyMinimizer(crash_func, config)

        assert minimizer.config.max_iterations == 50


class TestStudyMinimizerGetSlices:
    """Test _get_slices method."""

    def test_get_slices_dcm_extension(self, tmp_path):
        """Test getting slices with .dcm extension."""
        # Create test files
        (tmp_path / "slice_001.dcm").touch()
        (tmp_path / "slice_002.dcm").touch()
        (tmp_path / "slice_003.dcm").touch()

        minimizer = StudyMinimizer(lambda x: True)
        slices = minimizer._get_slices(tmp_path)

        assert len(slices) == 3
        assert slices[0].name == "slice_001.dcm"
        assert slices[2].name == "slice_003.dcm"

    def test_get_slices_no_extension(self, tmp_path):
        """Test getting slices without extension (common in DICOM)."""
        # Create test files without extension
        (tmp_path / "IM0001").touch()
        (tmp_path / "IM0002").touch()

        minimizer = StudyMinimizer(lambda x: True)
        slices = minimizer._get_slices(tmp_path)

        assert len(slices) == 2

    def test_get_slices_mixed_extensions(self, tmp_path):
        """Test getting slices with mixed extensions."""
        (tmp_path / "slice_001.dcm").touch()
        (tmp_path / "slice_002.dicom").touch()
        (tmp_path / "IM0003").touch()
        (tmp_path / "readme.txt").touch()  # Should be ignored

        minimizer = StudyMinimizer(lambda x: True)
        slices = minimizer._get_slices(tmp_path)

        # .txt should be ignored
        assert len(slices) == 3

    def test_get_slices_sorted(self, tmp_path):
        """Test slices are sorted by name."""
        (tmp_path / "slice_003.dcm").touch()
        (tmp_path / "slice_001.dcm").touch()
        (tmp_path / "slice_002.dcm").touch()

        minimizer = StudyMinimizer(lambda x: True)
        slices = minimizer._get_slices(tmp_path)

        assert slices[0].name == "slice_001.dcm"
        assert slices[1].name == "slice_002.dcm"
        assert slices[2].name == "slice_003.dcm"

    def test_get_slices_ignores_directories(self, tmp_path):
        """Test subdirectories are ignored."""
        (tmp_path / "slice.dcm").touch()
        (tmp_path / "subdir").mkdir()

        minimizer = StudyMinimizer(lambda x: True)
        slices = minimizer._get_slices(tmp_path)

        assert len(slices) == 1


class TestStudyMinimizerMinimize:
    """Test minimize method."""

    def test_minimize_empty_study(self, tmp_path):
        """Test minimizing empty study raises error."""
        minimizer = StudyMinimizer(lambda x: True)
        output_dir = tmp_path / "output"

        with pytest.raises(ValueError, match="No DICOM files found"):
            minimizer.minimize(tmp_path, output_dir)

    def test_minimize_not_reproducible(self, tmp_path):
        """Test when crash is not reproducible."""
        # Create test slices
        (tmp_path / "slice_001.dcm").touch()
        (tmp_path / "slice_002.dcm").touch()

        # Crash function always returns False
        minimizer = StudyMinimizer(lambda x: False)
        output_dir = tmp_path / "output"

        result = minimizer.minimize(tmp_path, output_dir)

        assert result.crash_reproducible is False
        assert "not reproducible" in result.notes[0].lower()

    def test_minimize_single_slice_trigger(self, tmp_path):
        """Test minimizing to single trigger slice."""
        # Create test slices
        trigger = tmp_path / "slice_002.dcm"
        (tmp_path / "slice_001.dcm").write_text("normal")
        trigger.write_text("crash trigger")
        (tmp_path / "slice_003.dcm").write_text("normal")

        # Crash if trigger file is present
        def crash_test(study_dir: Path) -> bool:
            for f in study_dir.iterdir():
                if f.read_text() == "crash trigger":
                    return True
            return False

        minimizer = StudyMinimizer(crash_test)
        output_dir = tmp_path / "output"

        result = minimizer.minimize(tmp_path, output_dir)

        assert result.crash_reproducible is True
        assert result.minimal_slice_count == 1
        # The trigger slice should be found
        assert output_dir.exists()

    def test_minimize_creates_output_dir(self, tmp_path):
        """Test that output directory is created."""
        (tmp_path / "slice.dcm").touch()

        minimizer = StudyMinimizer(lambda x: True)
        output_dir = tmp_path / "nested" / "output"

        minimizer.minimize(tmp_path, output_dir)

        assert output_dir.exists()

    def test_minimize_copies_slices(self, tmp_path):
        """Test that slices are copied to output."""
        slice_path = tmp_path / "slice_001.dcm"
        slice_path.write_text("test content")

        minimizer = StudyMinimizer(lambda x: True)
        output_dir = tmp_path / "output"

        minimizer.minimize(tmp_path, output_dir)

        output_slice = output_dir / "slice_001.dcm"
        assert output_slice.exists()
        assert output_slice.read_text() == "test content"


class TestBinaryReduce:
    """Test _binary_reduce method."""

    def test_binary_reduce_single_slice(self, tmp_path):
        """Test binary reduce with single slice."""
        slice_path = tmp_path / "slice.dcm"
        slice_path.touch()

        minimizer = StudyMinimizer(lambda x: True)
        result = minimizer._binary_reduce([slice_path])

        assert len(result) == 1
        assert result[0] == slice_path

    def test_binary_reduce_finds_first_half(self, tmp_path):
        """Test binary reduce when crash is in first half."""
        slices = []
        for i in range(4):
            p = tmp_path / f"slice_{i:03d}.dcm"
            p.write_text(f"content_{i}")
            slices.append(p)

        # Only crash if first two slices are present
        def crash_test(study_dir: Path) -> bool:
            files = list(study_dir.iterdir())
            return any("slice_000" in f.name or "slice_001" in f.name for f in files)

        minimizer = StudyMinimizer(crash_test)
        result = minimizer._binary_reduce(slices)

        # Should reduce to slices in first half
        assert len(result) < 4


class TestIncrementalReduce:
    """Test _incremental_reduce method."""

    def test_incremental_reduce_removes_unnecessary(self, tmp_path):
        """Test incremental reduce removes unnecessary slices."""
        # Create slices where only first is needed
        slices = []
        for i in range(3):
            p = tmp_path / f"slice_{i:03d}.dcm"
            p.write_text("trigger" if i == 0 else "normal")
            slices.append(p)

        # Crash only if trigger file is present
        def crash_test(study_dir: Path) -> bool:
            for f in study_dir.iterdir():
                if f.read_text() == "trigger":
                    return True
            return False

        minimizer = StudyMinimizer(crash_test)
        result = minimizer._incremental_reduce(slices)

        assert len(result) == 1


class TestFindTriggerSlice:
    """Test _find_trigger_slice method."""

    def test_find_trigger_slice_already_single(self, tmp_path):
        """Test when already down to one slice."""
        slice_path = tmp_path / "slice.dcm"
        slice_path.touch()

        minimizer = StudyMinimizer(lambda x: True)
        result = minimizer._find_trigger_slice([slice_path])

        assert result == slice_path

    def test_find_trigger_slice_found(self, tmp_path):
        """Test finding trigger slice among multiple."""
        slices = []
        for i in range(3):
            p = tmp_path / f"slice_{i:03d}.dcm"
            p.write_text("trigger" if i == 1 else "normal")
            slices.append(p)

        # Crash only if trigger file is present
        def crash_test(study_dir: Path) -> bool:
            for f in study_dir.iterdir():
                if f.read_text() == "trigger":
                    return True
            return False

        minimizer = StudyMinimizer(crash_test)
        result = minimizer._find_trigger_slice(slices)

        assert result is not None
        assert result.name == "slice_001.dcm"

    def test_find_trigger_slice_not_found(self, tmp_path):
        """Test when no single trigger slice exists."""
        slices = []
        for i in range(3):
            p = tmp_path / f"slice_{i:03d}.dcm"
            p.touch()
            slices.append(p)

        # Only crash if all slices are present (multi-slice bug)
        def crash_test(study_dir: Path) -> bool:
            return len(list(study_dir.iterdir())) >= 2

        minimizer = StudyMinimizer(crash_test)
        result = minimizer._find_trigger_slice(slices)

        # No single slice can trigger
        assert result is None


class TestTestCrash:
    """Test _test_crash method."""

    def test_test_crash_increments_counter(self, tmp_path):
        """Test iteration counter is incremented."""
        minimizer = StudyMinimizer(lambda x: True)
        assert minimizer._iteration_count == 0

        minimizer._test_crash(tmp_path)
        assert minimizer._iteration_count == 1

        minimizer._test_crash(tmp_path)
        assert minimizer._iteration_count == 2

    def test_test_crash_max_iterations(self, tmp_path):
        """Test max iterations limit."""
        config = MinimizationConfig(max_iterations=3)
        minimizer = StudyMinimizer(lambda x: True, config)

        # Set counter near limit
        minimizer._iteration_count = 3

        result = minimizer._test_crash(tmp_path)

        # Should return False after max iterations
        assert result is False

    def test_test_crash_handles_exception(self, tmp_path):
        """Test exception handling in crash test."""

        def failing_test(x: Path) -> bool:
            raise RuntimeError("Test failure")

        minimizer = StudyMinimizer(failing_test)
        result = minimizer._test_crash(tmp_path)

        assert result is False


class TestCleanup:
    """Test cleanup functionality."""

    def test_cleanup_temp_dirs(self, tmp_path):
        """Test temporary directory cleanup."""
        minimizer = StudyMinimizer(lambda x: True)

        # Create some temp dirs
        temp1 = tmp_path / "temp1"
        temp2 = tmp_path / "temp2"
        temp1.mkdir()
        temp2.mkdir()
        minimizer._temp_dirs = [temp1, temp2]

        minimizer._cleanup_temp_dirs()

        assert len(minimizer._temp_dirs) == 0

    def test_cleanup_temp_dirs_handles_missing(self, tmp_path):
        """Test cleanup handles already-deleted dirs."""
        minimizer = StudyMinimizer(lambda x: True)

        # Add non-existent dir
        minimizer._temp_dirs = [tmp_path / "nonexistent"]

        # Should not raise
        minimizer._cleanup_temp_dirs()

        # Verify temp_dirs list was cleared
        assert len(minimizer._temp_dirs) == 0


class TestCreateCrashTestFromRunner:
    """Test create_crash_test_from_runner function."""

    def test_create_crash_test_basic(self, tmp_path):
        """Test creating crash test from mock runner."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus

        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.result = ExecutionStatus.CRASH
        mock_runner.execute_test.return_value = mock_result

        # Create study with slice
        (tmp_path / "slice.dcm").touch()

        crash_test = create_crash_test_from_runner(mock_runner)
        result = crash_test(tmp_path)

        assert result is True
        mock_runner.execute_test.assert_called_once()

    def test_create_crash_test_no_crash(self, tmp_path):
        """Test crash test returns False for non-crash."""
        from dicom_fuzzer.core.target_runner import ExecutionStatus

        mock_runner = MagicMock()
        mock_result = MagicMock()
        mock_result.result = ExecutionStatus.SUCCESS
        mock_runner.execute_test.return_value = mock_result

        # Create study with slice
        (tmp_path / "slice.dcm").touch()

        crash_test = create_crash_test_from_runner(mock_runner)
        result = crash_test(tmp_path)

        assert result is False

    def test_create_crash_test_empty_dir(self, tmp_path):
        """Test crash test with empty directory."""
        mock_runner = MagicMock()
        crash_test = create_crash_test_from_runner(mock_runner)

        result = crash_test(tmp_path)

        assert result is False
        mock_runner.execute_test.assert_not_called()


class TestIntegration:
    """Integration tests for study minimization."""

    def test_full_minimization_workflow(self, tmp_path):
        """Test complete minimization workflow."""
        # Create study with 10 slices, one triggers crash
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        for i in range(10):
            slice_path = study_dir / f"slice_{i:03d}.dcm"
            slice_path.write_text("trigger" if i == 5 else "normal")

        # Crash if trigger slice is present
        def crash_test(study_dir: Path) -> bool:
            for f in study_dir.iterdir():
                if f.read_text() == "trigger":
                    return True
            return False

        config = MinimizationConfig(max_iterations=50)
        minimizer = StudyMinimizer(crash_test, config)
        output_dir = tmp_path / "output"

        result = minimizer.minimize(study_dir, output_dir)

        assert result.crash_reproducible is True
        assert result.original_slice_count == 10
        assert result.minimal_slice_count == 1
        assert result.trigger_slice is not None
        assert result.is_single_slice_bug is True
        assert result.reduction_ratio == 0.1  # 1/10

    def test_multi_slice_bug_minimization(self, tmp_path):
        """Test minimization of multi-slice bug."""
        # Create study where crash requires at least 2 specific slices
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        for i in range(5):
            slice_path = study_dir / f"slice_{i:03d}.dcm"
            slice_path.write_text("needed" if i in [1, 3] else "normal")

        # Crash only if both needed slices are present
        def crash_test(study_dir: Path) -> bool:
            needed_count = 0
            for f in study_dir.iterdir():
                if f.read_text() == "needed":
                    needed_count += 1
            return needed_count >= 2

        config = MinimizationConfig(max_iterations=50)
        minimizer = StudyMinimizer(crash_test, config)
        output_dir = tmp_path / "output"

        result = minimizer.minimize(study_dir, output_dir)

        assert result.crash_reproducible is True
        # Should reduce but not to single slice
        assert result.minimal_slice_count >= 2
        assert result.is_multi_slice_bug is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

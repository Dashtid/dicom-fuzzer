"""Tests for Atheris coverage-guided fuzzing integration.

Tests for:
- AtherisConfig dataclass
- AtherisStats dataclass
- AtherisCustomMutator
- AtherisDICOMFuzzer (mocked Atheris)
- Utility functions
"""

from __future__ import annotations

import io
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pydicom
import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.atheris_integration import (
    HAS_ATHERIS,
    AtherisConfig,
    AtherisCustomMutator,
    AtherisStats,
)
from dicom_fuzzer.core.types import MutationSeverity


class TestAtherisConfig:
    """Tests for AtherisConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = AtherisConfig()

        assert config.target_function is None
        assert config.target_modules == []
        assert config.max_time_seconds == 3600
        assert config.max_iterations == 0
        assert config.timeout_per_run == 5.0
        assert config.corpus_dir is None
        assert config.seed_dir is None
        assert config.max_input_size == 10 * 1024 * 1024
        assert config.deduplicate_crashes is True
        assert config.verbose is False
        assert config.dicom_aware_mutations is True
        assert config.use_dictionary_fuzzer is True
        assert config.mutation_severity == MutationSeverity.MODERATE

    def test_custom_values(self) -> None:
        """Test custom configuration values."""

        def my_target(data: bytes) -> None:
            pass

        config = AtherisConfig(
            target_function=my_target,
            target_modules=["my_module"],
            max_time_seconds=7200,
            max_iterations=1000,
            timeout_per_run=10.0,
            corpus_dir=Path("my_corpus"),
            crash_dir=Path("my_crashes"),
            verbose=True,
            dicom_aware_mutations=False,
            mutation_severity=MutationSeverity.AGGRESSIVE,
        )

        assert config.target_function == my_target
        assert config.target_modules == ["my_module"]
        assert config.max_time_seconds == 7200
        assert config.max_iterations == 1000
        assert config.timeout_per_run == 10.0
        assert config.corpus_dir == Path("my_corpus")
        assert config.crash_dir == Path("my_crashes")
        assert config.verbose is True
        assert config.dicom_aware_mutations is False
        assert config.mutation_severity == MutationSeverity.AGGRESSIVE

    def test_default_paths(self) -> None:
        """Test default path factories."""
        config = AtherisConfig()

        assert config.crash_dir == Path("atheris_crashes")
        assert config.output_dir == Path("atheris_output")


class TestAtherisStats:
    """Tests for AtherisStats dataclass."""

    def test_default_values(self) -> None:
        """Test default statistics values."""
        stats = AtherisStats()

        assert stats.total_executions == 0
        assert stats.total_crashes == 0
        assert stats.unique_crashes == 0
        assert stats.coverage_increases == 0
        assert stats.corpus_size == 0
        assert stats.exec_per_sec == 0.0
        assert stats.start_time > 0
        assert stats.last_coverage_time > 0

    def test_time_tracking(self) -> None:
        """Test time tracking fields are set properly."""
        before = time.time()
        stats = AtherisStats()
        after = time.time()

        assert before <= stats.start_time <= after
        assert before <= stats.last_coverage_time <= after

    def test_update_stats(self) -> None:
        """Test updating statistics."""
        stats = AtherisStats()

        stats.total_executions = 1000
        stats.total_crashes = 10
        stats.unique_crashes = 5
        stats.exec_per_sec = 100.0

        assert stats.total_executions == 1000
        assert stats.total_crashes == 10
        assert stats.unique_crashes == 5
        assert stats.exec_per_sec == 100.0


class TestAtherisCustomMutator:
    """Tests for AtherisCustomMutator class."""

    @pytest.fixture
    def mutator(self) -> AtherisCustomMutator:
        """Create a custom mutator instance."""
        return AtherisCustomMutator()

    @pytest.fixture
    def sample_dicom_bytes(self) -> bytes:
        """Create sample DICOM bytes for testing."""
        ds = Dataset()
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = pydicom.uid.generate_uid()

        ds.file_meta = pydicom.filereader.FileMetaDataset()
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian

        buffer = io.BytesIO()
        pydicom.dcmwrite(buffer, ds, write_like_original=False)
        return buffer.getvalue()

    def test_init_default(self, mutator: AtherisCustomMutator) -> None:
        """Test default initialization."""
        assert mutator.severity == MutationSeverity.MODERATE
        assert mutator.dictionary_fuzzer is not None
        assert mutator._mutation_count == 0

    def test_init_custom_severity(self) -> None:
        """Test initialization with custom severity."""
        mutator = AtherisCustomMutator(severity=MutationSeverity.EXTREME)
        assert mutator.severity == MutationSeverity.EXTREME

    def test_mutate_empty_data(self, mutator: AtherisCustomMutator) -> None:
        """Test mutation of empty data."""
        result = mutator.mutate(b"", max_size=1000, seed=42)

        # Should return minimal DICOM-like data
        assert len(result) > 0
        assert mutator._mutation_count == 1

    def test_mutate_small_data(self, mutator: AtherisCustomMutator) -> None:
        """Test mutation of data smaller than DICOM minimum."""
        data = b"small"
        result = mutator.mutate(data, max_size=1000, seed=42)

        # Should apply basic mutation
        assert len(result) > 0
        assert mutator._mutation_count == 1

    def test_mutate_dicom_data(
        self, mutator: AtherisCustomMutator, sample_dicom_bytes: bytes
    ) -> None:
        """Test mutation of valid DICOM data."""
        result = mutator.mutate(sample_dicom_bytes, max_size=100000, seed=42)

        assert len(result) > 0
        assert mutator._mutation_count == 1

    def test_mutate_respects_max_size(
        self, mutator: AtherisCustomMutator, sample_dicom_bytes: bytes
    ) -> None:
        """Test that mutation respects max_size limit."""
        max_size = 500
        result = mutator.mutate(sample_dicom_bytes, max_size=max_size, seed=42)

        assert len(result) <= max_size

    def test_mutate_increments_count(
        self, mutator: AtherisCustomMutator, sample_dicom_bytes: bytes
    ) -> None:
        """Test that mutation count is incremented."""
        for i in range(5):
            mutator.mutate(sample_dicom_bytes, max_size=100000, seed=i)

        assert mutator._mutation_count == 5

    def test_basic_mutate_bit_flip(self, mutator: AtherisCustomMutator) -> None:
        """Test basic mutation - bit flip."""
        data = b"ABCDEFGH"

        with patch("random.randint") as mock_randint:
            # Force bit flip mutation (type 0)
            mock_randint.side_effect = [0, 2, 3]  # type=0, pos=2, bit=3
            result = mutator._basic_mutate(data, max_size=100, seed=42)

        assert len(result) == len(data)
        # Byte at position 2 should be flipped
        assert result != data

    def test_basic_mutate_byte_replace(self, mutator: AtherisCustomMutator) -> None:
        """Test basic mutation - byte replacement."""
        data = b"ABCDEFGH"

        with patch("random.randint") as mock_randint:
            # Force byte replace mutation (type 1)
            mock_randint.side_effect = [1, 2, 42]  # type=1, pos=2, value=42
            result = mutator._basic_mutate(data, max_size=100, seed=42)

        assert len(result) == len(data)
        assert result[2] == 42

    def test_basic_mutate_insert(self, mutator: AtherisCustomMutator) -> None:
        """Test basic mutation - byte insertion."""
        data = b"ABCDEFGH"

        with patch("random.randint") as mock_randint:
            # Force insert mutation (type 2)
            mock_randint.side_effect = [2, 2, 42]  # type=2, pos=2, value=42
            result = mutator._basic_mutate(data, max_size=100, seed=42)

        assert len(result) == len(data) + 1
        assert result[2] == 42

    def test_basic_mutate_delete(self, mutator: AtherisCustomMutator) -> None:
        """Test basic mutation - byte deletion."""
        data = b"ABCDEFGH"

        with patch("random.randint") as mock_randint:
            # Force delete mutation (type 3)
            mock_randint.side_effect = [3, 2]  # type=3, pos=2
            result = mutator._basic_mutate(data, max_size=100, seed=42)

        assert len(result) == len(data) - 1

    def test_basic_mutate_swap(self, mutator: AtherisCustomMutator) -> None:
        """Test basic mutation - adjacent swap."""
        data = b"ABCDEFGH"

        with patch("random.randint") as mock_randint:
            # Force swap mutation (type 4)
            mock_randint.side_effect = [4, 2]  # type=4, pos=2
            result = mutator._basic_mutate(data, max_size=100, seed=42)

        assert len(result) == len(data)
        # C and D should be swapped
        assert result[2] == ord("D")
        assert result[3] == ord("C")

    def test_mutation_determinism(
        self, mutator: AtherisCustomMutator, sample_dicom_bytes: bytes
    ) -> None:
        """Test that same seed produces same result."""
        result1 = mutator._basic_mutate(sample_dicom_bytes, max_size=100000, seed=12345)
        result2 = mutator._basic_mutate(sample_dicom_bytes, max_size=100000, seed=12345)

        assert result1 == result2


class TestAtherisDICOMFuzzerWithoutAtheris:
    """Tests for AtherisDICOMFuzzer when Atheris is not available."""

    def test_import_error_when_no_atheris(self) -> None:
        """Test ImportError is raised when Atheris unavailable."""
        with patch("dicom_fuzzer.core.atheris_integration.HAS_ATHERIS", False):
            from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

            with pytest.raises(ImportError) as exc_info:
                AtherisDICOMFuzzer()

            assert "Atheris is not installed" in str(exc_info.value)


@pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
class TestAtherisDICOMFuzzerWithAtheris:
    """Tests for AtherisDICOMFuzzer when Atheris is available."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> dict[str, Path]:
        """Create temporary directories for testing."""
        corpus_dir = tmp_path / "corpus"
        crash_dir = tmp_path / "crashes"
        output_dir = tmp_path / "output"

        corpus_dir.mkdir()
        crash_dir.mkdir()
        output_dir.mkdir()

        return {
            "corpus": corpus_dir,
            "crash": crash_dir,
            "output": output_dir,
        }

    def test_init_creates_directories(self, temp_dirs: dict[str, Path]) -> None:
        """Test that initialization creates directories."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        config = AtherisConfig(
            corpus_dir=temp_dirs["corpus"],
            crash_dir=temp_dirs["crash"],
            output_dir=temp_dirs["output"],
        )

        fuzzer = AtherisDICOMFuzzer(config)

        assert fuzzer.config.crash_dir.exists()
        assert fuzzer.config.output_dir.exists()

    def test_create_minimal_dicom(self, temp_dirs: dict[str, Path]) -> None:
        """Test minimal DICOM creation."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        config = AtherisConfig(
            corpus_dir=temp_dirs["corpus"],
            crash_dir=temp_dirs["crash"],
        )

        fuzzer = AtherisDICOMFuzzer(config)
        minimal = fuzzer._create_minimal_dicom()

        # Should be valid DICOM
        ds = pydicom.dcmread(io.BytesIO(minimal), force=True)
        assert ds.PatientName == "Test"
        assert ds.PatientID == "123"


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_create_atheris_harness_no_atheris(self) -> None:
        """Test create_atheris_harness when Atheris unavailable."""
        with patch("dicom_fuzzer.core.atheris_integration.HAS_ATHERIS", False):
            from dicom_fuzzer.core.atheris_integration import create_atheris_harness

            def target(data: bytes) -> None:
                pass

            with pytest.raises(ImportError):
                create_atheris_harness(target)

    def test_fuzz_dicom_parser_no_atheris(self) -> None:
        """Test fuzz_dicom_parser when Atheris unavailable."""
        with patch("dicom_fuzzer.core.atheris_integration.HAS_ATHERIS", False):
            from dicom_fuzzer.core.atheris_integration import fuzz_dicom_parser

            # Should log error and return without exception
            fuzz_dicom_parser()


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_max_input_size_default(self) -> None:
        """Test default max input size."""
        config = AtherisConfig()
        assert config.max_input_size == 10 * 1024 * 1024  # 10MB

    def test_timeout_configuration(self) -> None:
        """Test timeout configuration."""
        config = AtherisConfig(timeout_per_run=30.0)
        assert config.timeout_per_run == 30.0

    def test_mutation_severity_options(self) -> None:
        """Test all mutation severity options."""
        for severity in MutationSeverity:
            config = AtherisConfig(mutation_severity=severity)
            assert config.mutation_severity == severity


class TestCrashDeduplication:
    """Tests for crash deduplication logic."""

    def test_crash_hash_set_initialization(self) -> None:
        """Test that crash hash set is initialized empty."""
        with patch("dicom_fuzzer.core.atheris_integration.HAS_ATHERIS", True):
            # Mock atheris module
            mock_atheris = MagicMock()
            with patch.dict("sys.modules", {"atheris": mock_atheris}):
                from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

                config = AtherisConfig()
                fuzzer = AtherisDICOMFuzzer(config)

                assert fuzzer._crash_hashes == set()


class TestAtherisArgvBuilding:
    """Tests for Atheris command-line argument building."""

    @pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
    def test_build_atheris_argv_basic(self, tmp_path: Path) -> None:
        """Test basic argv building."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = AtherisConfig(
            corpus_dir=corpus_dir,
            max_time_seconds=300,
            max_iterations=100,
            max_input_size=1000,
            timeout_per_run=2.0,
        )

        fuzzer = AtherisDICOMFuzzer(config)
        argv = fuzzer._build_atheris_argv(["test_program"])

        assert "test_program" in argv[0]
        assert f"-max_total_time={300}" in argv
        assert f"-runs={100}" in argv
        assert f"-max_len={1000}" in argv
        assert f"-timeout={2}" in argv

    @pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
    def test_build_atheris_argv_with_corpus(self, tmp_path: Path) -> None:
        """Test argv building with corpus directory."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        config = AtherisConfig(corpus_dir=corpus_dir)
        fuzzer = AtherisDICOMFuzzer(config)
        argv = fuzzer._build_atheris_argv(["test"])

        # Corpus dir should be in argv
        assert str(corpus_dir) in argv


class TestDICOMAwareMutations:
    """Tests for DICOM-aware mutation functionality."""

    @pytest.fixture
    def sample_dicom(self) -> bytes:
        """Create sample DICOM for testing."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = pydicom.uid.generate_uid()

        ds.file_meta = pydicom.filereader.FileMetaDataset()
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian

        buffer = io.BytesIO()
        pydicom.dcmwrite(buffer, ds, write_like_original=False)
        return buffer.getvalue()

    @pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
    def test_apply_dicom_mutations(self, tmp_path: Path, sample_dicom: bytes) -> None:
        """Test DICOM-aware mutation application."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        config = AtherisConfig(
            crash_dir=tmp_path / "crashes",
            output_dir=tmp_path / "output",
            dicom_aware_mutations=True,
        )

        fuzzer = AtherisDICOMFuzzer(config)
        result = fuzzer._apply_dicom_mutations(sample_dicom)

        # Should return bytes
        assert isinstance(result, bytes)
        assert len(result) > 0

    @pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
    def test_apply_dicom_mutations_invalid_data(self, tmp_path: Path) -> None:
        """Test DICOM mutation with invalid data."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        config = AtherisConfig(
            crash_dir=tmp_path / "crashes",
            output_dir=tmp_path / "output",
            dicom_aware_mutations=True,
        )

        fuzzer = AtherisDICOMFuzzer(config)

        # Invalid DICOM data should return original
        invalid_data = b"not valid dicom data"
        result = fuzzer._apply_dicom_mutations(invalid_data)

        assert result == invalid_data

    @pytest.mark.skipif(not HAS_ATHERIS, reason="Atheris not installed")
    def test_apply_dicom_mutations_disabled(
        self, tmp_path: Path, sample_dicom: bytes
    ) -> None:
        """Test with DICOM mutations disabled."""
        from dicom_fuzzer.core.atheris_integration import AtherisDICOMFuzzer

        config = AtherisConfig(
            crash_dir=tmp_path / "crashes",
            output_dir=tmp_path / "output",
            dicom_aware_mutations=False,
            use_dictionary_fuzzer=False,
        )

        fuzzer = AtherisDICOMFuzzer(config)
        result = fuzzer._apply_dicom_mutations(sample_dicom)

        # Should return original when disabled
        assert result == sample_dicom


class TestHasAtherisFlag:
    """Tests for HAS_ATHERIS availability flag."""

    def test_has_atheris_is_boolean(self) -> None:
        """Test that HAS_ATHERIS is a boolean."""
        assert isinstance(HAS_ATHERIS, bool)

    def test_has_atheris_reflects_import(self) -> None:
        """Test that HAS_ATHERIS reflects import status."""
        try:
            import atheris  # noqa: F401

            expected = True
        except ImportError:
            expected = False

        assert HAS_ATHERIS == expected

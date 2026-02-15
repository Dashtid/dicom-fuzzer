import struct
import sys
from pathlib import Path
from typing import Any

from pydicom.dataset import Dataset
from pydicom.uid import UID, generate_uid

from dicom_fuzzer.core.dicom.parser import DicomParser
from dicom_fuzzer.core.mutation.mutator import DicomMutator
from dicom_fuzzer.utils.identifiers import generate_short_id


class GenerationStats:
    """Track statistics during file generation."""

    def __init__(self) -> None:
        self.total_attempted = 0
        self.successful = 0
        self.failed = 0
        self.skipped_due_to_write_errors = 0
        self.strategies_used: dict[str, int] = {}
        self.error_types: dict[str, int] = {}

    def record_success(self, strategies: list[str]) -> None:
        """Record successful file generation."""
        self.successful += 1
        for strategy in strategies:
            self.strategies_used[strategy] = self.strategies_used.get(strategy, 0) + 1

    def record_failure(self, error_type: str) -> None:
        """Record failed file generation."""
        self.failed += 1
        self.error_types[error_type] = self.error_types.get(error_type, 0) + 1


class DICOMGenerator:
    """Generates batches of fuzzed DICOM files for security testing.

    Coordinates multiple fuzzing strategies to create a diverse set
    of test cases that stress different aspects of DICOM parsers.

    Delegates mutation orchestration to DicomMutator, which registers
    all 12 format fuzzers and handles strategy selection/application.
    """

    def __init__(
        self,
        output_dir: str | Path = "./artifacts/fuzzed",
        skip_write_errors: bool = True,
    ) -> None:
        """Initialize the generator.

        Args:
            output_dir: Directory to save generated files
            skip_write_errors: If True, skip files that can't be written due to
                             invalid mutations (good for fuzzing). If False,
                             raise errors (good for debugging).

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.skip_write_errors = skip_write_errors
        self.stats = GenerationStats()
        self.mutator = DicomMutator()

    def generate(self, output_path: str, tags: dict[str, Any] | None = None) -> Path:
        """Generate a single DICOM file from scratch.

        Args:
            output_path: Path where the DICOM file should be saved
            tags: Optional dictionary of DICOM tags to override defaults

        Returns:
            Path to the generated file

        """
        from pydicom.dataset import FileDataset, FileMetaDataset

        # Create file meta
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = UID(
            "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        )
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = UID(
            "1.2.840.10008.1.2"
        )  # Implicit VR Little Endian
        file_meta.ImplementationClassUID = generate_uid()

        # Create dataset
        ds = FileDataset(
            str(output_path), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )

        # Set required DICOM tags
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()

        # Set default patient/study information
        ds.PatientName = "TEST^PATIENT"
        ds.PatientID = "12345"
        ds.StudyDate = "20240101"
        ds.StudyTime = "120000"
        ds.Modality = "CT"

        # Set image properties
        ds.Rows = 128
        ds.Columns = 128
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"

        # Create dummy pixel data
        ds.PixelData = b"\x00" * (128 * 128 * 2)

        # Apply custom tags if provided
        if tags:
            for key, value in tags.items():
                if hasattr(ds, key):
                    setattr(ds, key, value)

        # Save the file
        output = Path(output_path)
        ds.save_as(str(output), write_like_original=False)

        return output

    def generate_batch(
        self,
        original_file: str,
        count: int = 100,
        strategies: list[str] | None = None,
    ) -> list[Path]:
        """Generate a batch of mutated DICOM files.

        Args:
            original_file: Path to original DICOM file
            count: Number of files to generate
            strategies: List of strategy names to use (None = all)

        Returns:
            List of paths to generated files

        """
        parser = DicomParser(original_file)
        base_dataset = parser.dataset

        generated_files = []
        self.stats = GenerationStats()
        self.mutator.start_session(base_dataset)

        for _i in range(count):
            result = self._generate_single_file(base_dataset, strategies)
            if result is not None:
                generated_files.append(result)

        self.mutator.end_session()
        return generated_files

    def _generate_single_file(
        self, base_dataset: Dataset, strategy_names: list[str] | None = None
    ) -> Path | None:
        """Generate a single fuzzed file. Returns None if generation fails.

        Temporarily increases the recursion limit because deeply nested
        sequence mutations (e.g. depth-500) can exceed the default limit
        during both mutation (deepcopy) and pydicom serialization.
        """
        self.stats.total_attempted += 1

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, 10000))
        try:
            # Create mutated dataset
            mutated_dataset, strategies_applied = self._apply_mutations(
                base_dataset, strategy_names
            )
            if mutated_dataset is None:
                return None

            # Save to file
            return self._save_mutated_file(mutated_dataset, strategies_applied)
        finally:
            sys.setrecursionlimit(old_limit)

    def _apply_mutations(
        self,
        base_dataset: Dataset,
        strategy_names: list[str] | None = None,
    ) -> tuple[Dataset | None, list[str]]:
        """Apply a single mutation to dataset via DicomMutator.

        Delegates to DicomMutator which handles strategy selection,
        application, and tracking. Default is one strategy per file
        for clean crash attribution.

        Returns (dataset, strategies) or (None, []).
        """
        try:
            mutated_dataset = self.mutator.apply_mutations(
                base_dataset,
                num_mutations=1,
                strategy_names=strategy_names,
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
            RecursionError,
        ) as e:
            return self._handle_mutation_error(e)

        # Get applied strategy names from session for stats
        strategies: list[str] = []
        if self.mutator.current_session and self.mutator.current_session.mutations:
            last_mutation = self.mutator.current_session.mutations[-1]
            if last_mutation.success:
                strategies = [last_mutation.strategy_name]

        return mutated_dataset, strategies

    def _handle_mutation_error(self, error: Exception) -> tuple[None, list[str]]:
        """Handle errors during mutation."""
        if self.skip_write_errors:
            self.stats.skipped_due_to_write_errors += 1
            return None, []

        self.stats.record_failure(type(error).__name__)
        raise error

    def _save_mutated_file(
        self, mutated_dataset: Dataset, strategies_applied: list[str]
    ) -> Path | None:
        """Save mutated dataset to file. Returns path or None on error."""
        filename = f"fuzzed_{generate_short_id()}.dcm"
        output_path = self.output_dir / filename

        try:
            mutated_dataset.save_as(output_path, enforce_file_format=False)
            self.stats.record_success(strategies_applied)
            return output_path
        except (
            RecursionError,
            OSError,
            struct.error,
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
            OverflowError,
            UnicodeEncodeError,
            UnicodeDecodeError,
        ) as e:
            if self.skip_write_errors:
                self.stats.skipped_due_to_write_errors += 1
                return None
            self.stats.record_failure(type(e).__name__)
            raise
        except Exception as e:
            self.stats.record_failure(type(e).__name__)
            raise

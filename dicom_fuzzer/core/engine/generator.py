"""Batch generation of fuzzed DICOM files for security testing."""

from __future__ import annotations

import os
import re
import struct
import sys
import warnings
from io import BytesIO
from pathlib import Path

from pydicom.dataset import Dataset
from pydicom.errors import BytesLengthException
from pydicom.filewriter import dcmwrite
from pydicom.tag import BaseTag, Tag
from pydicom.uid import ExplicitVRLittleEndian

from dicom_fuzzer.core.dicom.parser import DicomParser
from dicom_fuzzer.core.mutation.mutator import DicomMutator
from dicom_fuzzer.utils.identifiers import generate_short_id
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


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
        seed: int | None = None,
        safety_mode: str | None = None,
    ) -> None:
        """Initialize the generator.

        Args:
            output_dir: Directory to save generated files
            skip_write_errors: If True, skip files that can't be written due to
                             invalid mutations (good for fuzzing). If False,
                             raise errors (good for debugging).
            seed: Random seed for reproducible runs. Auto-generated if None.
            safety_mode: Critical-tag preservation mode (off/lenient/strict).

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.skip_write_errors = skip_write_errors
        self.stats = GenerationStats()
        self.cumulative_strategies: dict[str, int] = {}
        self.seed: int = (
            seed if seed is not None else int.from_bytes(os.urandom(4), "big")
        )
        mutator_config = (
            {"safety_mode": safety_mode}
            if safety_mode and safety_mode != "off"
            else None
        )
        self.mutator = DicomMutator(seed=self.seed, config=mutator_config)
        self.file_strategy_map: dict[str, str] = {}
        self.file_variant_map: dict[str, str] = {}
        self.file_binary_mutations_map: dict[str, list[str]] = {}

    @property
    def known_strategy_names(self) -> list[str]:
        """Return all registered strategy names in the mutator dispatch pool."""
        return [s.strategy_name for s in self.mutator.strategies]

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
        self.mutator.start_session()

        # Suppress pydicom warnings during generation -- mutations
        # intentionally create malformed data that triggers warnings
        # (encoding failures, VR mismatches, oversized elements).
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", module="pydicom")
            for _i in range(count):
                result = self._generate_single_file(base_dataset, strategies)
                if result is not None:
                    generated_files.append(result)

        self.mutator.end_session()

        # Accumulate strategy counts across batches so multi-batch
        # campaigns don't lose data when stats resets on next batch.
        for strategy, count in self.stats.strategies_used.items():
            self.cumulative_strategies[strategy] = (
                self.cumulative_strategies.get(strategy, 0) + count
            )

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
            mutated_dataset, strategies_applied, strategy_obj = self._apply_mutations(
                base_dataset, strategy_names
            )
            if mutated_dataset is None:
                return None

            # Save to file
            return self._save_mutated_file(
                mutated_dataset, strategies_applied, strategy_obj
            )
        finally:
            sys.setrecursionlimit(old_limit)

    def _apply_mutations(
        self,
        base_dataset: Dataset,
        strategy_names: list[str] | None = None,
    ) -> tuple[Dataset | None, list[str], object]:
        """Apply a single mutation to dataset via DicomMutator.

        Delegates to DicomMutator which handles strategy selection,
        application, and tracking. Default is one strategy per file
        for clean crash attribution.

        Returns (dataset, strategies, strategy_obj) or (None, [], None).
        The strategy_obj is the live strategy instance so the engine can
        call mutate_bytes() on the serialized output for binary-level mutations.
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

        # Resolve the strategy object by name so callers can invoke mutate_bytes()
        strategy_obj: object = None
        if strategies:
            for s in self.mutator.strategies:
                if s.strategy_name == strategies[0]:
                    strategy_obj = s
                    break

        return mutated_dataset, strategies, strategy_obj

    def _handle_mutation_error(self, error: Exception) -> tuple[None, list[str], None]:
        """Handle errors during mutation."""
        error_name = type(error).__name__
        if self.skip_write_errors:
            self.stats.record_failure(error_name)
            self.stats.skipped_due_to_write_errors += 1
            logger.debug("Mutation error skipped: %s: %s", error_name, error)
            return None, [], None

        self.stats.record_failure(error_name)
        raise error

    # SpecificCharacterSet tag -- root cause of encoding cascade errors
    _CHARSET_TAG = Tag(0x0008, 0x0005)

    @staticmethod
    def _prepare_dataset_for_save(dataset: Dataset) -> dict[str, bool]:
        """Fix dataset issues that prevent pydicom serialization.

        Applies three fixes so mutated datasets can be written to disk:
        1. Switches compressed transfer syntax to Explicit VR Little Endian
        2. Removes corrupted SpecificCharacterSet that breaks all string encoding
        3. Strips DICOM Command Set tags (group 0000)

        Returns dict with ``little_endian`` and ``implicit_vr`` kwargs
        for ``dcmwrite()``, derived from the dataset's transfer syntax.
        """
        # Defaults: Explicit VR Little Endian
        write_kwargs: dict[str, bool] = {"little_endian": True, "implicit_vr": False}

        file_meta = getattr(dataset, "file_meta", None)
        if file_meta is not None:
            ts = getattr(file_meta, "TransferSyntaxUID", None)
            if ts is not None:
                ts_str = str(ts)

                # Force compressed TS to Explicit VR Little Endian
                if ts_str not in {
                    "1.2.840.10008.1.2",  # Implicit VR Little Endian
                    "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
                    "1.2.840.10008.1.2.2",  # Explicit VR Big Endian
                }:
                    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
                    ts_str = str(ExplicitVRLittleEndian)

                # Derive encoding from transfer syntax
                if ts_str == "1.2.840.10008.1.2.2":  # Big Endian
                    write_kwargs = {"little_endian": False, "implicit_vr": False}
                elif ts_str == "1.2.840.10008.1.2":  # Implicit VR LE
                    write_kwargs = {"little_endian": True, "implicit_vr": True}

        # Remove corrupted SpecificCharacterSet -- when a mutation sets it
        # to a non-string type, pydicom fails to encode every string tag
        charset_tag = Tag(0x0008, 0x0005)
        if charset_tag in dataset:
            val = dataset[charset_tag].value
            if not isinstance(val, (str, type(None))):
                del dataset[charset_tag]

        # Strip Command Set tags (group 0000) — invalid in file datasets
        command_tags = [tag for tag in dataset if tag.tag.group == 0x0000]
        for tag in command_tags:
            del dataset[tag.tag]

        return write_kwargs

    # Regex to extract DICOM tag from pydicom error messages like
    # "With tag (0018,9324) got exception: ..." or "tag (0008,0005)"
    _TAG_RE = re.compile(r"\(([0-9A-Fa-f]{4}),\s*([0-9A-Fa-f]{4})\)")

    _SAVE_ERRORS = (
        RecursionError,
        OSError,
        struct.error,
        BytesLengthException,
        ValueError,
        TypeError,
        AttributeError,
        IndexError,
        OverflowError,
        UnicodeEncodeError,
        UnicodeDecodeError,
    )

    def _save_mutated_file(
        self,
        mutated_dataset: Dataset,
        strategies_applied: list[str],
        strategy_obj: object = None,
    ) -> Path | None:
        """Save mutated dataset to file with iterative error recovery.

        On save failure, extracts the offending DICOM tag from the error
        message, removes it from the dataset, and retries. This preserves
        all mutations except elements that pydicom physically cannot
        serialize (e.g. string in a float field).

        After a successful serialize, calls strategy_obj.mutate_bytes() for
        binary-level mutations (e.g. tag ordering, duplicate tags, length
        field corruption) that pydicom would undo during Dataset-level writes.
        """
        filename = f"fuzzed_{generate_short_id()}.dcm"
        output_path = self.output_dir / filename

        write_kwargs = self._prepare_dataset_for_save(mutated_dataset)

        max_retries = 10
        for attempt in range(max_retries):
            try:
                # Serialize to memory so binary mutations can be applied
                # before the final write to disk.
                buf = BytesIO()
                dcmwrite(buf, mutated_dataset, **write_kwargs)
                raw_bytes = buf.getvalue()

                # Apply binary-level mutations if strategy supports them.
                # mutate_bytes() is a no-op on the base class; only
                # StructureFuzzer (and future subclasses) override it.
                if strategy_obj is not None:
                    mutate_bytes = getattr(strategy_obj, "mutate_bytes", None)
                    if mutate_bytes is not None:
                        try:
                            raw_bytes = mutate_bytes(raw_bytes)
                        except Exception as e:
                            logger.debug("mutate_bytes failed: %s", e)

                output_path.write_bytes(raw_bytes)
                self.stats.record_success(strategies_applied)
                if strategies_applied:
                    self.file_strategy_map[output_path.name] = strategies_applied[0]
                    variant = getattr(strategy_obj, "last_variant", None)
                    if variant:
                        self.file_variant_map[output_path.name] = variant
                binary_muts = getattr(strategy_obj, "_applied_binary_mutations", [])
                if binary_muts:
                    self.file_binary_mutations_map[output_path.name] = list(binary_muts)
                return output_path
            except self._SAVE_ERRORS as e:
                if attempt < max_retries - 1 and self._try_recover(
                    mutated_dataset, str(e), attempt
                ):
                    continue

                # No recoverable tag or max retries -- give up
                error_name = type(e).__name__
                self.stats.record_failure(error_name)
                if self.skip_write_errors:
                    self.stats.skipped_due_to_write_errors += 1
                    # Clean up any partial file (write_bytes is atomic on
                    # success, but a previous attempt may have left a ghost).
                    output_path.unlink(missing_ok=True)
                    logger.debug("Save error skipped: %s: %s", error_name, e)
                    return None
                raise
            except Exception as e:
                self.stats.record_failure(type(e).__name__)
                raise

        return None  # pragma: no cover -- max_retries exhausted

    def _try_recover(self, dataset: Dataset, error_msg: str, attempt: int) -> bool:
        """Try to recover from a save error by removing the offending tag.

        Returns True if recovery succeeded (caller should retry save).
        """
        # Encoding cascade: corrupted SpecificCharacterSet breaks ALL
        # string tags. Remove root cause instead of individual strings.
        if self._is_encoding_error(error_msg) and self._CHARSET_TAG in dataset:
            del dataset[self._CHARSET_TAG]
            logger.debug(
                "Removed corrupted SpecificCharacterSet (attempt %d)",
                attempt + 1,
            )
            return True

        # Standard: extract and remove the offending tag
        tag = self._extract_error_tag(error_msg)
        if tag is not None and tag in dataset:
            del dataset[tag]
            logger.debug(
                "Removed unserializable tag %s (attempt %d)",
                tag,
                attempt + 1,
            )
            return True

        # Fallback: remove elements with VR=None (unresolvable private tags).
        # These cause struct.pack / TypeError failures in dcmwrite()
        # because pydicom cannot determine how to serialize them.
        # At runtime, iterating a Dataset can yield RawDataElement with VR=None
        # even though pydicom's stubs don't reflect this.
        for elem in list(dataset):
            if getattr(elem, "VR", "XX") is None:
                del dataset[elem.tag]
                logger.debug(
                    "Removed element with VR=None: %s (attempt %d)",
                    getattr(elem, "tag", "unknown"),
                    attempt + 1,
                )
                return True

        # Last resort: probe numeric elements for unpackable values.
        # Catches TypeErrors from C-level struct.pack failures where the
        # error message lacks a (XXXX,XXXX) tag pattern.
        pack_fmt = {
            "US": "<H",
            "SS": "<h",
            "UL": "<I",
            "SL": "<i",
            "FL": "<f",
            "FD": "<d",
        }
        for elem in list(dataset):
            vr = getattr(elem, "VR", None)
            fmt = pack_fmt.get(vr) if vr else None
            if fmt is None:
                continue
            val = getattr(elem, "value", None)
            if isinstance(val, (int, float)):
                try:
                    struct.pack(fmt, val)
                except (struct.error, TypeError, OverflowError):
                    del dataset[elem.tag]
                    logger.debug(
                        "Removed element with unpackable value: %s=%r (attempt %d)",
                        elem.tag,
                        val,
                        attempt + 1,
                    )
                    return True

        return False

    @classmethod
    def _extract_error_tag(cls, error_msg: str) -> BaseTag | None:
        """Extract a DICOM tag from a pydicom error message.

        Returns the Tag if found, or None if no tag pattern is present.
        """
        match = cls._TAG_RE.search(error_msg)
        if match:
            return Tag(int(match.group(1), 16), int(match.group(2), 16))
        return None

    @staticmethod
    def _is_encoding_error(error_msg: str) -> bool:
        """Check if error is caused by corrupted SpecificCharacterSet."""
        return "encode()" in error_msg and "encoding" in error_msg

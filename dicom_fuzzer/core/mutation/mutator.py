"""DICOM Fuzzer Mutation Engine.

Orchestrates mutation strategies to systematically test DICOM files.
Includes dictionary-based fuzzing for domain-aware mutations.
"""

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.identifiers import generate_short_id
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class MutationStrategy(Protocol):
    """Protocol defining required methods for mutation strategies."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply mutation to the dataset."""

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can be applied to this dataset."""


@dataclass
class MutationRecord:
    """Record of a single mutation applied to a file."""

    mutation_id: str = field(default_factory=generate_short_id)
    strategy_name: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error_message: str | None = None


@dataclass
class MutationSession:
    """Tracks all mutations applied to one original file."""

    session_id: str = field(default_factory=generate_short_id)
    original_file_info: dict[str, Any] = field(default_factory=dict)
    mutations: list[MutationRecord] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    total_mutations: int = 0
    successful_mutations: int = 0


class DicomMutator:
    """Coordinates mutation strategies and tracks changes to DICOM files.

    Uses the Strategy Pattern to manage different fuzzing approaches.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the mutator.

        Args:
            config: Optional configuration dictionary for customizing behavior

        """
        self.config = config or {}
        self.strategies: list[MutationStrategy] = []
        self.current_session: MutationSession | None = None
        self._strategy_cache: dict[tuple[Any, ...], list[MutationStrategy]] = {}

        self._load_default_config()

        if self.config.get("auto_register_strategies", True):
            self._register_default_strategies()

        logger.info("DicomMutator initialized with config: %s", self.config)

    def _load_default_config(self) -> None:
        """Fill in default values for any missing config keys."""
        default_config = {
            "max_mutations_per_file": 1,
            "mutation_probability": 1.0,
        }

        for key, value in default_config.items():
            if key not in self.config:
                self.config[key] = value

    def _register_default_strategies(self) -> None:
        """Register all format fuzzing strategies.

        Uses lazy imports to avoid circular dependencies.
        """
        from dicom_fuzzer.attacks.format.calibration_fuzzer import CalibrationFuzzer
        from dicom_fuzzer.attacks.format.compressed_pixel_fuzzer import (
            CompressedPixelFuzzer,
        )
        from dicom_fuzzer.attacks.format.conformance_fuzzer import ConformanceFuzzer
        from dicom_fuzzer.attacks.format.dictionary_fuzzer import DictionaryFuzzer
        from dicom_fuzzer.attacks.format.encapsulated_pdf_fuzzer import (
            EncapsulatedPdfFuzzer,
        )
        from dicom_fuzzer.attacks.format.encoding_fuzzer import EncodingFuzzer
        from dicom_fuzzer.attacks.format.header_fuzzer import HeaderFuzzer
        from dicom_fuzzer.attacks.format.metadata_fuzzer import MetadataFuzzer
        from dicom_fuzzer.attacks.format.nm_fuzzer import NuclearMedicineFuzzer
        from dicom_fuzzer.attacks.format.pet_fuzzer import PetFuzzer
        from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer
        from dicom_fuzzer.attacks.format.private_tag_fuzzer import PrivateTagFuzzer
        from dicom_fuzzer.attacks.format.reference_fuzzer import ReferenceFuzzer
        from dicom_fuzzer.attacks.format.rt_dose_fuzzer import RTDoseFuzzer
        from dicom_fuzzer.attacks.format.rtss_fuzzer import RTStructureSetFuzzer
        from dicom_fuzzer.attacks.format.seg_fuzzer import SegmentationFuzzer
        from dicom_fuzzer.attacks.format.sequence_fuzzer import SequenceFuzzer
        from dicom_fuzzer.attacks.format.structure_fuzzer import StructureFuzzer

        for fuzzer_cls in [
            CalibrationFuzzer,
            CompressedPixelFuzzer,
            ConformanceFuzzer,
            DictionaryFuzzer,
            EncapsulatedPdfFuzzer,
            EncodingFuzzer,
            HeaderFuzzer,
            MetadataFuzzer,
            NuclearMedicineFuzzer,
            PetFuzzer,
            PixelFuzzer,
            PrivateTagFuzzer,
            RTDoseFuzzer,
            RTStructureSetFuzzer,
            ReferenceFuzzer,
            SegmentationFuzzer,
            SequenceFuzzer,
            StructureFuzzer,
        ]:
            try:
                self.register_strategy(fuzzer_cls())  # type: ignore[abstract]
            except Exception as e:
                logger.warning("Could not register %s: %s", fuzzer_cls.__name__, e)

    def register_strategy(self, strategy: MutationStrategy) -> None:
        """Add a new fuzzing strategy to the collection.

        Args:
            strategy: A fuzzing strategy implementing MutationStrategy protocol

        """
        if (
            not hasattr(strategy, "mutate")
            or not hasattr(strategy, "strategy_name")
            or not hasattr(strategy, "can_mutate")
        ):
            raise ValueError(
                f"Strategy {strategy} does not implement MutationStrategy protocol"
            )

        self.strategies.append(strategy)
        self._strategy_cache.clear()
        logger.debug("Registered mutation strategy: %s", strategy.strategy_name)

    def start_session(self, file_info: dict[str, Any] | None = None) -> str:
        """Start a new mutation session for tracking.

        Args:
            file_info: Optional information about the source file

        Returns:
            str: Session ID for tracking

        """
        self.current_session = MutationSession(
            original_file_info=file_info or {},
        )

        logger.info("Started mutation session: %s", self.current_session.session_id)
        return self.current_session.session_id

    def apply_mutations(
        self,
        dataset: Dataset,
        num_mutations: int | None = None,
        strategy_names: list[str] | None = None,
    ) -> Dataset:
        """Apply mutations to a DICOM dataset.

        Args:
            dataset: The DICOM dataset to mutate
            num_mutations: How many mutations to apply (optional)
            strategy_names: Specific strategies to use (optional)

        Returns:
            Dataset: The mutated DICOM dataset

        """
        # Use defaults from config if not specified
        if num_mutations is None:
            num_mutations = int(self.config.get("max_mutations_per_file", 1))

        logger.info("Applying %s mutations", num_mutations)

        mutated_dataset = dataset.copy()

        # Get available strategies
        available_strategies = self._get_applicable_strategies(
            mutated_dataset, strategy_names
        )

        if not available_strategies:
            logger.warning("No applicable mutation strategies found")
            return mutated_dataset

        # Apply the requested number of mutations
        mutations_applied = 0
        for i in range(num_mutations):
            # Check probability to see if we should apply this mutation
            # Skip mutation if random value is greater than probability threshold
            # e.g., if probability=0.7, skip when random() > 0.7 (30% skip rate)
            if random.random() > self.config.get("mutation_probability", 1.0):
                logger.debug("Skipping mutation %s due to probability", i + 1)
                continue

            # Choose a random strategy
            strategy = random.choice(available_strategies)

            try:
                # Apply the mutation and track it
                mutated_dataset = self._apply_single_mutation(mutated_dataset, strategy)
                mutations_applied += 1

            except Exception as e:
                logger.error("Mutation failed: %s", e)
                # Record the failed mutation
                self._record_mutation(strategy, success=False, error=str(e))

        logger.info("Successfully applied %s mutations", mutations_applied)
        return mutated_dataset

    def _get_applicable_strategies(
        self, dataset: Dataset, strategy_names: list[str] | None = None
    ) -> list[MutationStrategy]:
        """Filter strategies that can work with this dataset.

        Caches results based on dataset features for performance.
        """
        modality_value = dataset.get("Modality", None)
        modality_str = str(modality_value) if modality_value is not None else None
        cache_key = (
            tuple(sorted(dataset.dir())),  # Tags present in dataset
            modality_str,  # Modality type (converted to string for hashability)
            bool(hasattr(dataset, "PixelData")),  # Has pixel data
            tuple(sorted(strategy_names))
            if strategy_names
            else None,  # Requested strategies
        )

        # Check cache first
        if cache_key in self._strategy_cache:
            logger.debug("Using cached strategies for dataset type")
            return self._strategy_cache[cache_key]

        # Cache miss - compute applicable strategies
        applicable = []

        for strategy in self.strategies:
            # Check if specific strategies were requested
            if strategy_names and strategy.strategy_name not in strategy_names:
                continue

            try:
                if strategy.can_mutate(dataset):
                    applicable.append(strategy)
                else:
                    logger.debug("Strategy %s not applicable", strategy.strategy_name)
            except Exception as e:
                logger.warning(
                    "Error checking strategy %s: %s", strategy.strategy_name, e
                )

        # Store in cache for future use
        self._strategy_cache[cache_key] = applicable
        logger.debug("Cached %s applicable strategies", len(applicable))

        return applicable

    def _apply_single_mutation(
        self, dataset: Dataset, strategy: MutationStrategy
    ) -> Dataset:
        """Apply a single mutation and track the results."""
        logger.debug("Applying %s mutation", strategy.strategy_name)

        mutated_dataset = strategy.mutate(dataset)
        self._record_mutation(strategy, success=True)

        return mutated_dataset

    def _record_mutation(
        self,
        strategy: MutationStrategy,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        """Record mutation details for tracking and analysis."""
        if not self.current_session:
            logger.warning("No active session - cannot record mutation")
            return

        mutation_record = MutationRecord(
            strategy_name=strategy.strategy_name,
            description=f"Applied {strategy.strategy_name}",
            success=success,
            error_message=error,
        )

        # Add to current session
        self.current_session.mutations.append(mutation_record)
        self.current_session.total_mutations += 1
        if success:
            self.current_session.successful_mutations += 1

        # Log for debugging
        logger.debug("Recorded mutation: %s", mutation_record.mutation_id)

    def end_session(self) -> MutationSession | None:
        """End the current mutation session and return statistics.

        Returns:
            MutationSession | None: The completed session with all records

        """
        if not self.current_session:
            logger.warning("No active session to end")
            return None

        self.current_session.end_time = datetime.now(UTC)

        completed_session = self.current_session
        logger.info(
            "Mutation session %s completed: %d/%d mutations successful",
            completed_session.session_id,
            completed_session.successful_mutations,
            completed_session.total_mutations,
        )

        self.current_session = None
        return completed_session

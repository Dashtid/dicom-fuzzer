"""DICOM Fuzzer Mutation Engine.

Orchestrates mutation strategies to systematically test DICOM files.
Includes dictionary-based fuzzing for domain-aware mutations.
"""

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

# Import DICOM libraries
from pydicom.dataset import Dataset

from dicom_fuzzer.utils.identifiers import generate_short_id
from dicom_fuzzer.utils.logger import SecurityEventLogger, get_logger

# Get a logger for this module
logger = get_logger(__name__)
security_logger = SecurityEventLogger(logger)


class MutationStrategy(Protocol):
    """Protocol defining required methods for mutation strategies."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        pass

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply mutation to the dataset."""
        pass

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can be applied to this dataset."""
        pass


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
        # Set up instance variables with default values
        self.config = config or {}
        self.strategies: list[MutationStrategy] = []
        self.current_session: MutationSession | None = None

        # OPTIMIZATION: Cache for applicable strategies based on dataset features
        self._strategy_cache: dict[tuple[Any, ...], list[MutationStrategy]] = {}

        # Load default configuration
        self._load_default_config()

        # Register default strategies if enabled
        if self.config.get("auto_register_strategies", True):
            self._register_default_strategies()

        # Log initialization
        logger.info(f"DicomMutator initialized with config: {self.config}")

    def _load_default_config(self) -> None:
        """Set up default configuration values."""
        default_config = {
            "max_mutations_per_file": 1,
            "mutation_probability": 1.0,
            "enable_mutation_tracking": True,
        }

        # Update config with defaults for missing keys
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
                self.register_strategy(fuzzer_cls())
            except Exception as e:
                logger.warning(f"Could not register {fuzzer_cls.__name__}: {e}")

    def register_strategy(self, strategy: MutationStrategy) -> None:
        """Add a new fuzzing strategy to the collection.

        Args:
            strategy: A fuzzing strategy implementing MutationStrategy protocol

        """
        if not hasattr(strategy, "mutate") or not hasattr(strategy, "strategy_name"):
            raise ValueError(
                f"Strategy {strategy} does not implement MutationStrategy protocol"
            )

        self.strategies.append(strategy)
        logger.debug(f"Registered mutation strategy: {strategy.strategy_name}")

    def start_session(
        self, original_dataset: Dataset | None, file_info: dict[str, Any] | None = None
    ) -> str:
        """Start a new mutation session for tracking.

        Args:
            original_dataset: The original DICOM dataset to mutate
            file_info: Optional information about the source file

        Returns:
            str: Session ID for tracking

        """
        # Create a new session object
        self.current_session = MutationSession(
            original_file_info=file_info or {},
        )

        # Log security event for audit trail
        logger.info(
            "mutation_session_started",
            security_event=True,
            session_id=self.current_session.session_id,
            file_info=file_info,
            config=self.config,
        )

        logger.info(f"Started mutation session: {self.current_session.session_id}")
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
        num_mutations = num_mutations or self.config.get("max_mutations_per_file", 1)

        logger.info(f"Applying {num_mutations} mutations")

        # OPTIMIZATION: Use Dataset.copy() instead of deepcopy for better performance
        # pydicom's copy() is optimized for DICOM datasets and 2-3x faster than deepcopy
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
                logger.debug(f"Skipping mutation {i + 1} due to probability")
                continue

            # Choose a random strategy
            strategy = random.choice(available_strategies)

            try:
                # Apply the mutation and track it
                mutated_dataset = self._apply_single_mutation(mutated_dataset, strategy)
                mutations_applied += 1

            except Exception as e:
                logger.error(f"Mutation failed: {e}")
                # Record the failed mutation
                self._record_mutation(strategy, success=False, error=str(e))

        logger.info(f"Successfully applied {mutations_applied} mutations")
        return mutated_dataset

    def _get_applicable_strategies(
        self, dataset: Dataset, strategy_names: list[str] | None = None
    ) -> list[MutationStrategy]:
        """Filter strategies that can work with this dataset.

        Caches results based on dataset features for performance.
        """
        # OPTIMIZATION: Create cache key from dataset features
        # This avoids re-checking strategy applicability for similar datasets
        # NOTE: Convert Modality to str to avoid pydicom MultiValue hashing issues
        # (MultiValue objects are unhashable in Python 3.11+ / pydicom 3.0+)
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
                    logger.debug(f"Strategy {strategy.strategy_name} not applicable")
            except Exception as e:
                logger.warning(f"Error checking strategy {strategy.strategy_name}: {e}")

        # Store in cache for future use
        self._strategy_cache[cache_key] = applicable
        logger.debug(f"Cached {len(applicable)} applicable strategies")

        return applicable

    def _apply_single_mutation(
        self, dataset: Dataset, strategy: MutationStrategy
    ) -> Dataset:
        """Apply a single mutation and track the results."""
        logger.debug(f"Applying {strategy.strategy_name} mutation")

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
        logger.debug(f"Recorded mutation: {mutation_record.mutation_id}")

    def end_session(self) -> MutationSession | None:
        """End the current mutation session and return statistics.

        Returns:
            MutationSession | None: The completed session with all records

        """
        if not self.current_session:
            logger.warning("No active session to end")
            return None

        # Mark the end time
        end_time = datetime.now(UTC)
        self.current_session.end_time = end_time

        # Log session summary
        session = self.current_session
        logger.info(
            "mutation_session_completed",
            security_event=True,
            session_id=session.session_id,
            total_mutations=session.total_mutations,
            successful_mutations=session.successful_mutations,
            duration_seconds=(end_time - session.start_time).total_seconds(),
            success_rate=session.successful_mutations / max(session.total_mutations, 1),
        )

        # Return the session and clear current
        completed_session = self.current_session
        self.current_session = None

        return completed_session

    def get_session_summary(self) -> dict[str, Any] | None:
        """Get a summary of the current session.

        Returns:
            dict[str, Any] | None: Summary information about the session

        """
        if not self.current_session:
            return None

        session = self.current_session
        return {
            "session_id": session.session_id,
            "start_time": session.start_time.isoformat(),
            "mutations_applied": len(session.mutations),
            "successful_mutations": session.successful_mutations,
            "strategies_used": list({m.strategy_name for m in session.mutations}),
        }

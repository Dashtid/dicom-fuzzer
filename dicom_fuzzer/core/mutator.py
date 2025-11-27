"""DICOM Fuzzer Mutation Engine

LEARNING OBJECTIVE: This module demonstrates advanced object-oriented programming
concepts including the Strategy Pattern, Command Pattern, and composition.

CONCEPT: The mutator is the "conductor" that orchestrates different mutation
strategies to systematically test DICOM files.

UPDATED: Now includes dictionary-based fuzzing for intelligent, domain-aware mutations.
"""

# LEARNING: Import necessary modules
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

# LEARNING: Import our logging system with fallback for direct execution
try:
    # Try relative import first (when imported as a module)
    from ..utils.identifiers import generate_short_id
    from ..utils.logger import SecurityEventLogger, get_logger
except ImportError:
    # Fall back to absolute import (when running directly)
    import sys

    # Add the parent directory to the path so we can import utils
    sys.path.append(str(Path(__file__).parent.parent))
    from dicom_fuzzer.utils.identifiers import generate_short_id
    from dicom_fuzzer.utils.logger import SecurityEventLogger, get_logger

# LEARNING: Import DICOM libraries
from pydicom.dataset import Dataset

# LEARNING: Import shared types
try:
    from .types import MutationSeverity
except ImportError:
    import sys

    sys.path.append(str(Path(__file__).parent.parent))
    from dicom_fuzzer.core.types import MutationSeverity

# Get a logger for this module
logger = get_logger(__name__)
security_logger = SecurityEventLogger(logger)


# LEARNING: This is a Protocol - it defines what methods a class must have
class MutationStrategy(Protocol):
    """LEARNING: A Protocol is like a contract that classes must follow.

    CONCEPT: Any class that wants to be a "mutation strategy" must have
    these methods. This is called "duck typing" - if it walks like a duck
    and quacks like a duck, it's a duck!

    WHY: This ensures all our fuzzing strategies work the same way.
    """

    def mutate(self, dataset: Dataset, severity: MutationSeverity) -> Dataset:
        """Apply mutation to the dataset"""
        ...

    def get_strategy_name(self) -> str:
        """Get the name of this strategy"""
        ...

    def can_mutate(self, dataset: Dataset) -> bool:
        """Check if this strategy can be applied to this dataset"""
        ...


# LEARNING: This is a dataclass - a special type of class for storing data
@dataclass
class MutationRecord:
    """LEARNING: @dataclass automatically creates __init__, __repr__, and other methods

    CONCEPT: This is like a structured record that tracks what we did to a file.
    Think of it like a medical chart that records what treatments were applied.

    WHY: We need to track mutations for debugging, analysis, and compliance.
    """

    mutation_id: str = field(default_factory=generate_short_id)
    strategy_name: str = ""
    severity: MutationSeverity = MutationSeverity.MINIMAL
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error_message: str | None = None


# LEARNING: This is a dataclass for tracking the overall mutation session
@dataclass
class MutationSession:
    """CONCEPT: A session tracks all the mutations applied to one original file.
    Like a medical procedure where multiple treatments are applied.
    """

    session_id: str = field(default_factory=generate_short_id)
    original_file_info: dict[str, Any] = field(default_factory=dict)
    mutations: list[MutationRecord] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    total_mutations: int = 0
    successful_mutations: int = 0


class DicomMutator:
    """LEARNING: This is the main mutator class - the "conductor" of our orchestra

    CONCEPT: This class coordinates different mutation strategies and tracks
    what changes are made to DICOM files.

    ARCHITECTURE: Uses the Strategy Pattern to manage different fuzzing approaches
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """LEARNING: __init__ is the constructor - sets up the object when created

        Args:
            config: Optional configuration dictionary for customizing behavior

        """
        # LEARNING: Set up instance variables with default values
        self.config = config or {}
        self.strategies: list[MutationStrategy] = []
        self.current_session: MutationSession | None = None

        # OPTIMIZATION: Cache for applicable strategies based on dataset features
        self._strategy_cache: dict[tuple, list[MutationStrategy]] = {}

        # LEARNING: Load default configuration
        self._load_default_config()

        # LEARNING: Register default strategies if enabled
        if self.config.get("auto_register_strategies", True):
            self._register_default_strategies()

        # LEARNING: Log that we've created a new mutator
        logger.info(f"DicomMutator initialized with config: {self.config}")

    def _load_default_config(self) -> None:
        """LEARNING: Private method (starts with _) for internal setup

        CONCEPT: We set up reasonable defaults but allow them to be overridden
        """
        # LEARNING: The .get() method returns a default value if key doesn't exist
        default_config = {
            "max_mutations_per_file": 3,
            "mutation_probability": 0.7,
            "default_severity": MutationSeverity.MODERATE,
            "preserve_critical_elements": True,
            "enable_mutation_tracking": True,
            "safety_checks": True,
        }

        # LEARNING: Update our config with defaults for any missing keys
        for key, value in default_config.items():
            if key not in self.config:
                self.config[key] = value

    def _register_default_strategies(self) -> None:
        """LEARNING: Register default fuzzing strategies

        CONCEPT: Automatically register dictionary-based and other default
        fuzzing strategies for immediate use.

        WHY: We import strategies here (lazy import) to avoid circular imports
        """
        try:
            # Lazy import to avoid circular dependency
            from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer

            # Register dictionary fuzzer for intelligent mutations
            dict_fuzzer = DictionaryFuzzer()
            self.register_strategy(dict_fuzzer)
            logger.info("Registered dictionary fuzzer strategy")
        except Exception as e:
            logger.warning(f"Could not register dictionary fuzzer: {e}")

    def register_strategy(self, strategy: MutationStrategy) -> None:
        """LEARNING: This method adds a new fuzzing strategy to our collection

        CONCEPT: This is the "registration" pattern - strategies register
        themselves with the mutator.

        Args:
            strategy: A fuzzing strategy that follows our MutationStrategy protocol

        """
        # LEARNING: Check if strategy follows our protocol
        if not hasattr(strategy, "mutate") or not hasattr(
            strategy, "get_strategy_name"
        ):
            raise ValueError(
                f"Strategy {strategy} does not implement MutationStrategy protocol"
            )

        self.strategies.append(strategy)
        logger.debug(f"Registered mutation strategy: {strategy.get_strategy_name()}")

    def start_session(
        self, original_dataset: Dataset | None, file_info: dict[str, Any] | None = None
    ) -> str:
        """LEARNING: Start a new mutation session for tracking purposes

        CONCEPT: A session groups all mutations applied to one source file.
        Like starting a new medical procedure.

        Args:
            original_dataset: The original DICOM dataset to mutate
            file_info: Optional information about the source file

        Returns:
            str: Session ID for tracking

        """
        # LEARNING: Create a new session object
        self.current_session = MutationSession(
            original_file_info=file_info or {},
        )

        # LEARNING: Log security event for audit trail
        # Convert config to JSON-safe format
        safe_config = {}
        for key, value in self.config.items():
            if isinstance(value, MutationSeverity):
                safe_config[key] = value.value  # Convert enum to string
            else:
                safe_config[key] = value

        logger.info(
            "mutation_session_started",
            security_event=True,
            session_id=self.current_session.session_id,
            file_info=file_info,
            config=safe_config,
        )

        logger.info(f"Started mutation session: {self.current_session.session_id}")
        return self.current_session.session_id

    def apply_mutations(
        self,
        dataset: Dataset,
        num_mutations: int | None = None,
        severity: MutationSeverity | None = None,
        strategy_names: list[str] | None = None,
    ) -> Dataset:
        """LEARNING: This is the main method that applies mutations to a DICOM dataset

        CONCEPT: This method orchestrates the mutation process using the
        Strategy Pattern to apply different types of corruptions.

        Args:
            dataset: The DICOM dataset to mutate
            num_mutations: How many mutations to apply (optional)
            severity: How aggressive the mutations should be (optional)
            strategy_names: Specific strategies to use (optional)

        Returns:
            Dataset: The mutated DICOM dataset

        """
        # LEARNING: Use defaults from config if not specified
        num_mutations = num_mutations or self.config.get("max_mutations_per_file", 3)
        severity = severity or self.config.get(
            "default_severity", MutationSeverity.MODERATE
        )

        # LEARNING: Handle both enum and string severity values
        severity_str = (
            severity.value if isinstance(severity, MutationSeverity) else severity
        )

        logger.info(f"Applying {num_mutations} mutations with {severity_str} severity")

        # OPTIMIZATION: Use Dataset.copy() instead of deepcopy for better performance
        # pydicom's copy() is optimized for DICOM datasets and 2-3x faster than deepcopy
        mutated_dataset = dataset.copy()

        # LEARNING: Get available strategies
        available_strategies = self._get_applicable_strategies(
            mutated_dataset, strategy_names
        )

        if not available_strategies:
            logger.warning("No applicable mutation strategies found")
            return mutated_dataset

        # LEARNING: Apply the requested number of mutations
        mutations_applied = 0
        for i in range(num_mutations):
            # LEARNING: Check probability to see if we should apply this mutation
            # Skip mutation if random value is greater than probability threshold
            # e.g., if probability=0.7, skip when random() > 0.7 (30% skip rate)
            if random.random() > self.config.get("mutation_probability", 0.7):
                logger.debug(f"Skipping mutation {i + 1} due to probability")
                continue

            # LEARNING: Choose a random strategy
            strategy = random.choice(available_strategies)

            try:
                # LEARNING: Apply the mutation and track it
                mutated_dataset = self._apply_single_mutation(
                    mutated_dataset, strategy, severity
                )
                mutations_applied += 1

            except Exception as e:
                logger.error(f"Mutation failed: {e}")
                # LEARNING: Record the failed mutation
                self._record_mutation(strategy, severity, success=False, error=str(e))

        logger.info(f"Successfully applied {mutations_applied} mutations")
        return mutated_dataset

    def _get_applicable_strategies(
        self, dataset: Dataset, strategy_names: list[str] | None = None
    ) -> list[MutationStrategy]:
        """LEARNING: Private method to filter strategies that can work with this dataset

        CONCEPT: Not every strategy can be applied to every file. For example,
        pixel fuzzing only works on files that have image data.

        OPTIMIZATION: Cache results based on dataset features to avoid repeated checks
        """
        # OPTIMIZATION: Create cache key from dataset features
        # This avoids re-checking strategy applicability for similar datasets
        cache_key = (
            tuple(sorted(dataset.dir())),  # Tags present in dataset
            dataset.get("Modality", None),  # Modality type
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
            # LEARNING: Check if specific strategies were requested
            if strategy_names and strategy.get_strategy_name() not in strategy_names:
                continue

            # LEARNING: Check if strategy can handle this dataset
            try:
                if strategy.can_mutate(dataset):
                    applicable.append(strategy)
                else:
                    logger.debug(
                        f"Strategy {strategy.get_strategy_name()} not applicable"
                    )
            except Exception as e:
                logger.warning(
                    f"Error checking strategy {strategy.get_strategy_name()}: {e}"
                )

        # Store in cache for future use
        self._strategy_cache[cache_key] = applicable
        logger.debug(f"Cached {len(applicable)} applicable strategies")

        return applicable

    def _apply_single_mutation(
        self, dataset: Dataset, strategy: MutationStrategy, severity: MutationSeverity
    ) -> Dataset:
        """LEARNING: Apply a single mutation and track the results

        CONCEPT: This method wraps the actual mutation with safety checks
        and logging.
        """
        logger.debug(f"Applying {strategy.get_strategy_name()} mutation")

        # LEARNING: Perform safety checks if enabled
        if self.config.get("safety_checks", True):
            if not self._is_safe_to_mutate(dataset, strategy):
                raise ValueError(
                    f"Safety check failed for {strategy.get_strategy_name()}"
                )

        # LEARNING: Apply the mutation
        mutated_dataset = strategy.mutate(dataset, severity)

        # LEARNING: Record what we did
        self._record_mutation(strategy, severity, success=True)

        return mutated_dataset

    def _is_safe_to_mutate(self, dataset: Dataset, strategy: MutationStrategy) -> bool:
        """LEARNING: Safety check to prevent dangerous mutations

        CONCEPT: Some mutations could completely break files or expose
        sensitive data. This method checks for those conditions.
        """
        # LEARNING: Check if we should preserve critical elements
        if self.config.get("preserve_critical_elements", True):
            # This would check for critical DICOM tags that shouldn't be modified
            pass

        # LEARNING: For now, always return True (we'll enhance this later)
        return True

    def _record_mutation(
        self,
        strategy: MutationStrategy,
        severity: MutationSeverity,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        """LEARNING: Record details of a mutation for tracking and analysis

        CONCEPT: This is like writing in a medical chart - we record
        everything we do for later analysis.
        """
        if not self.current_session:
            logger.warning("No active session - cannot record mutation")
            return

        # LEARNING: Create a mutation record
        # Handle both enum and string severity values
        severity_str = (
            severity.value if isinstance(severity, MutationSeverity) else severity
        )

        mutation_record = MutationRecord(
            strategy_name=strategy.get_strategy_name(),
            severity=severity,
            description=f"Applied {strategy.get_strategy_name()} with {severity_str} severity",
            success=success,
            error_message=error,
        )

        # LEARNING: Add to current session
        self.current_session.mutations.append(mutation_record)
        self.current_session.total_mutations += 1
        if success:
            self.current_session.successful_mutations += 1

        # LEARNING: Log for debugging
        logger.debug(f"Recorded mutation: {mutation_record.mutation_id}")

    def end_session(self) -> MutationSession | None:
        """LEARNING: End the current mutation session and return statistics

        Returns:
            MutationSession | None: The completed session with all records

        """
        if not self.current_session:
            logger.warning("No active session to end")
            return None

        # LEARNING: Mark the end time
        end_time = datetime.now(UTC)
        self.current_session.end_time = end_time

        # LEARNING: Log session summary
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

        # LEARNING: Return the session and clear current
        completed_session = self.current_session
        self.current_session = None

        return completed_session

    def get_session_summary(self) -> dict[str, Any] | None:
        """LEARNING: Get a summary of the current session

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


# LEARNING: This code runs when the module is imported for testing
if __name__ == "__main__":
    """
    LEARNING: Basic testing of the mutator functionality
    """
    print("Testing DICOM Mutator...")

    # Create a test mutator
    mutator = DicomMutator()

    # Test configuration
    print(f"Default config: {mutator.config}")

    # Test session management
    session_id = mutator.start_session(None, {"test": True})
    print(f"Started session: {session_id}")

    summary = mutator.get_session_summary()
    print(f"Session summary: {summary}")

    completed = mutator.end_session()
    print(f"Completed session: {completed.session_id if completed else 'None'}")

    print("Mutator testing complete!")

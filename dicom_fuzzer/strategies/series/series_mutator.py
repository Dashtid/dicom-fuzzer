"""3D DICOM Series Mutation Strategies

This module provides Series3DMutator with specialized mutation strategies
for fuzzing complete DICOM series (multi-slice 3D volumes).

MUTATION STRATEGIES (via mixins):
1-5. CoreMutationsMixin: metadata, slice position, boundary, gradient, inconsistency
6-10. Reconstruction3DAttacksMixin: orientation, gaps, overlap, aspect ratio, FoR
11-12. TemporalAttacksMixin: cross-slice reference, temporal inconsistency

SECURITY RATIONALE:
Based on 2025 CVE research (CVE-2025-35975, CVE-2025-36521, CVE-2025-5943),
DICOM viewers are vulnerable to:
- Memory corruption from malformed series metadata
- Out-of-bounds access from invalid slice positions
- Infinite loops from circular slice references
- Memory exhaustion from extreme dimensions

These strategies target the series-level parsing and rendering code paths that
individual file fuzzing cannot reach.

USAGE:
    mutator = Series3DMutator(severity="aggressive")
    fuzzed_datasets = mutator.mutate_series(series, strategy="slice_position_attack")
"""

import copy
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np
import pydicom
from pydicom.dataset import Dataset

from dicom_fuzzer.core.dicom.dicom_series import DicomSeries
from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

from .series_3d_attacks import Reconstruction3DAttacksMixin
from .series_core_mutations import CoreMutationsMixin
from .series_temporal_attacks import TemporalAttacksMixin

logger = get_logger(__name__)


class SeriesMutationStrategy(Enum):
    """Available series-level mutation strategies."""

    METADATA_CORRUPTION = "metadata_corruption"
    SLICE_POSITION_ATTACK = "slice_position_attack"
    BOUNDARY_SLICE_TARGETING = "boundary_slice_targeting"
    GRADIENT_MUTATION = "gradient_mutation"
    INCONSISTENCY_INJECTION = "inconsistency_injection"
    # v1.7.0 - 3D Reconstruction Attack Vectors
    NON_ORTHOGONAL_ORIENTATION = "non_orthogonal_orientation"
    SYSTEMATIC_SLICE_GAP = "systematic_slice_gap"
    SLICE_OVERLAP_INJECTION = "slice_overlap_injection"
    VOXEL_ASPECT_RATIO = "voxel_aspect_ratio"
    FRAME_OF_REFERENCE = "frame_of_reference"
    # v1.8.0 - Cross-Slice Reference and Temporal Attacks
    CROSS_SLICE_REFERENCE = "cross_slice_reference"
    TEMPORAL_INCONSISTENCY = "temporal_inconsistency"


@dataclass
class SeriesMutationRecord(SerializableMixin):
    """Record of a series-level mutation.

    Extends MutationRecord with series-specific information.
    """

    strategy: str
    slice_index: int | None = None  # Which slice was mutated (None = all slices)
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict[str, Any] = field(default_factory=dict)

    def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ensure values are converted to strings for JSON serialization."""
        # Convert values to strings if present (handles non-string types)
        if data.get("original_value") is not None:
            data["original_value"] = str(data["original_value"])
        if data.get("mutated_value") is not None:
            data["mutated_value"] = str(data["mutated_value"])
        return data


class Series3DMutator(
    CoreMutationsMixin, Reconstruction3DAttacksMixin, TemporalAttacksMixin
):
    """Mutator for 3D DICOM series with specialized attack strategies.

    This class implements series-level fuzzing that targets vulnerabilities
    in multi-slice DICOM loading, parsing, and rendering.

    Inherits mutation strategies from mixins:
    - CoreMutationsMixin: Strategies 1-5 (metadata, slice position, boundary, gradient, inconsistency)
    - Reconstruction3DAttacksMixin: Strategies 6-10 (orientation, gaps, overlap, aspect ratio, FoR)
    - TemporalAttacksMixin: Strategies 11-12 (cross-slice reference, temporal)
    """

    def __init__(self, severity: str = "moderate", seed: int | None = None):
        """Initialize Series3DMutator.

        Args:
            severity: Mutation severity (minimal, moderate, aggressive, extreme)
            seed: Random seed for reproducibility

        """
        if severity not in ["minimal", "moderate", "aggressive", "extreme"]:
            raise ValueError(f"Invalid severity: {severity}")

        self.severity = severity
        self.seed = seed
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        # Severity-based mutation counts
        self._mutation_counts = {
            "minimal": (1, 2),
            "moderate": (2, 5),
            "aggressive": (5, 10),
            "extreme": (10, 20),
        }

        logger.info(f"Series3DMutator initialized (severity={severity})")

    def mutate_series(
        self,
        series: DicomSeries,
        strategy: str | SeriesMutationStrategy | None = None,
        mutation_count: int | None = None,
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Mutate a complete DICOM series using specified strategy.

        Args:
            series: DicomSeries to mutate
            strategy: Mutation strategy name (random if None)
            mutation_count: Number of mutations (severity-based if None)

        Returns:
            Tuple of (list of mutated pydicom Datasets, list of mutation records)

        Raises:
            ValueError: If series is empty or strategy invalid

        """
        if not series.slices:
            raise ValueError("Cannot mutate empty series")

        # Select strategy
        if strategy is None:
            strategy = random.choice(list(SeriesMutationStrategy)).value
        elif not isinstance(strategy, str):
            strategy = strategy.value

        if strategy not in [s.value for s in SeriesMutationStrategy]:
            raise ValueError(f"Invalid strategy: {strategy}")

        # Determine mutation count
        if mutation_count is None:
            min_count, max_count = self._mutation_counts[self.severity]
            mutation_count = random.randint(min_count, max_count)

        logger.info(
            f"Mutating series with {mutation_count} mutations "
            f"(strategy={strategy}, severity={self.severity})"
        )

        # Load all datasets
        datasets = self._load_datasets(series)

        # Apply strategy
        strategy_method = {
            SeriesMutationStrategy.METADATA_CORRUPTION.value: self._mutate_metadata_corruption,
            SeriesMutationStrategy.SLICE_POSITION_ATTACK.value: self._mutate_slice_position_attack,
            SeriesMutationStrategy.BOUNDARY_SLICE_TARGETING.value: self._mutate_boundary_slice_targeting,
            SeriesMutationStrategy.GRADIENT_MUTATION.value: self._mutate_gradient_mutation,
            SeriesMutationStrategy.INCONSISTENCY_INJECTION.value: self._mutate_inconsistency_injection,
            # v1.7.0 - 3D Reconstruction Attack Vectors
            SeriesMutationStrategy.NON_ORTHOGONAL_ORIENTATION.value: self._mutate_non_orthogonal_orientation,
            SeriesMutationStrategy.SYSTEMATIC_SLICE_GAP.value: self._mutate_systematic_slice_gap,
            SeriesMutationStrategy.SLICE_OVERLAP_INJECTION.value: self._mutate_slice_overlap_injection,
            SeriesMutationStrategy.VOXEL_ASPECT_RATIO.value: self._mutate_voxel_aspect_ratio,
            SeriesMutationStrategy.FRAME_OF_REFERENCE.value: self._mutate_frame_of_reference,
            # v1.8.0 - Cross-Slice Reference and Temporal Attacks
            SeriesMutationStrategy.CROSS_SLICE_REFERENCE.value: self._mutate_cross_slice_reference,
            SeriesMutationStrategy.TEMPORAL_INCONSISTENCY.value: self._mutate_temporal_inconsistency,
        }[strategy]

        mutated_datasets, records = strategy_method(datasets, series, mutation_count)

        logger.info(f"Applied {len(records)} mutations to series")
        return mutated_datasets, records

    def _load_datasets(self, series: DicomSeries) -> list[Dataset]:
        """Load all DICOM datasets from series.

        Args:
            series: DicomSeries object

        Returns:
            List of pydicom Dataset objects (deep copies)

        """
        datasets: list[Dataset] = []
        for slice_path in series.slices:
            try:
                ds = pydicom.dcmread(slice_path)
                # Deep copy to avoid modifying original
                datasets.append(copy.deepcopy(ds))
            except Exception as e:
                logger.error(f"Failed to load slice {slice_path}: {e}")
                raise

        return datasets

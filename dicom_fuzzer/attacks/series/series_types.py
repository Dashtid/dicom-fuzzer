"""Series mutation types shared across mixin modules.

This module contains the data types used by the series mutation system,
extracted to avoid circular imports between series_mutator and its mixins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from dicom_fuzzer.core.serialization import SerializableMixin


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

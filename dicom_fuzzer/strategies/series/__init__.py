"""Series-level DICOM mutation strategies.

This subpackage contains mutators for fuzzing complete DICOM series
(multi-slice 3D volumes). Unlike slice-level fuzzing, series mutations
target cross-slice relationships and 3D reconstruction vulnerabilities.

Classes:
- Series3DMutator: Main series mutator with all strategies
- SeriesMutationRecord: Records details of applied mutations
- SeriesMutationStrategy: Enum of available strategies

Mixins (used internally by Series3DMutator):
- CoreMutationsMixin: Basic metadata and slice mutations
- Reconstruction3DAttacksMixin: 3D reconstruction attacks
- TemporalAttacksMixin: Cross-slice and temporal attacks
"""

from .series_3d_attacks import Reconstruction3DAttacksMixin
from .series_core_mutations import CoreMutationsMixin
from .series_mutator import (
    Series3DMutator,
    SeriesMutationRecord,
    SeriesMutationStrategy,
)
from .series_temporal_attacks import TemporalAttacksMixin

__all__ = [
    "Series3DMutator",
    "SeriesMutationRecord",
    "SeriesMutationStrategy",
    "CoreMutationsMixin",
    "Reconstruction3DAttacksMixin",
    "TemporalAttacksMixin",
]

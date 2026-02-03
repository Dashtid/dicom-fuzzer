"""Multi-frame mutation strategies subpackage.

This package contains modular mutation strategies for multi-frame DICOM:
- FrameCountMismatchStrategy: NumberOfFrames mismatch attacks
- FrameTimeCorruptionStrategy: Temporal information corruption
- PerFrameDimensionStrategy: Per-frame dimension mismatch
- SharedGroupStrategy: Shared functional groups corruption
- FrameIncrementStrategy: Frame increment pointer attacks
- DimensionOverflowStrategy: Integer overflow via dimensions
- FunctionalGroupStrategy: Per-frame functional group attacks
- PixelDataTruncationStrategy: Pixel data size mismatch

"""

from .base import MutationStrategyBase
from .dimension_overflow import (
    DimensionOverflowStrategy,
)
from .frame_count import (
    FrameCountMismatchStrategy,
)
from .frame_increment import (
    FrameIncrementStrategy,
)
from .frame_time import (
    FrameTimeCorruptionStrategy,
)
from .functional_group import (
    FunctionalGroupStrategy,
)
from .per_frame_dimension import (
    PerFrameDimensionStrategy,
)
from .pixel_truncation import (
    PixelDataTruncationStrategy,
)
from .shared_group import SharedGroupStrategy

__all__ = [
    # Base class
    "MutationStrategyBase",
    # Strategy implementations
    "FrameCountMismatchStrategy",
    "FrameTimeCorruptionStrategy",
    "PerFrameDimensionStrategy",
    "SharedGroupStrategy",
    "FrameIncrementStrategy",
    "DimensionOverflowStrategy",
    "FunctionalGroupStrategy",
    "PixelDataTruncationStrategy",
]

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

from dicom_fuzzer.core.multiframe_strategies.base import MutationStrategyBase
from dicom_fuzzer.core.multiframe_strategies.dimension_overflow import (
    DimensionOverflowStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.frame_count import (
    FrameCountMismatchStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.frame_increment import (
    FrameIncrementStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.frame_time import (
    FrameTimeCorruptionStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.functional_group import (
    FunctionalGroupStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.per_frame_dimension import (
    PerFrameDimensionStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.pixel_truncation import (
    PixelDataTruncationStrategy,
)
from dicom_fuzzer.core.multiframe_strategies.shared_group import SharedGroupStrategy

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

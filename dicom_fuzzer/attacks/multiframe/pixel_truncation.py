"""Pixel Data Truncation mutation strategy.

Strategy 8: Mismatch between declared frame count and actual pixel data:
- Truncate PixelData mid-frame
- Extra bytes after declared frames
- Empty PixelData with NumberOfFrames > 0

Targets: Frame extraction, buffer handling

"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord

from .base import MutationStrategyBase

if TYPE_CHECKING:
    from pydicom.dataset import Dataset


class PixelDataTruncationStrategy(MutationStrategyBase):
    """Mutation strategy for pixel data truncation attacks."""

    @property
    def strategy_name(self) -> str:
        """Return the strategy name."""
        return "pixel_data_truncation"

    def mutate(
        self,
        dataset: Dataset,
        mutation_count: int,
    ) -> tuple[Dataset, list[MultiFrameMutationRecord]]:
        """Apply pixel data truncation mutations.

        Args:
            dataset: pydicom Dataset to mutate
            mutation_count: Number of mutations to apply

        Returns:
            Tuple of (mutated Dataset, list of mutation records)

        """
        records: list[MultiFrameMutationRecord] = []

        if not hasattr(dataset, "PixelData"):
            return dataset, records

        original_size = len(dataset.PixelData)
        frame_size = self._calculate_frame_size(dataset)

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "truncate_mid_frame",
                    "truncate_partial",
                    "extra_bytes",
                    "empty_pixel_data",
                    "single_byte",
                ]
            )

            if attack_type == "truncate_mid_frame":
                # Cut pixel data in the middle of a frame
                if frame_size > 0 and original_size > frame_size:
                    cut_point = frame_size + (frame_size // 2)
                    dataset.PixelData = dataset.PixelData[:cut_point]

                    records.append(
                        MultiFrameMutationRecord(
                            strategy=self.strategy_name,
                            tag="PixelData",
                            original_value=f"{original_size} bytes",
                            mutated_value=f"{cut_point} bytes (mid-frame)",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )
                else:
                    # Fall back to single_byte when mid-frame cut isn't possible
                    dataset.PixelData = b"\x00"
                    records.append(
                        MultiFrameMutationRecord(
                            strategy=self.strategy_name,
                            tag="PixelData",
                            original_value=f"{original_size} bytes",
                            mutated_value="1 byte (mid-frame fallback)",
                            severity=self.severity,
                            details={"attack_type": "truncate_mid_frame_fallback"},
                        )
                    )

            elif attack_type == "truncate_partial":
                # Leave only partial first frame
                partial_size = frame_size // 4 if frame_size > 0 else 100
                dataset.PixelData = dataset.PixelData[:partial_size]

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value=f"{partial_size} bytes (partial frame)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extra_bytes":
                # Add random bytes after declared data
                extra = bytes(random.getrandbits(8) for _ in range(1000))
                dataset.PixelData = dataset.PixelData + extra

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value=f"{original_size + 1000} bytes (extra)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_pixel_data":
                # Empty pixel data but NumberOfFrames > 0
                dataset.PixelData = b""

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value="0 bytes (empty)",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "single_byte":
                # Only one byte of pixel data
                dataset.PixelData = b"\x00"

                records.append(
                    MultiFrameMutationRecord(
                        strategy=self.strategy_name,
                        tag="PixelData",
                        original_value=f"{original_size} bytes",
                        mutated_value="1 byte",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return dataset, records


__all__ = ["PixelDataTruncationStrategy"]

"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Targets pixel data with various corruptions to test parser robustness:
- Random noise injection
- Dimension mismatches
- Bit depth inconsistencies
- Photometric interpretation violations
- Multi-frame inconsistencies
"""

import random
import struct

import numpy as np
from pydicom.dataset import Dataset
from pydicom.tag import Tag
from pydicom.uid import (
    ExplicitVRLittleEndian,
    JPEG2000,
    JPEGBaseline8Bit,
    RLELossless,
)


class PixelFuzzer:
    """Fuzzes DICOM pixel data to test image handling robustness.

    Tests application handling of:
    - Corrupted pixel values
    - Encapsulated (compressed) pixel data malformations
    - Multi-frame inconsistencies
    - Dimension/bit depth mismatches
    """

    def __init__(self) -> None:
        """Initialize pixel fuzzer with attack patterns."""
        self.encapsulated_syntaxes = [
            JPEGBaseline8Bit,
            JPEG2000,
            RLELossless,
        ]

    def mutate_pixels(self, dataset: Dataset) -> Dataset:
        """Apply pixel data mutations to the dataset.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        mutations = [
            self._noise_injection,
            self._dimension_mismatch,
            self._bit_depth_attack,
            self._photometric_confusion,
        ]

        # Apply 1-2 mutations
        for mutation in random.sample(mutations, k=random.randint(1, 2)):
            try:
                dataset = mutation(dataset)
            except Exception:
                pass

        return dataset

    def _noise_injection(self, dataset: Dataset) -> Dataset:
        """Introduce random noise into pixel data.

        Original mutation - injects random values into pixel array.
        """
        if "PixelData" not in dataset:
            return dataset

        try:
            pixels = dataset.pixel_array.copy()
            noise_mask = np.random.random(pixels.shape) < 0.01
            noise_count = int(np.sum(noise_mask))
            pixels[noise_mask] = np.random.randint(0, 255, noise_count)
            dataset.PixelData = pixels.tobytes()
        except (ValueError, AttributeError, TypeError):
            pass

        return dataset

    def _dimension_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatch between declared dimensions and actual pixel data.

        Dimension mismatches can cause:
        - Buffer overread when reading past actual data
        - Buffer overwrite when dimensions indicate larger area
        - Integer overflow in size calculations
        """
        if "PixelData" not in dataset:
            return dataset

        attack = random.choice([
            "rows_larger",
            "columns_larger",
            "both_larger",
            "rows_zero",
            "columns_zero",
            "extreme_dimensions",
        ])

        try:
            if attack == "rows_larger":
                if hasattr(dataset, "Rows"):
                    dataset.Rows = dataset.Rows * 10
            elif attack == "columns_larger":
                if hasattr(dataset, "Columns"):
                    dataset.Columns = dataset.Columns * 10
            elif attack == "both_larger":
                if hasattr(dataset, "Rows"):
                    dataset.Rows = dataset.Rows * 5
                if hasattr(dataset, "Columns"):
                    dataset.Columns = dataset.Columns * 5
            elif attack == "rows_zero":
                dataset.Rows = 0
            elif attack == "columns_zero":
                dataset.Columns = 0
            elif attack == "extreme_dimensions":
                # Very large dimensions that may cause integer overflow
                extreme = random.choice([65535, 2147483647, 4294967295])
                if random.random() > 0.5:
                    dataset.Rows = extreme
                else:
                    dataset.Columns = extreme
        except Exception:
            pass

        return dataset

    def _bit_depth_attack(self, dataset: Dataset) -> Dataset:
        """Create inconsistencies in bit depth fields.

        Tests for:
        - BitsAllocated vs actual data size
        - BitsStored > BitsAllocated (invalid)
        - HighBit inconsistencies
        - Negative or zero bit values
        """
        attack = random.choice([
            "bits_stored_greater",
            "high_bit_invalid",
            "bits_allocated_mismatch",
            "zero_bits",
            "extreme_bits",
        ])

        try:
            if attack == "bits_stored_greater":
                # BitsStored > BitsAllocated is invalid
                if hasattr(dataset, "BitsAllocated"):
                    dataset.BitsStored = dataset.BitsAllocated + 1
            elif attack == "high_bit_invalid":
                # HighBit should be BitsStored - 1
                if hasattr(dataset, "BitsStored"):
                    dataset.HighBit = dataset.BitsStored + 10
            elif attack == "bits_allocated_mismatch":
                # Change BitsAllocated without changing pixel data
                current = getattr(dataset, "BitsAllocated", 8)
                dataset.BitsAllocated = 32 if current == 8 else 8
            elif attack == "zero_bits":
                dataset.BitsAllocated = 0
                dataset.BitsStored = 0
            elif attack == "extreme_bits":
                dataset.BitsAllocated = random.choice([1, 64, 128, 255])
        except Exception:
            pass

        return dataset

    def _photometric_confusion(self, dataset: Dataset) -> Dataset:
        """Set invalid or mismatched photometric interpretation.

        Tests for handling of:
        - Wrong photometric for actual data
        - Invalid photometric strings
        - Photometric/SamplesPerPixel mismatches
        """
        invalid_photometrics = [
            "INVALID",
            "MONOCHROME3",  # Invalid (only 1 and 2 exist)
            "RGB" if getattr(dataset, "SamplesPerPixel", 1) == 1 else "MONOCHROME2",
            "",
            "X" * 100,
            "\x00MONO",
        ]

        try:
            dataset.PhotometricInterpretation = random.choice(invalid_photometrics)
        except Exception:
            pass

        return dataset


class MultiFrameFuzzer:
    """Fuzzes multi-frame DICOM images.

    Tests handling of:
    - Frame count mismatches
    - Missing/extra frames
    - Frame-specific metadata inconsistencies
    """

    def mutate_multiframe(self, dataset: Dataset) -> Dataset:
        """Apply multi-frame specific mutations.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        mutations = [
            self._frame_count_mismatch,
            self._extreme_frame_count,
            self._per_frame_corruption,
        ]

        for mutation in random.sample(mutations, k=random.randint(1, 2)):
            try:
                dataset = mutation(dataset)
            except Exception:
                pass

        return dataset

    def _frame_count_mismatch(self, dataset: Dataset) -> Dataset:
        """Set NumberOfFrames to wrong value.

        Frame count mismatch can cause:
        - Reading past actual pixel data
        - Index out of bounds in frame arrays
        - Memory allocation issues
        """
        current_frames = getattr(dataset, "NumberOfFrames", 1)

        attack = random.choice([
            "more_frames",
            "fewer_frames",
            "zero_frames",
            "one_frame_from_multi",
        ])

        try:
            if attack == "more_frames":
                dataset.NumberOfFrames = current_frames * 10
            elif attack == "fewer_frames" and current_frames > 1:
                dataset.NumberOfFrames = 1
            elif attack == "zero_frames":
                dataset.NumberOfFrames = 0
            elif attack == "one_frame_from_multi" and current_frames > 1:
                # Claim single frame but keep multi-frame data
                dataset.NumberOfFrames = 1
        except Exception:
            pass

        return dataset

    def _extreme_frame_count(self, dataset: Dataset) -> Dataset:
        """Set extreme NumberOfFrames values.

        Tests integer overflow in frame calculations.
        """
        extreme_values = [
            2147483647,  # MAX_INT
            4294967295,  # MAX_UINT
            65535,  # MAX_USHORT
            -1,  # Negative (if signed handling is wrong)
        ]

        try:
            dataset.NumberOfFrames = random.choice(extreme_values)
        except Exception:
            pass

        return dataset

    def _per_frame_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt per-frame functional groups if present.

        Multi-frame images often have PerFrameFunctionalGroupsSequence
        with frame-specific metadata. Corrupting this tests frame lookup.
        """
        per_frame_tag = Tag(0x5200, 0x9230)  # PerFrameFunctionalGroupsSequence

        if per_frame_tag not in dataset:
            return dataset

        try:
            seq = dataset[per_frame_tag].value
            if seq and len(seq) > 0:
                corruption = random.choice([
                    "remove_items",
                    "duplicate_items",
                    "empty_items",
                ])

                if corruption == "remove_items":
                    # Remove half the items
                    while len(seq) > 1:
                        seq.pop()

                elif corruption == "duplicate_items":
                    # Duplicate first item many times
                    first = seq[0]
                    for _ in range(10):
                        seq.append(first)

                elif corruption == "empty_items":
                    # Replace with empty items
                    from pydicom.dataset import Dataset as DS
                    for i in range(len(seq)):
                        seq[i] = DS()

        except Exception:
            pass

        return dataset

"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Category: generic

Attacks:
- SamplesPerPixel mismatch and invalid values
- PlanarConfiguration manipulation
- Row/column dimension mismatch with pixel data size
- Bit depth inconsistencies (BitsAllocated, BitsStored, HighBit)
- Photometric interpretation confusion (MONOCHROME1/2, RGB, YBR)
- Raw PixelData buffer truncation
- Raw PixelData byte flipping
- Raw PixelData uniform fill (0x00 / 0xFF)
- Raw PixelData random garbage replacement
- Raw PixelData oversized buffer injection
"""

from __future__ import annotations

import os
import random

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


class PixelFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM pixel data metadata to test image handling robustness.

    Tests application handling of:
    - Dimension/bit depth mismatches
    - Photometric interpretation confusion
    - SamplesPerPixel and PlanarConfiguration manipulation
    """

    def __init__(self) -> None:
        """Initialize pixel fuzzer with attack patterns."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "pixel"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply pixel data mutations to the dataset.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        mutations = [
            self._dimension_mismatch,
            self._bit_depth_attack,
            self._photometric_confusion,
            self._samples_per_pixel_attack,
            self._planar_configuration_attack,
            self._pixel_data_truncation,
            self._pixel_data_byte_flip,
            self._pixel_data_fill_pattern,
            self._pixel_data_random_garbage,
            self._pixel_data_oversized,
        ]

        # Apply 1-2 mutations
        for mutation in random.sample(mutations, k=random.randint(1, 2)):
            try:
                dataset = mutation(dataset)
            except Exception as e:
                logger.debug("Pixel mutation %s failed: %s", mutation.__name__, e)

        return dataset

    def _samples_per_pixel_attack(self, dataset: Dataset) -> Dataset:
        """Attack SamplesPerPixel field.

        SamplesPerPixel defines number of color channels (1=grayscale, 3=RGB).
        Mismatches with actual pixel data can cause crashes.
        """
        attack = random.choice(
            [
                "mismatch_grayscale_rgb",
                "invalid_value",
                "zero_samples",
                "extreme_samples",
            ]
        )

        try:
            if attack == "mismatch_grayscale_rgb":
                # If grayscale, claim RGB; if RGB, claim grayscale
                current = getattr(dataset, "SamplesPerPixel", 1)
                dataset.SamplesPerPixel = 3 if current == 1 else 1

            elif attack == "invalid_value":
                # Values other than 1, 3, or 4 are unusual
                dataset.SamplesPerPixel = random.choice([2, 5, 7, 255])

            elif attack == "zero_samples":
                dataset.SamplesPerPixel = 0

            elif attack == "extreme_samples":
                dataset.SamplesPerPixel = random.choice([65535, 256, 128])

        except Exception as e:
            logger.debug("Samples per pixel attack failed: %s", e)

        return dataset

    def _planar_configuration_attack(self, dataset: Dataset) -> Dataset:
        """Attack PlanarConfiguration field.

        PlanarConfiguration defines pixel data organization for color images:
        0 = color-by-pixel (R1G1B1, R2G2B2, ...)
        1 = color-by-plane (R1R2..., G1G2..., B1B2...)

        Only valid when SamplesPerPixel > 1.
        """
        attack = random.choice(
            [
                "wrong_configuration",
                "invalid_value",
                "planar_without_color",
            ]
        )

        try:
            if attack == "wrong_configuration":
                # Swap between 0 and 1
                current = getattr(dataset, "PlanarConfiguration", 0)
                dataset.PlanarConfiguration = 1 if current == 0 else 0

            elif attack == "invalid_value":
                # Values other than 0 or 1 are invalid
                dataset.PlanarConfiguration = random.choice([2, 255, -1])

            elif attack == "planar_without_color":
                # Set PlanarConfiguration when SamplesPerPixel = 1
                dataset.SamplesPerPixel = 1
                dataset.PlanarConfiguration = 1

        except Exception as e:
            logger.debug("Planar configuration attack failed: %s", e)

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

        attack = random.choice(
            [
                "rows_larger",
                "columns_larger",
                "both_larger",
                "rows_zero",
                "columns_zero",
                "extreme_dimensions",
            ]
        )

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
        except Exception as e:
            logger.debug("Dimension mismatch attack failed: %s", e)

        return dataset

    def _bit_depth_attack(self, dataset: Dataset) -> Dataset:
        """Create inconsistencies in bit depth fields.

        Tests for:
        - BitsAllocated vs actual data size
        - BitsStored > BitsAllocated (invalid)
        - HighBit inconsistencies
        - Negative or zero bit values
        """
        attack = random.choice(
            [
                "bits_stored_greater",
                "high_bit_invalid",
                "bits_allocated_mismatch",
                "zero_bits",
                "extreme_bits",
            ]
        )

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
        except Exception as e:
            logger.debug("Bit depth attack failed: %s", e)

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
        except Exception as e:
            logger.debug("Photometric confusion attack failed: %s", e)

        return dataset

    def _pixel_data_truncation(self, dataset: Dataset) -> Dataset:
        """Replace PixelData with a truncated slice (10-90% of original size).

        Forces buffer-read past end of data on the viewer side when dimensions
        and declared sizes indicate more bytes than are present.
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            fraction = random.uniform(0.1, 0.9)
            dataset.PixelData = data[: max(1, int(len(data) * fraction))]
        except Exception as e:
            logger.debug("Pixel data truncation attack failed: %s", e)
        return dataset

    def _pixel_data_byte_flip(self, dataset: Dataset) -> Dataset:
        """XOR random bytes in PixelData with a random non-zero value.

        Flip count is 1% of the buffer length (minimum 1). Low crash
        probability but high anomaly surface for decode paths.
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            buf = bytearray(data)
            n_flips = max(1, min(len(buf) // 100, len(buf)))
            for i in random.sample(range(len(buf)), n_flips):
                buf[i] ^= random.randint(1, 255)
            dataset.PixelData = bytes(buf)
        except Exception as e:
            logger.debug("Pixel data byte flip attack failed: %s", e)
        return dataset

    def _pixel_data_fill_pattern(self, dataset: Dataset) -> Dataset:
        """Replace PixelData with a uniform fill of 0x00 or 0xFF.

        Tests LUT/window handling edge cases where every sample has the
        same value (black frame or saturated frame).
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            fill_byte = random.choice([0x00, 0xFF])
            dataset.PixelData = bytes([fill_byte] * len(data))
        except Exception as e:
            logger.debug("Pixel data fill pattern attack failed: %s", e)
        return dataset

    def _pixel_data_random_garbage(self, dataset: Dataset) -> Dataset:
        """Replace PixelData with cryptographically random bytes of the same length.

        Most aggressive option -- exercises all downstream pixel decode paths
        with maximally unpredictable input.
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            dataset.PixelData = os.urandom(len(data))
        except Exception as e:
            logger.debug("Pixel data random garbage attack failed: %s", e)
        return dataset

    def _pixel_data_oversized(self, dataset: Dataset) -> Dataset:
        """Append extra random bytes to PixelData (2x-4x declared size total).

        Some viewers allocate exactly the declared pixel buffer size and then
        read the full (larger) stream, causing heap overread or OOM conditions.
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            multiplier = random.uniform(2.0, 4.0)
            extra_len = max(1, int(len(data) * multiplier) - len(data))
            dataset.PixelData = data + os.urandom(extra_len)
        except Exception as e:
            logger.debug("Pixel data oversized attack failed: %s", e)
        return dataset

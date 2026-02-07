"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Targets pixel data with various corruptions to test parser robustness:
- Random noise injection
- Dimension mismatches
- Bit depth inconsistencies
- Photometric interpretation violations
- Multi-frame inconsistencies
"""

import random

import numpy as np
from pydicom.dataset import Dataset
from pydicom.uid import (
    JPEG2000,
    JPEGBaseline8Bit,
    RLELossless,
)

from .base import FormatFuzzerBase


class PixelFuzzer(FormatFuzzerBase):
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
            self._noise_injection,
            self._dimension_mismatch,
            self._bit_depth_attack,
            self._photometric_confusion,
            self._samples_per_pixel_attack,
            self._planar_configuration_attack,
        ]

        # Apply 1-2 mutations
        for mutation in random.sample(mutations, k=random.randint(1, 2)):
            try:
                dataset = mutation(dataset)
            except Exception:
                pass  # Individual mutations may fail on incompatible datasets

        return dataset

    mutate_pixels = mutate

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

        except Exception:
            pass  # Mutation may fail on incompatible datasets

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

        except Exception:
            pass  # Mutation may fail on incompatible datasets

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
            pass  # Pixel array may be unreadable or incompatible

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
        except Exception:
            pass  # Mutation may fail on incompatible datasets

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
        except Exception:
            pass  # Mutation may fail on incompatible datasets

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
            pass  # Mutation may fail on incompatible datasets

        return dataset

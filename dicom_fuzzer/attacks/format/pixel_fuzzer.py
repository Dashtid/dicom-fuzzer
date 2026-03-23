"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Category: generic

Attacks:
- SamplesPerPixel mismatch and invalid values
- PlanarConfiguration manipulation
- Row/column dimension mismatch with pixel data size
- Bit depth inconsistencies (BitsAllocated, BitsStored, HighBit)
- Photometric interpretation confusion (MONOCHROME1/2, RGB, YBR)
- PixelRepresentation sign flip and invalid values
- NumberOfFrames mismatch (declare N frames, supply data for 1)
- SmallestImagePixelValue / LargestImagePixelValue inversion and extremes
- RescaleSlope / RescaleIntercept zero, NaN, Inf, and extreme values
- WindowCenter / WindowWidth zero-width and negative-width attacks
- Multi-field extreme contradiction (allocation-math overflow attack)
- Raw PixelData buffer truncation
- Raw PixelData random garbage replacement
- Raw PixelData oversized buffer injection
- Raw PixelData byte flip (XOR ~1% of bytes)
- Raw PixelData fill pattern (uniform 0x00 or 0xFF)
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
            self._pixel_representation_attack,
            self._number_of_frames_mismatch,
            self._pixel_value_range_attack,
            self._rescale_attack,
            self._window_attack,
            self._extreme_contradiction,
            self._pixel_data_truncation,
            self._pixel_data_random_garbage,
            self._pixel_data_oversized,
            self._pixel_data_byte_flip,
            self._pixel_data_fill_pattern,
        ]

        # Apply 1-2 mutations
        selected = random.sample(mutations, k=random.randint(1, 2))
        self.last_variant = ",".join(m.__name__ for m in selected)
        for mutation in selected:
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
                dataset.Rows = 65535
            elif attack == "columns_larger":
                dataset.Columns = 65535
            elif attack == "both_larger":
                dataset.Rows = 65535
                dataset.Columns = 65535
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

    def _pixel_representation_attack(self, dataset: Dataset) -> Dataset:
        """Attack PixelRepresentation field.

        PixelRepresentation defines pixel sign convention:
        0 = unsigned integer, 1 = signed two's complement.

        Flipping sign causes display inversion and sign-extension misreads.
        Invalid values (outside 0-1) test parser validation.
        """
        attack = random.choice(["flip_sign", "invalid_value"])

        try:
            if attack == "flip_sign":
                current = getattr(dataset, "PixelRepresentation", 0)
                dataset.PixelRepresentation = 1 if current == 0 else 0
            elif attack == "invalid_value":
                dataset.PixelRepresentation = random.choice([2, 3, 255, 65535])
        except Exception as e:
            logger.debug("Pixel representation attack failed: %s", e)

        return dataset

    def _number_of_frames_mismatch(self, dataset: Dataset) -> Dataset:
        """Mismatch NumberOfFrames against actual pixel data size.

        Declares more frames than the pixel data contains, forcing viewers
        to read past the end of the buffer. Works on single-frame seeds by
        injecting a false frame count — the pixel data stays unchanged.
        """
        attack = random.choice(["over_declare", "extreme", "zero", "negative"])

        try:
            if attack == "over_declare":
                actual = int(getattr(dataset, "NumberOfFrames", 1))
                dataset.NumberOfFrames = actual * random.randint(10, 1000)
            elif attack == "extreme":
                dataset.NumberOfFrames = random.choice([65535, 2147483647])
            elif attack == "zero":
                dataset.NumberOfFrames = 0
            elif attack == "negative":
                dataset.NumberOfFrames = -1
        except Exception as e:
            logger.debug("NumberOfFrames mismatch attack failed: %s", e)

        return dataset

    def _pixel_value_range_attack(self, dataset: Dataset) -> Dataset:
        """Attack SmallestImagePixelValue and LargestImagePixelValue.

        These tags define the display range for auto-windowing. Inverted or
        zero-width ranges cause divide-by-zero and undefined behavior in
        normalization code.
        """
        attack = random.choice(
            ["inverted", "same_value", "extreme", "wider_than_bit_depth"]
        )

        try:
            if attack == "inverted":
                # Smallest > Largest: undefined behavior in auto-windowing
                dataset.SmallestImagePixelValue = 4000
                dataset.LargestImagePixelValue = 100
            elif attack == "same_value":
                # Zero-width range: divide-by-zero in normalization
                dataset.SmallestImagePixelValue = 0
                dataset.LargestImagePixelValue = 0
            elif attack == "extreme":
                dataset.SmallestImagePixelValue = -32768
                dataset.LargestImagePixelValue = 65535
            elif attack == "wider_than_bit_depth":
                bits = getattr(dataset, "BitsAllocated", 8)
                max_val = (1 << bits) - 1
                dataset.SmallestImagePixelValue = -(max_val + 1)
                dataset.LargestImagePixelValue = max_val * 2
        except Exception as e:
            logger.debug("Pixel value range attack failed: %s", e)

        return dataset

    def _rescale_attack(self, dataset: Dataset) -> Dataset:
        """Attack RescaleSlope and RescaleIntercept.

        Used in CT to convert stored pixel values to Hounsfield Units:
        HU = stored * slope + intercept.

        Zero slope triggers divide-by-zero on inverse transforms.
        NaN/Inf values crash floating-point display pipelines.
        """
        attack = random.choice(
            ["zero_slope", "nan_slope", "inf_slope", "nan_intercept", "extreme_slope"]
        )

        try:
            if attack == "zero_slope":
                dataset.RescaleSlope = "0"
            elif attack == "nan_slope":
                dataset.RescaleSlope = "NaN"
            elif attack == "inf_slope":
                dataset.RescaleSlope = "Inf"
            elif attack == "nan_intercept":
                dataset.RescaleIntercept = "NaN"
            elif attack == "extreme_slope":
                dataset.RescaleSlope = str(random.choice([1e38, -1e38, 1e-38]))
        except Exception as e:
            logger.debug("Rescale attack failed: %s", e)

        return dataset

    def _window_attack(self, dataset: Dataset) -> Dataset:
        """Attack WindowCenter and WindowWidth.

        WindowWidth = 0 causes divide-by-zero in the linear windowing formula.
        WindowWidth < 0 is invalid per DICOM PS3.3 C.7.6.3.1.5 (must be >= 1).
        """
        attack = random.choice(
            ["zero_width", "negative_width", "extreme_center", "both_zero"]
        )

        try:
            if attack == "zero_width":
                dataset.WindowWidth = "0"
            elif attack == "negative_width":
                dataset.WindowWidth = str(random.choice([-1, -255, -32768]))
            elif attack == "extreme_center":
                dataset.WindowCenter = str(random.choice([2147483647, -2147483648]))
            elif attack == "both_zero":
                dataset.WindowCenter = "0"
                dataset.WindowWidth = "0"
        except Exception as e:
            logger.debug("Window attack failed: %s", e)

        return dataset

    def _extreme_contradiction(self, dataset: Dataset) -> Dataset:
        """Set multiple conflicting pixel metadata fields simultaneously.

        Single-field attacks let parsers recover field-by-field. Contradicting
        multiple allocation-math fields at once forces code paths that assume at
        least one field is valid — maximising the product rows x cols x bits/8 x
        samples that the viewer must compute before it can detect the inconsistency.
        """
        attack = random.choice(
            [
                "overflow_allocation",
                "zero_product",
                "color_space_conflict",
                "max_all_fields",
            ]
        )

        try:
            if attack == "overflow_allocation":
                # rows(65535) * cols(65535) * bytes(4) * samples(4) ≈ 64 GB
                dataset.Rows = 65535
                dataset.Columns = 65535
                dataset.BitsAllocated = 32
                dataset.SamplesPerPixel = 4
            elif attack == "zero_product":
                # Zero in every allocation field — hits all null-check paths
                dataset.Rows = 0
                dataset.Columns = 0
                dataset.BitsAllocated = 0
                dataset.SamplesPerPixel = 0
            elif attack == "color_space_conflict":
                # MONOCHROME2 requires SamplesPerPixel=1; BitsAllocated=128 is invalid
                dataset.SamplesPerPixel = 3
                dataset.PhotometricInterpretation = "MONOCHROME2"
                dataset.BitsAllocated = 128
                dataset.Rows = 65535
            elif attack == "max_all_fields":
                # Every allocation-math field at or beyond its declared maximum
                dataset.Rows = 4294967295
                dataset.Columns = 4294967295
                dataset.BitsAllocated = 255
                dataset.SamplesPerPixel = 65535
                dataset.NumberOfFrames = 4294967295
        except Exception as e:
            logger.debug("Extreme contradiction attack failed: %s", e)

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

    def _pixel_data_byte_flip(self, dataset: Dataset) -> Dataset:
        """XOR ~1% of PixelData bytes with a random non-zero value.

        Flips a small fraction of bytes to produce a subtly corrupted buffer.
        Exercises parsers that partially validate pixel content before rendering
        — single-pixel errors are more likely to reach deep decode paths than
        total garbage or truncation.
        """
        pixel_data = getattr(dataset, "PixelData", None)
        if not pixel_data:
            return dataset
        try:
            data = bytes(pixel_data)
            n_flips = max(1, min(len(data) // 100, len(data)))
            indices = random.sample(range(len(data)), n_flips)
            buf = bytearray(data)
            for i in indices:
                buf[i] ^= random.randint(1, 255)
            dataset.PixelData = bytes(buf)
        except Exception as e:
            logger.debug("Pixel data byte flip attack failed: %s", e)
        return dataset

    def _pixel_data_fill_pattern(self, dataset: Dataset) -> Dataset:
        """Replace entire PixelData buffer with a uniform fill (0x00 or 0xFF).

        Uniform fills exercise LUT and window/level handling edge cases:
        0x00 (all black) hits min-clamp paths; 0xFF (all white) hits max-clamp
        and overflow paths. Some viewers special-case these and skip decoding.
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

"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Category: generic

Dataset-level attacks:
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
- Overlay origin negative (fo-dicom #1559)
- Overlay dimension mismatch
- Overlay bit position undefined behavior (fo-dicom #2087)

Binary-level attacks (mutate_bytes):
- Odd-length pixel data (fo-dicom #1403)
"""

from __future__ import annotations

import os
import random
import struct

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

# Binary-level constants for mutate_bytes
_PIXEL_DATA_TAG = b"\xe0\x7f\x10\x00"  # (7FE0,0010) little-endian
_UNDEFINED_LENGTH = b"\xff\xff\xff\xff"
_DICM_MAGIC = b"DICM"
_DICM_OFFSET = 128
_DATA_OFFSET = 132

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
        structural = [
            self._dimension_mismatch,  # [STRUCTURAL] buffer overread (rows/cols vs data)
            self._bit_depth_attack,  # [STRUCTURAL] allocation math violations
            self._samples_per_pixel_attack,  # [STRUCTURAL] channel count mismatch vs data size
            self._number_of_frames_mismatch,  # [STRUCTURAL] count vs actual frame data
            self._pixel_value_range_attack,  # [STRUCTURAL] divide-by-zero in normalization
            self._rescale_attack,  # [STRUCTURAL] divide-by-zero / NaN in HU pipeline
            self._window_attack,  # [STRUCTURAL] divide-by-zero in display pipeline
            self._extreme_contradiction,  # [STRUCTURAL] multi-field overflow allocation
            self._pixel_data_truncation,  # [STRUCTURAL] buffer read past end
            self._pixel_data_random_garbage,  # [STRUCTURAL] all decode paths exercised
            self._pixel_data_oversized,  # [STRUCTURAL] heap overread / OOM
            self._pixel_data_byte_flip,  # [STRUCTURAL] XOR corruption trips decoders
            self._pixel_data_fill_pattern,  # [STRUCTURAL] uniform buffer exposes decode failures
            self._negative_overlay_origin,  # [STRUCTURAL] overlay compositing IndexOutOfRange
            self._overlay_dimension_mismatch,  # [STRUCTURAL] overlay >> image dims -> OOM / overread
            self._overlay_bit_position,  # [STRUCTURAL] bit extraction UB on non-zero position
            self._palette_color_overflow,  # [STRUCTURAL] LUT descriptor count > data -> heap overflow
            self._overlay_data_truncation,  # [STRUCTURAL] OverlayData shorter than dims -> OOB read
            self._concurrent_field_mismatch,  # [STRUCTURAL] all pixel fields wrong simultaneously
        ]
        content = [
            self._photometric_confusion,  # [CONTENT] string value, parser moves on
            self._pixel_representation_attack,  # [CONTENT] sign flip, no alloc effect
            self._planar_configuration_attack,  # [CONTENT] interleave mode, display issue
        ]

        selected = random.sample(structural, k=random.randint(1, 2))
        if random.random() < 0.33:
            selected.append(random.choice(content))
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
                "highbit_exceeds_allocated",
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
            elif attack == "highbit_exceeds_allocated":
                # DCMTK CVE-2024-52333/47796: HighBit used as array index
                # without bounds check in determineMinMax(); when
                # HighBit >= BitsAllocated the index overflows the buffer.
                bits_alloc = getattr(dataset, "BitsAllocated", 8)
                dataset.HighBit = bits_alloc + random.choice([0, 7, 15, 31])
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
            # GDCM CVE-2025-53618/53619, DCMTK CVE-2025-9732: wrong color
            # conversion path selected when PI doesn't match pixel data encoding
            "YBR_FULL",
            "YBR_FULL_422",
            "YBR_PARTIAL_422",
            "YBR_ICT",
            "YBR_RCT",
            "PALETTE COLOR",
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

    def _concurrent_field_mismatch(self, dataset: Dataset) -> Dataset:
        """Set NumberOfFrames, BitsAllocated, and SamplesPerPixel all wrong.

        Parsers assume these three fields are mutually consistent
        and use their product (frames * rows * cols * samples *
        bits/8) to compute buffer sizes. When all three are wrong
        simultaneously the allocation is wildly incorrect, causing
        heap overflow or OOM that single-field attacks miss.
        """
        try:
            dataset.NumberOfFrames = random.choice([0, 999, 65535])
            dataset.BitsAllocated = random.choice([1, 3, 48, 128])
            dataset.SamplesPerPixel = random.choice([0, 5, 255])
        except Exception as e:
            logger.debug("Concurrent field mismatch failed: %s", e)
        return dataset

    # ------------------------------------------------------------------
    # Overlay attacks
    # ------------------------------------------------------------------

    def _add_overlay_scaffold(self, dataset: Dataset) -> None:
        """Set the minimum overlay tags needed for a parser to attempt rendering.

        Sets OverlayRows/Columns to match image dimensions (or 64),
        OverlayBitsAllocated to 1, OverlayOrigin to [1, 1], and
        provides minimal zero-filled OverlayData.
        """
        rows = getattr(dataset, "Rows", 64)
        cols = getattr(dataset, "Columns", 64)
        dataset.add_new(Tag(0x6000, 0x0010), "US", rows)  # OverlayRows
        dataset.add_new(Tag(0x6000, 0x0011), "US", cols)  # OverlayColumns
        dataset.add_new(Tag(0x6000, 0x0040), "CS", "G")  # OverlayType (Graphics)
        dataset.add_new(Tag(0x6000, 0x0050), "SS", [1, 1])  # OverlayOrigin
        dataset.add_new(Tag(0x6000, 0x0100), "US", 1)  # OverlayBitsAllocated
        dataset.add_new(Tag(0x6000, 0x0102), "US", 0)  # OverlayBitPosition
        # Minimal overlay data: ceil(rows * cols / 8) zero bytes
        data_len = (rows * cols + 7) // 8
        dataset.add_new(Tag(0x6000, 0x3000), "OB", b"\x00" * data_len)

    def _negative_overlay_origin(self, dataset: Dataset) -> Dataset:
        """Set OverlayOrigin to negative coordinates.

        fo-dicom #1559. Overlay compositing uses the origin as a pixel
        offset into the image buffer. Negative values cause
        IndexOutOfRangeException when the renderer indexes
        ``image[row + origin_y, col + origin_x]``.
        """
        self._add_overlay_scaffold(dataset)
        dataset[Tag(0x6000, 0x0050)].value = [-100, -100]
        return dataset

    def _overlay_dimension_mismatch(self, dataset: Dataset) -> Dataset:
        """Set OverlayRows/Columns much larger than image dimensions.

        When overlay dimensions exceed the image, the renderer either
        allocates a huge compositing buffer (OOM) or reads past the
        end of the image buffer during overlay blending.
        """
        self._add_overlay_scaffold(dataset)
        dataset[Tag(0x6000, 0x0010)].value = 64000  # OverlayRows
        dataset[Tag(0x6000, 0x0011)].value = 64000  # OverlayColumns
        # OverlayData stays small — the mismatch is the attack
        return dataset

    def _overlay_bit_position(self, dataset: Dataset) -> Dataset:
        """Set OverlayBitPosition to a non-zero value with BitsAllocated=1.

        fo-dicom #2087. When BitsAllocated is 1, the overlay bit
        extraction code computes ``(pixel >> BitPosition) & 1``.
        A non-zero BitPosition with single-bit allocation causes
        undefined behavior — the shift may exceed the word size or
        read from the wrong bit plane entirely.
        """
        self._add_overlay_scaffold(dataset)
        dataset[Tag(0x6000, 0x0102)].value = random.choice([7, 15, 31])
        return dataset

    def _palette_color_overflow(self, dataset: Dataset) -> Dataset:
        """Set PALETTE COLOR photometric with mismatched LUT descriptor.

        Orthanc CVE-2026-5443, CVE-2026-5445, GDCM CVE-2024-22391
        (TALOS-2024-1924). Sets PhotometricInterpretation to
        "PALETTE COLOR" and adds LUT descriptor tags whose declared
        entry count exceeds the actual LUT data size. The parser
        allocates based on the descriptor count but the data is
        shorter, causing a heap buffer overflow during LUT indexing.
        """
        dataset.PhotometricInterpretation = "PALETTE COLOR"
        dataset.SamplesPerPixel = 1
        dataset.BitsAllocated = 8
        dataset.BitsStored = 8
        dataset.HighBit = 7
        dataset.PixelRepresentation = 0

        # LUT descriptor: [number_of_entries, first_stored_value, bits_per_entry]
        # Claim 4096 entries but provide only 16 bytes of data.
        descriptor = [4096, 0, 16]
        small_lut_data = b"\x00" * 16  # only 8 entries worth (16 bytes / 2)

        for _color, desc_tag, data_tag in [
            ("Red", 0x1101, 0x1201),
            ("Green", 0x1102, 0x1202),
            ("Blue", 0x1103, 0x1203),
        ]:
            dataset.add_new(Tag(0x0028, desc_tag), "US", descriptor)
            dataset.add_new(Tag(0x0028, data_tag), "OW", small_lut_data)

        return dataset

    def _overlay_data_truncation(self, dataset: Dataset) -> Dataset:
        """Set full overlay dimensions but truncate OverlayData.

        fo-dicom #1728. The overlay renderer assumes OverlayData is
        at least ``ceil(OverlayRows * OverlayColumns / 8)`` bytes.
        When the data is shorter, ``BitArray.Get()`` throws
        IndexOutOfRangeException reading past the buffer end.
        """
        self._add_overlay_scaffold(dataset)
        # Scaffold set correct-length data; overwrite with 1 byte
        dataset[Tag(0x6000, 0x3000)].value = b"\xff"
        return dataset

    # ------------------------------------------------------------------
    # Binary-level odd-length pixel data attack
    # ------------------------------------------------------------------

    @staticmethod
    def _find_native_pixel_data(
        file_data: bytes,
    ) -> tuple[int, int, int] | None:
        """Locate native (non-encapsulated) Pixel Data in raw DICOM bytes.

        Returns ``(length_field_offset, value_offset, value_length)`` for
        the Pixel Data element if it has a definite (even) length, or
        ``None`` if the element is encapsulated (undefined length), absent,
        or the file is too short to parse.
        """
        idx = file_data.rfind(_PIXEL_DATA_TAG)
        if idx < 0:
            return None

        pos = idx + 4  # past the 4-byte tag

        # Explicit VR: next 2 bytes are "OW" or "OB"
        if pos + 2 <= len(file_data) and file_data[pos : pos + 2] in (b"OW", b"OB"):
            # Long-VR: VR(2) + reserved(2) + length(4)
            length_field_offset = pos + 4
        else:
            # Implicit VR: length(4) immediately after tag
            length_field_offset = pos

        if length_field_offset + 4 > len(file_data):
            return None
        length_bytes = file_data[length_field_offset : length_field_offset + 4]
        if length_bytes == _UNDEFINED_LENGTH:
            return None  # encapsulated — not native

        value_length = struct.unpack_from("<I", file_data, length_field_offset)[0]
        value_offset = length_field_offset + 4
        return length_field_offset, value_offset, value_length

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Apply binary-level pixel data mutations (odd-length attack).

        Locates native Pixel Data in the serialized byte stream and
        makes its length odd, violating DICOM Part 5 Section 8.
        Returns file_data unchanged if no native pixel data is found.
        """
        self._applied_binary_mutations = []

        if len(file_data) < _DATA_OFFSET + 4:
            return file_data
        if file_data[_DICM_OFFSET:_DATA_OFFSET] != _DICM_MAGIC:
            return file_data

        info = self._find_native_pixel_data(file_data)
        if info is None:
            return file_data

        try:
            result = self._binary_odd_length_pixel_data(file_data, info)
            if result is not file_data:
                self._applied_binary_mutations.append("_binary_odd_length_pixel_data")
            return result
        except Exception as e:
            logger.debug("Binary odd-length attack failed: %s", e)
            return file_data

    @staticmethod
    def _binary_odd_length_pixel_data(
        file_data: bytes, info: tuple[int, int, int]
    ) -> bytes:
        """Make the Pixel Data element's length field odd.

        fo-dicom #1403. DICOM Part 5 Section 8 requires all elements to
        have even length. pydicom pads values with a trailing null byte
        on write. This attack subtracts 1 from the length field and
        removes the last (padding) byte, producing a structurally valid
        but spec-violating odd-length element that triggers padding/
        truncation bugs in parsers and transcoders.
        """
        length_field_offset, value_offset, value_length = info

        if value_length == 0 or value_length % 2 != 0:
            return file_data  # already odd or empty

        value_end = value_offset + value_length
        if value_end > len(file_data):
            return file_data

        new_length = value_length - 1
        result = bytearray(file_data)
        struct.pack_into("<I", result, length_field_offset, new_length)
        # Remove the last byte (the padding byte pydicom added)
        result = result[: value_end - 1] + result[value_end:]
        return bytes(result)

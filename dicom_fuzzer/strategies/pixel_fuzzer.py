"""Pixel Fuzzer - DICOM Pixel Data Mutations.

Targets pixel data with various corruptions including:
- Random noise injection
- Encapsulated pixel data fragment attacks (CVE-2025-11266 pattern)
- Multi-frame inconsistencies
- Dimension mismatches
- Bit depth inconsistencies

Based on CVE patterns:
- CVE-2025-11266 (GDCM): Out-of-bounds write in encapsulated PixelData fragments
- Integer underflow in fragment offset calculations
- Buffer overread from dimension mismatches
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


class EncapsulatedPixelFuzzer:
    """Fuzzes encapsulated (compressed) pixel data.

    Targets the fragment structure of compressed DICOM images.
    Based on CVE-2025-11266: Out-of-bounds write in GDCM from
    malformed encapsulated PixelData fragments.
    """

    def create_encapsulated_attacks(self) -> list[tuple[str, bytes]]:
        """Create binary attacks for encapsulated pixel data.

        Returns list of (attack_name, bytes) for injection into DICOM files.
        These attacks target the Basic Offset Table and fragment structure.
        """
        attacks = []

        # PixelData tag for encapsulated data
        pixel_tag = b"\xE0\x7F\x10\x00"  # (7FE0,0010) little endian

        # Attack 1: Empty Basic Offset Table with fragments
        empty_bot = (
            pixel_tag
            + b"OB"  # VR
            + b"\x00\x00"  # Reserved
            + b"\xFF\xFF\xFF\xFF"  # Undefined length
            # Item for BOT (empty)
            + b"\xFE\xFF\x00\xE0"  # Item tag
            + b"\x00\x00\x00\x00"  # Zero length
            # Fragment with data
            + b"\xFE\xFF\x00\xE0"  # Item tag
            + b"\x10\x00\x00\x00"  # Length 16
            + b"\xFF" * 16  # Fragment data
            # Sequence delimiter
            + b"\xFE\xFF\xDD\xE0"
            + b"\x00\x00\x00\x00"
        )
        attacks.append(("empty_bot", empty_bot))

        # Attack 2: Fragment with zero length
        zero_fragment = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT
            + b"\xFE\xFF\x00\xE0\x00\x00\x00\x00"
            # Zero-length fragment
            + b"\xFE\xFF\x00\xE0"
            + b"\x00\x00\x00\x00"  # Zero length
            # Delimiter
            + b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"
        )
        attacks.append(("zero_length_fragment", zero_fragment))

        # Attack 3: Fragment with 0xFFFFFFFF length (undefined)
        undefined_fragment = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT
            + b"\xFE\xFF\x00\xE0\x00\x00\x00\x00"
            # Undefined length fragment
            + b"\xFE\xFF\x00\xE0"
            + b"\xFF\xFF\xFF\xFF"  # Undefined length
            + b"\xFF" * 100  # Some data
            # Item delimiter (required for undefined length)
            + b"\xFE\xFF\x0D\xE0\x00\x00\x00\x00"
            # Sequence delimiter
            + b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"
        )
        attacks.append(("undefined_length_fragment", undefined_fragment))

        # Attack 4: Missing sequence delimiter
        missing_delim = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT
            + b"\xFE\xFF\x00\xE0\x00\x00\x00\x00"
            # Fragment
            + b"\xFE\xFF\x00\xE0"
            + b"\x10\x00\x00\x00"
            + b"\xFF" * 16
            # NO sequence delimiter - parser should detect EOF
        )
        attacks.append(("missing_sequence_delimiter", missing_delim))

        # Attack 5: Overlapping fragment offsets in BOT
        # BOT with offsets that point to overlapping regions
        overlapping_bot = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT with 3 offsets pointing to overlapping positions
            + b"\xFE\xFF\x00\xE0"
            + b"\x0C\x00\x00\x00"  # BOT length = 12 (3 x 4 bytes)
            + struct.pack("<I", 0)  # Offset 0
            + struct.pack("<I", 8)  # Offset 8 (overlaps)
            + struct.pack("<I", 4)  # Offset 4 (overlaps with both)
            # Fragments
            + b"\xFE\xFF\x00\xE0\x20\x00\x00\x00" + b"\xFF" * 32
            # Delimiter
            + b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"
        )
        attacks.append(("overlapping_offsets", overlapping_bot))

        # Attack 6: Very large offset (integer underflow potential)
        large_offset_bot = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT with very large offset
            + b"\xFE\xFF\x00\xE0"
            + b"\x04\x00\x00\x00"  # BOT length = 4
            + struct.pack("<I", 0x7FFFFFFF)  # Large offset (2GB-1)
            # Small fragment (offset points way past this)
            + b"\xFE\xFF\x00\xE0\x10\x00\x00\x00" + b"\xFF" * 16
            # Delimiter
            + b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"
        )
        attacks.append(("large_offset", large_offset_bot))

        # Attack 7: Negative offset (as unsigned = very large)
        negative_offset_bot = (
            pixel_tag
            + b"OB\x00\x00"
            + b"\xFF\xFF\xFF\xFF"
            # BOT with "negative" offset
            + b"\xFE\xFF\x00\xE0"
            + b"\x04\x00\x00\x00"
            + struct.pack("<i", -1)  # -1 as signed = 0xFFFFFFFF
            # Fragment
            + b"\xFE\xFF\x00\xE0\x10\x00\x00\x00" + b"\xFF" * 16
            # Delimiter
            + b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"
        )
        attacks.append(("negative_offset", negative_offset_bot))

        return attacks


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

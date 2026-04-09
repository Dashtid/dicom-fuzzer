"""Empty Value Fuzzer - Present-but-empty DICOM tag mutations.

Category: generic (structural)

Targets the .NET "present but empty" crash pattern: a DICOM element
exists in the dataset with a zero-length value, and .NET parsers call
`element.Get<T>()` (or equivalent) without null/empty checks, producing
IndexOutOfRangeException, NullReferenceException, or division-by-zero.

Every attack here maps to a fixed fo-dicom issue or CVE, giving each
mutation a concrete real-world crash footprint to emulate:

- _empty_pixel_spacing           -> fo-dicom #2043 (fixed 5.2.5)
- _empty_voi_lut_function        -> fo-dicom #1891 (fixed 5.2.0)
- _empty_specific_charset        -> fo-dicom #1879 (fixed 5.1.4)
- _empty_image_position          -> fo-dicom #2067
- _empty_image_orientation       -> fo-dicom #2067
- _zero_window_width             -> fo-dicom #1905
- _comma_decimal_string          -> fo-dicom #1296
- _empty_shared_functional_group -> fo-dicom #1884 (fixed 5.1.5)
- _empty_window_center           -> null reference in LUT pipeline

All nine attacks are STRUCTURAL: they exercise parser/renderer code
paths that assume the element, if present, has at least one value.
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import BaseTag, Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)


class EmptyValueFuzzer(FormatFuzzerBase):
    """Fuzzer that injects present-but-empty (zero-length) DICOM elements.

    Each attack adds the target tag to the dataset with an empty value
    instead of deleting it. This triggers the ".NET Get<T>() without
    null/empty check" crash family that has produced nine distinct
    fo-dicom crashes across the 5.x release train.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "empty_value"

    def __init__(self) -> None:
        """Initialize EmptyValueFuzzer."""
        super().__init__()
        # Target tag for post-serialize comma-decimal substitution (set by
        # _comma_decimal_string in mutate(), consumed and cleared by
        # mutate_bytes()). pydicom rejects "1,5" at the Dataset level because
        # DS values are parsed as floats on assignment, so this attack has
        # to patch the raw bytes after dcmwrite.
        self._comma_target_tag: BaseTag | None = None

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply present-but-empty mutations (FormatFuzzerBase interface).

        Picks one structural attack per call (occasionally two, matching
        peer fuzzers' 33% double-attack rate). Every attack in the pool
        is structural, so no content/structural split is needed here.
        """
        structural = [
            self._empty_pixel_spacing,  # [STRUCTURAL] ImageData ctor null deref
            self._empty_voi_lut_function,  # [STRUCTURAL] "must contain a single value" crash
            self._empty_specific_charset,  # [STRUCTURAL] GetEncodings()[0] index-out-of-range
            self._empty_image_position,  # [STRUCTURAL] geometry pipeline null deref
            self._empty_image_orientation,  # [STRUCTURAL] geometry pipeline null deref
            self._zero_window_width,  # [STRUCTURAL] divide-by-zero in windowing
            self._comma_decimal_string,  # [STRUCTURAL] locale-specific DS parse crash
            self._empty_shared_functional_group,  # [STRUCTURAL] FunctionalGroupValues[0] OOB
            self._empty_window_center,  # [STRUCTURAL] LUT pipeline null deref
        ]

        selected = random.sample(structural, k=1)
        if random.random() < 0.33:
            remaining = [a for a in structural if a not in selected]
            selected.append(random.choice(remaining))

        applied: list[str] = []
        for attack in selected:
            try:
                dataset = attack(dataset)
                applied.append(attack.__name__)
            except Exception as e:
                logger.debug("EmptyValue %s failed: %s", attack.__name__, e)
        self.last_variant = ",".join(applied) if applied else None

        return dataset

    def _empty_pixel_spacing(self, dataset: Dataset) -> Dataset:
        """Set (0028,0030) PixelSpacing to empty.

        fo-dicom #2043 (fixed 5.2.5). ImageData construction tries to
        index PixelSpacing[0] and crashes when the element is present
        but has zero values.
        """
        dataset.add_new(Tag(0x0028, 0x0030), "DS", "")
        return dataset

    def _empty_voi_lut_function(self, dataset: Dataset) -> Dataset:
        """Set (0028,1056) VOILUTFunction to empty.

        fo-dicom #1891 (fixed 5.2.0). VOI LUT application path raises
        'must contain a single value, but contains 0' when the element
        exists with no values.
        """
        dataset.add_new(Tag(0x0028, 0x1056), "CS", "")
        return dataset

    def _empty_specific_charset(self, dataset: Dataset) -> Dataset:
        """Set (0008,0005) SpecificCharacterSet to empty.

        fo-dicom #1879 (fixed 5.1.4). Charset lookup calls
        GetEncodings()[0], triggering IndexOutOfRangeException.
        """
        dataset.add_new(Tag(0x0008, 0x0005), "CS", "")
        return dataset

    def _empty_image_position(self, dataset: Dataset) -> Dataset:
        """Set (0020,0032) ImagePositionPatient to empty.

        fo-dicom #2067. Geometry pipeline assumes three DS values and
        null-derefs when the element is present but empty.
        """
        dataset.add_new(Tag(0x0020, 0x0032), "DS", "")
        return dataset

    def _empty_image_orientation(self, dataset: Dataset) -> Dataset:
        """Set (0020,0037) ImageOrientationPatient to empty.

        fo-dicom #2067. Geometry pipeline assumes six DS values
        (two direction cosines) and null-derefs on empty element.
        """
        dataset.add_new(Tag(0x0020, 0x0037), "DS", "")
        return dataset

    def _zero_window_width(self, dataset: Dataset) -> Dataset:
        """Set (0028,1051) WindowWidth to 0, 0.001, or -1.

        fo-dicom #1905. Windowing formula (pixel - center) / width
        divides by zero; negative widths invert rendering.
        """
        value = random.choice(["0", "0.001", "-1"])
        dataset.add_new(Tag(0x0028, 0x1051), "DS", value)
        return dataset

    def _comma_decimal_string(self, dataset: Dataset) -> Dataset:
        """Flag a DS-VR tag for post-serialize '.' -> ',' substitution.

        fo-dicom #1296. Locale-specific parsers (de-DE, fr-FR) accept
        comma as decimal separator and crash on '1.5'; inverse-locale
        parsers crash on '1,5'. Either way the DS value fails to round-
        trip through float.Parse / double.Parse.

        pydicom validates DS values as floats on assignment, so "1,5"
        cannot be injected at the Dataset level. Instead we set a valid
        float value here (ensuring the element is present with a period-
        formatted decimal) and record the target tag; mutate_bytes()
        then does the '.' -> ',' substitution on the serialized bytes.
        """
        candidates: list[tuple[BaseTag, float | list[float]]] = [
            (Tag(0x0018, 0x0050), 1.5),  # SliceThickness
            (Tag(0x0028, 0x0030), [0.5, 0.5]),  # PixelSpacing
            (Tag(0x0020, 0x1041), 12.75),  # SliceLocation
        ]
        tag, value = random.choice(candidates)
        dataset.add_new(tag, "DS", value)
        self._comma_target_tag = tag
        return dataset

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Post-serialize binary patching for the comma-decimal attack.

        If _comma_decimal_string was selected during mutate(), locate the
        target tag in the serialized byte stream (Explicit VR LE) and
        replace every '.' byte in its value with a ',' byte. 1:1 byte
        substitution preserves the length field, so no re-length is
        needed.

        All other EmptyValueFuzzer attacks modify the Dataset directly
        and don't need binary post-processing; this override is a no-op
        when no comma target is pending.
        """
        self._applied_binary_mutations = []
        if self._comma_target_tag is None:
            return file_data
        target = self._comma_target_tag
        self._comma_target_tag = None  # consume once we know we have a target

        # Explicit VR LE short-VR header:
        #   group_lo group_hi elem_lo elem_hi 'D' 'S' len_lo len_hi
        header = bytes(
            [
                target.group & 0xFF,
                (target.group >> 8) & 0xFF,
                target.element & 0xFF,
                (target.element >> 8) & 0xFF,
                ord("D"),
                ord("S"),
            ]
        )
        idx = file_data.find(header)
        if idx < 0:
            # Tag not present (seed may use implicit VR, or the add_new
            # value got dropped during write). Silently skip.
            return file_data

        len_offset = idx + 6
        if len_offset + 2 > len(file_data):
            return file_data
        value_length = int.from_bytes(file_data[len_offset : len_offset + 2], "little")
        value_offset = len_offset + 2
        value_end = value_offset + value_length
        if value_end > len(file_data):
            return file_data

        value_bytes = file_data[value_offset:value_end]
        new_value = value_bytes.replace(b".", b",")
        if new_value == value_bytes:
            return file_data

        self._applied_binary_mutations.append("_comma_decimal_string")
        return file_data[:value_offset] + new_value + file_data[value_end:]

    def _empty_shared_functional_group(self, dataset: Dataset) -> Dataset:
        """Set (5200,9229) SharedFunctionalGroupsSequence to empty Sequence.

        fo-dicom #1884 (fixed 5.1.5). Multi-frame readers access
        SharedFunctionalGroups[0].<inner> and raise IndexOutOfBounds
        when the sequence is present but has zero items.
        """
        dataset.add_new(Tag(0x5200, 0x9229), "SQ", Sequence([]))
        return dataset

    def _empty_window_center(self, dataset: Dataset) -> Dataset:
        """Set (0028,1050) WindowCenter to empty.

        LUT pipeline null-dereferences when WindowCenter is present
        but has zero values, since the rendering code assumes at least
        one preset is available.
        """
        dataset.add_new(Tag(0x0028, 0x1050), "DS", "")
        return dataset


__all__ = ["EmptyValueFuzzer"]

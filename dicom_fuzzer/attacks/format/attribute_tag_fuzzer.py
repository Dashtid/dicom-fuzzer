"""Attribute Tag Fuzzer - DICOM AT VR pointer-semantics mutations.

Category: generic

The DICOM AT (Attribute Tag) VR encodes a pointer to another DICOM tag as
a 4-byte ``(group, element)`` pair. Standard tags using AT include
DimensionIndexPointer (0020,9165), FunctionalGroupPointer (0020,9167) and
OffendingElement (0000,0901). Parsers and downstream consumers commonly
assume the *target* tag exists and is well-formed; attacks against that
assumption are not covered by HeaderFuzzer (which mutates AT *length*
encoding) or ReferenceFuzzer (which targets UI-typed cross-references).

Attacks (Dataset-level):
- Repoint AT values at a nonexistent tag (e.g. (0xFFFF, 0xFFFF)) — exercises
  resolver error paths.
- Repoint AT values at the AT element's own tag — creates a self-pointer
  loop; resolvers that walk pointers without cycle detection may recurse.
- Repoint AT values at a private tag not present in this dataset — forces
  a private-dictionary lookup miss on the target.
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.tag import BaseTag, Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Standard AT-typed tag we add when the input dataset has none. Multi-frame
# Enhanced SOP Classes use DimensionIndexPointer to identify the dimension
# this index entry refers to, so an AT element here is type-legal.
_FALLBACK_AT_TAG = Tag(0x0020, 0x9165)  # DimensionIndexPointer

# A tag that is extremely unlikely to be defined in any dataset. Group
# 0xFFFF is reserved per PS3.5 and not used by any standard or private
# allocation we have observed.
_NONEXISTENT_TAG = Tag(0xFFFF, 0xFFFF)

# Private tag (odd group) that no real dataset is expected to define.
# Group 0x0009 is private, element 0x10FF is past the typical creator-block
# range so resolvers that consult a private dictionary will miss.
_UNDEFINED_PRIVATE_TAG = Tag(0x0009, 0x10FF)


class AttributeTagFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Attribute Tag (AT VR) values.

    Targets the pointer-semantics of AT-typed elements: the *value* of an
    AT element is itself a DICOM tag, which downstream code resolves. The
    fuzzer rewrites those values to point at tags that don't exist, point
    at themselves, or point at private tags not present in the dataset.
    """

    def __init__(self) -> None:
        """Initialize the AT fuzzer with attack patterns."""
        super().__init__()
        self.mutation_strategies = [
            self._at_to_nonexistent,  # repoint at (FFFF,FFFF)
            self._at_to_self,  # repoint at the AT element's own tag
            self._at_to_private,  # repoint at an undefined private tag
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "attribute_tag"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply an AT pointer-semantics mutation to the dataset.

        If no AT-typed element exists, a fallback DimensionIndexPointer is
        added first so the chosen strategy always has a target.
        """
        strategy = random.choice(self.mutation_strategies)
        self.last_variant = strategy.__name__
        try:
            dataset = strategy(dataset)
        except Exception as e:
            logger.debug("AT mutation %s failed: %s", strategy.__name__, e)
        return dataset

    def _find_at_elements(self, dataset: Dataset) -> list[BaseTag]:
        """Return the tags of every AT-typed element in the dataset."""
        return [
            tag
            for tag, elem in dataset.items()
            if hasattr(elem, "VR") and elem.VR == "AT"
        ]

    def _ensure_at_element(self, dataset: Dataset) -> BaseTag:
        """Guarantee at least one AT element exists; return its tag.

        When the input dataset has no AT-typed element, add
        DimensionIndexPointer so subsequent strategies have a target.
        """
        existing = self._find_at_elements(dataset)
        if existing:
            return existing[0]
        dataset.add_new(_FALLBACK_AT_TAG, "AT", Tag(0x0028, 0x0010))
        return _FALLBACK_AT_TAG

    def _at_to_nonexistent(self, dataset: Dataset) -> Dataset:
        """Repoint every AT value at (FFFF, FFFF).

        Group 0xFFFF is reserved and never appears in real datasets, so
        resolvers that look up the target will miss. Tests the resolver's
        not-found path, which on poorly-written code paths can throw an
        unhandled exception or return a default that surprises callers.
        """
        target = self._ensure_at_element(dataset)
        for tag in self._find_at_elements(dataset):
            dataset[tag].value = _NONEXISTENT_TAG
        # Touch the ensured tag specifically so the test fixture sees a
        # change even if the dataset already had AT elements that the
        # loop above already rewrote.
        dataset[target].value = _NONEXISTENT_TAG
        return dataset

    def _at_to_self(self, dataset: Dataset) -> Dataset:
        """Repoint every AT value at its own element's tag.

        The AT element points at itself: `dataset[(0020,9165)].value =
        (0020,9165)`. Code that walks the pointer chain without a visited
        set may recurse indefinitely; code that materialises the target
        eagerly may infinite-loop.
        """
        self._ensure_at_element(dataset)
        for tag in self._find_at_elements(dataset):
            dataset[tag].value = Tag(tag)
        return dataset

    def _at_to_private(self, dataset: Dataset) -> Dataset:
        """Repoint every AT value at an undefined private tag.

        Resolvers that consult a private dictionary will fail to find the
        target. Path coverage in private-tag resolution is generally
        thinner than in the standard-dictionary path, so missed lookups
        here may surface different bugs than the (FFFF,FFFF) case.
        """
        self._ensure_at_element(dataset)
        for tag in self._find_at_elements(dataset):
            dataset[tag].value = _UNDEFINED_PRIVATE_TAG
        return dataset

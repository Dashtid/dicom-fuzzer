#!/usr/bin/env python3
"""DICOM Network Seed Corpus Generator.

Generates seed files for network protocol fuzzing containing valid DICOM
PDUs for C-STORE, C-FIND, C-GET, C-MOVE, and C-ECHO operations.

These seeds can be used with:
- AFLNet for stateful protocol fuzzing
- The dicom_network_harness.py for mutation-based fuzzing
- Manual replay and debugging

Usage:
    python seed_generator.py --output ./network_seeds
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


class DicomSeedGenerator:
    """Generate DICOM network protocol seed files."""

    # Standard DICOM UIDs
    VERIFICATION_SOP_CLASS = "1.2.840.10008.1.1"
    CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"
    MR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.4"
    PATIENT_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.1.1"
    STUDY_ROOT_QR_FIND = "1.2.840.10008.5.1.4.1.2.2.1"
    PATIENT_ROOT_QR_GET = "1.2.840.10008.5.1.4.1.2.1.3"
    PATIENT_ROOT_QR_MOVE = "1.2.840.10008.5.1.4.1.2.1.2"
    IMPLICIT_VR_LE = "1.2.840.10008.1.2"
    EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
    APP_CONTEXT = "1.2.840.10008.3.1.1.1"

    def __init__(
        self,
        calling_ae: str = "FUZZER",
        called_ae: str = "ORTHANC",
    ) -> None:
        self.calling_ae = calling_ae.ljust(16)[:16]
        self.called_ae = called_ae.ljust(16)[:16]

    def _build_item(self, item_type: int, data: bytes) -> bytes:
        """Build a variable item (Type + Reserved + Length + Data)."""
        return struct.pack(">BBH", item_type, 0, len(data)) + data

    def _build_pdu(self, pdu_type: int, data: bytes) -> bytes:
        """Build a complete PDU (Type + Reserved + Length + Data)."""
        return struct.pack(">BBL", pdu_type, 0, len(data)) + data

    def _build_element_implicit(
        self, group: int, element: int, value: bytes | str
    ) -> bytes:
        """Build DICOM element in Implicit VR Little Endian."""
        if isinstance(value, str):
            value = value.encode("ascii")
            if len(value) % 2:
                value += b" "  # Pad string with space
        return struct.pack("<HHL", group, element, len(value)) + value

    def _build_pdv(
        self, context_id: int, data: bytes, is_command: bool, is_last: bool
    ) -> bytes:
        """Build Presentation Data Value item."""
        mch = 0x00
        if is_command:
            mch |= 0x01
        if is_last:
            mch |= 0x02
        pdv_length = 2 + len(data)
        return struct.pack(">LBB", pdv_length, context_id, mch) + data

    def generate_associate_rq(
        self,
        abstract_syntax: str = VERIFICATION_SOP_CLASS,
        transfer_syntaxes: list[str] | None = None,
    ) -> bytes:
        """Generate A-ASSOCIATE-RQ PDU."""
        if transfer_syntaxes is None:
            transfer_syntaxes = [self.IMPLICIT_VR_LE, self.EXPLICIT_VR_LE]

        # Header
        data = struct.pack(">H", 1)  # Protocol version
        data += b"\x00\x00"  # Reserved
        data += self.called_ae.encode("ascii")
        data += self.calling_ae.encode("ascii")
        data += b"\x00" * 32  # Reserved

        # Application Context
        data += self._build_item(0x10, self.APP_CONTEXT.encode("ascii"))

        # Presentation Context
        pc_data = struct.pack(">BBH", 1, 0, 0)  # PC-ID=1
        pc_data += self._build_item(0x30, abstract_syntax.encode("ascii"))
        for ts in transfer_syntaxes:
            pc_data += self._build_item(0x40, ts.encode("ascii"))
        data += self._build_item(0x20, pc_data)

        # User Information
        user_info = self._build_item(0x51, struct.pack(">L", 16384))  # Max PDU
        user_info += self._build_item(0x52, b"1.2.3.4.5.6.7.8.9")  # Impl Class
        user_info += self._build_item(0x55, b"DICOM_FUZZER")  # Impl Version
        data += self._build_item(0x50, user_info)

        return self._build_pdu(0x01, data)

    def generate_associate_rq_multi_pc(self) -> bytes:
        """Generate A-ASSOCIATE-RQ with multiple presentation contexts."""
        data = struct.pack(">H", 1)
        data += b"\x00\x00"
        data += self.called_ae.encode("ascii")
        data += self.calling_ae.encode("ascii")
        data += b"\x00" * 32

        data += self._build_item(0x10, self.APP_CONTEXT.encode("ascii"))

        # Multiple presentation contexts
        sop_classes = [
            (1, self.VERIFICATION_SOP_CLASS),
            (3, self.CT_IMAGE_STORAGE),
            (5, self.MR_IMAGE_STORAGE),
            (7, self.PATIENT_ROOT_QR_FIND),
            (9, self.STUDY_ROOT_QR_FIND),
        ]

        for pc_id, sop_class in sop_classes:
            pc_data = struct.pack(">BBH", pc_id, 0, 0)
            pc_data += self._build_item(0x30, sop_class.encode("ascii"))
            pc_data += self._build_item(0x40, self.IMPLICIT_VR_LE.encode("ascii"))
            pc_data += self._build_item(0x40, self.EXPLICIT_VR_LE.encode("ascii"))
            data += self._build_item(0x20, pc_data)

        user_info = self._build_item(0x51, struct.pack(">L", 16384))
        user_info += self._build_item(0x52, b"1.2.3.4.5.6.7.8.9")
        data += self._build_item(0x50, user_info)

        return self._build_pdu(0x01, data)

    def generate_c_echo_rq(self, message_id: int = 1) -> bytes:
        """Generate C-ECHO-RQ command in P-DATA-TF PDU."""
        # Build command dataset
        cmd = b""
        cmd += self._build_element_implicit(0x0000, 0x0002, self.VERIFICATION_SOP_CLASS)
        cmd += self._build_element_implicit(0x0000, 0x0100, struct.pack("<H", 0x0030))
        cmd += self._build_element_implicit(
            0x0000, 0x0110, struct.pack("<H", message_id)
        )
        cmd += self._build_element_implicit(0x0000, 0x0800, struct.pack("<H", 0x0101))

        # Add CommandGroupLength
        length_elem = self._build_element_implicit(
            0x0000, 0x0000, struct.pack("<L", len(cmd))
        )
        cmd = length_elem + cmd

        pdv = self._build_pdv(1, cmd, is_command=True, is_last=True)
        return self._build_pdu(0x04, pdv)

    def generate_c_find_rq(
        self,
        message_id: int = 1,
        patient_name: str = "*",
        patient_id: str = "",
    ) -> bytes:
        """Generate C-FIND-RQ with query dataset."""
        # Command
        cmd = b""
        cmd += self._build_element_implicit(0x0000, 0x0002, self.PATIENT_ROOT_QR_FIND)
        cmd += self._build_element_implicit(0x0000, 0x0100, struct.pack("<H", 0x0020))
        cmd += self._build_element_implicit(
            0x0000, 0x0110, struct.pack("<H", message_id)
        )
        cmd += self._build_element_implicit(
            0x0000, 0x0700, struct.pack("<H", 0)
        )  # Priority
        cmd += self._build_element_implicit(
            0x0000, 0x0800, struct.pack("<H", 0)
        )  # Has dataset

        length_elem = self._build_element_implicit(
            0x0000, 0x0000, struct.pack("<L", len(cmd))
        )
        cmd = length_elem + cmd

        # Query dataset
        dataset = b""
        dataset += self._build_element_implicit(
            0x0008, 0x0052, "PATIENT"
        )  # Query Level
        dataset += self._build_element_implicit(
            0x0010, 0x0010, patient_name
        )  # Patient Name
        if patient_id:
            dataset += self._build_element_implicit(0x0010, 0x0020, patient_id)

        # PDVs
        cmd_pdv = self._build_pdv(1, cmd, is_command=True, is_last=True)
        data_pdv = self._build_pdv(1, dataset, is_command=False, is_last=True)

        return self._build_pdu(0x04, cmd_pdv + data_pdv)

    def generate_c_store_rq(
        self,
        message_id: int = 1,
        sop_class: str = CT_IMAGE_STORAGE,
        sop_instance: str = "1.2.3.4.5.6.7.8.9.10",
    ) -> bytes:
        """Generate C-STORE-RQ with minimal dataset."""
        # Command
        cmd = b""
        cmd += self._build_element_implicit(0x0000, 0x0002, sop_class)
        cmd += self._build_element_implicit(0x0000, 0x0100, struct.pack("<H", 0x0001))
        cmd += self._build_element_implicit(
            0x0000, 0x0110, struct.pack("<H", message_id)
        )
        cmd += self._build_element_implicit(0x0000, 0x0700, struct.pack("<H", 0))
        cmd += self._build_element_implicit(0x0000, 0x0800, struct.pack("<H", 0))
        cmd += self._build_element_implicit(0x0000, 0x1000, sop_instance)

        length_elem = self._build_element_implicit(
            0x0000, 0x0000, struct.pack("<L", len(cmd))
        )
        cmd = length_elem + cmd

        # Minimal dataset
        dataset = b""
        dataset += self._build_element_implicit(0x0008, 0x0016, sop_class)
        dataset += self._build_element_implicit(0x0008, 0x0018, sop_instance)
        dataset += self._build_element_implicit(0x0010, 0x0010, "Test^Patient")
        dataset += self._build_element_implicit(0x0010, 0x0020, "12345")

        cmd_pdv = self._build_pdv(1, cmd, is_command=True, is_last=True)
        data_pdv = self._build_pdv(1, dataset, is_command=False, is_last=True)

        return self._build_pdu(0x04, cmd_pdv + data_pdv)

    def generate_c_get_rq(self, message_id: int = 1) -> bytes:
        """Generate C-GET-RQ command."""
        cmd = b""
        cmd += self._build_element_implicit(0x0000, 0x0002, self.PATIENT_ROOT_QR_GET)
        cmd += self._build_element_implicit(0x0000, 0x0100, struct.pack("<H", 0x0010))
        cmd += self._build_element_implicit(
            0x0000, 0x0110, struct.pack("<H", message_id)
        )
        cmd += self._build_element_implicit(0x0000, 0x0700, struct.pack("<H", 0))
        cmd += self._build_element_implicit(0x0000, 0x0800, struct.pack("<H", 0))

        length_elem = self._build_element_implicit(
            0x0000, 0x0000, struct.pack("<L", len(cmd))
        )
        cmd = length_elem + cmd

        # Query identifier
        dataset = b""
        dataset += self._build_element_implicit(0x0008, 0x0052, "PATIENT")
        dataset += self._build_element_implicit(0x0010, 0x0020, "12345")

        cmd_pdv = self._build_pdv(1, cmd, is_command=True, is_last=True)
        data_pdv = self._build_pdv(1, dataset, is_command=False, is_last=True)

        return self._build_pdu(0x04, cmd_pdv + data_pdv)

    def generate_c_move_rq(
        self, message_id: int = 1, move_destination: str = "STORAGE"
    ) -> bytes:
        """Generate C-MOVE-RQ command."""
        cmd = b""
        cmd += self._build_element_implicit(0x0000, 0x0002, self.PATIENT_ROOT_QR_MOVE)
        cmd += self._build_element_implicit(0x0000, 0x0100, struct.pack("<H", 0x0021))
        cmd += self._build_element_implicit(
            0x0000, 0x0110, struct.pack("<H", message_id)
        )
        cmd += self._build_element_implicit(
            0x0000, 0x0600, move_destination.ljust(16)[:16]
        )
        cmd += self._build_element_implicit(0x0000, 0x0700, struct.pack("<H", 0))
        cmd += self._build_element_implicit(0x0000, 0x0800, struct.pack("<H", 0))

        length_elem = self._build_element_implicit(
            0x0000, 0x0000, struct.pack("<L", len(cmd))
        )
        cmd = length_elem + cmd

        dataset = b""
        dataset += self._build_element_implicit(0x0008, 0x0052, "STUDY")
        dataset += self._build_element_implicit(0x0020, 0x000D, "1.2.3.4.5")

        cmd_pdv = self._build_pdv(1, cmd, is_command=True, is_last=True)
        data_pdv = self._build_pdv(1, dataset, is_command=False, is_last=True)

        return self._build_pdu(0x04, cmd_pdv + data_pdv)

    def generate_release_rq(self) -> bytes:
        """Generate A-RELEASE-RQ PDU."""
        return self._build_pdu(0x05, b"\x00\x00\x00\x00")

    def generate_abort(self, source: int = 0, reason: int = 0) -> bytes:
        """Generate A-ABORT PDU."""
        data = struct.pack(">BBBB", 0, 0, source, reason)
        return self._build_pdu(0x07, data)

    def generate_malformed_seeds(self) -> list[tuple[str, bytes]]:
        """Generate malformed PDUs for vulnerability testing."""
        seeds = []

        # Truncated A-ASSOCIATE-RQ
        full_assoc = self.generate_associate_rq()
        seeds.append(("truncated_associate_half", full_assoc[: len(full_assoc) // 2]))
        seeds.append(("truncated_associate_header_only", full_assoc[:6]))

        # Invalid PDU type
        seeds.append(
            ("invalid_pdu_type_0xff", b"\xff\x00\x00\x00\x00\x04" + b"\x00" * 4)
        )
        seeds.append(
            ("invalid_pdu_type_0x00", b"\x00\x00\x00\x00\x00\x04" + b"\x00" * 4)
        )

        # Oversized length field
        seeds.append(("oversized_length", b"\x01\x00\xff\xff\xff\xff" + b"\x00" * 100))

        # Zero length with data
        seeds.append(("zero_length_with_data", b"\x01\x00\x00\x00\x00\x00" + b"A" * 50))

        # Mismatched length
        assoc = self.generate_associate_rq()
        bad_len = assoc[:2] + struct.pack(">L", 10) + assoc[6:]  # Wrong length
        seeds.append(("mismatched_length", bad_len))

        # Empty presentation context
        data = struct.pack(">H", 1) + b"\x00\x00"
        data += self.called_ae.encode("ascii") + self.calling_ae.encode("ascii")
        data += b"\x00" * 32
        data += self._build_item(0x10, self.APP_CONTEXT.encode("ascii"))
        data += self._build_item(0x20, b"")  # Empty PC
        seeds.append(("empty_presentation_context", self._build_pdu(0x01, data)))

        # Invalid transfer syntax
        data = struct.pack(">H", 1) + b"\x00\x00"
        data += self.called_ae.encode("ascii") + self.calling_ae.encode("ascii")
        data += b"\x00" * 32
        data += self._build_item(0x10, self.APP_CONTEXT.encode("ascii"))
        pc_data = struct.pack(">BBH", 1, 0, 0)
        pc_data += self._build_item(0x30, self.VERIFICATION_SOP_CLASS.encode("ascii"))
        pc_data += self._build_item(0x40, b"invalid.transfer.syntax")
        data += self._build_item(0x20, pc_data)
        seeds.append(("invalid_transfer_syntax", self._build_pdu(0x01, data)))

        # Nested sequence overflow attempt
        nested = b"\x04\x00"  # P-DATA-TF start
        for _ in range(100):
            nested += struct.pack(">L", 0xFFFFFFFF)  # Max length items
        seeds.append(("nested_overflow", nested[:1000]))

        return seeds

    def generate_all_seeds(self, output_dir: Path) -> int:
        """Generate all seed files to output directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        # Valid protocol sequences
        seeds = [
            ("associate_rq_verification", self.generate_associate_rq()),
            (
                "associate_rq_ct_storage",
                self.generate_associate_rq(self.CT_IMAGE_STORAGE),
            ),
            (
                "associate_rq_mr_storage",
                self.generate_associate_rq(self.MR_IMAGE_STORAGE),
            ),
            (
                "associate_rq_find",
                self.generate_associate_rq(self.PATIENT_ROOT_QR_FIND),
            ),
            ("associate_rq_multi_pc", self.generate_associate_rq_multi_pc()),
            ("c_echo_rq", self.generate_c_echo_rq()),
            ("c_find_rq_wildcard", self.generate_c_find_rq(patient_name="*")),
            ("c_find_rq_specific", self.generate_c_find_rq(patient_name="DOE^JOHN")),
            (
                "c_store_rq_ct",
                self.generate_c_store_rq(sop_class=self.CT_IMAGE_STORAGE),
            ),
            (
                "c_store_rq_mr",
                self.generate_c_store_rq(sop_class=self.MR_IMAGE_STORAGE),
            ),
            ("c_get_rq", self.generate_c_get_rq()),
            ("c_move_rq", self.generate_c_move_rq()),
            ("release_rq", self.generate_release_rq()),
            ("abort_user", self.generate_abort(source=0, reason=0)),
            ("abort_provider", self.generate_abort(source=2, reason=1)),
        ]

        # Add malformed seeds
        seeds.extend(self.generate_malformed_seeds())

        # Write all seeds
        for name, data in seeds:
            filepath = output_dir / f"{name}.bin"
            filepath.write_bytes(data)
            count += 1

        # Generate combined sequences
        sequences = [
            (
                "seq_associate_echo_release",
                [
                    self.generate_associate_rq(),
                    self.generate_c_echo_rq(),
                    self.generate_release_rq(),
                ],
            ),
            (
                "seq_associate_find_release",
                [
                    self.generate_associate_rq(self.PATIENT_ROOT_QR_FIND),
                    self.generate_c_find_rq(),
                    self.generate_release_rq(),
                ],
            ),
            (
                "seq_associate_store_release",
                [
                    self.generate_associate_rq(self.CT_IMAGE_STORAGE),
                    self.generate_c_store_rq(),
                    self.generate_release_rq(),
                ],
            ),
        ]

        for name, pdus in sequences:
            filepath = output_dir / f"{name}.bin"
            filepath.write_bytes(b"".join(pdus))
            count += 1

        return count


def main() -> None:
    """Generate DICOM network seed corpus."""
    parser = argparse.ArgumentParser(description="Generate DICOM network seeds")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("./artifacts/corpus/network_seeds"),
        help="Output directory for seeds",
    )
    parser.add_argument("--calling-ae", default="FUZZER", help="Calling AE title")
    parser.add_argument("--called-ae", default="ORTHANC", help="Called AE title")

    args = parser.parse_args()

    generator = DicomSeedGenerator(
        calling_ae=args.calling_ae,
        called_ae=args.called_ae,
    )

    count = generator.generate_all_seeds(args.output)
    print(f"[+] Generated {count} seed files in {args.output}")


if __name__ == "__main__":
    main()

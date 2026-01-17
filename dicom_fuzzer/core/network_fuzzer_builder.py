"""DICOM Protocol Message Builder.

Builds DICOM protocol messages for network fuzzing, including
valid and malformed A-ASSOCIATE and DIMSE messages.
"""

from __future__ import annotations

import struct

from dicom_fuzzer.core.network_fuzzer_base import DICOMCommand, PDUType


class DICOMProtocolBuilder:
    """Builds DICOM protocol messages for fuzzing.

    Provides methods to construct both valid and malformed DICOM
    protocol messages for testing server implementations.
    """

    # Common Transfer Syntaxes
    IMPLICIT_VR_LITTLE_ENDIAN = b"1.2.840.10008.1.2\x00"
    EXPLICIT_VR_LITTLE_ENDIAN = b"1.2.840.10008.1.2.1\x00"
    EXPLICIT_VR_BIG_ENDIAN = b"1.2.840.10008.1.2.2\x00"

    # Common SOP Classes
    VERIFICATION_SOP_CLASS = b"1.2.840.10008.1.1\x00"
    CT_IMAGE_STORAGE = b"1.2.840.10008.5.1.4.1.1.2\x00"
    MR_IMAGE_STORAGE = b"1.2.840.10008.5.1.4.1.1.4\x00"
    PATIENT_ROOT_QR_FIND = b"1.2.840.10008.5.1.4.1.2.1.1\x00"
    PATIENT_ROOT_QR_MOVE = b"1.2.840.10008.5.1.4.1.2.1.2\x00"

    @staticmethod
    def build_a_associate_rq(
        calling_ae: str = "FUZZER_SCU",
        called_ae: str = "ANY_SCP",
        application_context: bytes | None = None,
        presentation_contexts: list[bytes] | None = None,
        max_pdu_size: int = 16384,
    ) -> bytes:
        """Build an A-ASSOCIATE-RQ PDU.

        Args:
            calling_ae: Calling Application Entity Title
            called_ae: Called Application Entity Title
            application_context: Application context UID
            presentation_contexts: List of presentation context items
            max_pdu_size: Maximum PDU size

        Returns:
            Bytes of the A-ASSOCIATE-RQ PDU

        """
        # Default application context (DICOM)
        if application_context is None:
            application_context = b"1.2.840.10008.3.1.1.1\x00"

        # Default presentation context (Verification SOP Class)
        if presentation_contexts is None:
            presentation_contexts = [
                DICOMProtocolBuilder._build_presentation_context(
                    context_id=1,
                    abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
                    transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
                )
            ]

        # Pad AE titles to 16 bytes
        calling_ae_bytes = calling_ae.encode("ascii").ljust(16)[:16]
        called_ae_bytes = called_ae.encode("ascii").ljust(16)[:16]

        # Build Application Context Item (0x10)
        app_context_item = (
            struct.pack(">BBH", 0x10, 0x00, len(application_context))
            + application_context
        )

        # Build User Information Item (0x50)
        max_length_item = struct.pack(">BBHI", 0x51, 0x00, 4, max_pdu_size)
        implementation_uid = b"1.2.3.4.5.6.7.8.9\x00"
        impl_uid_item = (
            struct.pack(">BBH", 0x52, 0x00, len(implementation_uid))
            + implementation_uid
        )

        user_info_data = max_length_item + impl_uid_item
        user_info_item = (
            struct.pack(">BBH", 0x50, 0x00, len(user_info_data)) + user_info_data
        )

        # Combine presentation contexts
        pres_ctx_data = b"".join(presentation_contexts)

        # Build variable items
        variable_items = app_context_item + pres_ctx_data + user_info_item

        # Build PDU header
        # Protocol version (1), reserved (2 bytes), called AE (16), calling AE (16),
        # reserved (32 bytes)
        pdu_data = (
            struct.pack(">H", 1)
            + b"\x00\x00"  # Protocol version  # Reserved
            + called_ae_bytes
            + calling_ae_bytes
            + b"\x00" * 32  # Reserved
            + variable_items
        )

        # PDU header: type (1), reserved (1), length (4)
        pdu = struct.pack(">BBL", PDUType.A_ASSOCIATE_RQ.value, 0x00, len(pdu_data))
        return pdu + pdu_data

    @staticmethod
    def _build_presentation_context(
        context_id: int,
        abstract_syntax: bytes,
        transfer_syntaxes: list[bytes],
    ) -> bytes:
        """Build a Presentation Context Item.

        Args:
            context_id: Presentation context ID (odd number)
            abstract_syntax: Abstract syntax UID
            transfer_syntaxes: List of transfer syntax UIDs

        Returns:
            Bytes of the presentation context item

        """
        # Abstract Syntax Item (0x30)
        abstract_item = (
            struct.pack(">BBH", 0x30, 0x00, len(abstract_syntax)) + abstract_syntax
        )

        # Transfer Syntax Items (0x40)
        transfer_items = b""
        for ts in transfer_syntaxes:
            transfer_items += struct.pack(">BBH", 0x40, 0x00, len(ts)) + ts

        # Presentation Context Item (0x20)
        ctx_data = (
            struct.pack(">B", context_id)
            + b"\x00\x00\x00"  # Reserved
            + abstract_item
            + transfer_items
        )

        return struct.pack(">BBH", 0x20, 0x00, len(ctx_data)) + ctx_data

    @staticmethod
    def build_c_echo_rq(message_id: int = 1) -> bytes:
        """Build a C-ECHO-RQ DIMSE message.

        Args:
            message_id: Message ID for the request

        Returns:
            Bytes of the C-ECHO-RQ wrapped in P-DATA-TF

        """
        # Build Command Dataset
        # Affected SOP Class UID (0000,0002)
        sop_class = b"1.2.840.10008.1.1"
        sop_class_elem = (
            struct.pack("<HH", 0x0000, 0x0002)
            + struct.pack("<I", len(sop_class))
            + sop_class
        )
        # Command Field (0000,0100)
        cmd_field = (
            struct.pack("<HH", 0x0000, 0x0100)
            + struct.pack("<I", 2)
            + struct.pack("<H", DICOMCommand.C_ECHO_RQ.value)
        )
        # Message ID (0000,0110)
        msg_id = (
            struct.pack("<HH", 0x0000, 0x0110)
            + struct.pack("<I", 2)
            + struct.pack("<H", message_id)
        )
        # Data Set Type (0000,0800) - No data set
        data_set_type = (
            struct.pack("<HH", 0x0000, 0x0800)
            + struct.pack("<I", 2)
            + struct.pack("<H", 0x0101)
        )

        command_data = sop_class_elem + cmd_field + msg_id + data_set_type
        # Update group length
        group_length = struct.pack("<HH", 0x0000, 0x0000) + struct.pack(
            "<I", len(command_data) - 8
        )
        command_data = group_length + command_data

        # Wrap in PDV (Presentation Data Value)
        # Context ID (1) + Message Control Header (0x03 = last fragment, command)
        pdv = struct.pack(">I", len(command_data) + 2) + bytes([1, 0x03]) + command_data

        # Wrap in P-DATA-TF PDU
        return struct.pack(">BBL", PDUType.P_DATA_TF.value, 0x00, len(pdv)) + pdv

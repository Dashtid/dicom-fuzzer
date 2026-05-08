"""User Identity Negotiation fuzzer (PS3.7 D.3.3.7).

Builds malformed and malicious User Identity Sub-Item payloads for
A-ASSOCIATE-RQ. Five auth types live behind this single sub-item, and
SCP credential parsers are a high-value attack surface because they
process untrusted bytes from any peer that can complete a TCP
handshake.

Five baseline generators (one per auth type) and five mutation
generators (overflow, length confusion, format string, reserved type)
each return raw sub-item bytes. ``iter_all_payloads()`` yields
``(name, bytes)`` pairs for bulk runs.

Use :func:`build_rq_with_user_identity` to wrap a sub-item into a
complete A-ASSOCIATE-RQ ready to send on the wire.
"""

from __future__ import annotations

import struct
from collections.abc import Generator

from .builder import DICOMProtocolBuilder

# Auth types defined in PS3.7 D.3.3.7
TYPE_USERNAME = 1
TYPE_USERNAME_PASSWORD = 2
TYPE_KERBEROS = 3
TYPE_SAML = 4
TYPE_JWT = 5


class UserIdentityFuzzer:
    """Generate User Identity Sub-Item fuzz payloads.

    Each generator returns sub-item bytes (item header + body); wrap
    with :func:`build_rq_with_user_identity` to produce a sendable
    A-ASSOCIATE-RQ.
    """

    # ------------------------------------------------------------------
    # Baselines (1 per auth type)
    # ------------------------------------------------------------------

    def username(
        self, name: str = "testuser", positive_response: bool = False
    ) -> bytes:
        """Type=1 username only."""
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_USERNAME,
            primary=name.encode("utf-8"),
            positive_response=positive_response,
        )

    def username_password(
        self,
        name: str = "testuser",
        passcode: str = "fuzzcode",
        positive_response: bool = False,
    ) -> bytes:
        """Type=2 username + passcode (PS3.7 calls field 2 'Passcode')."""
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_USERNAME_PASSWORD,
            primary=name.encode("utf-8"),
            secondary=passcode.encode("utf-8"),
            positive_response=positive_response,
        )

    def kerberos(self, ticket: bytes = b"FAKE_KERBEROS_TICKET") -> bytes:
        """Type=3 Kerberos service ticket."""
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_KERBEROS,
            primary=ticket,
        )

    def saml(self, assertion: bytes = b"<saml:Assertion></saml:Assertion>") -> bytes:
        """Type=4 SAML assertion."""
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_SAML,
            primary=assertion,
        )

    def jwt(self, token: bytes = b"eyJ.eyJ.signature") -> bytes:
        """Type=5 JSON Web Token."""
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_JWT,
            primary=token,
        )

    # ------------------------------------------------------------------
    # Mutations (probe distinct parser bugs)
    # ------------------------------------------------------------------

    def oversized_primary_field(
        self, type_: int = TYPE_USERNAME, size: int = 32768
    ) -> bytes:
        """Primary field of ``size`` bytes (default 32KB). Probes
        buffer overflow on servers that assume usernames/tickets are
        short, or that allocate based on declared length without
        bounds-checking.

        Capped well below the 65535-byte 2-byte length-field max to
        leave room for the 6-byte sub-item overhead.
        """
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=type_,
            primary=b"A" * size,
        )

    def oversized_secondary_field(self, size: int = 32768) -> bytes:
        """Secondary field of ``size`` bytes. Used with type=2; probes
        password buffer overflow.
        """
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_USERNAME_PASSWORD,
            primary=b"user",
            secondary=b"P" * size,
        )

    def length_overflow(
        self,
        type_: int = TYPE_USERNAME,
        primary: bytes = b"user",
        declared_extra: int = 10000,
    ) -> bytes:
        """Sub-item header declares a length larger than the actual
        body. Parsers that trust the header without bounds-checking
        will read past the sub-item into adjacent PDU data.

        Hand-rolls the bytes because the canonical builder always
        computes lengths correctly.
        """
        body = (
            struct.pack(">B", type_ & 0xFF)
            + b"\x00"  # positive-response-requested
            + struct.pack(">H", len(primary))
            + primary
            + struct.pack(">H", 0)  # secondary length
        )
        # Inflate the declared item-length without changing the actual body.
        declared_len = min(len(body) + declared_extra, 0xFFFF)
        return struct.pack(">BBH", 0x58, 0x00, declared_len) + body

    def format_string_username(self) -> bytes:
        """Username containing classic format-string specifiers
        (%n, %p, %x, %s). Probes naive logging or formatting on the
        server that passes the username through ``printf``-family calls.
        """
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=TYPE_USERNAME,
            primary=b"%n%n%n%p%p%p%x%x%x%s%s%s",
        )

    def reserved_user_identity_type(self, type_value: int = 0) -> bytes:
        """Use a User-Identity-Type value DICOM does not define
        (defined values are 1..5). Default 0; 6 and 255 are also
        worth trying. PS3.7 says SCP must reject unknown types --
        a target that proceeds anyway has a parser bug.
        """
        return DICOMProtocolBuilder.build_user_identity_subitem(
            user_id_type=type_value,
            primary=b"unused",
        )

    # ------------------------------------------------------------------
    # Bulk iteration
    # ------------------------------------------------------------------

    def iter_all_payloads(self) -> Generator[tuple[str, bytes], None, None]:
        """Yield (name, sub-item bytes) for every generator.

        Order is stable so test reports are reproducible across runs.
        """
        yield "username", self.username()
        yield "username_password", self.username_password()
        yield "kerberos", self.kerberos()
        yield "saml", self.saml()
        yield "jwt", self.jwt()
        yield "oversized_primary_field", self.oversized_primary_field()
        yield "oversized_secondary_field", self.oversized_secondary_field()
        yield "length_overflow", self.length_overflow()
        yield "format_string_username", self.format_string_username()
        yield "reserved_user_identity_type", self.reserved_user_identity_type()


def build_rq_with_user_identity(subitem: bytes, **rq_kwargs: object) -> bytes:
    """Wrap a User Identity Sub-Item into a complete A-ASSOCIATE-RQ.

    Convenience around :meth:`DICOMProtocolBuilder.build_a_associate_rq`
    so callers don't have to remember the kwarg name.

    Args:
        subitem: Bytes returned from a UserIdentityFuzzer generator.
        **rq_kwargs: Forwarded to ``build_a_associate_rq`` (e.g.
            ``calling_ae``, ``called_ae``).

    Returns:
        Full A-ASSOCIATE-RQ PDU bytes.

    """
    return DICOMProtocolBuilder.build_a_associate_rq(
        user_identity_subitem=subitem,
        **rq_kwargs,  # type: ignore[arg-type]
    )


__all__ = [
    "TYPE_JWT",
    "TYPE_KERBEROS",
    "TYPE_SAML",
    "TYPE_USERNAME",
    "TYPE_USERNAME_PASSWORD",
    "UserIdentityFuzzer",
    "build_rq_with_user_identity",
]

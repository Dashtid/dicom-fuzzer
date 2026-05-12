"""Tests for UserIdentityFuzzer (PS3.7 D.3.3.7).

Each generator returns User Identity Sub-Item bytes. We assert two
things per generator: structural invariants (item type 0x58, declared
lengths) and attack-specific invariants (oversized field is the
expected size, format string contains specifiers, reserved type byte
matches what the test asks for).
"""

from __future__ import annotations

import struct

import pytest

from dicom_fuzzer.attacks.network.user_identity_fuzzer import (
    TYPE_JWT,
    TYPE_KERBEROS,
    TYPE_SAML,
    TYPE_USERNAME,
    TYPE_USERNAME_PASSWORD,
    UserIdentityFuzzer,
    build_rq_with_user_identity,
)


def _parse_subitem(data: bytes) -> dict:
    """Parse a User Identity Sub-Item, returning a dict of fields.

    Used by tests that need to inspect declared vs actual lengths.
    """
    item_type = data[0]
    item_len = struct.unpack(">H", data[2:4])[0]
    type_byte = data[4]
    response_byte = data[5]
    primary_len = struct.unpack(">H", data[6:8])[0]
    primary = data[8 : 8 + primary_len]
    sec_offset = 8 + primary_len
    secondary_len = struct.unpack(">H", data[sec_offset : sec_offset + 2])[0]
    secondary = data[sec_offset + 2 : sec_offset + 2 + secondary_len]
    return {
        "item_type": item_type,
        "item_len": item_len,
        "type": type_byte,
        "response": response_byte,
        "primary_len": primary_len,
        "primary": primary,
        "secondary_len": secondary_len,
        "secondary": secondary,
    }


@pytest.fixture
def fuzzer() -> UserIdentityFuzzer:
    return UserIdentityFuzzer()


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class TestUsername:
    def test_returns_bytes(self, fuzzer: UserIdentityFuzzer) -> None:
        assert isinstance(fuzzer.username(), bytes)

    def test_starts_with_0x58(self, fuzzer: UserIdentityFuzzer) -> None:
        assert fuzzer.username()[0] == 0x58

    def test_type_byte_is_username(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.username())
        assert parsed["type"] == TYPE_USERNAME

    def test_carries_supplied_name(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.username(name="alice"))
        assert parsed["primary"] == b"alice"

    def test_no_secondary(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.username())
        assert parsed["secondary_len"] == 0


class TestUsernamePassword:
    def test_type_byte_is_username_password(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.username_password())
        assert parsed["type"] == TYPE_USERNAME_PASSWORD

    def test_carries_both_fields(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(
            fuzzer.username_password(name="alice", passcode="hunter2")
        )
        assert parsed["primary"] == b"alice"
        assert parsed["secondary"] == b"hunter2"

    def test_positive_response_flag(self, fuzzer: UserIdentityFuzzer) -> None:
        with_resp = _parse_subitem(fuzzer.username_password(positive_response=True))
        without_resp = _parse_subitem(fuzzer.username_password(positive_response=False))
        assert with_resp["response"] == 0x01
        assert without_resp["response"] == 0x00


class TestKerberos:
    def test_type_byte(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.kerberos())
        assert parsed["type"] == TYPE_KERBEROS

    def test_carries_ticket(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.kerberos(ticket=b"\x01\x02\x03"))
        assert parsed["primary"] == b"\x01\x02\x03"


class TestSaml:
    def test_type_byte(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.saml())
        assert parsed["type"] == TYPE_SAML

    def test_carries_assertion(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.saml(assertion=b"<saml/>"))
        assert parsed["primary"] == b"<saml/>"


class TestJwt:
    def test_type_byte(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.jwt())
        assert parsed["type"] == TYPE_JWT

    def test_carries_token(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.jwt(token=b"a.b.c"))
        assert parsed["primary"] == b"a.b.c"


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


class TestOversizedPrimary:
    def test_default_size_is_32k(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.oversized_primary_field())
        assert parsed["primary_len"] == 32768

    def test_explicit_size_respected(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.oversized_primary_field(size=1024))
        assert parsed["primary_len"] == 1024
        assert parsed["primary"] == b"A" * 1024

    def test_type_overrideable(self, fuzzer: UserIdentityFuzzer) -> None:
        # Lets you probe oversized primaries on auth types that don't
        # normally have huge values (e.g. type=1 username).
        parsed = _parse_subitem(
            fuzzer.oversized_primary_field(type_=TYPE_KERBEROS, size=512)
        )
        assert parsed["type"] == TYPE_KERBEROS


class TestOversizedSecondary:
    def test_uses_username_password_type(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.oversized_secondary_field())
        assert parsed["type"] == TYPE_USERNAME_PASSWORD

    def test_default_size(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.oversized_secondary_field())
        assert parsed["secondary_len"] == 32768


class TestLengthOverflow:
    def test_declared_length_exceeds_actual(self, fuzzer: UserIdentityFuzzer) -> None:
        data = fuzzer.length_overflow()
        declared = struct.unpack(">H", data[2:4])[0]
        actual_body = len(data) - 4
        assert declared > actual_body, (
            f"Expected declared > actual body, got declared={declared}, "
            f"actual={actual_body}"
        )

    def test_declared_capped_at_uint16_max(self, fuzzer: UserIdentityFuzzer) -> None:
        data = fuzzer.length_overflow(declared_extra=999_999)
        declared = struct.unpack(">H", data[2:4])[0]
        # Cannot exceed 0xFFFF in a 2-byte length field.
        assert declared == 0xFFFF


class TestFormatStringUsername:
    def test_primary_contains_format_specifiers(
        self, fuzzer: UserIdentityFuzzer
    ) -> None:
        parsed = _parse_subitem(fuzzer.format_string_username())
        for token in (b"%n", b"%p", b"%x", b"%s"):
            assert token in parsed["primary"]


class TestReservedUserIdentityType:
    def test_default_is_zero(self, fuzzer: UserIdentityFuzzer) -> None:
        parsed = _parse_subitem(fuzzer.reserved_user_identity_type())
        assert parsed["type"] == 0

    def test_explicit_reserved_value(self, fuzzer: UserIdentityFuzzer) -> None:
        for value in (6, 99, 255):
            parsed = _parse_subitem(
                fuzzer.reserved_user_identity_type(type_value=value)
            )
            assert parsed["type"] == value


# ---------------------------------------------------------------------------
# Bulk iteration
# ---------------------------------------------------------------------------


class TestIterAllPayloads:
    def test_yields_ten_payloads(self, fuzzer: UserIdentityFuzzer) -> None:
        payloads = list(fuzzer.iter_all_payloads())
        assert len(payloads) == 10

    def test_names_are_unique(self, fuzzer: UserIdentityFuzzer) -> None:
        names = [name for name, _ in fuzzer.iter_all_payloads()]
        assert len(set(names)) == len(names)

    def test_names_are_stable_order(self, fuzzer: UserIdentityFuzzer) -> None:
        # Stability matters: fuzz reports correlate by name.
        names = [name for name, _ in fuzzer.iter_all_payloads()]
        assert names == [
            "username",
            "username_password",
            "kerberos",
            "saml",
            "jwt",
            "oversized_primary_field",
            "oversized_secondary_field",
            "length_overflow",
            "format_string_username",
            "reserved_user_identity_type",
        ]

    def test_each_payload_starts_with_0x58(self, fuzzer: UserIdentityFuzzer) -> None:
        for _name, payload in fuzzer.iter_all_payloads():
            assert payload[0] == 0x58


# ---------------------------------------------------------------------------
# build_rq_with_user_identity helper
# ---------------------------------------------------------------------------


class TestBuildRqWithUserIdentity:
    def test_wraps_subitem_into_a_associate_rq(
        self, fuzzer: UserIdentityFuzzer
    ) -> None:
        subitem = fuzzer.username()
        pdu = build_rq_with_user_identity(subitem)
        # First byte is the A-ASSOCIATE-RQ PDU type (0x01).
        assert pdu[0] == 0x01
        # Sub-item bytes embedded in the PDU.
        assert subitem in pdu

    def test_passes_through_rq_kwargs(self, fuzzer: UserIdentityFuzzer) -> None:
        subitem = fuzzer.username()
        pdu = build_rq_with_user_identity(subitem, calling_ae="ALICE", called_ae="BOB")
        # AE titles are 16 bytes, space-padded.
        assert b"ALICE" in pdu
        assert b"BOB" in pdu

    def test_accepts_each_baseline_payload(self, fuzzer: UserIdentityFuzzer) -> None:
        # Smoke check that the helper handles every baseline auth type
        # without choking on field lengths.
        for _name, payload in fuzzer.iter_all_payloads():
            pdu = build_rq_with_user_identity(payload)
            assert pdu[0] == 0x01
            assert payload in pdu

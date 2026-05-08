"""Tests for the rogue X.509 certificate generators.

Each test verifies that a generator produces a parseable PEM-encoded
cert with the expected validation-relevant fields. The fuzzer that
consumes these certs uses ``ssl.SSLContext.load_cert_chain`` which
needs the cert to at least be syntactically valid X.509; semantic
correctness (CN, validity dates, issuer, key size, chain depth) is
what makes each variant exercise a distinct target-side check.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography import x509

from dicom_fuzzer.utils.rogue_certs import (
    RogueCert,
    make_all_rogue_certs,
    make_expired,
    make_long_chain,
    make_not_yet_valid,
    make_self_signed,
    make_weak_key,
    make_wrong_cn,
    make_wrong_issuer,
)


def _load(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def _cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def _issuer_cn(cert: x509.Certificate) -> str:
    return cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


class TestSelfSigned:
    def test_returns_rogue_cert(self) -> None:
        assert isinstance(make_self_signed(), RogueCert)

    def test_name_is_self_signed(self) -> None:
        assert make_self_signed().name == "self_signed"

    def test_cert_parses(self) -> None:
        _load(make_self_signed().cert_pem)

    def test_issuer_equals_subject(self) -> None:
        cert = _load(make_self_signed().cert_pem)
        assert cert.issuer == cert.subject

    def test_no_chain(self) -> None:
        assert make_self_signed().chain_pem == []

    def test_san_when_hostname_supplied(self) -> None:
        cert = _load(make_self_signed(hostname="target.example.com").cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert "target.example.com" in san.value.get_values_for_type(x509.DNSName)


class TestExpired:
    def test_name_is_expired(self) -> None:
        assert make_expired().name == "expired"

    def test_not_after_in_past(self) -> None:
        cert = _load(make_expired().cert_pem)
        # Use UTC-aware variant; not_valid_after_utc avoids the deprecated naive comparison.
        assert cert.not_valid_after_utc < datetime.now(UTC)


class TestNotYetValid:
    def test_name_is_not_yet_valid(self) -> None:
        assert make_not_yet_valid().name == "not_yet_valid"

    def test_not_before_in_future(self) -> None:
        cert = _load(make_not_yet_valid().cert_pem)
        assert cert.not_valid_before_utc > datetime.now(UTC)


class TestWrongCn:
    def test_name_is_wrong_cn(self) -> None:
        assert make_wrong_cn().name == "wrong_cn"

    def test_cn_does_not_match_target_hostname(self) -> None:
        rc = make_wrong_cn(
            target_hostname="real.example.com", claimed_cn="evil.example.com"
        )
        cert = _load(rc.cert_pem)
        assert _cn(cert) == "evil.example.com"
        assert _cn(cert) != "real.example.com"

    def test_san_matches_claimed_cn_not_target(self) -> None:
        rc = make_wrong_cn(
            target_hostname="real.example.com", claimed_cn="evil.example.com"
        )
        cert = _load(rc.cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "evil.example.com" in dns_names
        assert "real.example.com" not in dns_names


class TestWrongIssuer:
    def test_name_is_wrong_issuer(self) -> None:
        assert make_wrong_issuer().name == "wrong_issuer"

    def test_chain_has_attacker_ca(self) -> None:
        rc = make_wrong_issuer()
        assert len(rc.chain_pem) == 1
        ca = _load(rc.chain_pem[0])
        assert _cn(ca) == "attacker-ca"

    def test_leaf_issued_by_attacker_ca(self) -> None:
        rc = make_wrong_issuer()
        leaf = _load(rc.cert_pem)
        assert _issuer_cn(leaf) == "attacker-ca"

    def test_attacker_ca_is_self_signed(self) -> None:
        # The attacker CA is a root we control -- its issuer is itself.
        rc = make_wrong_issuer()
        ca = _load(rc.chain_pem[0])
        assert ca.issuer == ca.subject


class TestWeakKey:
    def test_name_is_weak_key(self) -> None:
        assert make_weak_key().name == "weak_key"

    def test_default_key_size_is_1024(self) -> None:
        # 1024-bit RSA is the smallest cryptography lib will generate;
        # it's well below the modern 2048-bit minimum.
        cert = _load(make_weak_key().cert_pem)
        assert cert.public_key().key_size == 1024

    def test_explicit_key_size_respected(self) -> None:
        cert = _load(make_weak_key(key_size=2048).cert_pem)
        assert cert.public_key().key_size == 2048


class TestLongChain:
    def test_name_is_long_chain(self) -> None:
        assert make_long_chain().name == "long_chain"

    def test_chain_length_matches_depth_plus_root(self) -> None:
        # depth=N intermediates + 1 root = N+1 chain entries (leaf is separate)
        rc = make_long_chain(depth=5)
        assert len(rc.chain_pem) == 6

    def test_chain_pem_is_leaf_to_root_order(self) -> None:
        rc = make_long_chain(depth=3)
        # Reversed order: deepest intermediate first, root last.
        first = _load(rc.chain_pem[0])
        last = _load(rc.chain_pem[-1])
        assert _cn(first) == "chain-intermediate-2"
        assert _cn(last) == "chain-root"

    def test_leaf_issued_by_deepest_intermediate(self) -> None:
        rc = make_long_chain(depth=4)
        leaf = _load(rc.cert_pem)
        assert _issuer_cn(leaf) == "chain-intermediate-3"

    def test_zero_depth_raises(self) -> None:
        with pytest.raises(ValueError):
            make_long_chain(depth=0)


class TestMakeAllRogueCerts:
    def test_returns_seven(self) -> None:
        assert len(make_all_rogue_certs()) == 7

    def test_names_are_unique(self) -> None:
        names = [rc.name for rc in make_all_rogue_certs()]
        assert len(set(names)) == len(names)

    def test_names_are_stable_order(self) -> None:
        # Stability matters: test_name strings appear in fuzz reports
        # and must be deterministic across runs.
        names = [rc.name for rc in make_all_rogue_certs()]
        assert names == [
            "self_signed",
            "expired",
            "not_yet_valid",
            "wrong_cn",
            "wrong_issuer",
            "weak_key",
            "long_chain",
        ]

    def test_each_has_cert_and_key(self) -> None:
        for rc in make_all_rogue_certs():
            assert rc.cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
            assert b"PRIVATE KEY" in rc.key_pem

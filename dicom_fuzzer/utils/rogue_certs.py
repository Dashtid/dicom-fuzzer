"""Rogue X.509 certificate generators for TLS fuzzing.

Each generator returns a :class:`RogueCert` with PEM-encoded cert + key
bytes that exercise a distinct validation layer in the target's TLS
stack:

- ``self_signed``       no chain trust; signed by its own key
- ``expired``           ``notAfter`` set in the past
- ``not_yet_valid``     ``notBefore`` set in the future
- ``wrong_cn``          CN/SAN mismatched against target hostname
- ``wrong_issuer``      signed by an attacker-controlled CA
- ``weak_key``          1024-bit RSA (well below 2048 minimum)
- ``long_chain``        leaf signed by N stacked intermediates

Used by the TLS fuzzer (:class:`dicom_fuzzer.attacks.network.tls.DICOMTLSFuzzer`)
to present each variant as a client cert during mTLS handshake. A
target that accepts any of these certs has a validation bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

_DEFAULT_KEY_SIZE = 2048


@dataclass
class RogueCert:
    """A rogue X.509 certificate with its private key.

    Attributes:
        name: Short identifier for the variant (e.g. "expired").
        cert_pem: PEM-encoded leaf certificate.
        key_pem: PEM-encoded private key matching ``cert_pem``.
        chain_pem: PEM-encoded intermediate/root certs, leaf-to-root order
            (excluding the leaf itself). Empty for self-signed variants.

    """

    name: str
    cert_pem: bytes
    key_pem: bytes
    chain_pem: list[bytes] = field(default_factory=list)


def _new_rsa_key(size: int = _DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def _key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    pem: bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def _cert_to_pem(cert: x509.Certificate) -> bytes:
    pem: bytes = cert.public_bytes(serialization.Encoding.PEM)
    return pem


def _build_cert(
    *,
    subject_cn: str,
    issuer_cn: str,
    public_key: rsa.RSAPublicKey,
    signing_key: CertificateIssuerPrivateKeyTypes,
    not_before: datetime,
    not_after: datetime,
    san_dns: str | None = None,
    is_ca: bool = False,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san_dns is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]),
            critical=False,
        )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def make_self_signed(
    cn: str = "fuzzer-client", hostname: str | None = None
) -> RogueCert:
    """Cert signed by its own key; no chain to a trusted root."""
    key = _new_rsa_key()
    now = datetime.now(UTC)
    cert = _build_cert(
        subject_cn=cn,
        issuer_cn=cn,
        public_key=key.public_key(),
        signing_key=key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        san_dns=hostname,
    )
    return RogueCert(
        name="self_signed", cert_pem=_cert_to_pem(cert), key_pem=_key_to_pem(key)
    )


def make_expired(cn: str = "fuzzer-client", days_ago: int = 365) -> RogueCert:
    """Cert whose ``notAfter`` is in the past."""
    key = _new_rsa_key()
    now = datetime.now(UTC)
    cert = _build_cert(
        subject_cn=cn,
        issuer_cn=cn,
        public_key=key.public_key(),
        signing_key=key,
        not_before=now - timedelta(days=days_ago + 365),
        not_after=now - timedelta(days=days_ago),
    )
    return RogueCert(
        name="expired", cert_pem=_cert_to_pem(cert), key_pem=_key_to_pem(key)
    )


def make_not_yet_valid(cn: str = "fuzzer-client", days_ahead: int = 365) -> RogueCert:
    """Cert whose ``notBefore`` is in the future."""
    key = _new_rsa_key()
    now = datetime.now(UTC)
    cert = _build_cert(
        subject_cn=cn,
        issuer_cn=cn,
        public_key=key.public_key(),
        signing_key=key,
        not_before=now + timedelta(days=days_ahead),
        not_after=now + timedelta(days=days_ahead + 365),
    )
    return RogueCert(
        name="not_yet_valid",
        cert_pem=_cert_to_pem(cert),
        key_pem=_key_to_pem(key),
    )


def make_wrong_cn(
    target_hostname: str = "target.example.com",
    claimed_cn: str = "wrong.example.com",
) -> RogueCert:
    """Cert whose CN/SAN does not match the target hostname.

    The SAN entry is set to ``claimed_cn`` so a target that performs
    hostname verification will reject it.
    """
    key = _new_rsa_key()
    now = datetime.now(UTC)
    cert = _build_cert(
        subject_cn=claimed_cn,
        issuer_cn=claimed_cn,
        public_key=key.public_key(),
        signing_key=key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        san_dns=claimed_cn,
    )
    rc = RogueCert(
        name="wrong_cn", cert_pem=_cert_to_pem(cert), key_pem=_key_to_pem(key)
    )
    # target_hostname is captured for callers that want to log mismatch context.
    rc.chain_pem = []
    return rc


def make_wrong_issuer(cn: str = "fuzzer-client") -> RogueCert:
    """Leaf signed by an attacker-controlled CA the target does not trust."""
    ca_key = _new_rsa_key()
    leaf_key = _new_rsa_key()
    now = datetime.now(UTC)

    ca_cert = _build_cert(
        subject_cn="attacker-ca",
        issuer_cn="attacker-ca",
        public_key=ca_key.public_key(),
        signing_key=ca_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=3650),
        is_ca=True,
    )
    leaf_cert = _build_cert(
        subject_cn=cn,
        issuer_cn="attacker-ca",
        public_key=leaf_key.public_key(),
        signing_key=ca_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )
    return RogueCert(
        name="wrong_issuer",
        cert_pem=_cert_to_pem(leaf_cert),
        key_pem=_key_to_pem(leaf_key),
        chain_pem=[_cert_to_pem(ca_cert)],
    )


def make_weak_key(cn: str = "fuzzer-client", key_size: int = 1024) -> RogueCert:
    """Cert with an undersized RSA key (default 1024 bits).

    The cryptography library refuses to generate keys below 1024 bits;
    1024 is itself deprecated and OpenSSL with security level >=1
    rejects it. Targets that accept it have weak key-size validation.
    """
    key = _new_rsa_key(size=key_size)
    now = datetime.now(UTC)
    cert = _build_cert(
        subject_cn=cn,
        issuer_cn=cn,
        public_key=key.public_key(),
        signing_key=key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )
    return RogueCert(
        name="weak_key", cert_pem=_cert_to_pem(cert), key_pem=_key_to_pem(key)
    )


def make_long_chain(cn: str = "fuzzer-client", depth: int = 20) -> RogueCert:
    """Leaf at the end of a chain ``depth`` intermediates deep.

    Generates a self-signed root, then ``depth`` intermediate CAs each
    signed by its parent, then the leaf signed by the deepest
    intermediate. Targets with chain-depth limits (e.g. OpenSSL's
    default of 100) should still accept depth=20, but a target with a
    misconfigured low limit will reject it -- which is itself a useful
    signal.
    """
    if depth < 1:
        raise ValueError("depth must be >= 1")

    now = datetime.now(UTC)
    chain: list[x509.Certificate] = []

    root_key = _new_rsa_key()
    root = _build_cert(
        subject_cn="chain-root",
        issuer_cn="chain-root",
        public_key=root_key.public_key(),
        signing_key=root_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=3650),
        is_ca=True,
    )
    chain.append(root)
    parent_key: CertificateIssuerPrivateKeyTypes = root_key
    parent_cn = "chain-root"

    for i in range(depth):
        intermediate_key = _new_rsa_key()
        intermediate_cn = f"chain-intermediate-{i}"
        intermediate = _build_cert(
            subject_cn=intermediate_cn,
            issuer_cn=parent_cn,
            public_key=intermediate_key.public_key(),
            signing_key=parent_key,
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=3650),
            is_ca=True,
        )
        chain.append(intermediate)
        parent_key = intermediate_key
        parent_cn = intermediate_cn

    leaf_key = _new_rsa_key()
    leaf = _build_cert(
        subject_cn=cn,
        issuer_cn=parent_cn,
        public_key=leaf_key.public_key(),
        signing_key=parent_key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
    )

    # chain_pem is leaf-to-root order (excluding leaf), per
    # ssl.SSLContext.load_cert_chain expectations: the leaf goes in
    # cert_pem; the rest concatenated in cert_pem too OR served as a
    # bundle. We expose the intermediates+root list so the caller can
    # write a bundle file.
    chain_pem = [_cert_to_pem(c) for c in reversed(chain)]
    return RogueCert(
        name="long_chain",
        cert_pem=_cert_to_pem(leaf),
        key_pem=_key_to_pem(leaf_key),
        chain_pem=chain_pem,
    )


def make_all_rogue_certs(
    target_hostname: str = "target.example.com",
) -> list[RogueCert]:
    """Generate one of each rogue cert variant.

    Returns 7 certs in stable order so test_name strings in fuzz
    results stay deterministic.
    """
    return [
        make_self_signed(hostname=target_hostname),
        make_expired(),
        make_not_yet_valid(),
        make_wrong_cn(target_hostname=target_hostname),
        make_wrong_issuer(),
        make_weak_key(),
        make_long_chain(),
    ]


__all__ = [
    "RogueCert",
    "make_all_rogue_certs",
    "make_expired",
    "make_long_chain",
    "make_not_yet_valid",
    "make_self_signed",
    "make_weak_key",
    "make_wrong_cn",
    "make_wrong_issuer",
]

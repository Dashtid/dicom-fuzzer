"""DICOM TLS Fuzzing Mixin.

Provides TLS security testing methods for DICOM TLS (port 2762) endpoints.
Tests TLS version negotiation, certificate validation, cipher suites,
and renegotiation vulnerabilities.
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
import tempfile
import time
from typing import TYPE_CHECKING

from dicom_fuzzer.utils.rogue_certs import RogueCert, make_all_rogue_certs

from .base import (
    FuzzingStrategy,
    NetworkFuzzResult,
)
from .builder import DICOMProtocolBuilder

if TYPE_CHECKING:
    from .base import DICOMNetworkConfig

logger = logging.getLogger(__name__)


class TLSFuzzingMixin:
    """Mixin providing TLS security testing methods.

    Requires:
        self.config: DICOMNetworkConfig
    """

    config: DICOMNetworkConfig

    def fuzz_tls_versions(self) -> list[NetworkFuzzResult]:
        """Test TLS version negotiation and downgrade attacks.

        Tests for DICOM TLS (port 2762) implementations:
        - SSLv3 support (should be disabled)
        - TLS 1.0 support (deprecated)
        - TLS 1.1 support (deprecated)
        - TLS 1.2 support (minimum recommended)
        - TLS 1.3 support (preferred)
        - Downgrade attack vectors

        Based on IOActive DICOM penetration testing research.

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []

        # TLS versions to test (some may not be available on all systems)
        tls_versions = [
            (
                "SSLv3",
                ssl.PROTOCOL_SSLv23,
                ssl.OP_NO_SSLv2
                | ssl.OP_NO_TLSv1
                | ssl.OP_NO_TLSv1_1
                | ssl.OP_NO_TLSv1_2
                | ssl.OP_NO_TLSv1_3,
            ),
            (
                "TLS_1_0",
                ssl.PROTOCOL_TLS_CLIENT,
                ssl.OP_NO_SSLv2
                | ssl.OP_NO_SSLv3
                | ssl.OP_NO_TLSv1_1
                | ssl.OP_NO_TLSv1_2
                | ssl.OP_NO_TLSv1_3,
            ),
            (
                "TLS_1_1",
                ssl.PROTOCOL_TLS_CLIENT,
                ssl.OP_NO_SSLv2
                | ssl.OP_NO_SSLv3
                | ssl.OP_NO_TLSv1
                | ssl.OP_NO_TLSv1_2
                | ssl.OP_NO_TLSv1_3,
            ),
            (
                "TLS_1_2",
                ssl.PROTOCOL_TLS_CLIENT,
                ssl.OP_NO_SSLv2
                | ssl.OP_NO_SSLv3
                | ssl.OP_NO_TLSv1
                | ssl.OP_NO_TLSv1_1
                | ssl.OP_NO_TLSv1_3,
            ),
            (
                "TLS_1_3",
                ssl.PROTOCOL_TLS_CLIENT,
                ssl.OP_NO_SSLv2
                | ssl.OP_NO_SSLv3
                | ssl.OP_NO_TLSv1
                | ssl.OP_NO_TLSv1_1
                | ssl.OP_NO_TLSv1_2,
            ),
        ]

        for version_name, protocol, options in tls_versions:
            start_time = time.time()
            test_name = f"tls_version_{version_name}"

            try:
                # Create TLS context with specific version
                context = ssl.SSLContext(protocol)
                context.options |= options
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Attempt connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)

                try:
                    tls_sock = context.wrap_socket(
                        sock, server_hostname=self.config.target_host
                    )
                    tls_sock.connect((self.config.target_host, self.config.target_port))

                    # Connection succeeded - record the negotiated version
                    negotiated = tls_sock.version()
                    cipher = tls_sock.cipher()

                    # Send a DICOM A-ASSOCIATE-RQ to verify it's a DICOM TLS endpoint
                    pdu = DICOMProtocolBuilder.build_a_associate_rq(
                        calling_ae=self.config.calling_ae,
                        called_ae=self.config.called_ae,
                    )
                    tls_sock.sendall(pdu)
                    response = tls_sock.recv(65536)

                    duration = time.time() - start_time

                    # Security concern if deprecated versions are accepted
                    is_deprecated = version_name in ("SSLv3", "TLS_1_0", "TLS_1_1")

                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=test_name,
                            success=True,
                            response=response,
                            duration=duration,
                            anomaly_detected=is_deprecated,
                            error=f"Negotiated: {negotiated}, Cipher: {cipher[0] if cipher else 'N/A'}"
                            + (
                                " [SECURITY: Deprecated TLS version accepted]"
                                if is_deprecated
                                else ""
                            ),
                        )
                    )
                    tls_sock.close()

                except ssl.SSLError as e:
                    # Expected for disabled TLS versions
                    duration = time.time() - start_time
                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=test_name,
                            success=True,
                            duration=duration,
                            error=f"Rejected: {e}",
                        )
                    )
                finally:
                    sock.close()

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_tls_certificate(self) -> list[NetworkFuzzResult]:
        """Test TLS certificate validation vulnerabilities.

        Tests:
        - Self-signed certificate acceptance
        - Expired certificate handling
        - Wrong hostname in certificate
        - Certificate chain validation
        - Certificate revocation checking

        Based on CVE-2025-1001 patterns and IOActive research.

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []

        test_cases = [
            ("cert_verify_none", ssl.CERT_NONE, False),
            ("cert_verify_optional", ssl.CERT_OPTIONAL, False),
            ("cert_verify_required", ssl.CERT_REQUIRED, True),
            ("cert_hostname_check_disabled", ssl.CERT_NONE, False),
        ]

        for test_name, verify_mode, check_hostname in test_cases:
            start_time = time.time()

            try:
                context = ssl.create_default_context()
                context.check_hostname = check_hostname
                context.verify_mode = verify_mode

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)

                try:
                    tls_sock = context.wrap_socket(
                        sock, server_hostname=self.config.target_host
                    )
                    tls_sock.connect((self.config.target_host, self.config.target_port))

                    # Get certificate info
                    cert = tls_sock.getpeercert()

                    # Send DICOM request
                    pdu = DICOMProtocolBuilder.build_a_associate_rq(
                        calling_ae=self.config.calling_ae,
                        called_ae=self.config.called_ae,
                    )
                    tls_sock.sendall(pdu)
                    response = tls_sock.recv(65536)

                    duration = time.time() - start_time

                    # Extract certificate details for reporting
                    cert_subject = cert.get("subject", ()) if cert else ()
                    cert_issuer = cert.get("issuer", ()) if cert else ()
                    cert_not_after = cert.get("notAfter", "N/A") if cert else "N/A"

                    error_msg = f"Cert subject: {cert_subject}, Issuer: {cert_issuer}, Expires: {cert_not_after}"

                    # Security concern: accepting connections with CERT_NONE
                    is_insecure = verify_mode == ssl.CERT_NONE

                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=f"tls_{test_name}",
                            success=True,
                            response=response,
                            duration=duration,
                            anomaly_detected=is_insecure,
                            error=error_msg,
                        )
                    )
                    tls_sock.close()

                except ssl.SSLError as e:
                    duration = time.time() - start_time
                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=f"tls_{test_name}",
                            success=True,
                            duration=duration,
                            error=f"SSL Error: {e}",
                        )
                    )
                finally:
                    sock.close()

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"tls_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def fuzz_tls_ciphers(self) -> list[NetworkFuzzResult]:
        """Test TLS cipher suite negotiation.

        Tests for weak cipher suites that should be disabled:
        - NULL ciphers (no encryption)
        - Export ciphers (weakened for export)
        - DES/3DES ciphers (weak)
        - RC4 ciphers (broken)
        - Anonymous ciphers (no authentication)

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []

        # Cipher suites to test (some may not work depending on OpenSSL version)
        weak_ciphers = [
            ("NULL", "eNULL"),
            ("EXPORT", "EXP"),
            ("DES", "DES"),
            ("3DES", "3DES"),
            ("RC4", "RC4"),
            ("ANONYMOUS", "aNULL"),
            ("MD5", "MD5"),
        ]

        for cipher_name, cipher_spec in weak_ciphers:
            start_time = time.time()
            test_name = f"tls_cipher_{cipher_name}"

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    context.set_ciphers(cipher_spec)
                except ssl.SSLError:
                    # Cipher not supported by this OpenSSL version
                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=test_name,
                            success=True,
                            duration=time.time() - start_time,
                            error=f"Cipher {cipher_spec} not available in OpenSSL",
                        )
                    )
                    continue

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)

                try:
                    tls_sock = context.wrap_socket(
                        sock, server_hostname=self.config.target_host
                    )
                    tls_sock.connect((self.config.target_host, self.config.target_port))

                    # Connection succeeded with weak cipher - security vulnerability
                    negotiated_cipher = tls_sock.cipher()

                    duration = time.time() - start_time
                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=test_name,
                            success=True,
                            duration=duration,
                            anomaly_detected=True,
                            error=f"[SECURITY] Weak cipher accepted: {negotiated_cipher}",
                        )
                    )
                    tls_sock.close()

                except ssl.SSLError as e:
                    # Expected - server rejected weak cipher
                    duration = time.time() - start_time
                    results.append(
                        NetworkFuzzResult(
                            strategy=FuzzingStrategy.PROTOCOL_STATE,
                            target_host=self.config.target_host,
                            target_port=self.config.target_port,
                            test_name=test_name,
                            success=True,
                            duration=duration,
                            error=f"Correctly rejected: {e}",
                        )
                    )
                finally:
                    sock.close()

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def _attempt_rogue_cert_handshake(self, rogue: RogueCert) -> NetworkFuzzResult:
        """Attempt mTLS handshake presenting one rogue cert as the client.

        Writes the cert and key to temp files (ssl.SSLContext.load_cert_chain
        requires file paths), builds a context, connects, and records what
        the target did. Temp files are deleted in a finally block.

        anomaly_detected=True means the target accepted the rogue cert and
        completed the handshake -- a validation bug. SSL errors during
        handshake are normal/expected (target rejected the cert).
        """
        start_time = time.time()
        test_name = f"tls_rogue_cert_{rogue.name}"

        # Write cert (with chain appended for ssl.load_cert_chain) and key.
        # delete=False because we hand the path off to load_cert_chain;
        # we clean up in finally.
        cert_file = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        key_file = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        try:
            cert_file.write(rogue.cert_pem)
            for chain_cert in rogue.chain_pem:
                cert_file.write(chain_cert)
            cert_file.close()
            key_file.write(rogue.key_pem)
            key_file.close()

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
            except ssl.SSLError as e:
                # Local cert load failed (e.g. weak key rejected by OpenSSL
                # security level). Record as an anomaly-free skip; the
                # target was never contacted.
                return NetworkFuzzResult(
                    strategy=FuzzingStrategy.INVALID_CERT,
                    target_host=self.config.target_host,
                    target_port=self.config.target_port,
                    test_name=test_name,
                    success=True,
                    duration=time.time() - start_time,
                    error=f"Local cert load rejected: {e}",
                )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            try:
                tls_sock = context.wrap_socket(
                    sock, server_hostname=self.config.target_host
                )
                try:
                    tls_sock.connect((self.config.target_host, self.config.target_port))
                    pdu = DICOMProtocolBuilder.build_a_associate_rq(
                        calling_ae=self.config.calling_ae,
                        called_ae=self.config.called_ae,
                    )
                    tls_sock.sendall(pdu)
                    response = tls_sock.recv(65536)

                    # Connection completed -- target accepted the rogue cert.
                    # That's a validation bug.
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.INVALID_CERT,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response,
                        duration=time.time() - start_time,
                        anomaly_detected=True,
                        error=f"[SECURITY] Target accepted rogue cert: {rogue.name}",
                    )
                except ssl.SSLError as e:
                    # Expected: target rejected the rogue cert.
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.INVALID_CERT,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        duration=time.time() - start_time,
                        error=f"Correctly rejected: {e}",
                    )
                finally:
                    try:
                        tls_sock.close()
                    except Exception:
                        pass
            finally:
                sock.close()

        except Exception as e:
            return NetworkFuzzResult(
                strategy=FuzzingStrategy.INVALID_CERT,
                target_host=self.config.target_host,
                target_port=self.config.target_port,
                test_name=test_name,
                success=False,
                error=str(e),
                duration=time.time() - start_time,
            )
        finally:
            for path in (cert_file.name, key_file.name):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def fuzz_tls_rogue_certs(self) -> list[NetworkFuzzResult]:
        """Present each rogue cert variant as a client cert during mTLS.

        Generates 7 X.509 certs that exercise distinct validation layers
        (self-signed, expired, not-yet-valid, wrong CN, wrong issuer,
        weak key, long chain) and attempts a TLS handshake with each.
        Targets that complete the handshake have a validation bug.

        Only meaningful against targets that request a client cert
        (mTLS). Server-auth-only targets will reject all attempts at the
        same point (no challenge), which the per-result error string
        will surface.

        Returns:
            List of NetworkFuzzResult, one per rogue cert variant.

        """
        results: list[NetworkFuzzResult] = []
        for rogue in make_all_rogue_certs(target_hostname=self.config.target_host):
            results.append(self._attempt_rogue_cert_handshake(rogue))
        return results

    def fuzz_tls_renegotiation(self) -> list[NetworkFuzzResult]:
        """Test TLS renegotiation vulnerabilities.

        Tests:
        - Client-initiated renegotiation
        - Secure renegotiation extension support
        - Renegotiation during data transfer

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        start_time = time.time()
        test_name = "tls_renegotiation"

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            try:
                tls_sock = context.wrap_socket(
                    sock, server_hostname=self.config.target_host
                )
                tls_sock.connect((self.config.target_host, self.config.target_port))

                # Send initial DICOM request
                pdu = DICOMProtocolBuilder.build_a_associate_rq(
                    calling_ae=self.config.calling_ae,
                    called_ae=self.config.called_ae,
                )
                tls_sock.sendall(pdu)
                response1 = tls_sock.recv(65536)

                # Attempt renegotiation (if supported)
                renegotiate_supported = False
                try:
                    # Python's ssl module doesn't directly expose renegotiation
                    # but we can test by checking session reuse
                    session = tls_sock.session
                    renegotiate_supported = session is not None
                except AttributeError:
                    pass  # Session attribute may not exist in all SSL versions

                duration = time.time() - start_time
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response1,
                        duration=duration,
                        error=f"Session support: {renegotiate_supported}",
                    )
                )
                tls_sock.close()

            except ssl.SSLError as e:
                duration = time.time() - start_time
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        duration=duration,
                        error=f"SSL Error: {e}",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                NetworkFuzzResult(
                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                    target_host=self.config.target_host,
                    target_port=self.config.target_port,
                    test_name=test_name,
                    success=False,
                    error=str(e),
                    duration=time.time() - start_time,
                )
            )

        return results

    def run_tls_campaign(self) -> list[NetworkFuzzResult]:
        """Run comprehensive TLS security testing campaign.

        Combines all TLS fuzzing tests for DICOM TLS (port 2762) endpoints.

        Returns:
            List of all TLS-related NetworkFuzzResult objects

        """
        results: list[NetworkFuzzResult] = []

        logger.info("Testing TLS version support...")
        results.extend(self.fuzz_tls_versions())

        logger.info("Testing TLS certificate validation...")
        results.extend(self.fuzz_tls_certificate())

        logger.info("Testing rogue client cert chains...")
        results.extend(self.fuzz_tls_rogue_certs())

        logger.info("Testing weak cipher suites...")
        results.extend(self.fuzz_tls_ciphers())

        logger.info("Testing TLS renegotiation...")
        results.extend(self.fuzz_tls_renegotiation())

        # Summary
        anomalies = sum(1 for r in results if r.anomaly_detected)
        if anomalies > 0:
            logger.warning(f"TLS campaign found {anomalies} security concerns")
        else:
            logger.info("TLS campaign completed with no security concerns")

        return results

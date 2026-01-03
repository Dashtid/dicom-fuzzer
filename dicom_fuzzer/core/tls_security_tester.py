"""TLS Security Testing for DICOM Servers.

Test TLS configuration security including version support, weak ciphers,
and certificate validation. Extracted from dicom_tls_fuzzer.py to enable
better modularity.
"""

from __future__ import annotations

import socket
import ssl
import time

from dicom_fuzzer.core.tls_types import (
    DICOMTLSFuzzerConfig,
    TLSFuzzResult,
)

# =============================================================================
# TLS Constants
# =============================================================================


# Weak cipher suites to test for (no duplicates)
WEAK_CIPHERS = [
    "NULL-MD5",
    "NULL-SHA",
    "EXP-RC4-MD5",
    "EXP-RC2-CBC-MD5",
    "EXP-DES-CBC-SHA",
    "DES-CBC-SHA",
    "DES-CBC3-SHA",
    "RC4-MD5",
    "RC4-SHA",
    "IDEA-CBC-SHA",
]

# SSL/TLS versions to test (use ssl.TLSVersion for modern Python 3.11+)
SSL_VERSIONS: list[tuple[str, ssl.TLSVersion | None]] = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
    (
        "TLSv1.1",
        ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    ),
    (
        "TLSv1.2",
        ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None,
    ),
    (
        "TLSv1.3",
        ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    ),
]


# =============================================================================
# TLS Security Tester
# =============================================================================


class TLSSecurityTester:
    """Test TLS configuration security of DICOM servers."""

    # Class-level references to module constants for backward compatibility
    WEAK_CIPHERS = WEAK_CIPHERS
    SSL_VERSIONS = SSL_VERSIONS

    def __init__(self, config: DICOMTLSFuzzerConfig) -> None:
        """Initialize the TLS security tester.

        Args:
            config: DICOM TLS fuzzer configuration.

        """
        self.config = config
        self.results: list[TLSFuzzResult] = []

    def test_ssl_version_support(self) -> list[TLSFuzzResult]:
        """Test which SSL/TLS versions are supported.

        Returns:
            List of test results for each TLS version.

        """
        results = []

        for version_name, tls_version in self.SSL_VERSIONS:
            if tls_version is None:
                continue

            result = self._test_single_version(version_name, tls_version)
            results.append(result)

        return results

    def _test_single_version(
        self, version_name: str, tls_version: ssl.TLSVersion
    ) -> TLSFuzzResult:
        """Test support for a specific TLS version.

        Args:
            version_name: Human-readable version name.
            tls_version: SSL TLSVersion enum value.

        Returns:
            Test result for the specified version.

        """
        start_time = time.time()

        try:
            # Use modern SSLContext with version constraints
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Force specific TLS version
            context.minimum_version = tls_version
            context.maximum_version = tls_version

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                with context.wrap_socket(sock) as ssock:
                    actual_version = ssock.version()

                    # TLSv1.0 and TLSv1.1 are deprecated
                    is_vulnerable = version_name in ["TLSv1.0", "TLSv1.1"]

                    return TLSFuzzResult(
                        test_type=f"ssl_version_{version_name}",
                        target=f"{self.config.target_host}:{self.config.target_port}",
                        success=True,
                        vulnerability_found=is_vulnerable,
                        vulnerability_type="deprecated_tls" if is_vulnerable else "",
                        details=f"Server supports {version_name} (actual: {actual_version})",
                        duration_ms=(time.time() - start_time) * 1000,
                        severity="high" if is_vulnerable else "info",
                    )

        except ssl.SSLError as e:
            return TLSFuzzResult(
                test_type=f"ssl_version_{version_name}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                vulnerability_found=False,
                details=f"Version {version_name} not supported: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="info",
            )

        except Exception as e:
            return TLSFuzzResult(
                test_type=f"ssl_version_{version_name}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Connection error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

    def test_weak_ciphers(self) -> list[TLSFuzzResult]:
        """Test for weak cipher suite support.

        Returns:
            List of test results for each cipher tested.

        """
        results = []

        for cipher in self.WEAK_CIPHERS:
            result = self._test_cipher(cipher)
            results.append(result)

        return results

    def _test_cipher(self, cipher: str) -> TLSFuzzResult:
        """Test support for a specific cipher.

        Args:
            cipher: Cipher suite name to test.

        Returns:
            Test result for the specified cipher.

        """
        start_time = time.time()

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers(cipher)
            except ssl.SSLError:
                return TLSFuzzResult(
                    test_type=f"cipher_{cipher}",
                    target=f"{self.config.target_host}:{self.config.target_port}",
                    success=False,
                    details=f"Cipher {cipher} not available locally",
                    duration_ms=(time.time() - start_time) * 1000,
                    severity="info",
                )

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                with context.wrap_socket(sock) as ssock:
                    negotiated = ssock.cipher()

                    return TLSFuzzResult(
                        test_type=f"cipher_{cipher}",
                        target=f"{self.config.target_host}:{self.config.target_port}",
                        success=True,
                        vulnerability_found=True,
                        vulnerability_type="weak_cipher",
                        details=f"Server accepts weak cipher: {negotiated}",
                        duration_ms=(time.time() - start_time) * 1000,
                        severity="high",
                    )

        except ssl.SSLError:
            return TLSFuzzResult(
                test_type=f"cipher_{cipher}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                vulnerability_found=False,
                details=f"Cipher {cipher} rejected (good)",
                duration_ms=(time.time() - start_time) * 1000,
                severity="info",
            )

        except Exception as e:
            return TLSFuzzResult(
                test_type=f"cipher_{cipher}",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

    def test_certificate_validation(self) -> list[TLSFuzzResult]:
        """Test certificate validation behavior.

        Returns:
            List of test results for certificate validation tests.

        """
        results = []

        # Test 1: Self-signed certificate acceptance
        results.append(self._test_self_signed_cert())

        # Test 2: Expired certificate acceptance
        results.append(self._test_expired_cert())

        # Test 3: Hostname mismatch
        results.append(self._test_hostname_mismatch())

        return results

    def _test_self_signed_cert(self) -> TLSFuzzResult:
        """Test if server accepts connections without cert validation.

        Returns:
            Test result for self-signed certificate acceptance.

        """
        start_time = time.time()

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Don't verify cert

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert(binary_form=True)

                    return TLSFuzzResult(
                        test_type="cert_validation",
                        target=f"{self.config.target_host}:{self.config.target_port}",
                        success=True,
                        vulnerability_found=False,  # This is expected behavior for testing
                        details=f"Connection succeeded without cert validation. Cert size: {len(cert) if cert else 0}",
                        duration_ms=(time.time() - start_time) * 1000,
                        severity="info",
                    )

        except Exception as e:
            return TLSFuzzResult(
                test_type="cert_validation",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

    def _test_expired_cert(self) -> TLSFuzzResult:
        """Test behavior with expired certificate.

        Returns:
            Test result for expired certificate detection.

        """
        start_time = time.time()

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                try:
                    with context.wrap_socket(
                        sock, server_hostname=self.config.target_host
                    ):
                        return TLSFuzzResult(
                            test_type="expired_cert",
                            target=f"{self.config.target_host}:{self.config.target_port}",
                            success=True,
                            vulnerability_found=False,
                            details="Certificate validation passed",
                            duration_ms=(time.time() - start_time) * 1000,
                            severity="info",
                        )
                except ssl.CertificateError as e:
                    # Check if it's an expiry error
                    if "expired" in str(e).lower():
                        return TLSFuzzResult(
                            test_type="expired_cert",
                            target=f"{self.config.target_host}:{self.config.target_port}",
                            success=False,
                            vulnerability_found=True,
                            vulnerability_type="expired_cert",
                            details=f"Server has expired certificate: {e}",
                            duration_ms=(time.time() - start_time) * 1000,
                            severity="high",
                        )
                    raise

        except Exception as e:
            return TLSFuzzResult(
                test_type="expired_cert",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="info",
            )

    def _test_hostname_mismatch(self) -> TLSFuzzResult:
        """Test certificate hostname validation.

        Returns:
            Test result for hostname mismatch detection.

        """
        start_time = time.time()

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            # Use wrong hostname
            wrong_hostname = "definitely.wrong.hostname.example.com"

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target_host, self.config.target_port))

                try:
                    with context.wrap_socket(sock, server_hostname=wrong_hostname):
                        return TLSFuzzResult(
                            test_type="hostname_mismatch",
                            target=f"{self.config.target_host}:{self.config.target_port}",
                            success=True,
                            vulnerability_found=True,
                            vulnerability_type="hostname_mismatch",
                            details="Server accepted connection with wrong hostname!",
                            duration_ms=(time.time() - start_time) * 1000,
                            severity="high",
                        )
                except ssl.CertificateError:
                    return TLSFuzzResult(
                        test_type="hostname_mismatch",
                        target=f"{self.config.target_host}:{self.config.target_port}",
                        success=False,
                        vulnerability_found=False,
                        details="Hostname validation working correctly",
                        duration_ms=(time.time() - start_time) * 1000,
                        severity="info",
                    )

        except Exception as e:
            return TLSFuzzResult(
                test_type="hostname_mismatch",
                target=f"{self.config.target_host}:{self.config.target_port}",
                success=False,
                details=f"Error: {e}",
                duration_ms=(time.time() - start_time) * 1000,
                severity="error",
            )

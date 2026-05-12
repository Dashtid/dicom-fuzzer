"""Tests for TLSFuzzingMixin in network_fuzzer_tls.py.

Coverage target: 11% -> 70%+
Tests TLS version negotiation, certificate validation, cipher testing,
and renegotiation testing for DICOM TLS endpoints.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.attacks.network.base import FuzzingStrategy, NetworkFuzzResult
from dicom_fuzzer.attacks.network.tls_mixin import TLSFuzzingMixin


@dataclass
class MockConfig:
    """Mock config for TLSFuzzingMixin tests."""

    target_host: str = "localhost"
    target_port: int = 2762
    timeout: float = 5.0
    calling_ae: str = "TEST_SCU"
    called_ae: str = "TEST_SCP"


class TLSFuzzerForTest(TLSFuzzingMixin):
    """Concrete implementation for testing mixin."""

    def __init__(self, config: MockConfig) -> None:
        self.config = config


class TestTLSFuzzingMixinVersions:
    """Tests for fuzz_tls_versions method."""

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    def test_fuzz_tls_versions_returns_list(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test fuzz_tls_versions returns a list."""
        with patch("socket.socket") as mock_sock_class:
            mock_sock = MagicMock()
            mock_sock_class.return_value = mock_sock
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")

            results = fuzzer.fuzz_tls_versions()

            assert isinstance(results, list)
            assert len(results) == 5  # 5 TLS versions tested

    def test_fuzz_tls_versions_connection_refused(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test handling of connection refused errors."""
        with patch("socket.socket") as mock_sock_class:
            mock_sock = MagicMock()
            mock_sock_class.return_value = mock_sock
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")

            results = fuzzer.fuzz_tls_versions()

            for result in results:
                assert result.success is False
                assert result.strategy == FuzzingStrategy.PROTOCOL_STATE

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_fuzz_tls_versions_ssl_error_rejected(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test SSL error handling (version rejected)."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("Version not supported")

        results = fuzzer.fuzz_tls_versions()

        assert len(results) == 5
        for result in results:
            assert result.success is True
            assert "Rejected" in result.error

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_fuzz_tls_versions_successful_tls12(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test successful TLS 1.2 connection."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        mock_tls_sock.version.return_value = "TLSv1.2"
        mock_tls_sock.cipher.return_value = ("AES256-GCM-SHA384", "TLSv1.2", 256)
        mock_tls_sock.recv.return_value = b"\x02\x00" + b"\x00" * 100  # A-ASSOCIATE-AC

        results = fuzzer.fuzz_tls_versions()

        # Find TLS 1.2 result
        tls12_results = [r for r in results if "TLS_1_2" in r.test_name]
        assert len(tls12_results) == 1
        assert tls12_results[0].success is True
        assert tls12_results[0].anomaly_detected is False  # TLS 1.2 is not deprecated

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_fuzz_tls_versions_deprecated_version_detected(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test deprecated TLS version detection."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        mock_tls_sock.version.return_value = "TLSv1.0"
        mock_tls_sock.cipher.return_value = ("AES128-SHA", "TLSv1.0", 128)
        mock_tls_sock.recv.return_value = b"\x02\x00" + b"\x00" * 100

        results = fuzzer.fuzz_tls_versions()

        # Find TLS 1.0 result
        tls10_results = [r for r in results if "TLS_1_0" in r.test_name]
        if tls10_results and tls10_results[0].success:
            assert tls10_results[0].anomaly_detected is True
            assert "SECURITY" in tls10_results[0].error

    def test_fuzz_tls_versions_generic_exception(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test generic exception handling."""
        with patch("ssl.SSLContext") as mock_ssl_ctx:
            mock_ssl_ctx.side_effect = Exception("Unexpected error")

            results = fuzzer.fuzz_tls_versions()

            assert len(results) == 5
            for result in results:
                assert result.success is False


class TestTLSFuzzingMixinCertificate:
    """Tests for fuzz_tls_certificate method."""

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    def test_fuzz_tls_certificate_returns_list(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test fuzz_tls_certificate returns a list."""
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ConnectionRefusedError()

            results = fuzzer.fuzz_tls_certificate()

            assert isinstance(results, list)
            assert len(results) == 4  # 4 certificate test cases

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_fuzz_tls_certificate_cert_none_insecure(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test CERT_NONE detection as insecure."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        mock_tls_sock.getpeercert.return_value = {
            "subject": ((("commonName", "test"),),),
            "issuer": ((("commonName", "test-ca"),),),
            "notAfter": "Dec 31 23:59:59 2025 GMT",
        }
        mock_tls_sock.recv.return_value = b"\x02\x00" + b"\x00" * 100

        results = fuzzer.fuzz_tls_certificate()

        # cert_verify_none should be detected as insecure
        cert_none_results = [r for r in results if "cert_verify_none" in r.test_name]
        assert len(cert_none_results) == 1
        # When connection succeeds with CERT_NONE, it's a vulnerability
        if cert_none_results[0].success:
            assert cert_none_results[0].anomaly_detected is True

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_fuzz_tls_certificate_ssl_error(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test SSL error during certificate validation."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("Certificate verify failed")

        results = fuzzer.fuzz_tls_certificate()

        for result in results:
            assert result.success is True
            assert "SSL Error" in result.error

    def test_fuzz_tls_certificate_generic_exception(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test generic exception handling in certificate tests."""
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.side_effect = Exception("Context creation failed")

            results = fuzzer.fuzz_tls_certificate()

            assert len(results) == 4
            for result in results:
                assert result.success is False


class TestTLSFuzzingMixinCiphers:
    """Tests for fuzz_tls_ciphers method."""

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    def test_fuzz_tls_ciphers_returns_list(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test fuzz_tls_ciphers returns a list."""
        with patch("ssl.SSLContext") as mock_ctx:
            mock_ctx.return_value.set_ciphers.side_effect = ssl.SSLError(
                "Not available"
            )

            results = fuzzer.fuzz_tls_ciphers()

            assert isinstance(results, list)
            assert len(results) == 7  # 7 weak cipher categories

    @patch("ssl.SSLContext")
    def test_fuzz_tls_ciphers_not_available_locally(
        self, mock_ssl_ctx: MagicMock, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test when cipher not available in local OpenSSL."""
        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.set_ciphers.side_effect = ssl.SSLError("Cipher not available")

        results = fuzzer.fuzz_tls_ciphers()

        for result in results:
            assert result.success is True
            assert "not available" in result.error

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_fuzz_tls_ciphers_weak_cipher_accepted(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test weak cipher accepted by server (vulnerability)."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        mock_tls_sock.cipher.return_value = ("RC4-MD5", "TLSv1.2", 128)

        results = fuzzer.fuzz_tls_ciphers()

        # Find RC4 result
        rc4_results = [r for r in results if "RC4" in r.test_name]
        assert len(rc4_results) == 1
        assert rc4_results[0].anomaly_detected is True
        assert "[SECURITY]" in rc4_results[0].error

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_fuzz_tls_ciphers_weak_cipher_rejected(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test weak cipher rejected by server (good)."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("No ciphers available")

        results = fuzzer.fuzz_tls_ciphers()

        for result in results:
            assert result.success is True
            assert "rejected" in result.error.lower()

    def test_fuzz_tls_ciphers_generic_exception(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test generic exception handling."""
        with patch("ssl.SSLContext") as mock_ssl_ctx:
            mock_ctx = MagicMock()
            mock_ssl_ctx.return_value = mock_ctx
            mock_ctx.set_ciphers.return_value = None

            with patch("socket.socket") as mock_sock_class:
                mock_sock = MagicMock()
                mock_sock_class.return_value = mock_sock
                mock_sock.settimeout.side_effect = Exception("Unexpected")

                results = fuzzer.fuzz_tls_ciphers()

                for result in results:
                    assert result.success is False


class TestTLSFuzzingMixinRenegotiation:
    """Tests for fuzz_tls_renegotiation method."""

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    def test_fuzz_tls_renegotiation_returns_list(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test fuzz_tls_renegotiation returns a list."""
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ConnectionRefusedError()

            results = fuzzer.fuzz_tls_renegotiation()

            assert isinstance(results, list)
            assert len(results) == 1

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_fuzz_tls_renegotiation_session_support(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test TLS session/renegotiation support detection."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx

        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        mock_tls_sock.session = MagicMock()  # Session supported
        mock_tls_sock.recv.return_value = b"\x02\x00" + b"\x00" * 100

        results = fuzzer.fuzz_tls_renegotiation()

        assert len(results) == 1
        assert results[0].success is True
        assert "Session support: True" in results[0].error

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_fuzz_tls_renegotiation_ssl_error(
        self,
        mock_ssl_ctx: MagicMock,
        mock_sock_class: MagicMock,
        fuzzer: TLSFuzzerForTest,
    ) -> None:
        """Test SSL error during renegotiation test."""
        mock_sock = MagicMock()
        mock_sock_class.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("Renegotiation failed")

        results = fuzzer.fuzz_tls_renegotiation()

        assert len(results) == 1
        assert results[0].success is True
        assert "SSL Error" in results[0].error

    def test_fuzz_tls_renegotiation_generic_exception(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test generic exception handling."""
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.side_effect = Exception("Unexpected error")

            results = fuzzer.fuzz_tls_renegotiation()

            assert len(results) == 1
            assert results[0].success is False


class TestTLSFuzzingMixinCampaign:
    """Tests for run_tls_campaign method."""

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    def test_run_tls_campaign_calls_all_methods(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test run_tls_campaign calls all TLS fuzzing methods."""
        with patch.object(fuzzer, "fuzz_tls_versions") as mock_versions:
            with patch.object(fuzzer, "fuzz_tls_certificate") as mock_cert:
                with patch.object(fuzzer, "fuzz_tls_rogue_certs") as mock_rogue:
                    with patch.object(fuzzer, "fuzz_tls_ciphers") as mock_ciphers:
                        with patch.object(
                            fuzzer, "fuzz_tls_renegotiation"
                        ) as mock_reneg:
                            mock_versions.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name="version_test",
                                    success=True,
                                )
                            ]
                            mock_cert.return_value = []
                            mock_rogue.return_value = []
                            mock_ciphers.return_value = []
                            mock_reneg.return_value = []

                            results = fuzzer.run_tls_campaign()

                            mock_versions.assert_called_once()
                            mock_cert.assert_called_once()
                            mock_rogue.assert_called_once()
                            mock_ciphers.assert_called_once()
                            mock_reneg.assert_called_once()
                            assert len(results) == 1

    def test_run_tls_campaign_counts_anomalies(self, fuzzer: TLSFuzzerForTest) -> None:
        """Test run_tls_campaign counts security anomalies."""
        with patch.object(fuzzer, "fuzz_tls_versions") as mock_versions:
            with patch.object(fuzzer, "fuzz_tls_certificate") as mock_cert:
                with patch.object(fuzzer, "fuzz_tls_rogue_certs") as mock_rogue:
                    with patch.object(fuzzer, "fuzz_tls_ciphers") as mock_ciphers:
                        with patch.object(
                            fuzzer, "fuzz_tls_renegotiation"
                        ) as mock_reneg:
                            mock_versions.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name="tls10",
                                    success=True,
                                    anomaly_detected=True,
                                )
                            ]
                            mock_cert.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name="cert_none",
                                    success=True,
                                    anomaly_detected=True,
                                )
                            ]
                            mock_rogue.return_value = []
                            mock_ciphers.return_value = []
                            mock_reneg.return_value = []

                            results = fuzzer.run_tls_campaign()

                            anomalies = sum(1 for r in results if r.anomaly_detected)
                            assert anomalies == 2

    def test_run_tls_campaign_aggregates_results(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        """Test run_tls_campaign aggregates all results."""
        with patch.object(fuzzer, "fuzz_tls_versions") as mock_versions:
            with patch.object(fuzzer, "fuzz_tls_certificate") as mock_cert:
                with patch.object(fuzzer, "fuzz_tls_rogue_certs") as mock_rogue:
                    with patch.object(fuzzer, "fuzz_tls_ciphers") as mock_ciphers:
                        with patch.object(
                            fuzzer, "fuzz_tls_renegotiation"
                        ) as mock_reneg:
                            mock_versions.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name=f"version_{i}",
                                    success=True,
                                )
                                for i in range(5)
                            ]
                            mock_cert.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name=f"cert_{i}",
                                    success=True,
                                )
                                for i in range(4)
                            ]
                            mock_rogue.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.INVALID_CERT,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name=f"rogue_{i}",
                                    success=True,
                                )
                                for i in range(7)
                            ]
                            mock_ciphers.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name=f"cipher_{i}",
                                    success=True,
                                )
                                for i in range(7)
                            ]
                            mock_reneg.return_value = [
                                NetworkFuzzResult(
                                    strategy=FuzzingStrategy.PROTOCOL_STATE,
                                    target_host="localhost",
                                    target_port=2762,
                                    test_name="renegotiation",
                                    success=True,
                                )
                            ]

                            results = fuzzer.run_tls_campaign()

                            assert len(results) == 5 + 4 + 7 + 7 + 1  # 24 total


class TestTLSFuzzingMixinRogueCerts:
    """Tests for fuzz_tls_rogue_certs method.

    Verifies the loop returns one result per rogue cert variant and
    that the success/anomaly/error fields are populated correctly
    based on the simulated handshake outcome.
    """

    @pytest.fixture
    def fuzzer(self) -> TLSFuzzerForTest:
        return TLSFuzzerForTest(MockConfig())

    @staticmethod
    def _setup_handshake_mocks(connect_side_effect=None):
        """Build a context manager stack that mocks socket+SSLContext so
        the handshake never touches the network. Returns the
        (mock_ssl_ctx, mock_tls_sock) tuple for further configuration.
        """
        sock_patch = patch("socket.socket")
        ssl_patch = patch("ssl.SSLContext")
        mock_sock_cls = sock_patch.start()
        mock_ssl_ctx_cls = ssl_patch.start()

        mock_sock_cls.return_value = MagicMock()
        mock_ctx = MagicMock()
        mock_ssl_ctx_cls.return_value = mock_ctx
        mock_ctx.load_cert_chain.return_value = None
        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock
        if connect_side_effect is not None:
            mock_tls_sock.connect.side_effect = connect_side_effect

        return sock_patch, ssl_patch, mock_tls_sock

    def _run_with_handshake_mocks(
        self, fuzzer: TLSFuzzerForTest, connect_side_effect=None, recv_value=b""
    ) -> list[NetworkFuzzResult]:
        sock_patch, ssl_patch, mock_tls_sock = self._setup_handshake_mocks(
            connect_side_effect
        )
        if recv_value:
            mock_tls_sock.recv.return_value = recv_value
        try:
            return fuzzer.fuzz_tls_rogue_certs()
        finally:
            sock_patch.stop()
            ssl_patch.stop()

    def test_returns_one_result_per_rogue_cert(self, fuzzer: TLSFuzzerForTest) -> None:
        results = self._run_with_handshake_mocks(
            fuzzer, connect_side_effect=ConnectionRefusedError("refused")
        )
        assert len(results) == 7

    def test_strategy_is_invalid_cert(self, fuzzer: TLSFuzzerForTest) -> None:
        results = self._run_with_handshake_mocks(
            fuzzer, connect_side_effect=ConnectionRefusedError("refused")
        )
        assert all(r.strategy == FuzzingStrategy.INVALID_CERT for r in results)

    def test_test_name_carries_variant(self, fuzzer: TLSFuzzerForTest) -> None:
        results = self._run_with_handshake_mocks(
            fuzzer, connect_side_effect=ConnectionRefusedError("refused")
        )
        names = {r.test_name for r in results}
        for variant in (
            "self_signed",
            "expired",
            "not_yet_valid",
            "wrong_cn",
            "wrong_issuer",
            "weak_key",
            "long_chain",
        ):
            assert f"tls_rogue_cert_{variant}" in names

    def test_connection_refused_records_failure(self, fuzzer: TLSFuzzerForTest) -> None:
        # ConnectionRefusedError on connect bubbles to the outer except;
        # success=False because the target is unreachable, not because
        # of a cert-validation outcome.
        results = self._run_with_handshake_mocks(
            fuzzer, connect_side_effect=ConnectionRefusedError("refused")
        )
        assert all(r.success is False for r in results)

    def test_ssl_error_during_handshake_recorded_as_rejection(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        # Target rejected the rogue cert at handshake time -- expected
        # behavior, no anomaly.
        with patch("socket.socket") as mock_sock_class:
            mock_sock = MagicMock()
            mock_sock_class.return_value = mock_sock
            with patch("ssl.SSLContext") as mock_ssl_ctx:
                mock_ctx = MagicMock()
                mock_ssl_ctx.return_value = mock_ctx
                mock_ctx.load_cert_chain.return_value = None
                mock_tls_sock = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_tls_sock
                mock_tls_sock.connect.side_effect = ssl.SSLError(
                    "certificate verify failed"
                )

                results = fuzzer.fuzz_tls_rogue_certs()

        for r in results:
            assert r.success is True
            assert r.anomaly_detected is False
            assert "Correctly rejected" in r.error

    def test_target_accepts_rogue_cert_flagged_as_anomaly(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        # Target completed the handshake with a rogue cert -- security bug.
        with patch("socket.socket") as mock_sock_class:
            mock_sock = MagicMock()
            mock_sock_class.return_value = mock_sock
            with patch("ssl.SSLContext") as mock_ssl_ctx:
                mock_ctx = MagicMock()
                mock_ssl_ctx.return_value = mock_ctx
                mock_ctx.load_cert_chain.return_value = None
                mock_tls_sock = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_tls_sock
                mock_tls_sock.recv.return_value = b"\x02\x00\x00\x00"  # fake A-AC

                results = fuzzer.fuzz_tls_rogue_certs()

        for r in results:
            assert r.success is True
            assert r.anomaly_detected is True
            assert "[SECURITY]" in r.error

    def test_local_cert_load_failure_records_skip(
        self, fuzzer: TLSFuzzerForTest
    ) -> None:
        # If load_cert_chain rejects the cert (e.g. weak key under
        # security level >=2), the target was never contacted; we
        # record success=True with a "Local cert load rejected" error
        # rather than fabricating a network result.
        with patch("ssl.SSLContext") as mock_ssl_ctx:
            mock_ctx = MagicMock()
            mock_ssl_ctx.return_value = mock_ctx
            mock_ctx.load_cert_chain.side_effect = ssl.SSLError("key too small")

            results = fuzzer.fuzz_tls_rogue_certs()

        for r in results:
            assert r.success is True
            assert r.anomaly_detected is False
            assert "Local cert load rejected" in r.error

    def test_temp_files_cleaned_up(self, fuzzer: TLSFuzzerForTest) -> None:
        # Capture all temp file paths created during the run; verify
        # they don't exist after the loop completes.
        import tempfile

        created_paths: list[str] = []
        original = tempfile.NamedTemporaryFile

        def tracking_named_tempfile(*args, **kwargs):
            f = original(*args, **kwargs)
            created_paths.append(f.name)
            return f

        with patch("tempfile.NamedTemporaryFile", side_effect=tracking_named_tempfile):
            with patch("socket.socket") as mock_sock_class:
                mock_sock = MagicMock()
                mock_sock_class.return_value = mock_sock
                mock_sock.connect.side_effect = ConnectionRefusedError("refused")
                fuzzer.fuzz_tls_rogue_certs()

        assert created_paths, "Expected temp files to be created"
        for path in created_paths:
            assert not os.path.exists(path), f"Leaked temp file: {path}"

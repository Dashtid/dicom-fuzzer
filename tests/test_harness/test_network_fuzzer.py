"""Tests for DICOM Network Protocol Fuzzer module.

Tests for network-level DICOM protocol fuzzing including:
- PDU construction
- Protocol message building
- Fuzzing strategies
- Network fuzzer operations
"""

from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.strategies.robustness.network import (
    DICOMCommand,
    DICOMNetworkConfig,
    DICOMNetworkFuzzer,
    DICOMProtocolBuilder,
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUType,
)


class TestPDUType:
    """Tests for PDUType enum."""

    def test_pdu_type_values(self) -> None:
        """Test all PDU type values."""
        assert PDUType.A_ASSOCIATE_RQ.value == 0x01
        assert PDUType.A_ASSOCIATE_AC.value == 0x02
        assert PDUType.A_ASSOCIATE_RJ.value == 0x03
        assert PDUType.P_DATA_TF.value == 0x04
        assert PDUType.A_RELEASE_RQ.value == 0x05
        assert PDUType.A_RELEASE_RP.value == 0x06
        assert PDUType.A_ABORT.value == 0x07


class TestDICOMCommand:
    """Tests for DICOMCommand enum."""

    def test_dicom_command_values(self) -> None:
        """Test key DICOM command values."""
        assert DICOMCommand.C_STORE_RQ.value == 0x0001
        assert DICOMCommand.C_STORE_RSP.value == 0x8001
        assert DICOMCommand.C_FIND_RQ.value == 0x0020
        assert DICOMCommand.C_MOVE_RQ.value == 0x0021
        assert DICOMCommand.C_ECHO_RQ.value == 0x0030
        assert DICOMCommand.C_CANCEL_RQ.value == 0x0FFF


class TestFuzzingStrategy:
    """Tests for FuzzingStrategy enum."""

    def test_fuzzing_strategy_values(self) -> None:
        """Test all fuzzing strategy values."""
        assert FuzzingStrategy.MALFORMED_PDU.value == "malformed_pdu"
        assert FuzzingStrategy.INVALID_LENGTH.value == "invalid_length"
        assert FuzzingStrategy.BUFFER_OVERFLOW.value == "buffer_overflow"
        assert FuzzingStrategy.INTEGER_OVERFLOW.value == "integer_overflow"
        assert FuzzingStrategy.NULL_BYTES.value == "null_bytes"
        assert FuzzingStrategy.UNICODE_INJECTION.value == "unicode_injection"
        assert FuzzingStrategy.PROTOCOL_STATE.value == "protocol_state"
        assert FuzzingStrategy.TIMING_ATTACK.value == "timing_attack"


class TestNetworkFuzzResult:
    """Tests for NetworkFuzzResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating NetworkFuzzResult."""
        result = NetworkFuzzResult(
            strategy=FuzzingStrategy.MALFORMED_PDU,
            target_host="localhost",
            target_port=11112,
            test_name="test_case_1",
        )

        assert result.strategy == FuzzingStrategy.MALFORMED_PDU
        assert result.target_host == "localhost"
        assert result.target_port == 11112
        assert result.test_name == "test_case_1"
        assert result.success is True  # Default
        assert isinstance(result.timestamp, datetime)

    def test_result_with_all_fields(self) -> None:
        """Test NetworkFuzzResult with all fields."""
        result = NetworkFuzzResult(
            strategy=FuzzingStrategy.BUFFER_OVERFLOW,
            target_host="192.168.1.100",
            target_port=104,
            test_name="overflow_test",
            success=False,
            response=b"\x03\x00\x00\x00",
            error="Connection reset",
            duration=1.5,
            crash_detected=True,
            anomaly_detected=True,
        )

        assert result.crash_detected is True
        assert result.anomaly_detected is True
        assert result.error == "Connection reset"
        assert result.duration == 1.5

    def test_result_to_dict(self) -> None:
        """Test NetworkFuzzResult serialization."""
        result = NetworkFuzzResult(
            strategy=FuzzingStrategy.PROTOCOL_STATE,
            target_host="localhost",
            target_port=11112,
            test_name="state_test",
            response=b"\x01\x02\x03",
        )

        data = result.to_dict()

        assert data["strategy"] == "protocol_state"
        assert data["target_host"] == "localhost"
        assert data["target_port"] == 11112
        assert data["test_name"] == "state_test"
        assert data["response_length"] == 3
        assert "timestamp" in data


class TestDICOMNetworkConfig:
    """Tests for DICOMNetworkConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = DICOMNetworkConfig()

        assert config.target_host == "localhost"
        assert config.target_port == 11112
        assert config.calling_ae == "FUZZER_SCU"
        assert config.called_ae == "ANY_SCP"
        assert config.timeout == 5.0
        assert config.max_pdu_size == 16384
        assert config.use_tls is False

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = DICOMNetworkConfig(
            target_host="192.168.1.100",
            target_port=104,
            calling_ae="MY_SCU",
            called_ae="PACS_SCP",
            timeout=10.0,
            use_tls=True,
        )

        assert config.target_host == "192.168.1.100"
        assert config.target_port == 104
        assert config.calling_ae == "MY_SCU"
        assert config.use_tls is True


class TestDICOMProtocolBuilder:
    """Tests for DICOMProtocolBuilder class."""

    def test_transfer_syntax_constants(self) -> None:
        """Test transfer syntax constants."""
        assert b"1.2.840.10008.1.2" in DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN
        assert b"1.2.840.10008.1.2.1" in DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN

    def test_sop_class_constants(self) -> None:
        """Test SOP class constants."""
        assert b"1.2.840.10008.1.1" in DICOMProtocolBuilder.VERIFICATION_SOP_CLASS
        assert b"1.2.840.10008.5.1.4.1.1.2" in DICOMProtocolBuilder.CT_IMAGE_STORAGE

    def test_build_a_associate_rq(self) -> None:
        """Test building A-ASSOCIATE-RQ PDU."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq()

        # Check PDU type
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

        # Check reserved byte
        assert pdu[1] == 0x00

        # Check length field exists (4 bytes, big-endian)
        length = struct.unpack(">L", pdu[2:6])[0]
        assert length > 0
        assert len(pdu) == 6 + length

    def test_build_a_associate_rq_custom_ae(self) -> None:
        """Test building A-ASSOCIATE-RQ with custom AE titles."""
        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            calling_ae="TEST_SCU",
            called_ae="TEST_SCP",
        )

        # AE titles should be in the PDU (padded to 16 bytes)
        assert b"TEST_SCP" in pdu[6:22] or b"TEST_SCP" in pdu
        assert b"TEST_SCU" in pdu

    def test_build_a_associate_rq_ae_padding(self) -> None:
        """Test that AE titles are padded/truncated correctly."""
        # Test truncation of long AE
        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            calling_ae="VERY_LONG_AE_TITLE_NAME",  # > 16 chars
        )
        # Should still build successfully
        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value

    def test_build_presentation_context(self) -> None:
        """Test building presentation context item."""
        pres_ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=1,
            abstract_syntax=DICOMProtocolBuilder.VERIFICATION_SOP_CLASS,
            transfer_syntaxes=[DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN],
        )

        # Check item type (0x20)
        assert pres_ctx[0] == 0x20

        # Check context ID in data
        assert pres_ctx[4] == 1

    def test_build_c_echo_rq(self) -> None:
        """Test building C-ECHO-RQ message."""
        pdu = DICOMProtocolBuilder.build_c_echo_rq()

        # Should be wrapped in P-DATA-TF
        assert pdu[0] == PDUType.P_DATA_TF.value

    def test_build_c_echo_rq_custom_message_id(self) -> None:
        """Test C-ECHO-RQ with custom message ID."""
        pdu1 = DICOMProtocolBuilder.build_c_echo_rq(message_id=1)
        pdu2 = DICOMProtocolBuilder.build_c_echo_rq(message_id=100)

        # Both should be valid P-DATA-TF
        assert pdu1[0] == PDUType.P_DATA_TF.value
        assert pdu2[0] == PDUType.P_DATA_TF.value

        # Should be different due to message ID
        assert pdu1 != pdu2


class TestDICOMNetworkFuzzer:
    """Tests for DICOMNetworkFuzzer class."""

    def test_fuzzer_initialization(self) -> None:
        """Test fuzzer initialization."""
        fuzzer = DICOMNetworkFuzzer()

        assert fuzzer.config is not None
        assert fuzzer.config.target_host == "localhost"
        assert fuzzer._results == []

    def test_fuzzer_custom_config(self) -> None:
        """Test fuzzer with custom config."""
        config = DICOMNetworkConfig(
            target_host="192.168.1.1",
            target_port=104,
        )
        fuzzer = DICOMNetworkFuzzer(config)

        assert fuzzer.config.target_host == "192.168.1.1"
        assert fuzzer.config.target_port == 104

    @patch("socket.socket")
    def test_create_socket(self, mock_socket_class: MagicMock) -> None:
        """Test socket creation."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        fuzzer = DICOMNetworkFuzzer()
        sock = fuzzer._create_socket()

        mock_socket.settimeout.assert_called_once_with(5.0)
        mock_socket.connect.assert_called_once()

    @patch("socket.socket")
    def test_create_socket_connection_error(self, mock_socket_class: MagicMock) -> None:
        """Test socket creation failure."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = OSError("Connection refused")
        mock_socket_class.return_value = mock_socket

        fuzzer = DICOMNetworkFuzzer()

        with pytest.raises(ConnectionError):
            fuzzer._create_socket()

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_test_valid_association(self, mock_send_receive: MagicMock) -> None:
        """Test valid association test."""
        # Mock A-ASSOCIATE-AC response
        mock_send_receive.return_value = (
            bytes([PDUType.A_ASSOCIATE_AC.value]) + b"\x00" * 100,
            0.1,
        )

        fuzzer = DICOMNetworkFuzzer()
        result = fuzzer.test_valid_association()

        assert result.success is True
        assert result.test_name == "valid_association"

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_test_valid_association_rejected(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test association rejection response."""
        # Mock A-ASSOCIATE-RJ response
        mock_send_receive.return_value = (
            bytes([PDUType.A_ASSOCIATE_RJ.value]) + b"\x00" * 10,
            0.1,
        )

        fuzzer = DICOMNetworkFuzzer()
        result = fuzzer.test_valid_association()

        assert result.success is True
        assert "rejected" in result.error.lower()

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_pdu_length(self, mock_send_receive: MagicMock) -> None:
        """Test PDU length fuzzing."""
        mock_send_receive.return_value = (b"\x07\x00\x00\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_pdu_length()

        # Should have multiple test cases
        assert len(results) >= 5
        # All should be length-related tests
        for result in results:
            assert "pdu_length" in result.test_name

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_ae_title(self, mock_send_receive: MagicMock) -> None:
        """Test AE title fuzzing."""
        mock_send_receive.return_value = (b"\x03\x00\x00\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_ae_title()

        # Should have multiple test cases
        assert len(results) >= 10
        # Should test various payloads
        test_names = [r.test_name for r in results]
        assert any("overflow" in name for name in test_names)
        assert any("empty" in name for name in test_names)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_presentation_context(self, mock_send_receive: MagicMock) -> None:
        """Test presentation context fuzzing."""
        mock_send_receive.return_value = (b"\x03\x00\x00\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_presentation_context()

        assert len(results) >= 4
        for result in results:
            assert "pres_ctx" in result.test_name

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_random_bytes(self, mock_send_receive: MagicMock) -> None:
        """Test random bytes fuzzing."""
        mock_send_receive.return_value = (b"", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_random_bytes(count=5)

        assert len(results) == 5
        for result in results:
            assert "random_bytes" in result.test_name

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_protocol_state(self, mock_send_receive: MagicMock) -> None:
        """Test protocol state fuzzing."""
        mock_send_receive.return_value = (b"\x07\x00\x00\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_protocol_state()

        assert len(results) >= 3
        test_names = [r.test_name for r in results]
        assert any("state_" in name for name in test_names)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_run_campaign(self, mock_send_receive: MagicMock) -> None:
        """Test running full campaign."""
        mock_send_receive.return_value = (b"\x02\x00\x00\x00\x10", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.run_campaign()

        # Should have results from multiple strategies
        assert len(results) > 10

    def test_get_summary_empty(self) -> None:
        """Test getting summary with no results."""
        fuzzer = DICOMNetworkFuzzer()
        summary = fuzzer.get_summary()

        assert summary["total_tests"] == 0
        assert summary["crashes_detected"] == 0

    def test_get_summary_with_results(self) -> None:
        """Test getting summary with results."""
        fuzzer = DICOMNetworkFuzzer()
        fuzzer._results = [
            NetworkFuzzResult(
                strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                target_host="localhost",
                target_port=11112,
                test_name="test1",
                crash_detected=True,
            ),
            NetworkFuzzResult(
                strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                target_host="localhost",
                target_port=11112,
                test_name="test2",
                anomaly_detected=True,
            ),
            NetworkFuzzResult(
                strategy=FuzzingStrategy.MALFORMED_PDU,
                target_host="localhost",
                target_port=11112,
                test_name="test3",
            ),
        ]

        summary = fuzzer.get_summary()

        assert summary["total_tests"] == 3
        assert summary["crashes_detected"] == 1
        assert summary["anomalies_detected"] == 1
        assert "buffer_overflow" in summary["by_strategy"]
        assert len(summary["critical_findings"]) == 2

    def test_print_summary(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test printing summary."""
        fuzzer = DICOMNetworkFuzzer()
        fuzzer._results = [
            NetworkFuzzResult(
                strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                target_host="localhost",
                target_port=11112,
                test_name="test1",
            ),
        ]

        fuzzer.print_summary()

        captured = capsys.readouterr()
        assert "DICOM Network Fuzzing Campaign Results" in captured.out
        assert "localhost" in captured.out

    def test_save_results(self, tmp_path: Path) -> None:
        """Test saving results to file."""
        fuzzer = DICOMNetworkFuzzer()
        fuzzer._results = [
            NetworkFuzzResult(
                strategy=FuzzingStrategy.MALFORMED_PDU,
                target_host="localhost",
                target_port=11112,
                test_name="test1",
            ),
        ]

        output_file = tmp_path / "results.json"
        fuzzer.save_results(output_file)

        assert output_file.exists()
        import json

        with open(output_file) as f:
            data = json.load(f)

        assert "config" in data
        assert "summary" in data
        assert "results" in data
        assert len(data["results"]) == 1


class TestNetworkFuzzerErrorHandling:
    """Tests for error handling in network fuzzer."""

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_timeout_handling(self, mock_send_receive: MagicMock) -> None:
        """Test handling of socket timeout."""
        mock_send_receive.side_effect = TimeoutError("Timeout")

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_pdu_length()

        # Should handle timeout gracefully
        assert all(r.success is True or "timeout" in r.error.lower() for r in results)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_connection_error_handling(self, mock_send_receive: MagicMock) -> None:
        """Test handling of connection errors."""
        mock_send_receive.side_effect = OSError("Connection refused")

        fuzzer = DICOMNetworkFuzzer()
        result = fuzzer.test_valid_association()

        assert result.success is False
        assert len(result.error) > 0


class TestNetworkFuzzerTLS:
    """Tests for TLS/SSL handling in network fuzzer."""

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_create_socket_with_tls(
        self, mock_ssl_context: MagicMock, mock_socket_class: MagicMock
    ) -> None:
        """Test socket creation with TLS enabled."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_wrapped_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_wrapped_socket

        config = DICOMNetworkConfig(use_tls=True)
        fuzzer = DICOMNetworkFuzzer(config)
        sock = fuzzer._create_socket()

        mock_ssl_context.assert_called_once()
        mock_context.wrap_socket.assert_called_once()
        assert sock == mock_wrapped_socket

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_create_socket_with_tls_no_verify(
        self, mock_ssl_context: MagicMock, mock_socket_class: MagicMock
    ) -> None:
        """Test socket creation with TLS but no certificate verification."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_wrapped_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_wrapped_socket

        config = DICOMNetworkConfig(use_tls=True, verify_ssl=False)
        fuzzer = DICOMNetworkFuzzer(config)
        fuzzer._create_socket()

        # Should disable hostname and certificate verification
        assert mock_context.check_hostname is False


class TestNetworkFuzzerSendReceive:
    """Tests for send/receive functionality."""

    @patch("socket.socket")
    def test_send_receive_with_existing_socket(
        self, mock_socket_class: MagicMock
    ) -> None:
        """Test send/receive with an existing socket."""
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"\x02\x00\x00\x00\x10"

        fuzzer = DICOMNetworkFuzzer()
        response, duration = fuzzer._send_receive(b"\x01\x00\x00\x00", mock_socket)

        mock_socket.sendall.assert_called_once_with(b"\x01\x00\x00\x00")
        mock_socket.recv.assert_called_once()
        # Socket should NOT be closed since it was passed in
        mock_socket.close.assert_not_called()
        assert response == b"\x02\x00\x00\x00\x10"

    @patch.object(DICOMNetworkFuzzer, "_create_socket")
    def test_send_receive_creates_new_socket(
        self, mock_create_socket: MagicMock
    ) -> None:
        """Test send/receive creates socket when none provided."""
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"\x02"
        mock_create_socket.return_value = mock_socket

        fuzzer = DICOMNetworkFuzzer()
        response, duration = fuzzer._send_receive(b"\x01")

        mock_create_socket.assert_called_once()
        mock_socket.close.assert_called_once()


class TestNetworkFuzzerUnexpectedResponses:
    """Tests for handling unexpected server responses."""

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_valid_association_unexpected_response(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test handling of unexpected response type."""
        # Send an unknown PDU type
        mock_send_receive.return_value = (b"\xff\x00\x00\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        result = fuzzer.test_valid_association()

        assert result.success is False
        assert result.anomaly_detected is True
        assert "unexpected" in result.error.lower()

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_valid_association_empty_response(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test handling of empty response."""
        mock_send_receive.return_value = (b"", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        result = fuzzer.test_valid_association()

        # Empty response should be anomalous
        assert result.success is False
        assert result.anomaly_detected is True


class TestNetworkFuzzerCampaignStrategies:
    """Tests for campaign with specific strategies."""

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_run_campaign_single_strategy(self, mock_send_receive: MagicMock) -> None:
        """Test running campaign with single strategy."""
        mock_send_receive.return_value = (b"\x02\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.run_campaign(strategies=[FuzzingStrategy.INVALID_LENGTH])

        # Should have valid association test plus length tests
        assert len(results) >= 1
        # Should include length tests
        length_tests = [r for r in results if "length" in r.test_name]
        assert len(length_tests) >= 5

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_run_campaign_multiple_strategies(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test running campaign with multiple strategies."""
        mock_send_receive.return_value = (b"\x02\x00", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.run_campaign(
            strategies=[FuzzingStrategy.INVALID_LENGTH, FuzzingStrategy.BUFFER_OVERFLOW]
        )

        # Should have tests from both strategies
        length_tests = [r for r in results if "length" in r.test_name]
        ae_tests = [r for r in results if "ae_title" in r.test_name]

        assert len(length_tests) >= 5
        assert len(ae_tests) >= 10


class TestNetworkFuzzerCrashDetection:
    """Tests for crash and anomaly detection."""

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_pdu_length_detects_crash(self, mock_send_receive: MagicMock) -> None:
        """Test that empty response is detected as potential crash."""
        # Empty response indicates server may have crashed
        mock_send_receive.return_value = (b"", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_pdu_length()

        # At least some tests should detect crash
        crashes = [r for r in results if r.crash_detected]
        assert len(crashes) > 0

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_ae_title_detects_crash(self, mock_send_receive: MagicMock) -> None:
        """Test crash detection in AE title fuzzing."""
        mock_send_receive.return_value = (b"", 0.1)

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_ae_title()

        crashes = [r for r in results if r.crash_detected]
        assert len(crashes) > 0


class TestNetworkFuzzerExceptionHandling:
    """Tests for various exception scenarios."""

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_ae_title_exception_handling(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test exception handling in AE title fuzzing."""
        mock_send_receive.side_effect = OSError("Network error")

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_ae_title()

        # All should fail but not crash the fuzzer
        assert all(r.success is False for r in results)
        # Error message should contain the OSError message
        assert all(len(r.error) > 0 for r in results)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_presentation_context_exception(
        self, mock_send_receive: MagicMock
    ) -> None:
        """Test exception handling in presentation context fuzzing."""
        mock_send_receive.side_effect = ConnectionResetError("Reset")

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_presentation_context()

        assert all(r.success is False for r in results)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_random_bytes_exception(self, mock_send_receive: MagicMock) -> None:
        """Test exception handling in random bytes fuzzing."""
        mock_send_receive.side_effect = BrokenPipeError("Pipe broken")

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_random_bytes(count=3)

        assert len(results) == 3
        assert all(r.success is False for r in results)

    @patch.object(DICOMNetworkFuzzer, "_send_receive")
    def test_fuzz_protocol_state_exception(self, mock_send_receive: MagicMock) -> None:
        """Test exception handling in protocol state fuzzing."""
        mock_send_receive.side_effect = Exception("Unknown error")

        fuzzer = DICOMNetworkFuzzer()
        results = fuzzer.fuzz_protocol_state()

        assert all(r.success is False for r in results)


class TestNetworkFuzzerSummaryEdgeCases:
    """Tests for summary generation edge cases."""

    def test_summary_with_mixed_strategies(self) -> None:
        """Test summary with results from different strategies."""
        fuzzer = DICOMNetworkFuzzer()
        fuzzer._results = [
            NetworkFuzzResult(
                strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                target_host="localhost",
                target_port=11112,
                test_name="test1",
                success=True,
                crash_detected=True,
            ),
            NetworkFuzzResult(
                strategy=FuzzingStrategy.INVALID_LENGTH,
                target_host="localhost",
                target_port=11112,
                test_name="test2",
                success=False,
                anomaly_detected=True,
            ),
            NetworkFuzzResult(
                strategy=FuzzingStrategy.PROTOCOL_STATE,
                target_host="localhost",
                target_port=11112,
                test_name="test3",
                success=True,
            ),
            NetworkFuzzResult(
                strategy=FuzzingStrategy.NULL_BYTES,
                target_host="localhost",
                target_port=11112,
                test_name="test4",
                success=True,
                crash_detected=True,
                anomaly_detected=True,
            ),
        ]

        summary = fuzzer.get_summary()

        assert summary["total_tests"] == 4
        assert summary["successful"] == 3
        assert summary["failed"] == 1
        assert summary["crashes_detected"] == 2
        assert summary["anomalies_detected"] == 2
        assert len(summary["by_strategy"]) == 4
        assert len(summary["critical_findings"]) == 3  # 2 crashes + 1 anomaly only

    def test_summary_critical_findings_limit(self) -> None:
        """Test that critical findings are limited in print output."""
        fuzzer = DICOMNetworkFuzzer()
        # Add more than 10 critical findings
        fuzzer._results = [
            NetworkFuzzResult(
                strategy=FuzzingStrategy.BUFFER_OVERFLOW,
                target_host="localhost",
                target_port=11112,
                test_name=f"crash_test_{i}",
                crash_detected=True,
            )
            for i in range(15)
        ]

        summary = fuzzer.get_summary()

        # All 15 should be in critical findings
        assert len(summary["critical_findings"]) == 15


class TestProtocolBuilderEdgeCases:
    """Tests for protocol builder edge cases."""

    def test_build_presentation_context_multiple_transfer_syntaxes(self) -> None:
        """Test building presentation context with multiple transfer syntaxes."""
        pres_ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=3,
            abstract_syntax=DICOMProtocolBuilder.CT_IMAGE_STORAGE,
            transfer_syntaxes=[
                DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN,
                DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN,
                DICOMProtocolBuilder.EXPLICIT_VR_BIG_ENDIAN,
            ],
        )

        # Should contain all three transfer syntaxes
        assert DICOMProtocolBuilder.IMPLICIT_VR_LITTLE_ENDIAN[:-1] in pres_ctx
        assert DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN[:-1] in pres_ctx

    def test_build_a_associate_rq_with_custom_contexts(self) -> None:
        """Test building A-ASSOCIATE-RQ with custom presentation contexts."""
        custom_ctx = DICOMProtocolBuilder._build_presentation_context(
            context_id=5,
            abstract_syntax=DICOMProtocolBuilder.MR_IMAGE_STORAGE,
            transfer_syntaxes=[DICOMProtocolBuilder.EXPLICIT_VR_LITTLE_ENDIAN],
        )

        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            calling_ae="CUSTOM_SCU",
            called_ae="CUSTOM_SCP",
            presentation_contexts=[custom_ctx],
            max_pdu_size=32768,
        )

        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value
        # Should contain MR Image Storage SOP class
        assert b"1.2.840.10008.5.1.4.1.1.4" in pdu

    def test_build_a_associate_rq_custom_application_context(self) -> None:
        """Test building A-ASSOCIATE-RQ with custom application context."""
        custom_app_ctx = b"1.2.3.4.5.6.7.8.9\x00"

        pdu = DICOMProtocolBuilder.build_a_associate_rq(
            application_context=custom_app_ctx,
        )

        assert pdu[0] == PDUType.A_ASSOCIATE_RQ.value
        assert b"1.2.3.4.5.6.7.8.9" in pdu

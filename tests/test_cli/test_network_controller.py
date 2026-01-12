"""Tests for network_controller.py.

Coverage target: 30% -> 70%+
Tests DICOM network protocol fuzzing controller.
"""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.network_controller import (
    HAS_NETWORK_FUZZER,
    STRATEGY_MAP,
    NetworkFuzzingController,
)


class TestNetworkFuzzingControllerAvailability:
    """Tests for availability checking."""

    def test_is_available(self) -> None:
        """Test is_available returns correct value."""
        result = NetworkFuzzingController.is_available()
        assert result == HAS_NETWORK_FUZZER

    def test_strategy_map_populated_if_available(self) -> None:
        """Test STRATEGY_MAP is populated when network fuzzer available."""
        if HAS_NETWORK_FUZZER:
            assert len(STRATEGY_MAP) > 0
            assert "malformed_pdu" in STRATEGY_MAP
            assert "buffer_overflow" in STRATEGY_MAP
            assert "all" in STRATEGY_MAP
            # 'all' should map to None
            assert STRATEGY_MAP["all"] is None


class TestNetworkFuzzingControllerRun:
    """Tests for run method."""

    @pytest.fixture
    def basic_args(self) -> Namespace:
        """Create basic args namespace."""
        args = Namespace()
        args.host = "localhost"
        args.port = 11112
        args.ae_title = "TEST_SCU"
        args.timeout = 5.0
        args.network_strategy = "all"
        args.verbose = False
        return args

    def test_run_not_available(self, basic_args: Namespace) -> None:
        """Test run when network fuzzer not available."""
        with patch("dicom_fuzzer.cli.network_controller.HAS_NETWORK_FUZZER", False):
            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 1  # Failure

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_success(self, basic_args: Namespace) -> None:
        """Test successful run."""
        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer = MagicMock()
            mock_fuzzer_class.return_value = mock_fuzzer
            mock_fuzzer.run_campaign.return_value = []

            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 0
            mock_fuzzer.run_campaign.assert_called_once()

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_with_specific_strategy(self, basic_args: Namespace) -> None:
        """Test run with specific strategy."""
        basic_args.network_strategy = "malformed_pdu"

        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer = MagicMock()
            mock_fuzzer_class.return_value = mock_fuzzer
            mock_fuzzer.run_campaign.return_value = []

            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 0
            # Should be called with specific strategy list
            mock_fuzzer.run_campaign.assert_called_once()
            call_kwargs = mock_fuzzer.run_campaign.call_args
            assert call_kwargs[1]["strategies"] is not None

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_all_strategies(self, basic_args: Namespace) -> None:
        """Test run with 'all' strategy."""
        basic_args.network_strategy = "all"

        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer = MagicMock()
            mock_fuzzer_class.return_value = mock_fuzzer
            mock_fuzzer.run_campaign.return_value = []

            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 0
            # 'all' should pass None for strategies
            call_kwargs = mock_fuzzer.run_campaign.call_args
            assert call_kwargs[1]["strategies"] is None

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_exception_handling(self, basic_args: Namespace) -> None:
        """Test run handles exceptions gracefully."""
        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer_class.side_effect = Exception("Connection failed")

            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 1

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_exception_verbose(self, basic_args: Namespace) -> None:
        """Test run shows traceback in verbose mode."""
        basic_args.verbose = True

        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer_class.side_effect = Exception("Connection failed")

            result = NetworkFuzzingController.run(args=basic_args)

            assert result == 1

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_run_with_generated_files(self, basic_args: Namespace) -> None:
        """Test run with generated_files parameter (for interface consistency)."""
        with patch(
            "dicom_fuzzer.cli.network_controller.DICOMNetworkFuzzer"
        ) as mock_fuzzer_class:
            mock_fuzzer = MagicMock()
            mock_fuzzer_class.return_value = mock_fuzzer
            mock_fuzzer.run_campaign.return_value = []

            # generated_files should be ignored
            result = NetworkFuzzingController.run(
                args=basic_args,
                generated_files=[Path("/fake/file.dcm")],
            )

            assert result == 0


class TestNetworkFuzzingControllerDisplayResults:
    """Tests for _display_results method."""

    def test_display_results_no_errors(self, capsys) -> None:
        """Test displaying results with no errors."""
        mock_result = MagicMock()
        mock_result.error = None

        NetworkFuzzingController._display_results(
            results=[mock_result, mock_result],
            verbose=False,
        )

        captured = capsys.readouterr()
        assert "Total PDUs sent:  2" in captured.out
        assert "Errors detected:  0" in captured.out

    def test_display_results_with_errors(self, capsys) -> None:
        """Test displaying results with errors."""
        mock_result_ok = MagicMock()
        mock_result_ok.error = None

        mock_result_err = MagicMock()
        mock_result_err.error = "Connection timeout"
        mock_result_err.strategy = MagicMock()
        mock_result_err.strategy.value = "malformed_pdu"

        NetworkFuzzingController._display_results(
            results=[mock_result_ok, mock_result_err],
            verbose=False,
        )

        captured = capsys.readouterr()
        assert "Errors detected:  1" in captured.out

    def test_display_results_verbose_shows_errors(self, capsys) -> None:
        """Test verbose mode shows error details."""
        mock_result_err = MagicMock()
        mock_result_err.error = "Protocol error"
        mock_result_err.strategy = MagicMock()
        mock_result_err.strategy.value = "buffer_overflow"

        NetworkFuzzingController._display_results(
            results=[mock_result_err],
            verbose=True,
        )

        captured = capsys.readouterr()
        assert "Protocol error" in captured.out
        assert "buffer_overflow" in captured.out

    def test_display_results_non_verbose_hides_details(self, capsys) -> None:
        """Test non-verbose mode hides error details."""
        mock_result_err = MagicMock()
        mock_result_err.error = "Secret error details"
        mock_result_err.strategy = MagicMock()
        mock_result_err.strategy.value = "test"

        NetworkFuzzingController._display_results(
            results=[mock_result_err],
            verbose=False,
        )

        captured = capsys.readouterr()
        # Error count shown but not details
        assert "Errors detected:  1" in captured.out
        assert "Secret error details" not in captured.out

    def test_display_results_empty_list(self, capsys) -> None:
        """Test displaying empty results."""
        NetworkFuzzingController._display_results(
            results=[],
            verbose=False,
        )

        captured = capsys.readouterr()
        assert "Total PDUs sent:  0" in captured.out
        assert "Errors detected:  0" in captured.out


class TestStrategyMap:
    """Tests for STRATEGY_MAP constant."""

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_all_expected_strategies_present(self) -> None:
        """Test all expected strategies are in the map."""
        expected = [
            "malformed_pdu",
            "invalid_length",
            "buffer_overflow",
            "integer_overflow",
            "null_bytes",
            "unicode_injection",
            "protocol_state",
            "timing_attack",
            "all",
        ]
        for strategy in expected:
            assert strategy in STRATEGY_MAP

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_all_strategy_is_none(self) -> None:
        """Test 'all' strategy maps to None."""
        assert STRATEGY_MAP["all"] is None

    @pytest.mark.skipif(not HAS_NETWORK_FUZZER, reason="Network fuzzer not available")
    def test_specific_strategies_are_not_none(self) -> None:
        """Test specific strategies map to actual enum values."""
        for key, value in STRATEGY_MAP.items():
            if key != "all":
                assert value is not None

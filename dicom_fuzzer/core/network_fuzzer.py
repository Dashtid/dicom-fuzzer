"""DICOM Network Protocol Fuzzer.

This module provides network-level fuzzing capabilities for DICOM protocol
implementations, targeting:
- A-ASSOCIATE handshake fuzzing
- C-STORE operation fuzzing
- C-FIND query fuzzing
- C-MOVE operation fuzzing
- DICOM TLS implementation testing

Based on research from:
- IOActive: Penetration Testing of the DICOM Protocol
- DICOM-Fuzzer (SpringerLink) - Vulnerability mining framework
- NetworkFuzzer (ARES 2025) - Response-aware network fuzzing
- EXPLIoT Framework - DICOM testing capabilities

References:
- https://www.ioactive.com/penetration-testing-of-the-dicom-protocol-real-world-attacks/
- https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38
- https://github.com/r1b/dicom-fuzz
- https://expliot.readthedocs.io/en/latest/tests/dicom.html

"""

from __future__ import annotations

import logging
import socket
import struct
import time
from pathlib import Path
from typing import Any

# Re-export base types for backward compatibility
from dicom_fuzzer.core.network_fuzzer_base import (
    DICOMCommand,
    DICOMNetworkConfig,
    FuzzingStrategy,
    NetworkFuzzResult,
    PDUType,
)
from dicom_fuzzer.core.network_fuzzer_builder import DICOMProtocolBuilder
from dicom_fuzzer.core.network_fuzzer_pdu import PDUFuzzingMixin
from dicom_fuzzer.core.network_fuzzer_tls import TLSFuzzingMixin

__all__ = [
    "DICOMCommand",
    "PDUType",
    "FuzzingStrategy",
    "NetworkFuzzResult",
    "DICOMNetworkConfig",
    "DICOMProtocolBuilder",
    "DICOMNetworkFuzzer",
]

logger = logging.getLogger(__name__)


class DICOMNetworkFuzzer(PDUFuzzingMixin, TLSFuzzingMixin):
    """DICOM Network Protocol Fuzzer.

    Performs network-level fuzzing of DICOM protocol implementations
    to discover vulnerabilities in:
    - Association establishment (A-ASSOCIATE)
    - DIMSE operations (C-STORE, C-FIND, C-MOVE, C-ECHO)
    - Protocol state handling
    - Length field parsing
    - Buffer handling

    Usage:
        fuzzer = DICOMNetworkFuzzer(config)
        results = fuzzer.run_campaign()
        fuzzer.print_summary(results)

    """

    def __init__(self, config: DICOMNetworkConfig | None = None):
        """Initialize network fuzzer.

        Args:
            config: Network configuration (uses defaults if None)

        """
        self.config = config or DICOMNetworkConfig()
        self._results: list[NetworkFuzzResult] = []

        logger.info(
            f"DICOMNetworkFuzzer initialized: "
            f"target={self.config.target_host}:{self.config.target_port}"
        )

    def _create_socket(self) -> socket.socket:
        """Create a socket connection to the target.

        Returns:
            Connected socket

        Raises:
            ConnectionError: If connection fails

        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            if self.config.use_tls:
                import ssl

                context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(
                    sock, server_hostname=self.config.target_host
                )

            sock.connect((self.config.target_host, self.config.target_port))
            return sock

        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}") from e

    def _send_receive(
        self, data: bytes, sock: socket.socket | None = None
    ) -> tuple[bytes, float]:
        """Send data and receive response.

        Args:
            data: Data to send
            sock: Existing socket or None to create new one

        Returns:
            Tuple of (response bytes, duration in seconds)

        """
        close_sock = sock is None
        if sock is None:
            sock = self._create_socket()

        start_time = time.time()
        try:
            sock.sendall(data)
            response = sock.recv(65536)
            duration = time.time() - start_time
            return response, duration
        finally:
            if close_sock:
                sock.close()

    def test_valid_association(self) -> NetworkFuzzResult:
        """Test valid A-ASSOCIATE-RQ to verify connectivity.

        Returns:
            NetworkFuzzResult with test outcome

        """
        test_name = "valid_association"
        start_time = time.time()

        try:
            pdu = DICOMProtocolBuilder.build_a_associate_rq(
                calling_ae=self.config.calling_ae,
                called_ae=self.config.called_ae,
            )
            response, _ = self._send_receive(pdu)
            duration = time.time() - start_time

            # Check response type
            if len(response) >= 1:
                pdu_type = response[0]
                if pdu_type == PDUType.A_ASSOCIATE_AC.value:
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response,
                        duration=duration,
                    )
                elif pdu_type == PDUType.A_ASSOCIATE_RJ.value:
                    return NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=test_name,
                        success=True,
                        response=response,
                        duration=duration,
                        error="Association rejected",
                    )

            return NetworkFuzzResult(
                strategy=FuzzingStrategy.PROTOCOL_STATE,
                target_host=self.config.target_host,
                target_port=self.config.target_port,
                test_name=test_name,
                success=False,
                response=response,
                duration=duration,
                error="Unexpected response",
                anomaly_detected=True,
            )

        except Exception as e:
            return NetworkFuzzResult(
                strategy=FuzzingStrategy.PROTOCOL_STATE,
                target_host=self.config.target_host,
                target_port=self.config.target_port,
                test_name=test_name,
                success=False,
                error=str(e),
                duration=time.time() - start_time,
            )

    def fuzz_protocol_state(self) -> list[NetworkFuzzResult]:
        """Test protocol state machine violations.

        Tests:
        - Sending P-DATA before association
        - Sending multiple A-ASSOCIATE-RQ
        - Sending A-RELEASE without association
        - Sending commands out of order

        Returns:
            List of NetworkFuzzResult objects

        """
        results = []
        test_cases = [
            ("pdata_before_assoc", DICOMProtocolBuilder.build_c_echo_rq()),
            (
                "release_before_assoc",
                struct.pack(">BBL", PDUType.A_RELEASE_RQ.value, 0x00, 4) + b"\x00" * 4,
            ),
            (
                "abort_before_assoc",
                struct.pack(">BBL", PDUType.A_ABORT.value, 0x00, 4) + b"\x00" * 4,
            ),
        ]

        for test_name, pdu in test_cases:
            start_time = time.time()
            try:
                response, _ = self._send_receive(pdu)
                duration = time.time() - start_time

                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"state_{test_name}",
                        success=True,
                        response=response,
                        duration=duration,
                    )
                )

            except Exception as e:
                results.append(
                    NetworkFuzzResult(
                        strategy=FuzzingStrategy.PROTOCOL_STATE,
                        target_host=self.config.target_host,
                        target_port=self.config.target_port,
                        test_name=f"state_{test_name}",
                        success=False,
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                )

        return results

    def run_campaign(
        self, strategies: list[FuzzingStrategy] | None = None
    ) -> list[NetworkFuzzResult]:
        """Run complete fuzzing campaign.

        Args:
            strategies: List of strategies to run (all if None)

        Returns:
            List of all NetworkFuzzResult objects

        """
        if strategies is None:
            strategies = list(FuzzingStrategy)

        results: list[NetworkFuzzResult] = []

        # First test valid association
        logger.info("Testing valid association...")
        results.append(self.test_valid_association())

        if FuzzingStrategy.INVALID_LENGTH in strategies:
            logger.info("Fuzzing PDU length fields...")
            results.extend(self.fuzz_pdu_length())

        if FuzzingStrategy.BUFFER_OVERFLOW in strategies:
            logger.info("Fuzzing AE titles (buffer overflow)...")
            results.extend(self.fuzz_ae_title())

        if FuzzingStrategy.MALFORMED_PDU in strategies:
            logger.info("Fuzzing presentation contexts...")
            results.extend(self.fuzz_presentation_context())

            logger.info("Sending random bytes...")
            results.extend(self.fuzz_random_bytes())

        if FuzzingStrategy.PROTOCOL_STATE in strategies:
            logger.info("Testing protocol state violations...")
            results.extend(self.fuzz_protocol_state())

        self._results = results
        return results

    def get_summary(self) -> dict[str, Any]:
        """Get summary of fuzzing results.

        Returns:
            Dictionary with result statistics

        """
        results = self._results

        summary: dict[str, Any] = {
            "total_tests": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "crashes_detected": sum(1 for r in results if r.crash_detected),
            "anomalies_detected": sum(1 for r in results if r.anomaly_detected),
            "by_strategy": {},
            "critical_findings": [],
        }

        for result in results:
            strategy = result.strategy.value
            if strategy not in summary["by_strategy"]:
                summary["by_strategy"][strategy] = {
                    "total": 0,
                    "successful": 0,
                    "crashes": 0,
                    "anomalies": 0,
                }
            summary["by_strategy"][strategy]["total"] += 1
            if result.success:
                summary["by_strategy"][strategy]["successful"] += 1
            if result.crash_detected:
                summary["by_strategy"][strategy]["crashes"] += 1
            if result.anomaly_detected:
                summary["by_strategy"][strategy]["anomalies"] += 1

            if result.crash_detected or result.anomaly_detected:
                summary["critical_findings"].append(result.to_dict())

        return summary

    def print_summary(self) -> None:
        """Print formatted summary to console."""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("  DICOM Network Fuzzing Campaign Results")
        print("=" * 70)
        print(
            f"  Target:            {self.config.target_host}:{self.config.target_port}"
        )
        print(f"  Total Tests:       {summary['total_tests']}")
        print(f"  Successful:        {summary['successful']}")
        print(f"  Failed:            {summary['failed']}")
        print(f"  Crashes Detected:  {summary['crashes_detected']}")
        print(f"  Anomalies:         {summary['anomalies_detected']}")

        print("\n--- Results by Strategy ---")
        for strategy, stats in summary["by_strategy"].items():
            print(
                f"  {strategy}: {stats['total']} tests, "
                f"{stats['crashes']} crashes, {stats['anomalies']} anomalies"
            )

        if summary["critical_findings"]:
            print("\n--- Critical Findings ---")
            for finding in summary["critical_findings"][:10]:
                print(
                    f"  [!] {finding['test_name']}: {finding.get('error', 'anomaly')}"
                )

        print("=" * 70 + "\n")

    def save_results(self, output_path: Path) -> None:
        """Save results to JSON file.

        Args:
            output_path: Path to save results

        """
        import json

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(
                {
                    "config": {
                        "target_host": self.config.target_host,
                        "target_port": self.config.target_port,
                        "calling_ae": self.config.calling_ae,
                        "called_ae": self.config.called_ae,
                    },
                    "summary": self.get_summary(),
                    "results": [r.to_dict() for r in self._results],
                },
                f,
                indent=2,
            )
        logger.info(f"Results saved to {output_path}")

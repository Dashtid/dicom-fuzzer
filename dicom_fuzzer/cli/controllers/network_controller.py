"""Network Fuzzing Controller for DICOM Fuzzer CLI.

Handles DICOM network protocol fuzzing operations.
"""

from __future__ import annotations

import logging
from argparse import Namespace
from typing import TYPE_CHECKING

from dicom_fuzzer.cli.utils import output as cli

if TYPE_CHECKING:
    from pathlib import Path

    from dicom_fuzzer.attacks.network import NetworkFuzzResult

logger = logging.getLogger(__name__)

# Check for network fuzzer availability
try:
    from dicom_fuzzer.attacks.network import (
        DICOMNetworkConfig,
        DICOMNetworkFuzzer,
        FuzzingStrategy,
    )

    HAS_NETWORK_FUZZER = True
except ImportError:
    HAS_NETWORK_FUZZER = False


# Strategy name to enum mapping
STRATEGY_MAP: dict[str, FuzzingStrategy | None] = {}
if HAS_NETWORK_FUZZER:
    STRATEGY_MAP = {
        "malformed_pdu": FuzzingStrategy.MALFORMED_PDU,
        "invalid_length": FuzzingStrategy.INVALID_LENGTH,
        "buffer_overflow": FuzzingStrategy.BUFFER_OVERFLOW,
        "integer_overflow": FuzzingStrategy.INTEGER_OVERFLOW,
        "null_bytes": FuzzingStrategy.NULL_BYTES,
        "unicode_injection": FuzzingStrategy.UNICODE_INJECTION,
        "protocol_state": FuzzingStrategy.PROTOCOL_STATE,
        "timing_attack": FuzzingStrategy.TIMING_ATTACK,
        "all": None,  # None means run all strategies
    }


class NetworkFuzzingController:
    """Controller for DICOM network protocol fuzzing."""

    @staticmethod
    def is_available() -> bool:
        """Check if network fuzzing module is available."""
        return HAS_NETWORK_FUZZER

    @staticmethod
    def run(args: Namespace, generated_files: list[Path] | None = None) -> int:
        """Run network fuzzing campaign.

        Args:
            args: Parsed command-line arguments
            generated_files: List of generated files (unused, for interface consistency)

        Returns:
            Exit code (0 for success, 1 for failure)

        """
        if not HAS_NETWORK_FUZZER:
            cli.error("Network fuzzing module not available.")
            cli.status(
                "Please check that dicom_fuzzer.core.network_fuzzer is installed."
            )
            return 1

        # Display header
        cli.header("DICOM Network Protocol Fuzzing")
        cli.detail("Host", f"{args.host}:{args.port}")
        cli.detail("AE Title", args.ae_title)
        cli.detail("Strategy", args.network_strategy)
        cli.divider()

        try:
            # Create network fuzzer configuration
            network_config = DICOMNetworkConfig(
                target_host=args.host,
                target_port=args.port,
                calling_ae=args.ae_title,
                timeout=args.timeout,
            )
            network_fuzzer = DICOMNetworkFuzzer(network_config)

            # Run network fuzzing with selected strategy
            logger.info("Starting DICOM network protocol fuzzing...")
            selected_strategy = STRATEGY_MAP.get(args.network_strategy)
            strategies = [selected_strategy] if selected_strategy else None
            network_results = network_fuzzer.run_campaign(strategies=strategies)

            # Print results
            NetworkFuzzingController._display_results(
                network_results, verbose=args.verbose
            )

            return 0

        except Exception as e:
            logger.error(f"Network fuzzing failed: {e}", exc_info=args.verbose)
            print(f"\n[ERROR] Network fuzzing failed: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()
            return 1

    @staticmethod
    def _display_results(
        results: list[NetworkFuzzResult], verbose: bool = False
    ) -> None:
        """Display network fuzzing results.

        Args:
            results: List of NetworkFuzzResult objects
            verbose: Whether to show detailed error information

        """
        print("\n  Network Fuzzing Results:")
        print(f"  Total PDUs sent:  {len(results)}")
        errors = sum(1 for r in results if r.error)
        print(f"  Errors detected:  {errors}")

        # Print errors if any
        if errors > 0 and verbose:
            print("\n  Errors:")
            for result in results:
                if result.error:
                    print(f"    - {result.strategy.value}: {result.error}")

        print("=" * 70 + "\n")

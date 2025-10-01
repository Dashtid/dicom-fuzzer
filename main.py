"""
DICOM Fuzzer - Command Line Interface

A security testing tool for comprehensive fuzzing of DICOM implementations.
Generates mutated DICOM files to test parser robustness and security.
"""

import argparse
import logging
import sys
from pathlib import Path

from core.generator import DICOMGenerator


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def validate_input_file(file_path: str) -> Path:
    """
    Validate that the input file exists and is a DICOM file.

    Args:
        file_path: Path to input DICOM file

    Returns:
        Validated Path object

    Raises:
        SystemExit: If file doesn't exist or isn't accessible
    """
    path = Path(file_path)
    if not path.exists():
        print(f"Error: Input file '{file_path}' not found")
        sys.exit(1)
    if not path.is_file():
        print(f"Error: '{file_path}' is not a file")
        sys.exit(1)
    return path


def parse_strategies(strategies_str: str) -> list:
    """
    Parse comma-separated strategy list.

    Args:
        strategies_str: Comma-separated strategy names

    Returns:
        List of strategy names
    """
    valid_strategies = {"metadata", "header", "pixel", "structure"}
    strategies = [s.strip().lower() for s in strategies_str.split(",")]

    invalid = set(strategies) - valid_strategies
    if invalid:
        print(f"Warning: Unknown strategies {invalid} will be ignored")
        print(f"Valid strategies: {', '.join(sorted(valid_strategies))}")

    return [s for s in strategies if s in valid_strategies]


def main():
    """Execute DICOM fuzzing campaign with specified parameters."""
    parser = argparse.ArgumentParser(
        description="DICOM Fuzzer - Security testing tool for medical imaging systems",
        epilog="Example: %(prog)s input.dcm -c 50 -o ./output -s metadata,header -v",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument("input_file", help="Path to original DICOM file to fuzz")

    # Optional arguments
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=100,
        metavar="N",
        help="Number of fuzzed files to generate (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./fuzzed_dicoms",
        metavar="DIR",
        help="Output directory for fuzzed files (default: ./fuzzed_dicoms)",
    )
    parser.add_argument(
        "-s",
        "--strategies",
        type=str,
        metavar="STRAT",
        help="Comma-separated list of fuzzing strategies: metadata,header,pixel,structure (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging output"
    )
    parser.add_argument("--version", action="version", version="DICOM Fuzzer v1.0.0")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Validate input file
    input_path = validate_input_file(args.input_file)
    logger.info(f"Input file: {input_path}")

    # Parse strategies if specified
    selected_strategies = None
    if args.strategies:
        selected_strategies = parse_strategies(args.strategies)
        if not selected_strategies:
            print("Error: No valid strategies specified")
            sys.exit(1)
        logger.info(f"Selected strategies: {', '.join(selected_strategies)}")
    else:
        logger.info("Using all available fuzzing strategies")

    # Create output directory if needed
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_path}")

    # Generate fuzzed files
    logger.info(f"Generating {args.count} fuzzed files...")
    try:
        generator = DICOMGenerator(args.output)
        files = generator.generate_batch(
            str(input_path), count=args.count, strategies=selected_strategies
        )

        print(f"\n[SUCCESS] Generated {len(files)} fuzzed DICOM files")
        print(f"  Output directory: {args.output}")
        if selected_strategies:
            print(f"  Strategies used: {', '.join(selected_strategies)}")

        if args.verbose:
            print("\nGenerated files:")
            for f in files[:10]:  # Show first 10
                print(f"  - {f.name}")  # noqa: E221
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}", exc_info=args.verbose)
        print(f"\n[ERROR] Fuzzing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

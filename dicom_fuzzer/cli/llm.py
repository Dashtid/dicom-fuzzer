"""LLM Subcommand for DICOM Fuzzer.

LLM-assisted fuzzing capabilities using AI models.

Supported backends:
- Mock (testing without API)
- OpenAI (GPT-4)
- Anthropic (Claude)
- Ollama (local models)

NOTE: This CLI module provides a simplified interface to the core LLM fuzzer.
For advanced usage, import dicom_fuzzer.core.llm_fuzzer directly.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Supported LLM backends
SUPPORTED_BACKENDS = ["mock", "openai", "anthropic", "ollama"]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for llm subcommand."""
    parser = argparse.ArgumentParser(
        description="LLM-assisted DICOM fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate mutation specs using mock backend (no API needed)
  dicom-fuzzer llm --generate -o ./output --backend mock

  # List available backends
  dicom-fuzzer llm --list-backends

Output:
  Generates JSON mutation specifications that describe how to
  modify DICOM elements for security testing purposes.

Environment Variables:
  OPENAI_API_KEY     - API key for OpenAI backend
  ANTHROPIC_API_KEY  - API key for Anthropic backend
  OLLAMA_HOST        - Host URL for Ollama (default: http://localhost:11434)

For advanced testing, use the Python API:
  from dicom_fuzzer.core.llm_fuzzer import LLMFuzzer
        """,
    )

    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--generate",
        action="store_true",
        help="Generate LLM-guided mutations for input DICOM file",
    )
    action_group.add_argument(
        "--list-backends",
        action="store_true",
        help="List available LLM backends and their status",
    )

    # Backend options
    backend_group = parser.add_argument_group("backend options")
    backend_group.add_argument(
        "--backend",
        type=str,
        choices=SUPPORTED_BACKENDS,
        default="mock",
        help="LLM backend to use (default: mock)",
    )
    backend_group.add_argument(
        "--model",
        type=str,
        default="gpt-4",
        help="Model name for the selected backend (default: gpt-4)",
    )

    # Output options
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        default="./llm_output",
        metavar="DIR",
        help="Output directory (default: ./llm_output)",
    )
    output_group.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        metavar="N",
        help="Number of mutations to generate (default: 10)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


def run_generate(args: argparse.Namespace) -> int:
    """Generate LLM-guided mutation specifications."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  DICOM Fuzzer - LLM-Assisted Mutation Generation")
    print("=" * 70)
    print(f"  Backend:  {args.backend}")
    print(f"  Model:    {args.model}")
    print(f"  Output:   {output_dir}")
    print(f"  Count:    {args.count}")
    print("=" * 70 + "\n")

    try:
        from dicom_fuzzer.core.llm_fuzzer import create_llm_fuzzer

        print("[i] Creating LLM fuzzer...")
        fuzzer = create_llm_fuzzer(
            backend=args.backend,
            model=args.model,
        )

        print("[i] Generating mutation strategies...")
        # Generate mutations (returns mutation specifications, not binary data)
        mutations = fuzzer.generate_fuzzing_corpus(count=args.count)

        # Save mutations as JSON specifications
        for i, mutation in enumerate(mutations):
            output_file = output_dir / f"mutation_{i:04d}.json"
            with open(output_file, "w") as f:
                json.dump(mutation.to_dict(), f, indent=2)
            if args.verbose:
                print(f"  [+] {output_file.name}: {mutation.target_element}")

        print(f"\n[+] Generated {len(mutations)} mutation specifications")
        print(f"    Output: {output_dir}")
        print("[i] Use these specs to apply mutations to actual DICOM files")

        return 0

    except ImportError as e:
        print(f"[-] LLM fuzzer not available: {e}")
        print("[i] Ensure LLM dependencies are installed")
        return 1
    except Exception as e:
        print(f"[-] Generation failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


def run_list_backends(args: argparse.Namespace) -> int:
    """List available LLM backends and their status."""
    print("\n" + "=" * 70)
    print("  Available LLM Backends")
    print("=" * 70 + "\n")

    backends: list[dict[str, str | bool | None]] = [
        {
            "name": "mock",
            "description": "Mock backend for testing (no API needed)",
            "env_var": None,
            "available": True,
        },
        {
            "name": "openai",
            "description": "OpenAI GPT models (GPT-4, GPT-4o)",
            "env_var": "OPENAI_API_KEY",
            "available": bool(os.environ.get("OPENAI_API_KEY")),
        },
        {
            "name": "anthropic",
            "description": "Anthropic Claude models",
            "env_var": "ANTHROPIC_API_KEY",
            "available": bool(os.environ.get("ANTHROPIC_API_KEY")),
        },
        {
            "name": "ollama",
            "description": "Local Ollama models (llama3, mixtral, etc.)",
            "env_var": "OLLAMA_HOST",
            "available": True,  # Assumes local Ollama may be available
        },
    ]

    for b in backends:
        available = bool(b["available"])
        status = "[+]" if available else "[-]"
        print(f"  {status} {b['name']}")
        print(f"      {b['description']}")
        env_var = b["env_var"]
        if env_var:
            configured = "configured" if available else "not set"
            print(f"      Environment: {env_var} ({configured})")
        print()

    print("=" * 70)
    print("\nUsage: dicom-fuzzer llm --generate -i input.dcm --backend <name>")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for llm subcommand."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.generate:
        return run_generate(args)
    elif args.list_backends:
        return run_list_backends(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

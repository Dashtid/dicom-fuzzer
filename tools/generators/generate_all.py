#!/usr/bin/env python3
"""Generate all security sample categories.

Generates CVE reproductions, parser stress tests, preamble attacks,
and compliance violation samples in a single command.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    """Generate all sample categories."""
    parser = argparse.ArgumentParser(
        description="Generate all security sample categories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m samples.generate_all --output samples/generated/
  python -m samples.generate_all --categories cve,stress
  python -m samples.generate_all --list
        """,
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("samples/generated"),
        help="Output directory (default: samples/generated)",
    )
    parser.add_argument(
        "--categories",
        "-c",
        help="Comma-separated list: cve,stress,preamble,compliance (default: all)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available categories",
    )

    args = parser.parse_args()

    categories = {
        "cve": ("CVE Reproductions", "samples.cve_reproductions.generator"),
        "stress": ("Parser Stress Tests", "samples.parser_stress.generator"),
        "preamble": ("Preamble Attacks", "samples.preamble_attacks.generator"),
        "compliance": (
            "Compliance Violations",
            "samples.compliance_violations.generator",
        ),
    }

    if args.list:
        print("Available categories:\n")
        for key, (name, _) in categories.items():
            print(f"  {key:12} - {name}")
        return 0

    # Parse selected categories
    if args.categories:
        selected = [c.strip().lower() for c in args.categories.split(",")]
        invalid = [c for c in selected if c not in categories]
        if invalid:
            print(f"[-] Unknown categories: {', '.join(invalid)}")
            print(f"[i] Valid categories: {', '.join(categories.keys())}")
            return 1
    else:
        selected = list(categories.keys())

    # Create output directory
    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[i] Output directory: {output_dir}")
    print(f"[i] Categories: {', '.join(selected)}\n")

    success_count = 0
    for cat_key in selected:
        cat_name, module_path = categories[cat_key]
        cat_output = output_dir / cat_key

        print(f"[+] Generating {cat_name}...")

        try:
            # Import and run the generator
            module = __import__(module_path, fromlist=[""])

            if hasattr(module, "main"):
                # Temporarily override sys.argv for the generator
                original_argv = sys.argv
                sys.argv = ["generator", "--output-dir", str(cat_output)]
                try:
                    module.main()
                    success_count += 1
                except SystemExit:
                    success_count += 1  # argparse exits on success
                finally:
                    sys.argv = original_argv
            else:
                print(f"    [-] No main() function in {module_path}")

        except ImportError as e:
            print(f"    [-] Import error: {e}")
        except Exception as e:
            print(f"    [-] Error: {e}")

    print(f"\n[+] Generated {success_count}/{len(selected)} categories")
    print(f"[i] Samples saved to: {output_dir}")

    return 0 if success_count == len(selected) else 1


if __name__ == "__main__":
    sys.exit(main())

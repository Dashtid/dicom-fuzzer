#!/usr/bin/env python3
"""Example: Security Testing with CVE Samples

This example demonstrates how to use CVE-specific samples for security testing.
"""

from pathlib import Path

from samples.cve_reproductions.generator import CVE_DATABASE, CVESampleGenerator


def main() -> None:
    """Run security testing example."""
    print("=" * 60)
    print("  DICOM Fuzzer - Security Testing Example")
    print("=" * 60)

    output_dir = Path("./artifacts/fuzzed/security_samples")
    output_dir.mkdir(parents=True, exist_ok=True)

    # List available CVEs
    print("\n[i] Available CVE samples:")
    print("-" * 60)
    for cve_id, info in CVE_DATABASE.items():
        print(f"  {cve_id}: {info.product}")
        print(f"           {info.vulnerability_type} (CVSS: {info.cvss})")

    # Generate samples
    print(f"\n[i] Generating CVE samples to: {output_dir}")
    print("-" * 60)

    generator = CVESampleGenerator(output_dir)
    results = generator.generate_all()

    # Summary
    success_count = sum(1 for p in results.values() if p is not None)
    print(f"\n[+] Generated {success_count}/{len(results)} CVE samples")

    # Testing recommendations
    print("\n[i] Testing Recommendations:")
    print("-" * 60)
    print("  1. Test against vulnerable software versions in isolated VM")
    print("  2. Monitor for crashes, hangs, or unexpected behavior")
    print("  3. Use memory sanitizers (ASan, MSan) when possible")
    print("  4. Document all findings for responsible disclosure")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()

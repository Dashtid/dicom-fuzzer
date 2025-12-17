#!/usr/bin/env python3
"""Example: Network Protocol Fuzzing

This example demonstrates DICOM network protocol fuzzing.

WARNING: Only use against systems you have authorization to test.
"""

# Configuration - Change these to match your test environment
TARGET_HOST = "localhost"
TARGET_PORT = 11112
AE_TITLE = "FUZZ_SCU"
FUZZ_COUNT = 100


def main() -> None:
    """Run network fuzzing example."""
    print("=" * 60)
    print("  DICOM Fuzzer - Network Protocol Fuzzing Example")
    print("=" * 60)
    print()
    print("[!] WARNING: Only use against authorized test systems!")
    print()

    print(f"[i] Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[i] AE Title: {AE_TITLE}")
    print(f"[i] Iterations: {FUZZ_COUNT}")
    print("-" * 60)

    # Create network fuzzer (uncomment to use)
    # fuzzer = DICOMNetworkFuzzer(
    #     host=TARGET_HOST,
    #     port=TARGET_PORT,
    #     ae_title=AE_TITLE,
    # )

    # Available strategies
    strategies = [
        "malformed_pdu",
        "invalid_length",
        "buffer_overflow",
        "integer_overflow",
        "null_bytes",
        "unicode_injection",
        "protocol_state",
    ]

    print("\n[i] Available fuzzing strategies:")
    for strategy in strategies:
        print(f"    - {strategy}")

    # Run fuzzing (uncomment to execute)
    print("\n[i] To run fuzzing, uncomment the code below and ensure")
    print("    you have authorization to test the target system.")

    # Uncomment to run:
    # print("\n[i] Starting network fuzzing...")
    # results = fuzzer.fuzz(
    #     count=FUZZ_COUNT,
    #     strategies=strategies,
    # )
    # print(f"[+] Completed {len(results)} test cases")
    # crashes = [r for r in results if r.crashed]
    # if crashes:
    #     print(f"[!] Found {len(crashes)} potential issues")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()

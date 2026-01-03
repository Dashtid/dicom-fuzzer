"""Shared constants for DICOM fuzzing operations.

AFL-inspired boundary values and fuzzing parameters used across
multiple mutator implementations. These values are proven effective
at triggering boundary conditions and edge cases in parsers.

References:
- AFL whitepaper: https://lcamtuf.coredump.cx/afl/technical_details.txt
- AFL++ documentation: https://aflplus.plus/docs/fuzzing_in_depth/

"""

from __future__ import annotations

from typing import Final

# =============================================================================
# Coverage Tracking Constants
# =============================================================================

#: Coverage bitmap size (matches AFL default)
MAP_SIZE: Final[int] = 65536

#: log2(MAP_SIZE) for bit operations
MAP_SIZE_POW2: Final[int] = 16

# =============================================================================
# Arithmetic Mutation Constants
# =============================================================================

#: Maximum delta for arithmetic mutations (AFL default)
ARITH_MAX: Final[int] = 35

# =============================================================================
# Interesting Values for Boundary Testing
# Based on AFL/AFL++ fuzzer - boundary conditions that often trigger bugs
# =============================================================================

#: 8-bit interesting values (signed, includes INT8_MIN/MAX)
INTERESTING_8: Final[list[int]] = [
    -128,  # INT8_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    16,  # Power of 2
    32,  # Power of 2
    64,  # Power of 2
    100,  # Common boundary
    127,  # INT8_MAX
]

#: 16-bit interesting values (signed, includes INT16_MIN/MAX)
INTERESTING_16: Final[list[int]] = [
    -32768,  # INT16_MIN
    -129,  # Below INT8_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    128,  # Above INT8_MAX
    255,  # UINT8_MAX
    256,  # Above UINT8_MAX
    512,  # Power of 2
    1000,  # Common boundary
    1024,  # Power of 2
    4096,  # Power of 2
    32767,  # INT16_MAX
    65535,  # UINT16_MAX
]

#: 32-bit interesting values (signed, includes INT32_MIN/MAX)
INTERESTING_32: Final[list[int]] = [
    -2147483648,  # INT32_MIN
    -100663046,  # Large negative
    -32769,  # Below INT16_MIN
    -1,  # All bits set
    0,  # Zero
    1,  # One
    32768,  # Above INT16_MAX
    65535,  # UINT16_MAX
    65536,  # Above UINT16_MAX
    100663045,  # Large positive
    2147483647,  # INT32_MAX
    4294967295,  # UINT32_MAX (as signed: -1)
]

# =============================================================================
# Unsigned Variants for VR Encoding
# Some DICOM Value Representations reject negative values, use these instead
# =============================================================================

#: 8-bit unsigned interesting values
INTERESTING_8_UNSIGNED: Final[list[int]] = [
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
]

#: 16-bit unsigned interesting values
INTERESTING_16_UNSIGNED: Final[list[int]] = [
    0,
    1,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
]

#: 32-bit unsigned interesting values
INTERESTING_32_UNSIGNED: Final[list[int]] = [
    0,
    1,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
    4294967295,
]

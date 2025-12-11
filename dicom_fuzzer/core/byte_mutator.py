"""AFL-Style Byte-Level Mutator for DICOM Fuzzing.

This module implements low-level byte mutations inspired by AFL/AFL++ fuzzer,
providing fundamental mutation operations that complement the DICOM-aware
strategies.

Mutation Stages (based on AFL):
1. Deterministic Stage: Systematic mutations at each position
   - Bit flips (1, 2, 4 bits)
   - Byte flips (1, 2, 4 bytes)
   - Arithmetic operations (+/- 1 to 35)
   - Interesting value substitution

2. Havoc Stage: Random combinations of mutations
   - Random bit/byte flips
   - Random arithmetic
   - Block deletion/insertion/overwrite
   - Clone operations

References:
- AFL whitepaper: https://lcamtuf.coredump.cx/afl/technical_details.txt
- AFL++ documentation: https://aflplus.plus/docs/fuzzing_in_depth/

"""

from __future__ import annotations

import random
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class MutationStage(Enum):
    """AFL-style mutation stages."""

    DETERMINISTIC = auto()  # Systematic mutations
    HAVOC = auto()  # Random chaos mutations
    SPLICE = auto()  # Combine with other inputs


class ByteMutationType(Enum):
    """Types of byte-level mutations."""

    BIT_FLIP_1 = "bit_flip_1"
    BIT_FLIP_2 = "bit_flip_2"
    BIT_FLIP_4 = "bit_flip_4"
    BYTE_FLIP_1 = "byte_flip_1"
    BYTE_FLIP_2 = "byte_flip_2"
    BYTE_FLIP_4 = "byte_flip_4"
    ARITH_8 = "arith_8"
    ARITH_16 = "arith_16"
    ARITH_32 = "arith_32"
    INTEREST_8 = "interest_8"
    INTEREST_16 = "interest_16"
    INTEREST_32 = "interest_32"
    HAVOC = "havoc"
    SPLICE = "splice"


# AFL's "interesting" values - boundary conditions that often trigger bugs
INTERESTING_8 = [
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

INTERESTING_16 = [
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

INTERESTING_32 = [
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


@dataclass
class ByteMutationRecord:
    """Record of a byte-level mutation."""

    mutation_type: ByteMutationType
    offset: int
    original_bytes: bytes
    mutated_bytes: bytes
    description: str = ""


@dataclass
class ByteMutatorConfig:
    """Configuration for byte-level mutations."""

    # Deterministic stage settings
    enable_bit_flips: bool = True
    enable_byte_flips: bool = True
    enable_arithmetic: bool = True
    enable_interesting: bool = True

    # Arithmetic range (AFL uses 35)
    arith_max: int = 35

    # Havoc stage settings
    havoc_cycles: int = 256
    havoc_stack_power: int = 7  # 2^7 = 128 max stacked mutations

    # Splice settings
    enable_splice: bool = True
    splice_cycles: int = 16

    # Size limits
    max_input_size: int = 10 * 1024 * 1024  # 10MB
    min_input_size: int = 4

    # Efficiency settings
    skip_deterministic_for_large: int = 50 * 1024  # Skip deterministic if > 50KB
    effector_map_threshold: float = 0.9  # Skip if >90% positions are effectors


@dataclass
class ByteMutatorStats:
    """Statistics for byte mutation operations."""

    total_mutations: int = 0
    bit_flips: int = 0
    byte_flips: int = 0
    arithmetic: int = 0
    interesting: int = 0
    havoc: int = 0
    splice: int = 0
    mutations_by_type: dict[str, int] = field(default_factory=dict)


class ByteMutator:
    """AFL-style byte-level mutator.

    Implements systematic and random byte-level mutations for fuzzing.
    Can operate on any binary data, making it suitable for raw DICOM bytes.
    """

    def __init__(self, config: ByteMutatorConfig | None = None):
        """Initialize byte mutator.

        Args:
            config: Configuration for mutation behavior

        """
        self.config = config or ByteMutatorConfig()
        self.stats = ByteMutatorStats()
        self._effector_map: dict[int, bool] = {}
        self._mutation_history: list[ByteMutationRecord] = []

        logger.info("ByteMutator initialized with AFL-style mutations")

    def mutate(
        self,
        data: bytes,
        stage: MutationStage = MutationStage.HAVOC,
        num_mutations: int = 1,
    ) -> bytes:
        """Apply byte-level mutations to data.

        Args:
            data: Input bytes to mutate
            stage: Mutation stage to use
            num_mutations: Number of mutations to apply

        Returns:
            Mutated bytes

        """
        if len(data) < self.config.min_input_size:
            logger.warning(f"Input too small ({len(data)} bytes), skipping mutation")
            return data

        if len(data) > self.config.max_input_size:
            logger.warning(f"Input too large ({len(data)} bytes), truncating")
            data = data[: self.config.max_input_size]

        mutated = bytearray(data)

        if stage == MutationStage.DETERMINISTIC:
            mutated = self._deterministic_stage(mutated)
        elif stage == MutationStage.HAVOC:
            for _ in range(num_mutations):
                mutated = self._havoc_stage(mutated)
        elif stage == MutationStage.SPLICE:
            # Splice requires another input, handled separately
            mutated = self._havoc_stage(mutated)

        self.stats.total_mutations += num_mutations
        return bytes(mutated)

    def _deterministic_stage(self, data: bytearray) -> bytearray:
        """Apply deterministic mutations systematically.

        AFL's deterministic stage applies mutations at every position
        to find "effector" positions that change program behavior.
        """
        # Skip for large inputs (too slow)
        if len(data) > self.config.skip_deterministic_for_large:
            logger.debug("Skipping deterministic stage for large input")
            return self._havoc_stage(data)

        result = bytearray(data)

        # Walking bit flips
        if self.config.enable_bit_flips:
            result = self._walking_bit_flip(result, 1)
            result = self._walking_bit_flip(result, 2)
            result = self._walking_bit_flip(result, 4)

        # Walking byte flips
        if self.config.enable_byte_flips:
            result = self._walking_byte_flip(result, 1)
            result = self._walking_byte_flip(result, 2)
            result = self._walking_byte_flip(result, 4)

        # Arithmetic
        if self.config.enable_arithmetic:
            result = self._arithmetic_8(result)
            if len(result) >= 2:
                result = self._arithmetic_16(result)
            if len(result) >= 4:
                result = self._arithmetic_32(result)

        # Interesting values
        if self.config.enable_interesting:
            result = self._interesting_8(result)
            if len(result) >= 2:
                result = self._interesting_16(result)
            if len(result) >= 4:
                result = self._interesting_32(result)

        return result

    def _walking_bit_flip(self, data: bytearray, num_bits: int) -> bytearray:
        """Flip 1, 2, or 4 consecutive bits at each position."""
        result = bytearray(data)

        # Pick a random position to actually flip (we don't flip everything)
        if len(result) == 0:
            return result

        byte_pos = random.randint(0, len(result) - 1)
        bit_pos = random.randint(0, 7)

        for i in range(num_bits):
            actual_bit = bit_pos + i
            actual_byte = byte_pos + (actual_bit // 8)
            if actual_byte < len(result):
                result[actual_byte] ^= 1 << (actual_bit % 8)

        self.stats.bit_flips += 1
        self._record_mutation(
            ByteMutationType.BIT_FLIP_1
            if num_bits == 1
            else (
                ByteMutationType.BIT_FLIP_2
                if num_bits == 2
                else ByteMutationType.BIT_FLIP_4
            ),
            byte_pos,
            data[byte_pos : byte_pos + (num_bits + 7) // 8],
            result[byte_pos : byte_pos + (num_bits + 7) // 8],
            f"Flip {num_bits} bit(s) at position {byte_pos}:{bit_pos}",
        )

        return result

    def _walking_byte_flip(self, data: bytearray, num_bytes: int) -> bytearray:
        """Flip 1, 2, or 4 consecutive bytes at each position."""
        result = bytearray(data)

        if len(result) < num_bytes:
            return result

        pos = random.randint(0, len(result) - num_bytes)

        for i in range(num_bytes):
            result[pos + i] ^= 0xFF

        self.stats.byte_flips += 1
        mutation_type = {
            1: ByteMutationType.BYTE_FLIP_1,
            2: ByteMutationType.BYTE_FLIP_2,
            4: ByteMutationType.BYTE_FLIP_4,
        }.get(num_bytes, ByteMutationType.BYTE_FLIP_1)

        self._record_mutation(
            mutation_type,
            pos,
            data[pos : pos + num_bytes],
            result[pos : pos + num_bytes],
            f"Flip {num_bytes} byte(s) at position {pos}",
        )

        return result

    def _arithmetic_8(self, data: bytearray) -> bytearray:
        """Apply arithmetic mutations to single bytes."""
        result = bytearray(data)
        if len(result) == 0:
            return result

        pos = random.randint(0, len(result) - 1)
        delta = random.randint(1, self.config.arith_max)
        if random.random() < 0.5:
            delta = -delta

        original = result[pos]
        result[pos] = (result[pos] + delta) & 0xFF

        self.stats.arithmetic += 1
        self._record_mutation(
            ByteMutationType.ARITH_8,
            pos,
            bytes([original]),
            bytes([result[pos]]),
            f"Arithmetic {delta:+d} at byte {pos}",
        )

        return result

    def _arithmetic_16(self, data: bytearray) -> bytearray:
        """Apply arithmetic mutations to 16-bit values."""
        result = bytearray(data)
        if len(result) < 2:
            return result

        pos = random.randint(0, len(result) - 2)
        delta = random.randint(1, self.config.arith_max)
        if random.random() < 0.5:
            delta = -delta

        # Try both endianness
        use_be = random.random() < 0.5
        fmt = ">H" if use_be else "<H"

        try:
            original = struct.unpack(fmt, result[pos : pos + 2])[0]
            new_value = (original + delta) & 0xFFFF
            result[pos : pos + 2] = struct.pack(fmt, new_value)

            self.stats.arithmetic += 1
            self._record_mutation(
                ByteMutationType.ARITH_16,
                pos,
                data[pos : pos + 2],
                result[pos : pos + 2],
                f"Arithmetic16 {delta:+d} at position {pos} ({'BE' if use_be else 'LE'})",
            )
        except struct.error:
            pass

        return result

    def _arithmetic_32(self, data: bytearray) -> bytearray:
        """Apply arithmetic mutations to 32-bit values."""
        result = bytearray(data)
        if len(result) < 4:
            return result

        pos = random.randint(0, len(result) - 4)
        delta = random.randint(1, self.config.arith_max)
        if random.random() < 0.5:
            delta = -delta

        use_be = random.random() < 0.5
        fmt = ">I" if use_be else "<I"

        try:
            original = struct.unpack(fmt, result[pos : pos + 4])[0]
            new_value = (original + delta) & 0xFFFFFFFF
            result[pos : pos + 4] = struct.pack(fmt, new_value)

            self.stats.arithmetic += 1
            self._record_mutation(
                ByteMutationType.ARITH_32,
                pos,
                data[pos : pos + 4],
                result[pos : pos + 4],
                f"Arithmetic32 {delta:+d} at position {pos} ({'BE' if use_be else 'LE'})",
            )
        except struct.error:
            pass

        return result

    def _interesting_8(self, data: bytearray) -> bytearray:
        """Substitute bytes with interesting 8-bit values."""
        result = bytearray(data)
        if len(result) == 0:
            return result

        pos = random.randint(0, len(result) - 1)
        value = random.choice(INTERESTING_8)
        original = result[pos]
        result[pos] = value & 0xFF

        self.stats.interesting += 1
        self._record_mutation(
            ByteMutationType.INTEREST_8,
            pos,
            bytes([original]),
            bytes([result[pos]]),
            f"Interesting8 value {value} at position {pos}",
        )

        return result

    def _interesting_16(self, data: bytearray) -> bytearray:
        """Substitute with interesting 16-bit values."""
        result = bytearray(data)
        if len(result) < 2:
            return result

        pos = random.randint(0, len(result) - 2)
        value = random.choice(INTERESTING_16)
        use_be = random.random() < 0.5
        fmt = ">h" if use_be else "<h"

        try:
            result[pos : pos + 2] = struct.pack(fmt, value)
            self.stats.interesting += 1
            self._record_mutation(
                ByteMutationType.INTEREST_16,
                pos,
                data[pos : pos + 2],
                result[pos : pos + 2],
                f"Interesting16 value {value} at position {pos}",
            )
        except struct.error:
            pass

        return result

    def _interesting_32(self, data: bytearray) -> bytearray:
        """Substitute with interesting 32-bit values."""
        result = bytearray(data)
        if len(result) < 4:
            return result

        pos = random.randint(0, len(result) - 4)
        value = random.choice(INTERESTING_32)
        use_be = random.random() < 0.5
        fmt = ">i" if use_be else "<i"

        try:
            result[pos : pos + 4] = struct.pack(fmt, value)
            self.stats.interesting += 1
            self._record_mutation(
                ByteMutationType.INTEREST_32,
                pos,
                data[pos : pos + 4],
                result[pos : pos + 4],
                f"Interesting32 value {value} at position {pos}",
            )
        except struct.error:
            pass

        return result

    def _havoc_stage(self, data: bytearray) -> bytearray:
        """Apply random havoc mutations.

        Havoc stage combines multiple random mutations for maximum chaos.
        """
        result = bytearray(data)

        # Stack multiple mutations
        num_stacked = 1 << random.randint(1, self.config.havoc_stack_power)
        num_stacked = min(num_stacked, 128)  # Cap at 128

        havoc_ops: list[Callable[[bytearray], bytearray]] = [
            self._havoc_flip_bit,
            self._havoc_flip_byte,
            self._havoc_arith_byte,
            self._havoc_interesting_byte,
            self._havoc_random_byte,
            self._havoc_delete_bytes,
            self._havoc_clone_bytes,
            self._havoc_overwrite_bytes,
            self._havoc_insert_bytes,
        ]

        for _ in range(num_stacked):
            if len(result) < self.config.min_input_size:
                break
            op = random.choice(havoc_ops)
            try:
                result = op(result)
            except (IndexError, ValueError):
                # Some operations may fail on small inputs
                pass

        self.stats.havoc += 1
        return result

    def _havoc_flip_bit(self, data: bytearray) -> bytearray:
        """Havoc: flip a random bit."""
        if len(data) == 0:
            return data
        pos = random.randint(0, len(data) - 1)
        data[pos] ^= 1 << random.randint(0, 7)
        return data

    def _havoc_flip_byte(self, data: bytearray) -> bytearray:
        """Havoc: flip a random byte."""
        if len(data) == 0:
            return data
        pos = random.randint(0, len(data) - 1)
        data[pos] ^= 0xFF
        return data

    def _havoc_arith_byte(self, data: bytearray) -> bytearray:
        """Havoc: random arithmetic on a byte."""
        if len(data) == 0:
            return data
        pos = random.randint(0, len(data) - 1)
        delta = random.randint(-35, 35)
        data[pos] = (data[pos] + delta) & 0xFF
        return data

    def _havoc_interesting_byte(self, data: bytearray) -> bytearray:
        """Havoc: insert an interesting byte value."""
        if len(data) == 0:
            return data
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.choice(INTERESTING_8) & 0xFF
        return data

    def _havoc_random_byte(self, data: bytearray) -> bytearray:
        """Havoc: set a random byte to random value."""
        if len(data) == 0:
            return data
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
        return data

    def _havoc_delete_bytes(self, data: bytearray) -> bytearray:
        """Havoc: delete a chunk of bytes."""
        if len(data) <= self.config.min_input_size:
            return data

        max_delete = min(len(data) - self.config.min_input_size, len(data) // 4)
        if max_delete <= 0:
            return data

        delete_len = random.randint(1, max_delete)
        pos = random.randint(0, len(data) - delete_len)
        del data[pos : pos + delete_len]
        return data

    def _havoc_clone_bytes(self, data: bytearray) -> bytearray:
        """Havoc: clone a chunk of bytes to another position."""
        if len(data) < 4:
            return data

        clone_len = random.randint(1, min(len(data) // 4, 1024))
        src_pos = random.randint(0, len(data) - clone_len)
        dest_pos = random.randint(0, len(data))

        chunk = data[src_pos : src_pos + clone_len]
        data[dest_pos:dest_pos] = chunk
        return data

    def _havoc_overwrite_bytes(self, data: bytearray) -> bytearray:
        """Havoc: overwrite bytes with data from another position."""
        if len(data) < 4:
            return data

        copy_len = random.randint(1, min(len(data) // 4, 1024))
        src_pos = random.randint(0, len(data) - copy_len)
        dest_pos = random.randint(0, len(data) - copy_len)

        chunk = bytes(data[src_pos : src_pos + copy_len])
        data[dest_pos : dest_pos + copy_len] = chunk
        return data

    def _havoc_insert_bytes(self, data: bytearray) -> bytearray:
        """Havoc: insert random bytes."""
        insert_len = random.randint(1, min(128, len(data) // 4 + 1))
        pos = random.randint(0, len(data))

        # Either random bytes or repeated value
        if random.random() < 0.5:
            chunk = bytes(random.randint(0, 255) for _ in range(insert_len))
        else:
            chunk = bytes([random.randint(0, 255)] * insert_len)

        data[pos:pos] = chunk
        return data

    def splice(self, data1: bytes, data2: bytes) -> bytes:
        """Splice two inputs together at random points.

        Args:
            data1: First input
            data2: Second input to splice with

        Returns:
            Spliced output combining parts of both inputs

        """
        if len(data1) < 4 or len(data2) < 4:
            return data1

        # Find a random splice point in each
        pos1 = random.randint(1, len(data1) - 1)
        pos2 = random.randint(1, len(data2) - 1)

        # Combine first part of data1 with second part of data2
        result = data1[:pos1] + data2[pos2:]

        self.stats.splice += 1
        self._record_mutation(
            ByteMutationType.SPLICE,
            pos1,
            b"",
            b"",
            f"Splice at {pos1} with external data at {pos2}",
        )

        return result

    def _record_mutation(
        self,
        mutation_type: ByteMutationType,
        offset: int,
        original: bytes,
        mutated: bytes,
        description: str,
    ) -> None:
        """Record a mutation for tracking."""
        record = ByteMutationRecord(
            mutation_type=mutation_type,
            offset=offset,
            original_bytes=original,
            mutated_bytes=mutated,
            description=description,
        )
        self._mutation_history.append(record)

        # Track by type
        type_name = mutation_type.value
        self.stats.mutations_by_type[type_name] = (
            self.stats.mutations_by_type.get(type_name, 0) + 1
        )

    def get_mutation_history(self) -> list[ByteMutationRecord]:
        """Get the mutation history."""
        return self._mutation_history.copy()

    def clear_history(self) -> None:
        """Clear mutation history."""
        self._mutation_history.clear()

    def get_stats(self) -> dict[str, int | dict[str, int]]:
        """Get mutation statistics."""
        return {
            "total_mutations": self.stats.total_mutations,
            "bit_flips": self.stats.bit_flips,
            "byte_flips": self.stats.byte_flips,
            "arithmetic": self.stats.arithmetic,
            "interesting": self.stats.interesting,
            "havoc": self.stats.havoc,
            "splice": self.stats.splice,
            "by_type": self.stats.mutations_by_type.copy(),
        }


class DICOMByteMutator(ByteMutator):
    """Specialized byte mutator for DICOM files.

    Extends ByteMutator with DICOM-specific knowledge to target
    high-value mutation positions.
    """

    # DICOM magic bytes and important offsets
    DICOM_PREAMBLE_SIZE = 128
    DICOM_PREFIX = b"DICM"
    DICOM_PREFIX_OFFSET = 128

    # Common tag positions that are valuable for fuzzing
    HIGH_VALUE_REGIONS = [
        (0, 132),  # Preamble + DICM prefix
        (132, 256),  # File meta information
    ]

    def __init__(self, config: ByteMutatorConfig | None = None):
        """Initialize DICOM byte mutator."""
        super().__init__(config)
        self._target_regions: list[tuple[int, int]] = []

    def mutate_dicom(
        self,
        data: bytes,
        preserve_magic: bool = False,
        target_regions: list[tuple[int, int]] | None = None,
    ) -> bytes:
        """Mutate DICOM bytes with optional preservation of magic bytes.

        Args:
            data: Raw DICOM file bytes
            preserve_magic: If True, preserve DICM prefix to keep file readable
            target_regions: Optional list of (start, end) regions to focus mutations

        Returns:
            Mutated DICOM bytes

        """
        self._target_regions = target_regions or self.HIGH_VALUE_REGIONS

        result = bytearray(data)

        # Apply havoc mutations
        result = self._havoc_stage(result)

        # Optionally restore DICM prefix
        if preserve_magic and len(result) > self.DICOM_PREFIX_OFFSET + 4:
            result[self.DICOM_PREFIX_OFFSET : self.DICOM_PREFIX_OFFSET + 4] = (
                self.DICOM_PREFIX
            )

        return bytes(result)

    def mutate_targeted(
        self,
        data: bytes,
        regions: list[tuple[int, int]],
        num_mutations: int = 1,
    ) -> bytes:
        """Apply mutations targeted at specific byte regions.

        Args:
            data: Input bytes
            regions: List of (start, end) tuples defining target regions
            num_mutations: Number of mutations to apply

        Returns:
            Mutated bytes

        """
        result = bytearray(data)

        for _ in range(num_mutations):
            # Pick a random region
            if not regions:
                break

            region = random.choice(regions)
            start, end = region
            end = min(end, len(result))

            if start >= end:
                continue

            # Pick a position within the region
            pos = random.randint(start, end - 1)

            # Apply a random mutation at this position
            mutation_type = random.choice(
                [
                    "flip",
                    "arith",
                    "interesting",
                    "random",
                ]
            )

            if mutation_type == "flip":
                result[pos] ^= 1 << random.randint(0, 7)
            elif mutation_type == "arith":
                delta = random.randint(-35, 35)
                result[pos] = (result[pos] + delta) & 0xFF
            elif mutation_type == "interesting":
                result[pos] = random.choice(INTERESTING_8) & 0xFF
            else:
                result[pos] = random.randint(0, 255)

        return bytes(result)


# Convenience function for quick mutations
def quick_mutate(data: bytes, num_mutations: int = 1) -> bytes:
    """Quick helper to apply havoc mutations to data.

    Args:
        data: Input bytes
        num_mutations: Number of havoc cycles

    Returns:
        Mutated bytes

    """
    mutator = ByteMutator()
    return mutator.mutate(data, MutationStage.HAVOC, num_mutations)


def quick_splice(data1: bytes, data2: bytes) -> bytes:
    """Quick helper to splice two inputs.

    Args:
        data1: First input
        data2: Second input

    Returns:
        Spliced result

    """
    mutator = ByteMutator()
    return mutator.splice(data1, data2)

"""Coverage-Guided Mutation Engine for DICOM Fuzzer

Implements intelligent mutation strategies that adapt based on coverage feedback.
Learns which mutations are most effective for discovering new code paths.
"""

import random
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np

from .corpus_manager import Seed
from .coverage_instrumentation import CoverageInfo


class MutationType(Enum):
    """Types of mutations available."""

    # Byte-level mutations
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    RANDOM_BYTE = "random_byte"
    BYTE_INSERT = "byte_insert"
    BYTE_DELETE = "byte_delete"

    # Arithmetic mutations
    ARITHMETIC_INC = "arithmetic_inc"
    ARITHMETIC_DEC = "arithmetic_dec"
    ARITHMETIC_RANDOM = "arithmetic_random"

    # Block mutations
    BLOCK_REMOVE = "block_remove"
    BLOCK_DUPLICATE = "block_duplicate"
    BLOCK_SHUFFLE = "block_shuffle"

    # DICOM-specific mutations
    DICOM_TAG_CORRUPT = "dicom_tag_corrupt"
    DICOM_VR_MISMATCH = "dicom_vr_mismatch"
    DICOM_LENGTH_OVERFLOW = "dicom_length_overflow"
    DICOM_SEQUENCE_NEST = "dicom_sequence_nest"
    DICOM_TRANSFER_SYNTAX = "dicom_transfer_syntax"

    # Interesting values
    INTERESTING_BYTES = "interesting_bytes"
    INTERESTING_INTS = "interesting_ints"
    BOUNDARY_VALUES = "boundary_values"

    # Grammar-based
    GRAMMAR_MUTATE = "grammar_mutate"
    DICTIONARY_REPLACE = "dictionary_replace"


@dataclass
class MutationStrategy:
    """Represents a mutation strategy with success tracking."""

    mutation_type: MutationType
    success_count: int = 0
    total_count: int = 0
    coverage_gains: list[int] = field(default_factory=list)
    weight: float = 1.0
    enabled: bool = True

    def __post_init__(self) -> None:
        """Initialize coverage gains list if needed."""
        if not self.coverage_gains:
            self.coverage_gains = []

    @property
    def success_rate(self) -> float:
        """Calculate success rate of this mutation."""
        if self.total_count == 0:
            return 0.0
        return self.success_count / self.total_count

    def update(self, coverage_gained: bool, new_edges: int = 0) -> None:
        """Update strategy statistics."""
        self.total_count += 1
        if coverage_gained:
            self.success_count += 1
            self.coverage_gains.append(new_edges)

        # Adaptive weight adjustment
        if self.total_count >= 10:
            self.weight = max(0.1, min(10.0, self.success_rate * 5))


class CoverageGuidedMutator:
    """Intelligent mutator that adapts strategies based on coverage feedback."""

    def __init__(
        self,
        max_mutations: int = 10,
        adaptive_mode: bool = True,
        dicom_aware: bool = True,
    ):
        """Initialize the coverage-guided mutator.

        Args:
            max_mutations: Maximum mutations per input
            adaptive_mode: Enable adaptive mutation selection
            dicom_aware: Enable DICOM-specific mutations

        """
        self.max_mutations = max_mutations
        self.adaptive_mode = adaptive_mode
        self.dicom_aware = dicom_aware

        # Initialize mutation strategies
        self.strategies: dict[MutationType, MutationStrategy] = {}
        self._init_strategies()

        # Interesting values for mutations
        self.interesting_bytes = [
            0x00,
            0xFF,
            0x7F,
            0x80,  # Boundary values
            0x01,
            0xFE,
            0x10,
            0xEF,  # Near boundaries
        ]

        self.interesting_ints = [
            0,
            1,
            -1,
            16,
            -16,
            32,
            -32,
            64,
            -64,
            127,
            -128,
            255,
            -256,
            512,
            -512,
            1024,
            -1024,
            4096,
            -4096,
            32767,
            -32768,
            65535,
            -65536,
            2147483647,
            -2147483648,
        ]

        # DICOM-specific values
        self.dicom_tags = [
            b"\x08\x00",  # Group 0x0008
            b"\x10\x00",  # Group 0x0010 (Patient)
            b"\x20\x00",  # Group 0x0020 (Study)
            b"\x28\x00",  # Group 0x0028 (Image)
            b"\x7f\xe0",  # Pixel Data
        ]

        # Track mutation history
        self.mutation_history: list[tuple[MutationType, bool]] = []
        self.coverage_history: list[int] = []

    def _init_strategies(self) -> None:
        """Initialize all mutation strategies."""
        # Basic mutations
        for mutation_type in MutationType:
            self.strategies[mutation_type] = MutationStrategy(mutation_type)

        # Disable certain strategies if not DICOM-aware
        if not self.dicom_aware:
            for mutation_type in [
                MutationType.DICOM_TAG_CORRUPT,
                MutationType.DICOM_VR_MISMATCH,
                MutationType.DICOM_LENGTH_OVERFLOW,
                MutationType.DICOM_SEQUENCE_NEST,
                MutationType.DICOM_TRANSFER_SYNTAX,
            ]:
                self.strategies[mutation_type].enabled = False

    def mutate(
        self, seed: Seed | bytes, coverage_info: CoverageInfo | None = None
    ) -> list[tuple[bytes, MutationType]]:
        """Mutate a seed to generate new test cases.

        Args:
            seed: Seed object or raw bytes to mutate
            coverage_info: Optional coverage information for guided mutations

        Returns:
            List of (mutated_data, mutation_type) tuples

        """
        mutations = []

        # Handle both Seed objects and raw bytes
        if isinstance(seed, bytes):
            data = bytearray(seed)
            energy = 1.0  # Default energy for bytes input
        else:
            data = bytearray(seed.data)
            energy = seed.energy

        # Determine number of mutations based on seed energy
        num_mutations = min(
            self.max_mutations, max(1, int(energy * random.randint(1, 5)))
        )

        for _ in range(num_mutations):
            # Select mutation strategy
            mutation_type = self._select_mutation_strategy(coverage_info)

            # Apply mutation
            # Apply mutation on a fresh copy for each mutation
            data_copy = data.copy()
            mutated_data = self._apply_mutation(data_copy, mutation_type)

            if mutated_data and mutated_data != data:
                mutations.append((bytes(mutated_data), mutation_type))

        return mutations

    def _select_mutation_strategy(
        self, coverage_info: CoverageInfo | None = None
    ) -> MutationType:
        """Select mutation strategy based on weights and coverage."""
        if not self.adaptive_mode or random.random() < 0.1:
            # 10% random selection for exploration
            enabled_strategies = [mt for mt, s in self.strategies.items() if s.enabled]
            return random.choice(enabled_strategies)

        # Weighted selection based on success rates
        weights = []
        strategies = []

        for mutation_type, strategy in self.strategies.items():
            if strategy.enabled:
                strategies.append(mutation_type)
                weights.append(strategy.weight)

        if not strategies:
            return MutationType.BIT_FLIP  # Fallback

        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            weights = [w / total_weight for w in weights]
        else:
            weights = [1.0 / len(strategies)] * len(strategies)

        chosen = np.random.choice(strategies, p=weights)
        return MutationType(chosen) if not isinstance(chosen, MutationType) else chosen

    def _apply_mutation(
        self, data: bytearray, mutation_type: MutationType
    ) -> bytearray | None:
        """Apply specific mutation to data."""
        if len(data) == 0:
            return None

        mutated = data.copy()

        if mutation_type == MutationType.BIT_FLIP:
            mutated = self._bit_flip(mutated)

        elif mutation_type == MutationType.BYTE_FLIP:
            mutated = self._byte_flip(mutated)

        elif mutation_type == MutationType.RANDOM_BYTE:
            mutated = self._random_byte(mutated)

        elif mutation_type == MutationType.BYTE_INSERT:
            mutated = self._byte_insert(mutated)

        elif mutation_type == MutationType.BYTE_DELETE:
            mutated = self._byte_delete(mutated)

        elif mutation_type == MutationType.ARITHMETIC_INC:
            mutated = self._arithmetic_mutation(mutated, 1)

        elif mutation_type == MutationType.ARITHMETIC_DEC:
            mutated = self._arithmetic_mutation(mutated, -1)

        elif mutation_type == MutationType.ARITHMETIC_RANDOM:
            mutated = self._arithmetic_mutation(mutated, random.randint(-255, 255))

        elif mutation_type == MutationType.BLOCK_REMOVE:
            mutated = self._block_remove(mutated)

        elif mutation_type == MutationType.BLOCK_DUPLICATE:
            mutated = self._block_duplicate(mutated)

        elif mutation_type == MutationType.BLOCK_SHUFFLE:
            mutated = self._block_shuffle(mutated)

        elif mutation_type == MutationType.INTERESTING_BYTES:
            mutated = self._interesting_bytes(mutated)

        elif mutation_type == MutationType.INTERESTING_INTS:
            mutated = self._interesting_ints(mutated)

        elif mutation_type == MutationType.BOUNDARY_VALUES:
            mutated = self._boundary_values(mutated)

        # DICOM-specific mutations
        elif mutation_type == MutationType.DICOM_TAG_CORRUPT:
            mutated = self._dicom_tag_corrupt(mutated)

        elif mutation_type == MutationType.DICOM_VR_MISMATCH:
            mutated = self._dicom_vr_mismatch(mutated)

        elif mutation_type == MutationType.DICOM_LENGTH_OVERFLOW:
            mutated = self._dicom_length_overflow(mutated)

        elif mutation_type == MutationType.DICOM_SEQUENCE_NEST:
            mutated = self._dicom_sequence_nest(mutated)

        elif mutation_type == MutationType.DICOM_TRANSFER_SYNTAX:
            mutated = self._dicom_transfer_syntax(mutated)

        return mutated

    # Basic mutation operations
    def _bit_flip(self, data: bytearray) -> bytearray:
        """Flip random bits."""
        if not data:
            return data

        num_flips = random.randint(1, min(8, len(data)))
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= 1 << bit
        return data

    def _byte_flip(self, data: bytearray) -> bytearray:
        """Flip random bytes."""
        if not data:
            return data

        num_flips = random.randint(1, min(4, len(data)))
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF
        return data

    def _random_byte(self, data: bytearray) -> bytearray:
        """Replace bytes with random values."""
        if not data:
            return data

        num_replacements = random.randint(1, min(10, len(data)))
        for _ in range(num_replacements):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        return data

    def _byte_insert(self, data: bytearray) -> bytearray:
        """Insert random bytes."""
        if len(data) > 100000:  # Limit growth
            return data

        num_insertions = random.randint(1, min(10, len(data) // 10 + 1))
        for _ in range(num_insertions):
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))
        return data

    def _byte_delete(self, data: bytearray) -> bytearray:
        """Delete random bytes."""
        if len(data) < 10:  # Keep minimum size
            return data

        num_deletions = random.randint(1, min(10, len(data) // 10))
        for _ in range(num_deletions):
            if data:
                pos = random.randint(0, len(data) - 1)
                del data[pos]
        return data

    def _arithmetic_mutation(self, data: bytearray, delta: int) -> bytearray:
        """Apply arithmetic operations."""
        if not data:
            return data

        # Select random positions
        num_mods = random.randint(1, min(10, len(data)))
        for _ in range(num_mods):
            pos = random.randint(0, len(data) - 1)
            data[pos] = (data[pos] + delta) & 0xFF
        return data

    def _block_remove(self, data: bytearray) -> bytearray:
        """Remove random blocks."""
        if len(data) < 20:
            return data

        block_size = random.randint(1, min(100, len(data) // 4))
        pos = random.randint(0, len(data) - block_size)
        del data[pos : pos + block_size]
        return data

    def _block_duplicate(self, data: bytearray) -> bytearray:
        """Duplicate random blocks."""
        if not data or len(data) > 100000:
            return data

        block_size = random.randint(1, min(100, len(data) // 4))
        src_pos = random.randint(0, max(0, len(data) - block_size))
        dst_pos = random.randint(0, len(data))

        block = data[src_pos : src_pos + block_size]
        for i, byte in enumerate(block):
            data.insert(dst_pos + i, byte)
        return data

    def _block_shuffle(self, data: bytearray) -> bytearray:
        """Shuffle blocks within data."""
        if len(data) < 20:
            return data

        block_size = min(100, len(data) // 10)
        num_blocks = len(data) // block_size

        if num_blocks < 2:
            return data

        # Create blocks
        blocks = []
        for i in range(num_blocks):
            start = i * block_size
            end = min(start + block_size, len(data))
            blocks.append(data[start:end])

        # Shuffle
        random.shuffle(blocks)

        # Reconstruct
        result = bytearray()
        for block in blocks:
            result.extend(block)

        # Add remainder
        if len(result) < len(data):
            result.extend(data[len(result) :])

        return result

    def _interesting_bytes(self, data: bytearray) -> bytearray:
        """Replace with interesting byte values."""
        if not data:
            return data

        num_replacements = random.randint(1, min(10, len(data)))
        for _ in range(num_replacements):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.choice(self.interesting_bytes)
        return data

    def _interesting_ints(self, data: bytearray) -> bytearray:
        """Replace with interesting integer values."""
        if len(data) < 4:
            return data

        num_replacements = random.randint(1, min(5, len(data) // 4))
        for _ in range(num_replacements):
            pos = random.randint(0, len(data) - 4)
            value = random.choice(self.interesting_ints)

            # Try different encodings
            if random.random() < 0.5:
                # Little endian
                data[pos : pos + 4] = struct.pack("<i", value)
            else:
                # Big endian
                data[pos : pos + 4] = struct.pack(">i", value)
        return data

    def _boundary_values(self, data: bytearray) -> bytearray:
        """Insert boundary values at random positions."""
        boundaries = [
            b"\x00" * 4,  # Zeros
            b"\xff" * 4,  # Max values
            b"\x7f\xff\xff\xff",  # Max signed int
            b"\x80\x00\x00\x00",  # Min signed int
        ]

        if len(data) < 4:
            return data

        num_insertions = random.randint(1, 3)
        for _ in range(num_insertions):
            boundary = random.choice(boundaries)
            pos = random.randint(0, max(0, len(data) - len(boundary)))
            data[pos : pos + len(boundary)] = boundary

        return data

    # DICOM-specific mutations
    def _dicom_tag_corrupt(self, data: bytearray) -> bytearray:
        """Corrupt DICOM tags."""
        if len(data) < 132:  # Minimum DICOM header
            return data

        # Find and corrupt tags
        for i in range(132, len(data) - 4, 2):
            if random.random() < 0.1:  # 10% chance
                # Corrupt group or element number
                if random.random() < 0.5:
                    data[i] = random.randint(0, 255)
                else:
                    data[i + 1] = random.randint(0, 255)
        return data

    def _dicom_vr_mismatch(self, data: bytearray) -> bytearray:
        """Create VR mismatches."""
        vr_bytes = [
            b"AE",
            b"AS",
            b"AT",
            b"CS",
            b"DA",
            b"DS",
            b"DT",
            b"FL",
            b"FD",
            b"IS",
            b"LO",
            b"LT",
            b"OB",
            b"OD",
            b"OF",
            b"OW",
            b"PN",
            b"SH",
            b"SL",
            b"SQ",
            b"SS",
            b"ST",
            b"TM",
            b"UI",
            b"UL",
            b"UN",
            b"US",
            b"UT",
        ]

        if len(data) < 132:
            return data

        # Find and replace VR values
        for i in range(132, len(data) - 6, 2):
            if random.random() < 0.05:  # 5% chance
                vr = random.choice(vr_bytes)
                data[i + 4 : i + 6] = vr

        return data

    def _dicom_length_overflow(self, data: bytearray) -> bytearray:
        """Create length field overflows."""
        if len(data) < 140:
            return data

        # Find length fields and overflow them
        for i in range(132, len(data) - 8, 2):
            if random.random() < 0.05:
                # Set length to large value
                overflow_value = random.choice(
                    [
                        0xFFFFFFFF,  # Max uint32
                        0x7FFFFFFF,  # Max int32
                        0xFFFF,  # Max uint16
                        len(data) * 2,  # Double actual length
                    ]
                )
                data[i + 6 : i + 10] = struct.pack("<I", overflow_value & 0xFFFFFFFF)

        return data

    def _dicom_sequence_nest(self, data: bytearray) -> bytearray:
        """Create deeply nested sequences."""
        if len(data) < 200:
            return data

        # Insert sequence delimiters
        seq_start = b"\xfe\xff\x00\xe0"
        seq_end = b"\xfe\xff\x0d\xe0"

        # Add nested sequences
        depth = random.randint(1, 10)
        pos = random.randint(132, max(132, len(data) - 100))

        for _ in range(depth):
            data[pos:pos] = seq_start
            pos += len(seq_start) + random.randint(10, 50)

        # Add closing tags
        for _ in range(depth):
            data[pos:pos] = seq_end
            pos += len(seq_end)

        return data

    def _dicom_transfer_syntax(self, data: bytearray) -> bytearray:
        """Mutate transfer syntax."""
        transfer_syntaxes = [
            b"1.2.840.10008.1.2",  # Implicit VR Little Endian
            b"1.2.840.10008.1.2.1",  # Explicit VR Little Endian
            b"1.2.840.10008.1.2.2",  # Explicit VR Big Endian
            b"1.2.840.10008.1.2.4.50",  # JPEG Baseline
            b"1.2.840.10008.1.2.4.70",  # JPEG Lossless
            b"1.2.840.10008.1.2.5",  # RLE Lossless
            b"INVALID.SYNTAX",  # Invalid syntax
        ]

        # Try to find and replace transfer syntax
        for syntax in transfer_syntaxes[:3]:  # Check common ones
            if syntax in data:
                new_syntax = random.choice(transfer_syntaxes)
                data = data.replace(syntax, new_syntax)
                break

        return data

    def update_strategy_feedback(
        self, mutation_type: MutationType, coverage_gained: bool, new_edges: int = 0
    ) -> None:
        """Update mutation strategy based on feedback."""
        if mutation_type in self.strategies:
            self.strategies[mutation_type].update(coverage_gained, new_edges)

        # Track history
        self.mutation_history.append((mutation_type, coverage_gained))
        if coverage_gained:
            self.coverage_history.append(new_edges)

        # Adaptive strategy adjustment
        if self.adaptive_mode and len(self.mutation_history) % 100 == 0:
            self._adjust_strategies()

    def _adjust_strategies(self) -> None:
        """Adjust strategy weights based on performance."""
        # Calculate recent success rates
        recent_history = self.mutation_history[-500:]
        recent_success = {}

        for mutation_type in MutationType:
            successes = sum(
                1 for mt, success in recent_history if mt == mutation_type and success
            )
            total = sum(1 for mt, _ in recent_history if mt == mutation_type)

            if total > 0:
                recent_success[mutation_type] = successes / total
            else:
                recent_success[mutation_type] = 0.0

        # Adjust weights
        for mutation_type, strategy in self.strategies.items():
            if mutation_type in recent_success:
                # Increase weight for successful strategies
                if recent_success[mutation_type] > 0.1:
                    strategy.weight = min(10.0, strategy.weight * 1.1)
                elif recent_success[mutation_type] < 0.01:
                    strategy.weight = max(0.1, strategy.weight * 0.9)

    def get_mutation_stats(self) -> dict[str, Any]:
        """Get mutation statistics."""
        stats = {}
        for mutation_type, strategy in self.strategies.items():
            if strategy.total_count > 0:
                stats[mutation_type.value] = {
                    "success_rate": strategy.success_rate,
                    "total_count": strategy.total_count,
                    "success_count": strategy.success_count,
                    "weight": strategy.weight,
                    "avg_coverage_gain": (
                        np.mean(strategy.coverage_gains)
                        if strategy.coverage_gains
                        else 0
                    ),
                }
        return stats

"""Coverage-Guided Mutation Engine for DICOM Fuzzer

Implements intelligent mutation strategies that adapt based on coverage feedback.
Learns which mutations are most effective for discovering new code paths.

Note: CVE-based mutations have been removed from the fuzzer.
For CVE replication, use the dedicated 'cve' subcommand:
    dicom-fuzzer cve --help
"""

import random
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from dicom_fuzzer.core.constants import MutationType
from dicom_fuzzer.core.coverage.corpus_manager import Seed
from dicom_fuzzer.core.coverage.coverage_instrumentation import CoverageInfo
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


# Stub functions for removed CVE mutations
# CVE replication is now in dicom_fuzzer.cve module (deterministic, not fuzzing)
def get_mutation_func(name: str) -> None:
    """Stub: CVE mutations removed from fuzzer. Use dicom-fuzzer cve command."""
    return None


def apply_cve_mutation(data: bytes) -> tuple[bytes, Any]:
    """Stub: CVE mutations removed from fuzzer. Use dicom-fuzzer cve command."""

    class StubMutation:
        cve_id = "DISABLED"
        category = type("Category", (), {"value": "disabled"})()

    return data, StubMutation()


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
        security_aware: bool = True,
        cve_mutation_probability: float = 0.2,
    ):
        """Initialize the coverage-guided mutator.

        Args:
            max_mutations: Maximum mutations per input
            adaptive_mode: Enable adaptive mutation selection
            dicom_aware: Enable DICOM-specific mutations
            security_aware: Enable CVE-based security mutations (default: True)
            cve_mutation_probability: Probability of selecting CVE mutation (default: 0.2)

        """
        self.max_mutations = max_mutations
        self.adaptive_mode = adaptive_mode
        self.dicom_aware = dicom_aware
        self.security_aware = security_aware
        self.cve_mutation_probability = cve_mutation_probability

        # Track CVE mutation statistics
        self.cve_mutation_count = 0
        self.cve_mutations_applied: dict[str, int] = {}

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

        # Initialize mutation dispatch table
        self._mutation_handlers = self._build_mutation_handlers()

    def _build_mutation_handlers(
        self,
    ) -> dict[MutationType, Callable[[bytearray], bytearray]]:
        """Build dispatch table for mutation handlers."""
        return {
            # Basic mutations
            MutationType.BIT_FLIP: self._bit_flip,
            MutationType.BYTE_FLIP: self._byte_flip,
            MutationType.RANDOM_BYTE: self._random_byte,
            MutationType.BYTE_INSERT: self._byte_insert,
            MutationType.BYTE_DELETE: self._byte_delete,
            MutationType.ARITHMETIC_INC: lambda d: self._arithmetic_mutation(d, 1),
            MutationType.ARITHMETIC_DEC: lambda d: self._arithmetic_mutation(d, -1),
            MutationType.ARITHMETIC_RANDOM: (
                lambda d: self._arithmetic_mutation(d, random.randint(-255, 255))
            ),
            MutationType.BLOCK_REMOVE: self._block_remove,
            MutationType.BLOCK_DUPLICATE: self._block_duplicate,
            MutationType.BLOCK_SHUFFLE: self._block_shuffle,
            MutationType.INTERESTING_BYTES: self._interesting_bytes,
            MutationType.INTERESTING_INTS: self._interesting_ints,
            MutationType.BOUNDARY_VALUES: self._boundary_values,
            # DICOM-specific mutations
            MutationType.DICOM_TAG_CORRUPT: self._dicom_tag_corrupt,
            MutationType.DICOM_VR_MISMATCH: self._dicom_vr_mismatch,
            MutationType.DICOM_LENGTH_OVERFLOW: self._dicom_length_overflow,
            MutationType.DICOM_SEQUENCE_NEST: self._dicom_sequence_nest,
            MutationType.DICOM_TRANSFER_SYNTAX: self._dicom_transfer_syntax,
            # CVE-based security mutations
            MutationType.CVE_HEAP_OVERFLOW: self._cve_heap_overflow,
            MutationType.CVE_INTEGER_OVERFLOW: self._cve_integer_overflow,
            MutationType.CVE_MALFORMED_LENGTH: self._cve_malformed_length,
            MutationType.CVE_PATH_TRAVERSAL: self._cve_path_traversal,
            MutationType.CVE_DEEP_NESTING: self._cve_deep_nesting,
            MutationType.CVE_POLYGLOT: self._cve_polyglot,
            MutationType.CVE_ENCAPSULATED_PIXEL: self._cve_encapsulated_pixel,
            MutationType.CVE_JPEG_CODEC: self._cve_jpeg_codec,
            MutationType.CVE_RANDOM: self._cve_random,
        }

    def _init_strategies(self) -> None:
        """Initialize all mutation strategies."""
        # Basic mutations - iterate over enum members explicitly
        for mutation_type in list(MutationType):
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

        # Disable CVE mutations if not security-aware
        if not self.security_aware:
            for mutation_type in [
                MutationType.CVE_HEAP_OVERFLOW,
                MutationType.CVE_INTEGER_OVERFLOW,
                MutationType.CVE_MALFORMED_LENGTH,
                MutationType.CVE_PATH_TRAVERSAL,
                MutationType.CVE_DEEP_NESTING,
                MutationType.CVE_POLYGLOT,
                MutationType.CVE_ENCAPSULATED_PIXEL,
                MutationType.CVE_JPEG_CODEC,
                MutationType.CVE_RANDOM,
            ]:
                self.strategies[mutation_type].enabled = False
        else:
            # Give CVE mutations higher initial weight for security testing
            for mutation_type in [
                MutationType.CVE_HEAP_OVERFLOW,
                MutationType.CVE_INTEGER_OVERFLOW,
                MutationType.CVE_MALFORMED_LENGTH,
                MutationType.CVE_PATH_TRAVERSAL,
                MutationType.CVE_DEEP_NESTING,
                MutationType.CVE_POLYGLOT,
                MutationType.CVE_ENCAPSULATED_PIXEL,
                MutationType.CVE_JPEG_CODEC,
                MutationType.CVE_RANDOM,
            ]:
                self.strategies[mutation_type].weight = 2.0  # Higher weight

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
        weights: list[float] = []
        strategies: list[MutationType] = []

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

        # Convert to indices for numpy choice, then map back to MutationType
        idx = int(np.random.choice(len(strategies), p=weights))
        return strategies[idx]

    def _apply_mutation(
        self, data: bytearray, mutation_type: MutationType
    ) -> bytearray | None:
        """Apply specific mutation to data using dispatch table."""
        if len(data) == 0:
            return None

        handler = self._mutation_handlers.get(mutation_type)
        if handler is None:
            return data.copy()

        mutated = data.copy()
        return handler(mutated)

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

    # CVE-based security mutation methods
    def _cve_heap_overflow(self, data: bytearray) -> bytearray:
        """Apply CVE-2025-5943 heap overflow mutation (pixel data parsing)."""
        try:
            func = get_mutation_func("mutate_heap_overflow_pixel_data")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2025-5943", "heap_overflow")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE heap overflow mutation failed: {e}")
        return data

    def _cve_integer_overflow(self, data: bytearray) -> bytearray:
        """Apply CVE-2025-5943 integer overflow mutation (dimensions)."""
        try:
            func = get_mutation_func("mutate_integer_overflow_dimensions")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2025-5943", "integer_overflow")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE integer overflow mutation failed: {e}")
        return data

    def _cve_malformed_length(self, data: bytearray) -> bytearray:
        """Apply CVE-2020-29625 malformed length field mutation."""
        try:
            # Randomly choose between malformed and oversized length
            if random.random() < 0.5:
                func = get_mutation_func("mutate_malformed_length_field")
            else:
                func = get_mutation_func("mutate_oversized_length")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2020-29625", "malformed_length")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE malformed length mutation failed: {e}")
        return data

    def _cve_path_traversal(self, data: bytearray) -> bytearray:
        """Apply CVE-2021-41946 path traversal mutation."""
        try:
            func = get_mutation_func("mutate_path_traversal_filename")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2021-41946", "path_traversal")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE path traversal mutation failed: {e}")
        return data

    def _cve_deep_nesting(self, data: bytearray) -> bytearray:
        """Apply CVE-2022-24193 deep nesting mutation (DoS)."""
        try:
            func = get_mutation_func("mutate_deep_nesting")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2022-24193", "deep_nesting")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE deep nesting mutation failed: {e}")
        return data

    def _cve_polyglot(self, data: bytearray) -> bytearray:
        """Apply CVE-2019-11687 polyglot mutation (preamble executable)."""
        try:
            # Randomly choose PE or ELF polyglot
            if random.random() < 0.5:
                func = get_mutation_func("mutate_pe_polyglot_preamble")
            else:
                func = get_mutation_func("mutate_elf_polyglot_preamble")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2019-11687", "polyglot")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE polyglot mutation failed: {e}")
        return data

    def _cve_encapsulated_pixel(self, data: bytearray) -> bytearray:
        """Apply CVE-2025-11266 encapsulated PixelData mutation."""
        try:
            # Randomly choose underflow or fragment mismatch
            if random.random() < 0.5:
                func = get_mutation_func("mutate_encapsulated_pixeldata_underflow")
            else:
                func = get_mutation_func("mutate_fragment_count_mismatch")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2025-11266", "encapsulated_pixel")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE encapsulated pixel mutation failed: {e}")
        return data

    def _cve_jpeg_codec(self, data: bytearray) -> bytearray:
        """Apply CVE-2025-53618/53619 JPEG codec mutation."""
        try:
            # Randomly choose OOB read or truncated stream
            if random.random() < 0.5:
                func = get_mutation_func("mutate_jpeg_codec_oob_read")
            else:
                func = get_mutation_func("mutate_jpeg_truncated_stream")
            if func:
                result = func(bytes(data))
                self._track_cve_mutation("CVE-2025-53618", "jpeg_codec")
                return bytearray(result)
        except Exception as e:
            logger.debug(f"CVE JPEG codec mutation failed: {e}")
        return data

    def _cve_random(self, data: bytearray) -> bytearray:
        """Apply a random CVE mutation from the registry."""
        try:
            result, mutation_info = apply_cve_mutation(bytes(data))
            self._track_cve_mutation(mutation_info.cve_id, mutation_info.category.value)
            logger.debug(
                f"Applied random CVE mutation: {mutation_info.cve_id} "
                f"({mutation_info.category.value})"
            )
            return bytearray(result)
        except Exception as e:
            logger.debug(f"Random CVE mutation failed: {e}")
        return data

    def _track_cve_mutation(self, cve_id: str, mutation_type: str) -> None:
        """Track CVE mutation statistics."""
        self.cve_mutation_count += 1
        key = f"{cve_id}:{mutation_type}"
        self.cve_mutations_applied[key] = self.cve_mutations_applied.get(key, 0) + 1

    def get_cve_mutation_stats(self) -> dict[str, Any]:
        """Get CVE mutation statistics."""
        return {
            "total_cve_mutations": self.cve_mutation_count,
            "mutations_by_type": dict(self.cve_mutations_applied),
            "security_aware": self.security_aware,
            "cve_mutation_probability": self.cve_mutation_probability,
        }

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

        for mutation_type in list(MutationType):
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

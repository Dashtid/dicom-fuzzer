"""Input-to-state correspondence for targeted mutations.

Implements Redqueen/CMPLOG-style techniques:
- Comparison value capture during execution
- Input colorization to identify influential bytes
- Targeted mutation placement based on captured values
- Magic byte discovery and dictionary extraction

References:
- REDQUEEN: Fuzzing with Input-to-State Correspondence (NDSS 2019)
- AFL++ CMPLOG: https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md
- "Improving AFL++ CMPLOG" (arXiv 2022)

"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Literal

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ComparisonType(Enum):
    """Types of comparisons tracked."""

    EQUAL = auto()  # ==
    NOT_EQUAL = auto()  # !=
    LESS_THAN = auto()  # <
    LESS_EQUAL = auto()  # <=
    GREATER_THAN = auto()  # >
    GREATER_EQUAL = auto()  # >=
    MEMCMP = auto()  # Memory comparison
    STRCMP = auto()  # String comparison
    STRNCMP = auto()  # String comparison with length


@dataclass
class ComparisonRecord:
    """Record of a single comparison operation.

    Attributes:
        comp_type: Type of comparison
        operand1: First operand value
        operand2: Second operand value
        size: Size in bytes of comparison
        location: Code location (file:line or address)
        hit_count: Number of times this comparison was hit

    """

    comp_type: ComparisonType
    operand1: bytes
    operand2: bytes
    size: int
    location: str | None = None
    hit_count: int = 1

    def as_integers(self) -> tuple[int, int] | None:
        """Convert operands to integers if possible."""
        if self.size > 8:
            return None

        try:
            # Try little-endian interpretation
            val1 = int.from_bytes(self.operand1[: self.size], "little")
            val2 = int.from_bytes(self.operand2[: self.size], "little")
            return val1, val2
        except (ValueError, OverflowError):
            return None

    def get_solving_values(self) -> list[bytes]:
        """Get values that would satisfy this comparison.

        Returns:
            List of byte values that could solve the comparison

        """
        values = []

        # For equality checks, the other operand is the solution
        if self.comp_type == ComparisonType.EQUAL:
            values.append(self.operand2)
        elif self.comp_type == ComparisonType.NOT_EQUAL:
            # Any value except operand2
            pass
        elif self.comp_type in (ComparisonType.LESS_THAN, ComparisonType.LESS_EQUAL):
            # Need operand1 < operand2, so try operand2 - 1
            ints = self.as_integers()
            if ints:
                val1, val2 = ints
                if val2 > 0:
                    new_val = val2 - 1
                    values.append(new_val.to_bytes(self.size, "little"))
        elif self.comp_type in (
            ComparisonType.GREATER_THAN,
            ComparisonType.GREATER_EQUAL,
        ):
            # Need operand1 > operand2, so try operand2 + 1
            ints = self.as_integers()
            if ints:
                val1, val2 = ints
                max_val = (1 << (self.size * 8)) - 1
                if val2 < max_val:
                    new_val = val2 + 1
                    values.append(new_val.to_bytes(self.size, "little"))
        elif self.comp_type in (
            ComparisonType.MEMCMP,
            ComparisonType.STRCMP,
            ComparisonType.STRNCMP,
        ):
            # For memory/string comparison, the target is operand2
            values.append(self.operand2)

        return values


@dataclass
class ComparisonLog:
    """Log of all comparisons during an execution.

    Attributes:
        comparisons: List of comparison records
        unique_values: Set of unique comparison values seen
        input_hash: Hash of the input that generated this log

    """

    comparisons: list[ComparisonRecord] = field(default_factory=list)
    unique_values: set[bytes] = field(default_factory=set)
    input_hash: str | None = None

    def add(self, record: ComparisonRecord) -> None:
        """Add a comparison record."""
        self.comparisons.append(record)
        self.unique_values.add(record.operand1)
        self.unique_values.add(record.operand2)

    def get_magic_values(self, min_size: int = 2) -> list[bytes]:
        """Extract potential magic values from comparisons.

        Args:
            min_size: Minimum size of values to consider

        Returns:
            List of unique values that could be magic bytes

        """
        magic = []
        seen = set()

        for comp in self.comparisons:
            if comp.size >= min_size:
                for op in [comp.operand1, comp.operand2]:
                    op_key = op[: comp.size]
                    if op_key not in seen:
                        seen.add(op_key)
                        # Filter out all-zero and all-0xFF values (check actual bytes)
                        actual_len = len(op_key)
                        is_all_zero = op_key == b"\x00" * actual_len
                        is_all_ff = op_key == b"\xff" * actual_len
                        if not is_all_zero and not is_all_ff:
                            magic.append(op_key)

        return magic


@dataclass
class ColorizedRegion:
    """A region of input that affects comparisons.

    Attributes:
        offset: Start offset in input
        length: Length of region
        affected_comparisons: Indices of comparisons this region affects
        influence_score: How strongly this region affects comparisons

    """

    offset: int
    length: int
    affected_comparisons: list[int] = field(default_factory=list)
    influence_score: float = 0.0


@dataclass
class InputToStateConfig:
    """Configuration for input-to-state analysis.

    Attributes:
        max_comparisons: Maximum comparisons to track per execution
        colorize_chunk_size: Chunk size for colorization
        min_influence_score: Minimum influence to consider significant
        enable_arithmetic: Enable arithmetic solving
        enable_string_solving: Enable string comparison solving
        max_solving_attempts: Maximum attempts per comparison

    """

    max_comparisons: int = 256
    colorize_chunk_size: int = 4
    min_influence_score: float = 0.1
    enable_arithmetic: bool = True
    enable_string_solving: bool = True
    max_solving_attempts: int = 100


class ComparisonTracker:
    """Tracks comparison operations during execution.

    Simulates CMPLOG functionality by recording comparison
    operands for later analysis and targeted mutation.
    """

    def __init__(self, config: InputToStateConfig | None = None):
        """Initialize comparison tracker.

        Args:
            config: Configuration settings

        """
        self.config = config or InputToStateConfig()
        self._current_log: ComparisonLog | None = None
        self._logs: dict[str, ComparisonLog] = {}
        self._comparison_map: dict[str, list[ComparisonRecord]] = defaultdict(list)

    def start_tracking(self, input_hash: str) -> None:
        """Start tracking comparisons for a new input.

        Args:
            input_hash: Hash identifying the input

        """
        self._current_log = ComparisonLog(input_hash=input_hash)

    def stop_tracking(self) -> ComparisonLog | None:
        """Stop tracking and return the log.

        Returns:
            The comparison log or None

        """
        log = self._current_log
        if log and log.input_hash:
            self._logs[log.input_hash] = log
        self._current_log = None
        return log

    def record_comparison(
        self,
        comp_type: ComparisonType,
        operand1: bytes,
        operand2: bytes,
        size: int,
        location: str | None = None,
    ) -> None:
        """Record a comparison operation.

        Args:
            comp_type: Type of comparison
            operand1: First operand
            operand2: Second operand
            size: Size of comparison in bytes
            location: Code location

        """
        if not self._current_log:
            return

        if len(self._current_log.comparisons) >= self.config.max_comparisons:
            return

        record = ComparisonRecord(
            comp_type=comp_type,
            operand1=operand1,
            operand2=operand2,
            size=size,
            location=location,
        )

        self._current_log.add(record)

        if location:
            self._comparison_map[location].append(record)

    def record_int_comparison(
        self,
        comp_type: ComparisonType,
        val1: int,
        val2: int,
        size: int = 4,
        location: str | None = None,
    ) -> None:
        """Record an integer comparison.

        Args:
            comp_type: Type of comparison
            val1: First value
            val2: Second value
            size: Size in bytes (1, 2, 4, or 8)
            location: Code location

        """
        op1 = val1.to_bytes(size, "little", signed=val1 < 0)
        op2 = val2.to_bytes(size, "little", signed=val2 < 0)
        self.record_comparison(comp_type, op1, op2, size, location)

    def record_string_comparison(
        self,
        str1: str | bytes,
        str2: str | bytes,
        comp_type: ComparisonType = ComparisonType.STRCMP,
        location: str | None = None,
    ) -> None:
        """Record a string comparison.

        Args:
            str1: First string
            str2: Second string
            comp_type: Type of string comparison
            location: Code location

        """
        if isinstance(str1, str):
            str1 = str1.encode("utf-8", errors="replace")
        if isinstance(str2, str):
            str2 = str2.encode("utf-8", errors="replace")

        size = max(len(str1), len(str2))
        self.record_comparison(comp_type, str1, str2, size, location)

    def get_log(self, input_hash: str) -> ComparisonLog | None:
        """Get the comparison log for an input.

        Args:
            input_hash: Hash of the input

        Returns:
            Comparison log or None

        """
        return self._logs.get(input_hash)

    def get_all_magic_values(self) -> list[bytes]:
        """Get all magic values across all logs.

        Returns:
            List of unique magic values

        """
        all_magic = set()
        for log in self._logs.values():
            for val in log.get_magic_values():
                all_magic.add(val)
        return list(all_magic)


class InputColorizer:
    """Colorizes input to identify influential bytes.

    Uses differential analysis to determine which input
    bytes affect comparison operations.
    """

    def __init__(self, config: InputToStateConfig | None = None):
        """Initialize colorizer.

        Args:
            config: Configuration settings

        """
        self.config = config or InputToStateConfig()

    def colorize(
        self,
        original_input: bytes,
        original_log: ComparisonLog,
        execute_fn: Any,  # Callable[[bytes], ComparisonLog]
    ) -> list[ColorizedRegion]:
        """Colorize input to find influential regions.

        Args:
            original_input: Original input bytes
            original_log: Comparison log from original input
            execute_fn: Function to execute input and get comparison log

        Returns:
            List of colorized regions

        """
        regions: list[ColorizedRegion] = []
        chunk_size = self.config.colorize_chunk_size

        for offset in range(0, len(original_input), chunk_size):
            # Create modified input with random bytes in this chunk
            modified = bytearray(original_input)
            end = min(offset + chunk_size, len(modified))

            # XOR with pattern to change bytes
            for i in range(offset, end):
                modified[i] ^= 0xFF

            # Execute and compare
            try:
                modified_log = execute_fn(bytes(modified))
            except Exception:
                continue

            # Check how many comparisons changed
            affected = self._compare_logs(original_log, modified_log)

            if affected:
                influence = len(affected) / max(len(original_log.comparisons), 1)
                if influence >= self.config.min_influence_score:
                    regions.append(
                        ColorizedRegion(
                            offset=offset,
                            length=end - offset,
                            affected_comparisons=affected,
                            influence_score=influence,
                        )
                    )

        return regions

    def _compare_logs(self, log1: ComparisonLog, log2: ComparisonLog) -> list[int]:
        """Compare two logs and return indices of differing comparisons."""
        affected = []

        min_len = min(len(log1.comparisons), len(log2.comparisons))
        for i in range(min_len):
            comp1 = log1.comparisons[i]
            comp2 = log2.comparisons[i]

            if comp1.operand1 != comp2.operand1 or comp1.operand2 != comp2.operand2:
                affected.append(i)

        return affected


class InputToStateResolver:
    """Resolves input-to-state correspondence for targeted mutations.

    Combines comparison tracking with input colorization to
    generate targeted mutations that solve comparisons.
    """

    def __init__(self, config: InputToStateConfig | None = None):
        """Initialize resolver.

        Args:
            config: Configuration settings

        """
        self.config = config or InputToStateConfig()
        self.tracker = ComparisonTracker(config)
        self.colorizer = InputColorizer(config)
        self._solving_cache: dict[str, list[bytes]] = {}

    def analyze_input(
        self,
        input_data: bytes,
        comparison_log: ComparisonLog,
    ) -> list[tuple[int, bytes]]:
        """Analyze input and generate targeted mutations.

        Args:
            input_data: Input bytes to analyze
            comparison_log: Log of comparisons from executing input

        Returns:
            List of (offset, replacement) tuples for targeted mutations

        """
        mutations: list[tuple[int, bytes]] = []

        for comp in comparison_log.comparisons:
            solving_values = comp.get_solving_values()

            for value in solving_values:
                # Find where this value might be placed
                positions = self._find_value_positions(input_data, comp.operand1)

                for pos in positions:
                    if pos + len(value) <= len(input_data):
                        mutations.append((pos, value))

        return mutations

    def _find_value_positions(self, data: bytes, value: bytes) -> list[int]:
        """Find positions where a value appears in data."""
        positions = []
        start = 0

        while True:
            pos = data.find(value, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1

        return positions

    def generate_solving_mutations(
        self,
        input_data: bytes,
        comparison_log: ComparisonLog,
        colorized_regions: list[ColorizedRegion] | None = None,
    ) -> list[bytes]:
        """Generate mutated inputs that attempt to solve comparisons.

        Args:
            input_data: Original input
            comparison_log: Comparison log
            colorized_regions: Optional pre-computed colorized regions

        Returns:
            List of mutated inputs

        """
        mutations = []
        attempts = 0

        for comp in comparison_log.comparisons:
            if attempts >= self.config.max_solving_attempts:
                break

            solving_values = comp.get_solving_values()

            for value in solving_values:
                # Strategy 1: Direct replacement at matching positions
                positions = self._find_value_positions(input_data, comp.operand1)
                for pos in positions[:3]:  # Limit positions per value
                    mutated = self._apply_mutation(input_data, pos, value)
                    if mutated:
                        mutations.append(mutated)
                        attempts += 1

                # Strategy 2: Placement in colorized regions
                if colorized_regions:
                    for region in colorized_regions[:5]:
                        if comp in [
                            comparison_log.comparisons[i]
                            for i in region.affected_comparisons
                            if i < len(comparison_log.comparisons)
                        ]:
                            mutated = self._apply_mutation(
                                input_data, region.offset, value
                            )
                            if mutated:
                                mutations.append(mutated)
                                attempts += 1

                # Strategy 3: Arithmetic solving
                if self.config.enable_arithmetic and comp.size <= 8:
                    arith_mutations = self._arithmetic_solving(input_data, comp)
                    mutations.extend(arith_mutations[:3])
                    attempts += len(arith_mutations[:3])

        return mutations

    def _apply_mutation(self, data: bytes, offset: int, value: bytes) -> bytes | None:
        """Apply a mutation at the given offset."""
        if offset < 0 or offset + len(value) > len(data):
            return None

        result = bytearray(data)
        result[offset : offset + len(value)] = value
        return bytes(result)

    def _arithmetic_solving(self, data: bytes, comp: ComparisonRecord) -> list[bytes]:
        """Generate arithmetic-based solving mutations."""
        mutations: list[bytes] = []
        ints = comp.as_integers()

        if not ints:
            return mutations

        val1, val2 = ints

        # Try to find val1 in data and replace with solving value
        positions = self._find_integer_positions(data, val1, comp.size)

        for pos in positions[:3]:
            # For equality, replace with val2
            if comp.comp_type == ComparisonType.EQUAL:
                mutated = self._apply_int_mutation(data, pos, val2, comp.size)
                if mutated:
                    mutations.append(mutated)

            # For less-than, try values less than val2
            elif comp.comp_type in (
                ComparisonType.LESS_THAN,
                ComparisonType.LESS_EQUAL,
            ):
                if val2 > 0:
                    for delta in [1, 2, 10, 100]:
                        new_val = val2 - delta
                        if new_val >= 0:
                            mutated = self._apply_int_mutation(
                                data, pos, new_val, comp.size
                            )
                            if mutated:
                                mutations.append(mutated)

            # For greater-than, try values greater than val2
            elif comp.comp_type in (
                ComparisonType.GREATER_THAN,
                ComparisonType.GREATER_EQUAL,
            ):
                max_val = (1 << (comp.size * 8)) - 1
                for delta in [1, 2, 10, 100]:
                    new_val = val2 + delta
                    if new_val <= max_val:
                        mutated = self._apply_int_mutation(
                            data, pos, new_val, comp.size
                        )
                        if mutated:
                            mutations.append(mutated)

        return mutations

    def _find_integer_positions(self, data: bytes, value: int, size: int) -> list[int]:
        """Find positions where an integer value appears."""
        positions: list[int] = []

        # Try both endiannesses
        endians: list[Literal["little", "big"]] = ["little", "big"]
        for endian in endians:
            try:
                value_bytes = value.to_bytes(size, endian)
                start = 0
                while True:
                    pos = data.find(value_bytes, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
            except (OverflowError, ValueError):
                # Value cannot be converted to bytes representation
                logger.debug("Could not convert value %r to bytes", value)

        return positions

    def _apply_int_mutation(
        self, data: bytes, offset: int, value: int, size: int
    ) -> bytes | None:
        """Apply an integer mutation."""
        try:
            value_bytes = value.to_bytes(size, "little")
            return self._apply_mutation(data, offset, value_bytes)
        except (OverflowError, ValueError):
            return None

    def extract_dictionary(self, comparison_logs: list[ComparisonLog]) -> list[bytes]:
        """Extract dictionary values from comparison logs.

        Args:
            comparison_logs: List of comparison logs

        Returns:
            List of dictionary values for mutation

        """
        dictionary: set[bytes] = set()

        for log in comparison_logs:
            # Add magic values
            for val in log.get_magic_values(min_size=2):
                dictionary.add(val)

            # Add solving values
            for comp in log.comparisons:
                for val in comp.get_solving_values():
                    if 2 <= len(val) <= 32:  # Reasonable size range
                        dictionary.add(val)

        # Sort by length for predictable ordering
        return sorted(dictionary, key=len)


@dataclass
class I2SStats:
    """Statistics for input-to-state analysis.

    Attributes:
        total_comparisons: Total comparisons tracked
        unique_values: Number of unique comparison values
        solved_comparisons: Comparisons successfully solved
        colorized_regions: Number of influential regions found
        dictionary_size: Size of extracted dictionary

    """

    total_comparisons: int = 0
    unique_values: int = 0
    solved_comparisons: int = 0
    colorized_regions: int = 0
    dictionary_size: int = 0


class InputToStateManager:
    """High-level manager for input-to-state analysis.

    Coordinates comparison tracking, colorization, and
    mutation generation across fuzzing iterations.
    """

    def __init__(self, config: InputToStateConfig | None = None):
        """Initialize manager.

        Args:
            config: Configuration settings

        """
        self.config = config or InputToStateConfig()
        self.resolver = InputToStateResolver(config)
        self._dictionary: list[bytes] = []
        self._stats = I2SStats()

    def process_execution(
        self,
        input_data: bytes,
        input_hash: str,
    ) -> ComparisonLog:
        """Process an execution and track comparisons.

        This should be called during/after executing an input.

        Args:
            input_data: The input that was executed
            input_hash: Hash identifying the input

        Returns:
            The comparison log

        """
        self.resolver.tracker.start_tracking(input_hash)
        # Note: In real usage, comparisons would be recorded during execution
        # via instrumentation hooks. Here we just return an empty log
        # that can be populated by the caller.
        return ComparisonLog(input_hash=input_hash)

    def finish_execution(self) -> ComparisonLog | None:
        """Finish tracking an execution.

        Returns:
            The completed comparison log

        """
        log = self.resolver.tracker.stop_tracking()
        if log:
            self._stats.total_comparisons += len(log.comparisons)
            self._stats.unique_values = len(
                self.resolver.tracker.get_all_magic_values()
            )
        return log

    def generate_mutations(
        self,
        input_data: bytes,
        comparison_log: ComparisonLog,
    ) -> list[bytes]:
        """Generate targeted mutations based on comparison log.

        Args:
            input_data: Original input
            comparison_log: Log of comparisons

        Returns:
            List of mutated inputs

        """
        mutations = self.resolver.generate_solving_mutations(input_data, comparison_log)
        return mutations

    def update_dictionary(self, logs: list[ComparisonLog]) -> None:
        """Update the mutation dictionary from comparison logs.

        Args:
            logs: List of comparison logs to process

        """
        new_values = self.resolver.extract_dictionary(logs)
        existing = set(self._dictionary)

        for val in new_values:
            if val not in existing:
                self._dictionary.append(val)
                existing.add(val)

        self._stats.dictionary_size = len(self._dictionary)

    def get_dictionary(self) -> list[bytes]:
        """Get the current mutation dictionary.

        Returns:
            List of dictionary values

        """
        return self._dictionary.copy()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics.

        Returns:
            Dictionary of statistics

        """
        return {
            "total_comparisons": self._stats.total_comparisons,
            "unique_values": self._stats.unique_values,
            "solved_comparisons": self._stats.solved_comparisons,
            "colorized_regions": self._stats.colorized_regions,
            "dictionary_size": self._stats.dictionary_size,
        }

"""
Crash Deduplication - Intelligent Grouping of Similar Crashes

This module provides sophisticated crash deduplication to identify unique bugs
by analyzing multiple crash characteristics:
- Stack trace similarity (Levenshtein distance, structural patterns)
- Exception type and message matching
- Mutation pattern similarity
- Configurable weighting and thresholds
"""

import hashlib
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Dict, List, Optional

from core.fuzzing_session import CrashRecord


@dataclass
class DeduplicationConfig:
    """Configuration for crash deduplication strategies."""

    # Enable/disable strategies
    use_stack_trace: bool = True
    use_exception_type: bool = True
    use_mutation_pattern: bool = True

    # Weights for each strategy (must sum to 1.0)
    stack_trace_weight: float = 0.5
    exception_weight: float = 0.3
    mutation_weight: float = 0.2

    # Similarity thresholds (0.0-1.0)
    stack_trace_threshold: float = 0.8
    exception_threshold: float = 0.9
    mutation_threshold: float = 0.7

    # Overall similarity threshold for considering crashes duplicates
    overall_threshold: float = 0.75

    def __post_init__(self):
        """Validate configuration."""
        total_weight = (
            self.stack_trace_weight + self.exception_weight + self.mutation_weight
        )
        if abs(total_weight - 1.0) > 0.01:
            raise ValueError(f"Weights must sum to 1.0, got {total_weight}")


class CrashDeduplicator:
    """
    Deduplicate crashes using multiple similarity strategies.

    Analyzes crashes from multiple perspectives to identify unique bugs,
    helping security researchers focus on distinct vulnerabilities.
    """

    def __init__(self, config: Optional[DeduplicationConfig] = None):
        """
        Initialize crash deduplicator.

        Args:
            config: Deduplication configuration (uses defaults if None)
        """
        self.config = config or DeduplicationConfig()
        self.crash_groups: List[List[CrashRecord]] = []
        self.group_signatures: List[str] = []

    def deduplicate_crashes(
        self, crashes: List[CrashRecord]
    ) -> Dict[str, List[CrashRecord]]:
        """
        Deduplicate list of crashes into groups.

        Args:
            crashes: List of crash records to deduplicate

        Returns:
            Dictionary mapping group ID to list of similar crashes
        """
        if not crashes:
            return {}

        self.crash_groups = []
        self.group_signatures = []

        for crash in crashes:
            # Find best matching group or create new one
            best_group_idx = self._find_best_group(crash)

            if best_group_idx is not None:
                # Add to existing group
                self.crash_groups[best_group_idx].append(crash)
            else:
                # Create new group
                self.crash_groups.append([crash])
                self.group_signatures.append(self._generate_signature(crash))

        # Convert to dictionary with group IDs
        groups = {}
        for idx, crash_list in enumerate(self.crash_groups):
            group_id = f"group_{idx + 1:03d}_{self.group_signatures[idx][:8]}"
            groups[group_id] = crash_list

        return groups

    def get_unique_crash_count(self) -> int:
        """Get count of unique crash groups."""
        return len(self.crash_groups)

    def get_deduplication_stats(self) -> Dict:
        """
        Get deduplication statistics.

        Returns:
            Dictionary with deduplication metrics
        """
        if not self.crash_groups:
            return {
                "total_crashes": 0,
                "unique_groups": 0,
                "largest_group": 0,
                "deduplication_ratio": 0.0,
            }

        total_crashes = sum(len(group) for group in self.crash_groups)
        largest_group = max(len(group) for group in self.crash_groups)

        return {
            "total_crashes": total_crashes,
            "unique_groups": len(self.crash_groups),
            "largest_group": largest_group,
            "deduplication_ratio": (total_crashes - len(self.crash_groups))
            / total_crashes
            if total_crashes > 0
            else 0.0,
            "group_sizes": [len(group) for group in self.crash_groups],
        }

    def _find_best_group(self, crash: CrashRecord) -> Optional[int]:
        """
        Find best matching group for crash.

        Args:
            crash: Crash record to match

        Returns:
            Index of best matching group, or None if no good match
        """
        if not self.crash_groups:
            return None

        best_idx = None
        best_similarity = 0.0

        for idx, group in enumerate(self.crash_groups):
            # Compare with representative (first) crash in group
            representative = group[0]
            similarity = self._calculate_similarity(crash, representative)

            if (
                similarity > best_similarity
                and similarity >= self.config.overall_threshold
            ):
                best_similarity = similarity
                best_idx = idx

        return best_idx

    def _calculate_similarity(self, crash1: CrashRecord, crash2: CrashRecord) -> float:
        """
        Calculate overall similarity between two crashes.

        Args:
            crash1: First crash
            crash2: Second crash

        Returns:
            Similarity score (0.0-1.0)
        """
        similarities = {}

        # Stack trace similarity
        if self.config.use_stack_trace and crash1.stack_trace and crash2.stack_trace:
            similarities["stack_trace"] = self._compare_stack_traces(
                crash1.stack_trace, crash2.stack_trace
            )
        else:
            similarities["stack_trace"] = 0.0

        # Exception similarity
        if self.config.use_exception_type:
            similarities["exception"] = self._compare_exceptions(crash1, crash2)
        else:
            similarities["exception"] = 0.0

        # Mutation pattern similarity (would need mutation data from fuzzing session)
        if self.config.use_mutation_pattern:
            similarities["mutation"] = self._compare_mutation_patterns(crash1, crash2)
        else:
            similarities["mutation"] = 0.0

        # Weighted average
        overall = (
            similarities["stack_trace"] * self.config.stack_trace_weight
            + similarities["exception"] * self.config.exception_weight
            + similarities["mutation"] * self.config.mutation_weight
        )

        return overall

    def _compare_stack_traces(self, trace1: str, trace2: str) -> float:
        """
        Compare stack trace similarity.

        Uses multiple techniques:
        1. Sequence matching for overall similarity
        2. Function/file matching for structural similarity

        Args:
            trace1: First stack trace
            trace2: Second stack trace

        Returns:
            Similarity score (0.0-1.0)
        """
        # Normalize traces (remove addresses, line numbers that may vary)
        norm1 = self._normalize_stack_trace(trace1)
        norm2 = self._normalize_stack_trace(trace2)

        # Sequence matching
        seq_similarity = SequenceMatcher(None, norm1, norm2).ratio()

        # Extract function call sequences
        funcs1 = self._extract_function_sequence(trace1)
        funcs2 = self._extract_function_sequence(trace2)

        if funcs1 and funcs2:
            func_similarity = SequenceMatcher(None, funcs1, funcs2).ratio()
        else:
            func_similarity = seq_similarity

        # Combine (favor function matching)
        return 0.4 * seq_similarity + 0.6 * func_similarity

    def _normalize_stack_trace(self, trace: str) -> str:
        """
        Normalize stack trace by removing variable parts.

        Removes:
        - Memory addresses (0x...)
        - Line numbers
        - Timestamps
        - Process IDs

        Args:
            trace: Raw stack trace

        Returns:
            Normalized trace
        """
        import re

        # Remove memory addresses
        normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", trace)

        # Remove specific line numbers
        normalized = re.sub(r":\d+", ":LINE", normalized)

        # Remove timestamps
        normalized = re.sub(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "TIMESTAMP", normalized
        )

        # Remove process/thread IDs
        normalized = re.sub(r"\b(pid|tid|thread)[\s:]+\d+", r"\1:ID", normalized)

        return normalized

    def _extract_function_sequence(self, trace: str) -> List[str]:
        """
        Extract function call sequence from stack trace.

        Args:
            trace: Stack trace string

        Returns:
            List of function names in order
        """
        import re

        # Common patterns for function names in stack traces
        patterns = [
            r"at ([a-zA-Z_][a-zA-Z0-9_:<>]*)\(",  # Java/C++ style
            r"in ([a-zA-Z_][a-zA-Z0-9_]*)",  # Python style
            r"([a-zA-Z_][a-zA-Z0-9_:]+)\(",  # General
        ]

        functions = []
        for pattern in patterns:
            matches = re.findall(pattern, trace)
            if matches:
                functions.extend(matches)
                break

        return functions

    def _compare_exceptions(self, crash1: CrashRecord, crash2: CrashRecord) -> float:
        """
        Compare exception type and message similarity.

        Args:
            crash1: First crash
            crash2: Second crash

        Returns:
            Similarity score (0.0-1.0)
        """
        # Exception type match (exact or similar)
        type1 = crash1.exception_type or ""
        type2 = crash2.exception_type or ""

        if type1 == type2:
            type_match = 1.0
        elif type1 and type2:
            # Partial match for similar exception names
            type_match = SequenceMatcher(None, type1, type2).ratio()
        else:
            type_match = 0.0

        # Exception message similarity
        msg1 = crash1.exception_message or ""
        msg2 = crash2.exception_message or ""

        if msg1 and msg2:
            # Normalize messages (remove specific values)
            norm_msg1 = self._normalize_exception_message(msg1)
            norm_msg2 = self._normalize_exception_message(msg2)
            msg_match = SequenceMatcher(None, norm_msg1, norm_msg2).ratio()
        else:
            msg_match = 0.0 if msg1 or msg2 else 1.0

        # Weighted combination (type is more important)
        return 0.7 * type_match + 0.3 * msg_match

    def _normalize_exception_message(self, message: str) -> str:
        """
        Normalize exception message by removing specific values.

        Args:
            message: Exception message

        Returns:
            Normalized message
        """
        import re

        # Remove specific numbers first (before paths that might contain numbers)
        normalized = re.sub(r"\b\d+\b", "NUM", message)

        # Remove hex values
        normalized = re.sub(r"0x[0-9a-fA-F]+", "HEX", normalized)

        # Remove specific file paths (after numbers so we preserve NUM)
        normalized = re.sub(r"[A-Za-z]:\\[^\s]+", "PATH", normalized)
        normalized = re.sub(r"/[^\s]+", "PATH", normalized)

        return normalized

    def _compare_mutation_patterns(
        self, crash1: CrashRecord, crash2: CrashRecord
    ) -> float:
        """
        Compare mutation patterns that caused crashes.

        This would require access to the fuzzing session data
        to get mutation records for each crash.

        Args:
            crash1: First crash
            crash2: Second crash

        Returns:
            Similarity score (0.0-1.0)
        """
        # TODO: Implement when we have access to mutation data
        # For now, return neutral score
        return 0.5

    def _generate_signature(self, crash: CrashRecord) -> str:
        """
        Generate unique signature for crash group.

        Args:
            crash: Representative crash

        Returns:
            Signature string (hash)
        """
        # Combine key crash characteristics
        sig_parts = [
            crash.crash_type,
            crash.exception_type or "",
            crash.exception_message[:100] if crash.exception_message else "",
        ]

        if crash.stack_trace:
            # Use normalized stack trace for signature
            normalized = self._normalize_stack_trace(crash.stack_trace)
            sig_parts.append(normalized[:500])

        sig_str = "|".join(sig_parts)
        return hashlib.sha256(sig_str.encode()).hexdigest()


def deduplicate_session_crashes(
    session_data: Dict, config: Optional[DeduplicationConfig] = None
) -> Dict:
    """
    Deduplicate crashes from a fuzzing session.

    Args:
        session_data: Session report dictionary
        config: Deduplication configuration

    Returns:
        Dictionary with deduplication results
    """
    crashes = [
        CrashRecord(**crash_dict) for crash_dict in session_data.get("crashes", [])
    ]

    deduplicator = CrashDeduplicator(config)
    groups = deduplicator.deduplicate_crashes(crashes)
    stats = deduplicator.get_deduplication_stats()

    return {"groups": groups, "statistics": stats}

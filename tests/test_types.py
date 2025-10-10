"""
Comprehensive test suite for types.py

Tests shared type definitions including:
- MutationSeverity enum
- Enum value validation
- String representation
"""

import pytest

from dicom_fuzzer.core.types import MutationSeverity


class TestMutationSeverity:
    """Test MutationSeverity enum."""

    def test_enum_values_exist(self):
        """Test that all severity levels are defined."""
        assert hasattr(MutationSeverity, "MINIMAL")
        assert hasattr(MutationSeverity, "MODERATE")
        assert hasattr(MutationSeverity, "AGGRESSIVE")
        assert hasattr(MutationSeverity, "EXTREME")

    def test_enum_values_correct(self):
        """Test that enum values are correct."""
        assert MutationSeverity.MINIMAL.value == "minimal"
        assert MutationSeverity.MODERATE.value == "moderate"
        assert MutationSeverity.AGGRESSIVE.value == "aggressive"
        assert MutationSeverity.EXTREME.value == "extreme"

    def test_enum_member_count(self):
        """Test that enum has exactly 4 members."""
        assert len(MutationSeverity) == 4

    def test_enum_iteration(self):
        """Test iterating over enum members."""
        severities = list(MutationSeverity)
        assert len(severities) == 4
        assert MutationSeverity.MINIMAL in severities
        assert MutationSeverity.MODERATE in severities
        assert MutationSeverity.AGGRESSIVE in severities
        assert MutationSeverity.EXTREME in severities

    def test_enum_comparison(self):
        """Test comparing enum members."""
        assert MutationSeverity.MINIMAL == MutationSeverity.MINIMAL
        assert MutationSeverity.MINIMAL != MutationSeverity.MODERATE
        assert MutationSeverity.AGGRESSIVE != MutationSeverity.EXTREME

    def test_enum_string_representation(self):
        """Test string representation of enum members."""
        assert str(MutationSeverity.MINIMAL) == "MutationSeverity.MINIMAL"
        assert str(MutationSeverity.MODERATE) == "MutationSeverity.MODERATE"
        assert str(MutationSeverity.AGGRESSIVE) == "MutationSeverity.AGGRESSIVE"
        assert str(MutationSeverity.EXTREME) == "MutationSeverity.EXTREME"

    def test_enum_repr(self):
        """Test repr of enum members."""
        assert repr(MutationSeverity.MINIMAL) == "<MutationSeverity.MINIMAL: 'minimal'>"
        assert (
            repr(MutationSeverity.MODERATE) == "<MutationSeverity.MODERATE: 'moderate'>"
        )
        assert (
            repr(MutationSeverity.AGGRESSIVE)
            == "<MutationSeverity.AGGRESSIVE: 'aggressive'>"
        )
        assert repr(MutationSeverity.EXTREME) == "<MutationSeverity.EXTREME: 'extreme'>"

    def test_enum_name_property(self):
        """Test name property of enum members."""
        assert MutationSeverity.MINIMAL.name == "MINIMAL"
        assert MutationSeverity.MODERATE.name == "MODERATE"
        assert MutationSeverity.AGGRESSIVE.name == "AGGRESSIVE"
        assert MutationSeverity.EXTREME.name == "EXTREME"

    def test_enum_value_property(self):
        """Test value property of enum members."""
        assert MutationSeverity.MINIMAL.value == "minimal"
        assert MutationSeverity.MODERATE.value == "moderate"
        assert MutationSeverity.AGGRESSIVE.value == "aggressive"
        assert MutationSeverity.EXTREME.value == "extreme"

    def test_enum_access_by_name(self):
        """Test accessing enum members by name."""
        assert MutationSeverity["MINIMAL"] == MutationSeverity.MINIMAL
        assert MutationSeverity["MODERATE"] == MutationSeverity.MODERATE
        assert MutationSeverity["AGGRESSIVE"] == MutationSeverity.AGGRESSIVE
        assert MutationSeverity["EXTREME"] == MutationSeverity.EXTREME

    def test_enum_access_by_value(self):
        """Test accessing enum members by value."""
        assert MutationSeverity("minimal") == MutationSeverity.MINIMAL
        assert MutationSeverity("moderate") == MutationSeverity.MODERATE
        assert MutationSeverity("aggressive") == MutationSeverity.AGGRESSIVE
        assert MutationSeverity("extreme") == MutationSeverity.EXTREME

    def test_enum_invalid_access_by_name(self):
        """Test that accessing invalid name raises KeyError."""
        with pytest.raises(KeyError):
            _ = MutationSeverity["INVALID"]

    def test_enum_invalid_access_by_value(self):
        """Test that accessing invalid value raises ValueError."""
        with pytest.raises(ValueError):
            _ = MutationSeverity("invalid")

    def test_enum_membership(self):
        """Test membership testing."""
        assert MutationSeverity.MINIMAL in MutationSeverity
        assert MutationSeverity.MODERATE in MutationSeverity
        assert MutationSeverity.AGGRESSIVE in MutationSeverity
        assert MutationSeverity.EXTREME in MutationSeverity

    def test_enum_uniqueness(self):
        """Test that all enum values are unique."""
        values = [severity.value for severity in MutationSeverity]
        assert len(values) == len(set(values))

    def test_enum_immutability(self):
        """Test that enum members are immutable."""
        with pytest.raises(AttributeError):
            MutationSeverity.MINIMAL.value = "changed"

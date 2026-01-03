"""Tests for shared fuzzing constants."""

from __future__ import annotations

from dicom_fuzzer.core.constants import (
    ARITH_MAX,
    INTERESTING_8,
    INTERESTING_8_UNSIGNED,
    INTERESTING_16,
    INTERESTING_16_UNSIGNED,
    INTERESTING_32,
    INTERESTING_32_UNSIGNED,
    MAP_SIZE,
    MAP_SIZE_POW2,
)


class TestCoverageConstants:
    """Tests for coverage tracking constants."""

    def test_map_size_is_power_of_two(self) -> None:
        """Test MAP_SIZE is 2^16 (AFL default)."""
        assert MAP_SIZE == 65536
        assert MAP_SIZE == 2**16

    def test_map_size_pow2_matches(self) -> None:
        """Test MAP_SIZE_POW2 is log2(MAP_SIZE)."""
        assert MAP_SIZE_POW2 == 16
        assert 2**MAP_SIZE_POW2 == MAP_SIZE


class TestArithmeticConstants:
    """Tests for arithmetic mutation constants."""

    def test_arith_max_is_35(self) -> None:
        """Test ARITH_MAX matches AFL default of 35."""
        assert ARITH_MAX == 35
        assert ARITH_MAX > 0


class TestInteresting8:
    """Tests for 8-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_8 contains critical boundaries."""
        assert -128 in INTERESTING_8  # INT8_MIN
        assert 127 in INTERESTING_8  # INT8_MAX
        assert 0 in INTERESTING_8
        assert 1 in INTERESTING_8
        assert -1 in INTERESTING_8  # All bits set

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_8_UNSIGNED)
        assert 0 in INTERESTING_8_UNSIGNED
        assert 255 in INTERESTING_8_UNSIGNED  # UINT8_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_8) == len(set(INTERESTING_8))
        assert len(INTERESTING_8_UNSIGNED) == len(set(INTERESTING_8_UNSIGNED))


class TestInteresting16:
    """Tests for 16-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_16 contains critical boundaries."""
        assert -32768 in INTERESTING_16  # INT16_MIN
        assert 32767 in INTERESTING_16  # INT16_MAX
        assert 65535 in INTERESTING_16  # UINT16_MAX
        assert 0 in INTERESTING_16
        assert -1 in INTERESTING_16

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_16_UNSIGNED)
        assert 65535 in INTERESTING_16_UNSIGNED  # UINT16_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_16) == len(set(INTERESTING_16))
        assert len(INTERESTING_16_UNSIGNED) == len(set(INTERESTING_16_UNSIGNED))


class TestInteresting32:
    """Tests for 32-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_32 contains critical boundaries."""
        assert -2147483648 in INTERESTING_32  # INT32_MIN
        assert 2147483647 in INTERESTING_32  # INT32_MAX
        assert 4294967295 in INTERESTING_32  # UINT32_MAX
        assert 0 in INTERESTING_32
        assert -1 in INTERESTING_32

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_32_UNSIGNED)
        assert 4294967295 in INTERESTING_32_UNSIGNED  # UINT32_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_32) == len(set(INTERESTING_32))
        assert len(INTERESTING_32_UNSIGNED) == len(set(INTERESTING_32_UNSIGNED))


class TestConstantsImportFromCore:
    """Test constants can be imported from dicom_fuzzer.core."""

    def test_import_from_core(self) -> None:
        """Test constants are exported from core package."""
        from dicom_fuzzer.core import (
            ARITH_MAX as ARITH_MAX_CORE,
        )
        from dicom_fuzzer.core import (
            INTERESTING_8 as INTERESTING_8_CORE,
        )
        from dicom_fuzzer.core import (
            MAP_SIZE as MAP_SIZE_CORE,
        )

        assert ARITH_MAX_CORE == ARITH_MAX
        assert INTERESTING_8_CORE == INTERESTING_8
        assert MAP_SIZE_CORE == MAP_SIZE

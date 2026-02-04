"""Tests for encoding_fuzzer.py - Character Set and Text Encoding Mutations."""

import random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.attacks.format.encoding_fuzzer import EncodingFuzzer


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def fuzzer() -> EncodingFuzzer:
    """Create an EncodingFuzzer instance."""
    return EncodingFuzzer()


@pytest.fixture
def sample_dataset() -> Dataset:
    """Create a sample DICOM dataset with text fields."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Test Study"
    ds.SpecificCharacterSet = "ISO_IR 192"  # UTF-8
    return ds


@pytest.fixture
def minimal_dataset() -> Dataset:
    """Create a minimal DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    return ds


# =============================================================================
# EncodingFuzzer Initialization Tests
# =============================================================================
class TestEncodingFuzzerInit:
    """Tests for EncodingFuzzer initialization."""

    def test_mutation_strategies_defined(self, fuzzer: EncodingFuzzer) -> None:
        """Test that mutation_strategies list is defined."""
        assert hasattr(fuzzer, "mutation_strategies")
        assert isinstance(fuzzer.mutation_strategies, list)
        assert len(fuzzer.mutation_strategies) == 10

    def test_all_strategies_callable(self, fuzzer: EncodingFuzzer) -> None:
        """Test that all strategies are callable methods."""
        for strategy in fuzzer.mutation_strategies:
            assert callable(strategy)


# =============================================================================
# mutate_encoding Tests
# =============================================================================
class TestMutateEncoding:
    """Tests for mutate_encoding method."""

    def test_returns_dataset(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test that mutate_encoding returns a Dataset."""
        result = fuzzer.mutate_encoding(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_handles_empty_dataset(self, fuzzer: EncodingFuzzer) -> None:
        """Test handling of empty dataset."""
        ds = Dataset()
        result = fuzzer.mutate_encoding(ds)
        assert result is not None
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_charset_value Tests
# =============================================================================
class TestInvalidCharsetValue:
    """Tests for _invalid_charset_value method."""

    def test_unknown_charset(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test unknown charset attack."""
        with patch.object(random, "choice", side_effect=["unknown_charset", "INVALID_CHARSET"]):
            result = fuzzer._invalid_charset_value(sample_dataset)
        assert isinstance(result, Dataset)

    def test_malformed_charset(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test malformed charset attack."""
        with patch.object(random, "choice", return_value="malformed_charset"):
            result = fuzzer._invalid_charset_value(sample_dataset)
        assert isinstance(result, Dataset)
        assert "\x00" in result.SpecificCharacterSet

    def test_empty_charset_with_unicode(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test empty charset with unicode attack."""
        with patch.object(random, "choice", return_value="empty_charset_with_unicode"):
            result = fuzzer._invalid_charset_value(sample_dataset)
        assert isinstance(result, Dataset)

    def test_conflicting_charsets(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test conflicting charsets attack."""
        with patch.object(random, "choice", return_value="conflicting_charsets"):
            result = fuzzer._invalid_charset_value(sample_dataset)
        assert isinstance(result, Dataset)
        # pydicom returns MultiValue, not list, but should have multiple items
        charset = result.SpecificCharacterSet
        assert len(charset) == 3


# =============================================================================
# _charset_data_mismatch Tests
# =============================================================================
class TestCharsetDataMismatch:
    """Tests for _charset_data_mismatch method."""

    def test_latin1_declared_utf8_data(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test Latin-1 declared but UTF-8 data."""
        with patch.object(random, "choice", return_value="latin1_declared_utf8_data"):
            result = fuzzer._charset_data_mismatch(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.SpecificCharacterSet == "ISO_IR 100"

    def test_utf8_declared_latin1_data(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test UTF-8 declared but Latin-1 data."""
        with patch.object(random, "choice", return_value="utf8_declared_latin1_data"):
            result = fuzzer._charset_data_mismatch(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_ascii_declared_multibyte(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test ASCII declared but multibyte data."""
        with patch.object(random, "choice", return_value="ascii_declared_multibyte"):
            result = fuzzer._charset_data_mismatch(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _invalid_utf8_sequences Tests
# =============================================================================
class TestInvalidUtf8Sequences:
    """Tests for _invalid_utf8_sequences method."""

    def test_injects_invalid_utf8(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test injection of invalid UTF-8 sequences."""
        result = fuzzer._invalid_utf8_sequences(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"


# =============================================================================
# _escape_sequence_injection Tests
# =============================================================================
class TestEscapeSequenceInjection:
    """Tests for _escape_sequence_injection method."""

    def test_injects_escape_sequences(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test injection of ISO 2022 escape sequences."""
        result = fuzzer._escape_sequence_injection(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.SpecificCharacterSet == "ISO 2022 IR 87"


# =============================================================================
# _bom_injection Tests
# =============================================================================
class TestBomInjection:
    """Tests for _bom_injection method."""

    def test_bom_at_start(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test BOM at start of value."""
        with patch.object(random, "choice", side_effect=[b"\xEF\xBB\xBF", "bom_at_start"]):
            result = fuzzer._bom_injection(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_bom_in_middle(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test BOM in middle of value."""
        with patch.object(random, "choice", side_effect=[b"\xEF\xBB\xBF", "bom_in_middle"]):
            result = fuzzer._bom_injection(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_multiple_boms(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test multiple BOMs in value."""
        with patch.object(random, "choice", side_effect=[b"\xEF\xBB\xBF", "multiple_boms"]):
            result = fuzzer._bom_injection(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _null_byte_injection Tests
# =============================================================================
class TestNullByteInjection:
    """Tests for _null_byte_injection method."""

    def test_null_in_middle(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test null byte in middle of value."""
        with patch.object(random, "choice", return_value="null_in_middle"):
            result = fuzzer._null_byte_injection(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_null_at_end(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test null byte at end of value."""
        with patch.object(random, "choice", return_value="null_at_end"):
            result = fuzzer._null_byte_injection(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_multiple_nulls(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test multiple null bytes."""
        with patch.object(random, "choice", return_value="multiple_nulls"):
            result = fuzzer._null_byte_injection(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _control_character_injection Tests
# =============================================================================
class TestControlCharacterInjection:
    """Tests for _control_character_injection method."""

    def test_single_control(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test single control character."""
        with patch.object(random, "choice", side_effect=["single_control", "\x07"]):
            result = fuzzer._control_character_injection(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_control_sequence(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test control sequence (ANSI escape)."""
        with patch.object(random, "choice", return_value="control_sequence"):
            result = fuzzer._control_character_injection(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _overlong_utf8 Tests
# =============================================================================
class TestOverlongUtf8:
    """Tests for _overlong_utf8 method."""

    def test_injects_overlong_encoding(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test injection of overlong UTF-8 encoding."""
        result = fuzzer._overlong_utf8(minimal_dataset)
        assert isinstance(result, Dataset)
        assert result.SpecificCharacterSet == "ISO_IR 192"


# =============================================================================
# _mixed_encoding_attack Tests
# =============================================================================
class TestMixedEncodingAttack:
    """Tests for _mixed_encoding_attack method."""

    def test_mixes_encodings(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test mixing multiple encodings."""
        result = fuzzer._mixed_encoding_attack(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# _surrogate_pair_attack Tests
# =============================================================================
class TestSurrogatePairAttack:
    """Tests for _surrogate_pair_attack method."""

    def test_lone_high_surrogate(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test lone high surrogate."""
        with patch.object(random, "choice", return_value="lone_high_surrogate"):
            result = fuzzer._surrogate_pair_attack(minimal_dataset)
        assert isinstance(result, Dataset)

    def test_lone_low_surrogate(
        self, fuzzer: EncodingFuzzer, minimal_dataset: Dataset
    ) -> None:
        """Test lone low surrogate."""
        with patch.object(random, "choice", return_value="lone_low_surrogate"):
            result = fuzzer._surrogate_pair_attack(minimal_dataset)
        assert isinstance(result, Dataset)


# =============================================================================
# Integration Tests
# =============================================================================
class TestEncodingFuzzerIntegration:
    """Integration tests for EncodingFuzzer."""

    def test_full_mutation_cycle(
        self, fuzzer: EncodingFuzzer, sample_dataset: Dataset
    ) -> None:
        """Test a full mutation cycle produces valid output."""
        random.seed(42)
        result = fuzzer.mutate_encoding(sample_dataset)
        assert result is not None
        assert isinstance(result, Dataset)

    def test_multiple_mutations(
        self, fuzzer: EncodingFuzzer
    ) -> None:
        """Test multiple mutations in sequence."""
        for i in range(5):
            random.seed(i)
            ds = Dataset()
            ds.PatientName = "Test"
            result = fuzzer.mutate_encoding(ds)
            assert isinstance(result, Dataset)

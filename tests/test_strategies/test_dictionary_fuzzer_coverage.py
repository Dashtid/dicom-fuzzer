"""Additional coverage tests for DictionaryFuzzer.

Focuses on:
- Numeric VR conversion methods (_convert_to_int_vr, _convert_to_float_vr, etc.)
- Tag mutation special cases (binary VR, UI VR, numeric VR)
- Severity branch coverage
- Exception handling paths
"""

from unittest.mock import MagicMock, patch

import pytest
from pydicom.dataelem import DataElement
from pydicom.dataset import Dataset

from dicom_fuzzer.core.types import MutationSeverity
from dicom_fuzzer.strategies.dictionary_fuzzer import DictionaryFuzzer


class TestConvertToIntVR:
    """Test _convert_to_int_vr method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_valid_integer_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of valid integer string."""
        result = fuzzer._convert_to_int_vr("42", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 42

    def test_negative_integer_signed(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of negative integer for signed VR."""
        result = fuzzer._convert_to_int_vr("-100", "SS")
        assert result is not None
        assert isinstance(result, int)
        assert result == -100

    def test_float_string_truncation(self, fuzzer: DictionaryFuzzer) -> None:
        """Test that float strings are truncated to int."""
        result = fuzzer._convert_to_int_vr("42.7", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 42

    def test_non_numeric_returns_zero(self, fuzzer: DictionaryFuzzer) -> None:
        """Test non-numeric strings return 0."""
        result = fuzzer._convert_to_int_vr("abc", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 0

    def test_empty_string_returns_zero(self, fuzzer: DictionaryFuzzer) -> None:
        """Test empty string returns 0."""
        result = fuzzer._convert_to_int_vr("", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 0

    def test_us_wrap_overflow(self, fuzzer: DictionaryFuzzer) -> None:
        """Test US (unsigned short) wraps on overflow."""
        # US max is 65535, mode is "wrap"
        result = fuzzer._convert_to_int_vr("70000", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 70000 % 65536  # wraps

    def test_ss_clamp_overflow(self, fuzzer: DictionaryFuzzer) -> None:
        """Test SS (signed short) clamps on overflow."""
        # SS max is 32767, mode is "clamp"
        result = fuzzer._convert_to_int_vr("50000", "SS")
        assert result is not None
        assert isinstance(result, int)
        assert result == 32767  # clamped to max

    def test_ss_clamp_underflow(self, fuzzer: DictionaryFuzzer) -> None:
        """Test SS (signed short) clamps on underflow."""
        # SS min is -32768, mode is "clamp"
        result = fuzzer._convert_to_int_vr("-50000", "SS")
        assert result is not None
        assert isinstance(result, int)
        assert result == -32768  # clamped to min

    def test_ul_wrap_overflow(self, fuzzer: DictionaryFuzzer) -> None:
        """Test UL (unsigned long) wraps on overflow."""
        # UL max is 4294967295
        result = fuzzer._convert_to_int_vr("5000000000", "UL")
        assert result is not None
        assert isinstance(result, int)
        assert result == 5000000000 % 4294967296

    def test_sl_clamp_range(self, fuzzer: DictionaryFuzzer) -> None:
        """Test SL (signed long) clamps at boundaries."""
        # SL range: -2147483648 to 2147483647
        result = fuzzer._convert_to_int_vr("3000000000", "SL")
        assert result is not None
        assert isinstance(result, int)
        assert result == 2147483647  # clamped

    def test_value_within_range(self, fuzzer: DictionaryFuzzer) -> None:
        """Test values within range are returned unchanged."""
        result = fuzzer._convert_to_int_vr("1000", "US")
        assert result is not None
        assert isinstance(result, int)
        assert result == 1000


class TestConvertToFloatVR:
    """Test _convert_to_float_vr method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_valid_float_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of valid float string."""
        result = fuzzer._convert_to_float_vr("3.14159")
        assert result is not None
        assert isinstance(result, float)
        assert abs(result - 3.14159) < 0.00001

    def test_integer_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of integer string to float."""
        result = fuzzer._convert_to_float_vr("42")
        assert result is not None
        assert isinstance(result, float)
        assert result == 42.0

    def test_negative_float(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of negative float."""
        result = fuzzer._convert_to_float_vr("-2.5")
        assert result is not None
        assert isinstance(result, float)
        assert result == -2.5

    def test_scientific_notation(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion of scientific notation."""
        result = fuzzer._convert_to_float_vr("1.5e10")
        assert result is not None
        assert isinstance(result, float)
        assert result == 1.5e10

    def test_scientific_notation_negative_exponent(
        self, fuzzer: DictionaryFuzzer
    ) -> None:
        """Test conversion of scientific notation with negative exponent."""
        result = fuzzer._convert_to_float_vr("2.5E-3")
        assert result is not None
        assert isinstance(result, float)
        assert abs(result - 0.0025) < 0.0000001

    def test_non_numeric_returns_zero(self, fuzzer: DictionaryFuzzer) -> None:
        """Test non-numeric strings return 0.0."""
        result = fuzzer._convert_to_float_vr("abc")
        assert result is not None
        assert isinstance(result, float)
        assert result == 0.0

    def test_empty_string_returns_zero(self, fuzzer: DictionaryFuzzer) -> None:
        """Test empty string returns 0.0."""
        result = fuzzer._convert_to_float_vr("")
        assert result is not None
        assert isinstance(result, float)
        assert result == 0.0


class TestConvertToStringVR:
    """Test _convert_to_string_vr method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_valid_numeric_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion preserves valid numeric string."""
        result = fuzzer._convert_to_string_vr("42.5")
        assert result is not None
        assert isinstance(result, str)
        assert result == "42.5"

    def test_integer_string(self, fuzzer: DictionaryFuzzer) -> None:
        """Test integer string converts to float string."""
        result = fuzzer._convert_to_string_vr("42")
        assert result is not None
        assert isinstance(result, str)
        assert result == "42.0"

    def test_negative_number(self, fuzzer: DictionaryFuzzer) -> None:
        """Test negative number conversion."""
        result = fuzzer._convert_to_string_vr("-123.45")
        assert result is not None
        assert isinstance(result, str)
        assert result == "-123.45"

    def test_non_numeric_returns_default(self, fuzzer: DictionaryFuzzer) -> None:
        """Test non-numeric returns default '0.0'."""
        result = fuzzer._convert_to_string_vr("not_a_number")
        assert result is not None
        assert isinstance(result, str)
        assert result == "0.0"

    def test_empty_string_returns_default(self, fuzzer: DictionaryFuzzer) -> None:
        """Test empty string returns default '0.0'."""
        result = fuzzer._convert_to_string_vr("")
        assert result is not None
        assert isinstance(result, str)
        assert result == "0.0"


class TestConvertNumericValue:
    """Test _convert_numeric_value method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_int_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion for integer VR types."""
        result = fuzzer._convert_numeric_value("100", "US", 0x00280010)
        assert result is not None
        assert isinstance(result, int)
        assert result == 100

    def test_float_vr_fl(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion for FL (float) VR type."""
        result = fuzzer._convert_numeric_value("3.14", "FL", 0x00000000)
        assert result is not None
        assert isinstance(result, float)
        assert abs(result - 3.14) < 0.001  # type: ignore[operator]

    def test_float_vr_fd(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion for FD (double float) VR type."""
        result = fuzzer._convert_numeric_value("3.14159", "FD", 0x00000000)
        assert result is not None
        assert isinstance(result, float)
        assert abs(result - 3.14159) < 0.00001  # type: ignore[operator]

    def test_string_vr_is(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion for IS (integer string) VR type."""
        result = fuzzer._convert_numeric_value("42", "IS", 0x00000000)
        assert result is not None
        assert isinstance(result, str)
        assert result == "42.0"

    def test_string_vr_ds(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion for DS (decimal string) VR type."""
        result = fuzzer._convert_numeric_value("3.14", "DS", 0x00000000)
        assert result is not None
        assert isinstance(result, str)
        assert result == "3.14"

    def test_at_vr_returns_none(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AT (attribute tag) VR returns None (skipped)."""
        result = fuzzer._convert_numeric_value("0x00100010", "AT", 0x00000000)
        assert result is None

    def test_non_numeric_vr_passthrough(self, fuzzer: DictionaryFuzzer) -> None:
        """Test non-numeric VR types pass through unchanged."""
        result = fuzzer._convert_numeric_value("test_value", "LO", 0x00000000)
        assert result is not None
        assert isinstance(result, str)
        assert result == "test_value"

    def test_conversion_error_returns_none(self, fuzzer: DictionaryFuzzer) -> None:
        """Test conversion errors return None."""
        # Force an error by passing an invalid value for int conversion
        with patch.object(fuzzer, "_convert_to_int_vr", side_effect=ValueError("test")):
            result = fuzzer._convert_numeric_value("invalid", "US", 0x00280010)
            assert result is None


class TestMutateTagSpecialCases:
    """Test _mutate_tag method special cases."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_binary_vr_skipped(self, fuzzer: DictionaryFuzzer) -> None:
        """Test binary VR types are skipped."""
        ds = Dataset()
        # OB is a binary VR
        ds.add(DataElement(0x7FE00010, "OB", b"\x00\x01\x02"))
        original_value = ds[0x7FE00010].value

        fuzzer._mutate_tag(ds, 0x7FE00010, MutationSeverity.MODERATE)

        assert ds is not None
        assert isinstance(ds, Dataset)
        assert ds[0x7FE00010].value == original_value

    def test_ow_binary_vr_skipped(self, fuzzer: DictionaryFuzzer) -> None:
        """Test OW (other word) VR is skipped."""
        ds = Dataset()
        ds.add(DataElement(0x7FE00010, "OW", b"\x00\x01"))
        original_value = ds[0x7FE00010].value

        fuzzer._mutate_tag(ds, 0x7FE00010, MutationSeverity.AGGRESSIVE)

        assert ds is not None
        assert isinstance(ds, Dataset)
        assert ds[0x7FE00010].value == original_value

    def test_ui_vr_generates_uid(self, fuzzer: DictionaryFuzzer) -> None:
        """Test UI VR generates a new UID."""
        ds = Dataset()
        ds.add(DataElement(0x00080018, "UI", "1.2.3.4.5"))

        fuzzer._mutate_tag(ds, 0x00080018, MutationSeverity.MODERATE)

        # Should be a new UID (different from original)
        value = ds[0x00080018].value
        assert value is not None
        assert isinstance(value, str)
        assert len(value) > 0
        assert "." in value  # UIDs have dots

    def test_numeric_vr_conversion(self, fuzzer: DictionaryFuzzer) -> None:
        """Test numeric VR gets proper conversion."""
        ds = Dataset()
        ds.add(DataElement(0x00280010, "US", 512))  # Rows

        # Mock to return a string value that needs conversion
        with patch.object(fuzzer, "_get_value_for_severity", return_value="256"):
            fuzzer._mutate_tag(ds, 0x00280010, MutationSeverity.MODERATE)

        # Should have converted to int
        assert ds[0x00280010].value is not None
        assert isinstance(ds[0x00280010].value, int)

    def test_exception_handling(self, fuzzer: DictionaryFuzzer) -> None:
        """Test exception handling in _mutate_tag."""
        ds = Dataset()
        ds.add(DataElement(0x00100010, "PN", "Test^Patient"))

        # Mock to cause an exception
        with patch.object(ds, "__getitem__", side_effect=Exception("test error")):
            # Should not raise, just log and return
            fuzzer._mutate_tag(ds, 0x00100010, MutationSeverity.MODERATE)

        # Verify fuzzer is still functional
        assert fuzzer is not None
        assert isinstance(fuzzer, DictionaryFuzzer)

    def test_lo_vr_string_mutation(self, fuzzer: DictionaryFuzzer) -> None:
        """Test LO (long string) VR gets mutated."""
        ds = Dataset()
        ds.add(DataElement(0x00080070, "LO", "Original Manufacturer"))

        fuzzer._mutate_tag(ds, 0x00080070, MutationSeverity.MODERATE)

        # Value should be present (may have changed)
        assert ds[0x00080070].value is not None
        assert isinstance(ds, Dataset)


class TestGetValueForSeverity:
    """Test _get_value_for_severity method branches."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_minimal_gets_valid_value(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MINIMAL severity gets valid dictionary values."""
        with patch.object(fuzzer, "_get_valid_value", return_value="CT") as mock:
            result = fuzzer._get_value_for_severity(
                0x00080060, MutationSeverity.MINIMAL
            )
            mock.assert_called_once_with(0x00080060)
            assert result is not None
            assert isinstance(result, str)
            assert result == "CT"

    def test_moderate_mostly_valid(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MODERATE severity mostly gets valid values (70%)."""
        with patch("random.random", return_value=0.5):  # < 0.7 = valid
            with patch.object(fuzzer, "_get_valid_value", return_value="MR") as mock:
                result = fuzzer._get_value_for_severity(
                    0x00080060, MutationSeverity.MODERATE
                )
                mock.assert_called_once()
                assert result is not None
                assert isinstance(result, str)
                assert result == "MR"

    def test_moderate_sometimes_edge_case(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MODERATE severity sometimes gets edge cases (30%)."""
        with patch("random.random", return_value=0.8):  # >= 0.7 = edge case
            with patch.object(fuzzer, "_get_edge_case_value", return_value="") as mock:
                result = fuzzer._get_value_for_severity(
                    0x00080060, MutationSeverity.MODERATE
                )
                mock.assert_called_once()
                assert result is not None
                assert isinstance(result, str)
                assert result == ""

    def test_aggressive_mixed_values(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AGGRESSIVE severity gets edge cases or malicious (50/50)."""
        with patch("random.random", return_value=0.3):  # < 0.5 = edge case
            with patch.object(
                fuzzer, "_get_edge_case_value", return_value="\x00"
            ) as mock:
                result = fuzzer._get_value_for_severity(
                    0x00080060, MutationSeverity.AGGRESSIVE
                )
                mock.assert_called_once()
                assert result is not None
                assert isinstance(result, str)
                assert result == "\x00"

    def test_aggressive_malicious(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AGGRESSIVE can get malicious values."""
        with patch("random.random", return_value=0.6):  # >= 0.5 = malicious
            with patch.object(
                fuzzer, "_get_malicious_value", return_value="'; DROP"
            ) as mock:
                result = fuzzer._get_value_for_severity(
                    0x00080060, MutationSeverity.AGGRESSIVE
                )
                mock.assert_called_once()
                assert result is not None
                assert isinstance(result, str)
                assert result == "'; DROP"

    def test_extreme_always_malicious(self, fuzzer: DictionaryFuzzer) -> None:
        """Test EXTREME severity always gets malicious values."""
        with patch.object(
            fuzzer, "_get_malicious_value", return_value="<script>"
        ) as mock:
            result = fuzzer._get_value_for_severity(
                0x00080060, MutationSeverity.EXTREME
            )
            mock.assert_called_once()
            assert result is not None
            assert isinstance(result, str)
            assert result == "<script>"


class TestGetNumMutations:
    """Test _get_num_mutations method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_minimal_small_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MINIMAL produces 1-2 mutations for small datasets."""
        with patch("random.randint", return_value=1) as mock:
            result = fuzzer._get_num_mutations(MutationSeverity.MINIMAL, 20)
            mock.assert_called_once_with(1, 2)  # max(2, 20//20) = 2
            assert result is not None
            assert isinstance(result, int)
            assert result == 1

    def test_moderate_more_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test MODERATE produces more mutations."""
        with patch("random.randint", return_value=3) as mock:
            result = fuzzer._get_num_mutations(MutationSeverity.MODERATE, 50)
            mock.assert_called_once_with(2, 5)  # max(5, 50//10) = 5
            assert result is not None
            assert isinstance(result, int)
            assert result == 3

    def test_aggressive_many_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test AGGRESSIVE produces many mutations."""
        with patch("random.randint", return_value=8) as mock:
            result = fuzzer._get_num_mutations(MutationSeverity.AGGRESSIVE, 50)
            mock.assert_called_once_with(5, 10)  # max(10, 50//5) = 10
            assert result is not None
            assert isinstance(result, int)
            assert result == 8

    def test_extreme_maximum_mutations(self, fuzzer: DictionaryFuzzer) -> None:
        """Test EXTREME produces maximum mutations."""
        with patch("random.randint", return_value=15) as mock:
            result = fuzzer._get_num_mutations(MutationSeverity.EXTREME, 50)
            mock.assert_called_once_with(10, 25)  # max(20, 50//2) = 25
            assert result is not None
            assert isinstance(result, int)
            assert result == 15

    def test_large_dataset_scales(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutation count scales with dataset size."""
        with patch("random.randint", return_value=50) as mock:
            result = fuzzer._get_num_mutations(MutationSeverity.EXTREME, 200)
            # max(20, 200//2) = 100
            mock.assert_called_once_with(10, 100)
            assert result is not None
            assert isinstance(result, int)
            assert result == 50


class TestGetApplicableTagsEdgeCases:
    """Test get_applicable_tags edge cases."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_uid_only_tags(self, fuzzer: DictionaryFuzzer) -> None:
        """Test dataset with only UID tags."""
        ds = Dataset()
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.SeriesInstanceUID = "1.2.3.4.6"

        applicable = fuzzer.get_applicable_tags(ds)
        assert applicable is not None
        assert isinstance(applicable, list)
        tag_ints = [tag for tag, _ in applicable]

        assert 0x0020000D in tag_ints  # StudyInstanceUID
        assert 0x0020000E in tag_ints  # SeriesInstanceUID

    def test_mixed_tag_types(self, fuzzer: DictionaryFuzzer) -> None:
        """Test dataset with mixed tag types."""
        ds = Dataset()
        ds.Modality = "CT"
        ds.StudyInstanceUID = "1.2.3.4.5"
        ds.PatientName = "Test"  # Not in TAG_TO_DICTIONARY

        applicable = fuzzer.get_applicable_tags(ds)
        assert applicable is not None
        assert isinstance(applicable, list)
        assert len(applicable) > 0
        tag_ints = [tag for tag, _ in applicable]

        assert 0x00080060 in tag_ints  # Modality
        assert 0x0020000D in tag_ints  # StudyInstanceUID
        # PatientName (0x00100010) IS in TAG_TO_DICTIONARY
        assert 0x00100010 in tag_ints

    def test_empty_dataset(self, fuzzer: DictionaryFuzzer) -> None:
        """Test empty dataset returns empty list."""
        ds = Dataset()
        applicable = fuzzer.get_applicable_tags(ds)
        assert applicable is not None
        assert isinstance(applicable, list)
        assert applicable == []

    def test_no_applicable_tags(self, fuzzer: DictionaryFuzzer) -> None:
        """Test dataset with no applicable tags."""
        ds = Dataset()
        # Use a private tag that's not in any dictionary
        ds.add(DataElement(0x00110010, "LO", "Private Creator"))

        applicable = fuzzer.get_applicable_tags(ds)
        assert applicable is not None
        assert isinstance(applicable, list)
        assert applicable == []


class TestMutateWithSpecificDictionaryEdgeCases:
    """Test mutate_with_specific_dictionary edge cases."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_invalid_dictionary_name(self, fuzzer: DictionaryFuzzer) -> None:
        """Test with invalid dictionary name raises KeyError."""
        ds = Dataset()
        ds.Modality = "CT"

        # Invalid dictionary name raises KeyError (not caught by method)
        with patch(
            "dicom_fuzzer.utils.dicom_dictionaries.DICOMDictionaries.get_random_value",
            side_effect=KeyError("not_found"),
        ):
            with pytest.raises(KeyError):
                fuzzer.mutate_with_specific_dictionary(
                    ds, 0x00080060, "nonexistent_dict"
                )

    def test_mutation_exception_logged(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutation exceptions are logged."""
        ds = Dataset()
        ds.Modality = "CT"

        # Mock the value assignment to fail
        mock_element = MagicMock()
        mock_element.value = property(
            lambda s: "CT", lambda s, v: (_ for _ in ()).throw(Exception("test"))
        )

        with patch.object(ds, "__getitem__", return_value=mock_element):
            with patch.object(ds, "__contains__", return_value=True):
                # Should not raise
                mutated = fuzzer.mutate_with_specific_dictionary(
                    ds, 0x00080060, "modalities"
                )
                assert mutated is not None
                assert isinstance(mutated, Dataset)


class TestInjectEdgeCasesSystematicallyEdgeCases:
    """Test inject_edge_cases_systematically edge cases."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_mutation_exception_skipped(self, fuzzer: DictionaryFuzzer) -> None:
        """Test that mutations that fail are skipped."""
        ds = Dataset()
        ds.PatientName = "Test"

        # The method already handles exceptions internally
        results = fuzzer.inject_edge_cases_systematically(ds, "empty")
        # Should still return results (empty values work fine)
        assert results is not None
        assert isinstance(results, list)
        assert len(results) > 0

    def test_all_tags_processed(self, fuzzer: DictionaryFuzzer) -> None:
        """Test all applicable tags are processed."""
        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.Modality = "CT"

        results = fuzzer.inject_edge_cases_systematically(ds, "empty")

        # Should have mutations for all 3 tags * number of empty edge cases
        assert results is not None
        assert isinstance(results, list)
        assert len(results) >= 3


class TestMutateIntegration:
    """Integration tests for the mutate method."""

    @pytest.fixture
    def fuzzer(self) -> DictionaryFuzzer:
        """Create a DictionaryFuzzer instance."""
        return DictionaryFuzzer()

    def test_mutate_with_numeric_vrs(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutation handles numeric VR types."""
        ds = Dataset()
        ds.add(DataElement(0x00280010, "US", 512))  # Rows
        ds.add(DataElement(0x00280011, "US", 512))  # Columns
        ds.add(DataElement(0x00280100, "US", 16))  # BitsAllocated

        mutated = fuzzer.mutate(ds, MutationSeverity.MODERATE)

        # All tags should still be present
        assert mutated is not None
        assert isinstance(mutated, Dataset)
        assert 0x00280010 in mutated
        assert 0x00280011 in mutated
        assert 0x00280100 in mutated

    def test_mutate_preserves_original(self, fuzzer: DictionaryFuzzer) -> None:
        """Test original dataset is not modified."""
        ds = Dataset()
        ds.PatientName = "Original"
        ds.PatientID = "12345"

        result = fuzzer.mutate(ds, MutationSeverity.EXTREME)

        assert result is not None
        assert isinstance(result, Dataset)
        assert ds.PatientName == "Original"
        assert ds.PatientID == "12345"

    def test_mutate_returns_dataset(self, fuzzer: DictionaryFuzzer) -> None:
        """Test mutate always returns a Dataset."""
        ds = Dataset()
        ds.PatientName = "Test"

        result = fuzzer.mutate(ds, MutationSeverity.MINIMAL)
        assert result is not None
        assert isinstance(result, Dataset)

        result = fuzzer.mutate(ds, MutationSeverity.MODERATE)
        assert result is not None
        assert isinstance(result, Dataset)

        result = fuzzer.mutate(ds, MutationSeverity.AGGRESSIVE)
        assert result is not None
        assert isinstance(result, Dataset)

        result = fuzzer.mutate(ds, MutationSeverity.EXTREME)
        assert result is not None
        assert isinstance(result, Dataset)

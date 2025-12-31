"""Tests for dicom_fuzzer.utils.dicom_dictionaries module.

Tests DICOM-specific value dictionaries for intelligent fuzzing.
"""

from dicom_fuzzer.utils.dicom_dictionaries import (
    INSTITUTION_NAMES,
    MODALITY_CODES,
    PATIENT_SEX_CODES,
    SAMPLE_DATES,
    SAMPLE_TIMES,
    SOP_CLASS_UIDS,
    TRANSFER_SYNTAXES,
    DICOMDictionaries,
)


class TestTransferSyntaxes:
    """Tests for TRANSFER_SYNTAXES list."""

    def test_is_non_empty_list(self):
        """Verify is a non-empty list."""
        assert isinstance(TRANSFER_SYNTAXES, list)
        assert len(TRANSFER_SYNTAXES) > 0

    def test_all_strings(self):
        """Verify all entries are strings."""
        for ts in TRANSFER_SYNTAXES:
            assert isinstance(ts, str)

    def test_contains_standard_syntaxes(self):
        """Verify contains common DICOM transfer syntaxes."""
        # Implicit VR Little Endian (default)
        assert "1.2.840.10008.1.2" in TRANSFER_SYNTAXES
        # Explicit VR Little Endian
        assert "1.2.840.10008.1.2.1" in TRANSFER_SYNTAXES

    def test_uid_format(self):
        """Verify UIDs have valid format (numbers and dots)."""
        for ts in TRANSFER_SYNTAXES:
            assert all(c.isdigit() or c == "." for c in ts)


class TestSopClassUids:
    """Tests for SOP_CLASS_UIDS list."""

    def test_is_non_empty_list(self):
        """Verify is a non-empty list."""
        assert isinstance(SOP_CLASS_UIDS, list)
        assert len(SOP_CLASS_UIDS) > 0

    def test_contains_common_sop_classes(self):
        """Verify contains common SOP classes."""
        # CT Image Storage
        assert "1.2.840.10008.5.1.4.1.1.2" in SOP_CLASS_UIDS
        # MR Image Storage
        assert "1.2.840.10008.5.1.4.1.1.4" in SOP_CLASS_UIDS


class TestModalityCodes:
    """Tests for MODALITY_CODES list."""

    def test_is_non_empty_list(self):
        """Verify is a non-empty list."""
        assert isinstance(MODALITY_CODES, list)
        assert len(MODALITY_CODES) > 0

    def test_contains_standard_modalities(self):
        """Verify contains standard DICOM modalities."""
        standard_modalities = ["CT", "MR", "US", "CR", "DX"]
        for modality in standard_modalities:
            assert modality in MODALITY_CODES

    def test_contains_edge_cases(self):
        """Verify contains edge cases for fuzzing."""
        # Empty string
        assert "" in MODALITY_CODES
        # Invalid modality
        assert "XX" in MODALITY_CODES


class TestPatientSexCodes:
    """Tests for PATIENT_SEX_CODES list."""

    def test_contains_valid_codes(self):
        """Verify contains valid DICOM sex codes."""
        assert "M" in PATIENT_SEX_CODES
        assert "F" in PATIENT_SEX_CODES
        assert "O" in PATIENT_SEX_CODES

    def test_contains_edge_cases(self):
        """Verify contains edge cases."""
        assert "" in PATIENT_SEX_CODES
        assert "X" in PATIENT_SEX_CODES


class TestInstitutionNames:
    """Tests for INSTITUTION_NAMES list."""

    def test_is_non_empty_list(self):
        """Verify is a non-empty list."""
        assert isinstance(INSTITUTION_NAMES, list)
        assert len(INSTITUTION_NAMES) > 0

    def test_contains_realistic_names(self):
        """Verify contains realistic hospital names."""
        assert "Massachusetts General Hospital" in INSTITUTION_NAMES
        assert "Mayo Clinic" in INSTITUTION_NAMES

    def test_contains_injection_attempts(self):
        """Verify contains security test values."""
        injection_found = any("DROP TABLE" in name for name in INSTITUTION_NAMES)
        assert injection_found, "Should contain SQL injection test values"

        xss_found = any("<script>" in name for name in INSTITUTION_NAMES)
        assert xss_found, "Should contain XSS test values"


class TestSampleDates:
    """Tests for SAMPLE_DATES list."""

    def test_contains_valid_dates(self):
        """Verify contains valid DICOM date format."""
        assert "20240101" in SAMPLE_DATES
        assert "20231231" in SAMPLE_DATES

    def test_contains_edge_cases(self):
        """Verify contains date edge cases."""
        assert "00000000" in SAMPLE_DATES  # All zeros
        assert "20240230" in SAMPLE_DATES  # Invalid Feb 30
        assert "" in SAMPLE_DATES  # Empty


class TestSampleTimes:
    """Tests for SAMPLE_TIMES list."""

    def test_contains_valid_times(self):
        """Verify contains valid DICOM time format."""
        assert "120000" in SAMPLE_TIMES  # Noon
        assert "000000" in SAMPLE_TIMES  # Midnight

    def test_contains_edge_cases(self):
        """Verify contains time edge cases."""
        assert "240000" in SAMPLE_TIMES  # Invalid hour
        assert "" in SAMPLE_TIMES  # Empty


class TestDICOMDictionariesClass:
    """Tests for DICOMDictionaries class."""

    def test_all_dictionaries_is_dict(self):
        """Verify ALL_DICTIONARIES is a dictionary."""
        assert isinstance(DICOMDictionaries.ALL_DICTIONARIES, dict)

    def test_all_dictionaries_has_expected_keys(self):
        """Verify all expected dictionary names are present."""
        expected_keys = {
            "transfer_syntaxes",
            "sop_class_uids",
            "modalities",
            "patient_sex",
            "institutions",
            "manufacturers",
            "photometric_interpretations",
            "dates",
            "times",
            "patient_names",
            "study_descriptions",
            "accession_numbers",
            "patient_ids",
            "pixel_spacings",
            "window_centers",
            "window_widths",
            "character_sets",
            "uid_roots",
        }
        assert set(DICOMDictionaries.ALL_DICTIONARIES.keys()) == expected_keys


class TestGetDictionary:
    """Tests for DICOMDictionaries.get_dictionary method."""

    def test_returns_correct_dictionary(self):
        """Verify returns the correct dictionary by name."""
        result = DICOMDictionaries.get_dictionary("modalities")
        assert result == MODALITY_CODES

    def test_returns_empty_for_unknown(self):
        """Verify returns empty list for unknown dictionary name."""
        result = DICOMDictionaries.get_dictionary("nonexistent")
        assert result == []

    def test_all_dictionaries_accessible(self):
        """Verify all dictionaries can be accessed by name."""
        for name in DICOMDictionaries.get_all_dictionary_names():
            result = DICOMDictionaries.get_dictionary(name)
            assert isinstance(result, list)
            assert len(result) > 0


class TestGetAllDictionaryNames:
    """Tests for DICOMDictionaries.get_all_dictionary_names method."""

    def test_returns_list(self):
        """Verify returns a list."""
        result = DICOMDictionaries.get_all_dictionary_names()
        assert isinstance(result, list)

    def test_returns_all_keys(self):
        """Verify returns all dictionary keys."""
        result = DICOMDictionaries.get_all_dictionary_names()
        assert set(result) == set(DICOMDictionaries.ALL_DICTIONARIES.keys())

    def test_names_are_strings(self):
        """Verify all names are strings."""
        for name in DICOMDictionaries.get_all_dictionary_names():
            assert isinstance(name, str)


class TestGetRandomValue:
    """Tests for DICOMDictionaries.get_random_value method."""

    def test_returns_string(self):
        """Verify returns a string."""
        result = DICOMDictionaries.get_random_value("modalities")
        assert isinstance(result, str)

    def test_returns_value_from_dictionary(self):
        """Verify returns a value from the specified dictionary."""
        for _ in range(10):  # Test multiple times for randomness
            result = DICOMDictionaries.get_random_value("modalities")
            assert result in MODALITY_CODES

    def test_returns_empty_for_unknown(self):
        """Verify returns empty string for unknown dictionary."""
        result = DICOMDictionaries.get_random_value("nonexistent")
        assert result == ""

    def test_randomness(self):
        """Verify returns different values (with high probability)."""
        results = {DICOMDictionaries.get_random_value("modalities") for _ in range(50)}
        # Should get at least 2 different values in 50 attempts
        assert len(results) >= 2


class TestGenerateRandomUid:
    """Tests for DICOMDictionaries.generate_random_uid method."""

    def test_returns_string(self):
        """Verify returns a string."""
        result = DICOMDictionaries.generate_random_uid()
        assert isinstance(result, str)

    def test_default_root(self):
        """Verify uses default root."""
        result = DICOMDictionaries.generate_random_uid()
        assert result.startswith("1.2.840.10008.5.")

    def test_custom_root(self):
        """Verify uses custom root."""
        result = DICOMDictionaries.generate_random_uid(root="1.2.3.4")
        assert result.startswith("1.2.3.4.")

    def test_uid_format(self):
        """Verify UID has valid format (numbers and dots)."""
        result = DICOMDictionaries.generate_random_uid()
        assert all(c.isdigit() or c == "." for c in result)

    def test_unique_uids(self):
        """Verify generates unique UIDs."""
        uids = {DICOMDictionaries.generate_random_uid() for _ in range(100)}
        assert len(uids) == 100


class TestGetEdgeCases:
    """Tests for DICOMDictionaries.get_edge_cases method."""

    def test_returns_dict(self):
        """Verify returns a dictionary."""
        result = DICOMDictionaries.get_edge_cases()
        assert isinstance(result, dict)

    def test_has_expected_categories(self):
        """Verify has expected edge case categories."""
        result = DICOMDictionaries.get_edge_cases()
        expected_categories = {
            "empty",
            "whitespace",
            "null_bytes",
            "very_long",
            "special_chars",
            "sql_injection",
            "xss",
            "format_strings",
            "unicode",
            "numbers_as_strings",
        }
        assert set(result.keys()) == expected_categories

    def test_all_categories_are_lists(self):
        """Verify all categories contain lists."""
        for category, values in DICOMDictionaries.get_edge_cases().items():
            assert isinstance(values, list), f"{category} should be a list"
            assert len(values) > 0, f"{category} should not be empty"

    def test_empty_category(self):
        """Verify empty category contains empty string."""
        result = DICOMDictionaries.get_edge_cases()
        assert "" in result["empty"]

    def test_null_bytes_category(self):
        """Verify null_bytes category contains null bytes."""
        result = DICOMDictionaries.get_edge_cases()
        assert "\x00" in result["null_bytes"]


class TestGetMaliciousValues:
    """Tests for DICOMDictionaries.get_malicious_values method."""

    def test_returns_dict(self):
        """Verify returns a dictionary."""
        result = DICOMDictionaries.get_malicious_values()
        assert isinstance(result, dict)

    def test_has_expected_categories(self):
        """Verify has expected malicious value categories."""
        result = DICOMDictionaries.get_malicious_values()
        expected_categories = {
            "buffer_overflow",
            "integer_overflow",
            "path_traversal",
            "command_injection",
            "format_string",
            "null_dereference",
        }
        assert set(result.keys()) == expected_categories

    def test_buffer_overflow_values(self):
        """Verify buffer overflow values are long strings."""
        result = DICOMDictionaries.get_malicious_values()
        for value in result["buffer_overflow"]:
            assert len(value) >= 1024

    def test_integer_overflow_values(self):
        """Verify integer overflow values include boundary values."""
        result = DICOMDictionaries.get_malicious_values()
        values = result["integer_overflow"]
        assert "2147483647" in values  # INT_MAX
        assert "2147483648" in values  # INT_MAX + 1

    def test_path_traversal_values(self):
        """Verify path traversal values include common patterns."""
        result = DICOMDictionaries.get_malicious_values()
        values = result["path_traversal"]
        assert any("../" in v or "..\\" in v for v in values)

    def test_command_injection_values(self):
        """Verify command injection values include common patterns."""
        result = DICOMDictionaries.get_malicious_values()
        values = result["command_injection"]
        shell_chars_found = any(c in "".join(values) for c in [";", "|", "&", "`", "$"])
        assert shell_chars_found

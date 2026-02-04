"""Real-world tests for DICOM dictionaries module.

Tests the dictionary access, value generation, and edge case handling
functionality with actual usage patterns.
"""

from dicom_fuzzer.attacks.format.dicom_dictionaries import (
    CHARACTER_SETS,
    COMMON_UID_ROOTS,
    INSTITUTION_NAMES,
    MANUFACTURER_NAMES,
    MODALITY_CODES,
    PATIENT_SEX_CODES,
    PHOTOMETRIC_INTERPRETATION,
    PIXEL_SPACING_VALUES,
    SAMPLE_ACCESSION_NUMBERS,
    SAMPLE_DATES,
    SAMPLE_PATIENT_IDS,
    SAMPLE_PATIENT_NAMES,
    SAMPLE_TIMES,
    SOP_CLASS_UIDS,
    STUDY_DESCRIPTIONS,
    TRANSFER_SYNTAXES,
    WINDOW_CENTER_VALUES,
    WINDOW_WIDTH_VALUES,
    DICOMDictionaries,
)


class TestConstantDictionaries:
    """Test that all constant dictionaries are properly defined."""

    def test_transfer_syntaxes_defined(self):
        """Test transfer syntaxes list is not empty."""
        assert len(TRANSFER_SYNTAXES) > 0
        assert "1.2.840.10008.1.2" in TRANSFER_SYNTAXES  # Default

    def test_sop_class_uids_defined(self):
        """Test SOP class UIDs list is not empty."""
        assert len(SOP_CLASS_UIDS) > 0
        assert "1.2.840.10008.5.1.4.1.1.2" in SOP_CLASS_UIDS  # CT

    def test_modality_codes_defined(self):
        """Test modality codes list is not empty."""
        assert len(MODALITY_CODES) > 0
        assert "CT" in MODALITY_CODES
        assert "MR" in MODALITY_CODES

    def test_patient_sex_codes_defined(self):
        """Test patient sex codes list is not empty."""
        assert len(PATIENT_SEX_CODES) > 0
        assert "M" in PATIENT_SEX_CODES
        assert "F" in PATIENT_SEX_CODES

    def test_institution_names_defined(self):
        """Test institution names list is not empty."""
        assert len(INSTITUTION_NAMES) > 0
        assert any("Hospital" in name for name in INSTITUTION_NAMES)

    def test_manufacturer_names_defined(self):
        """Test manufacturer names list is not empty."""
        assert len(MANUFACTURER_NAMES) > 0
        assert "GE Healthcare" in MANUFACTURER_NAMES

    def test_photometric_interpretation_defined(self):
        """Test photometric interpretation list is not empty."""
        assert len(PHOTOMETRIC_INTERPRETATION) > 0
        assert "MONOCHROME2" in PHOTOMETRIC_INTERPRETATION

    def test_sample_dates_defined(self):
        """Test sample dates list is not empty."""
        assert len(SAMPLE_DATES) > 0
        assert "20240101" in SAMPLE_DATES

    def test_sample_times_defined(self):
        """Test sample times list is not empty."""
        assert len(SAMPLE_TIMES) > 0
        assert "120000" in SAMPLE_TIMES

    def test_sample_patient_names_defined(self):
        """Test sample patient names list is not empty."""
        assert len(SAMPLE_PATIENT_NAMES) > 0
        assert "Doe^John" in SAMPLE_PATIENT_NAMES

    def test_study_descriptions_defined(self):
        """Test study descriptions list is not empty."""
        assert len(STUDY_DESCRIPTIONS) > 0

    def test_sample_accession_numbers_defined(self):
        """Test accession numbers list is not empty."""
        assert len(SAMPLE_ACCESSION_NUMBERS) > 0

    def test_sample_patient_ids_defined(self):
        """Test patient IDs list is not empty."""
        assert len(SAMPLE_PATIENT_IDS) > 0

    def test_pixel_spacing_values_defined(self):
        """Test pixel spacing values list is not empty."""
        assert len(PIXEL_SPACING_VALUES) > 0
        assert "1.0\\1.0" in PIXEL_SPACING_VALUES

    def test_window_center_values_defined(self):
        """Test window center values list is not empty."""
        assert len(WINDOW_CENTER_VALUES) > 0

    def test_window_width_values_defined(self):
        """Test window width values list is not empty."""
        assert len(WINDOW_WIDTH_VALUES) > 0

    def test_character_sets_defined(self):
        """Test character sets list is not empty."""
        assert len(CHARACTER_SETS) > 0
        assert "ISO_IR 100" in CHARACTER_SETS

    def test_common_uid_roots_defined(self):
        """Test UID roots list is not empty."""
        assert len(COMMON_UID_ROOTS) > 0
        assert "1.2.840.10008" in COMMON_UID_ROOTS


class TestDICOMDictionariesClass:
    """Test DICOMDictionaries class methods."""

    def test_all_dictionaries_populated(self):
        """Test that ALL_DICTIONARIES contains expected keys."""
        expected_keys = [
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
        ]

        for key in expected_keys:
            assert key in DICOMDictionaries.ALL_DICTIONARIES
            assert len(DICOMDictionaries.ALL_DICTIONARIES[key]) > 0

    def test_get_dictionary_valid(self):
        """Test getting a valid dictionary."""
        modalities = DICOMDictionaries.get_dictionary("modalities")
        assert len(modalities) > 0
        assert "CT" in modalities

    def test_get_dictionary_invalid(self):
        """Test getting an invalid dictionary returns empty list."""
        result = DICOMDictionaries.get_dictionary("nonexistent")
        assert result == []

    def test_get_all_dictionary_names(self):
        """Test getting all dictionary names."""
        names = DICOMDictionaries.get_all_dictionary_names()
        assert len(names) > 0
        assert "modalities" in names
        assert "transfer_syntaxes" in names

    def test_get_random_value_valid_dictionary(self):
        """Test getting random value from valid dictionary."""
        value = DICOMDictionaries.get_random_value("modalities")
        assert value in MODALITY_CODES

    def test_get_random_value_invalid_dictionary(self):
        """Test getting random value from invalid dictionary returns empty."""
        value = DICOMDictionaries.get_random_value("nonexistent")
        assert value == ""

    def test_get_random_value_multiple_calls(self):
        """Test that multiple calls to get_random_value work."""
        values = []
        for _ in range(10):
            val = DICOMDictionaries.get_random_value("modalities")
            values.append(val)

        # All values should be valid
        for val in values:
            assert val in MODALITY_CODES

    def test_generate_random_uid_default(self):
        """Test generating UID with default root."""
        uid = DICOMDictionaries.generate_random_uid()

        assert isinstance(uid, str)
        assert len(uid) > 0
        assert "1.2.840.10008.5" in uid  # Default root
        assert uid.count(".") >= 4  # root.timestamp.random

    def test_generate_random_uid_custom_root(self):
        """Test generating UID with custom root."""
        custom_root = "1.2.3.4"
        uid = DICOMDictionaries.generate_random_uid(root=custom_root)

        assert isinstance(uid, str)
        assert uid.startswith(custom_root)
        assert uid.count(".") >= 3

    def test_generate_random_uid_uniqueness(self):
        """Test that generated UIDs are unique."""
        uids = set()
        for _ in range(100):
            uid = DICOMDictionaries.generate_random_uid()
            uids.add(uid)

        # Should have generated many unique UIDs
        assert len(uids) > 90  # Allow for small chance of collision

    def test_get_edge_cases_structure(self):
        """Test edge cases dictionary structure."""
        edge_cases = DICOMDictionaries.get_edge_cases()

        assert isinstance(edge_cases, dict)
        assert "empty" in edge_cases
        assert "whitespace" in edge_cases
        assert "null_bytes" in edge_cases
        assert "very_long" in edge_cases
        assert "special_chars" in edge_cases
        assert "sql_injection" in edge_cases
        assert "xss" in edge_cases
        assert "format_strings" in edge_cases
        assert "unicode" in edge_cases
        assert "numbers_as_strings" in edge_cases

    def test_get_edge_cases_empty(self):
        """Test edge cases contains empty strings."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert "" in edge_cases["empty"]

    def test_get_edge_cases_whitespace(self):
        """Test edge cases contains whitespace variations."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert " " in edge_cases["whitespace"]
        assert "\t" in edge_cases["whitespace"]

    def test_get_edge_cases_null_bytes(self):
        """Test edge cases contains null byte variations."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert "\x00" in edge_cases["null_bytes"]
        assert any("\x00" in val for val in edge_cases["null_bytes"])

    def test_get_edge_cases_very_long(self):
        """Test edge cases contains very long strings."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert any(len(s) >= 64 for s in edge_cases["very_long"])
        assert any(len(s) >= 256 for s in edge_cases["very_long"])

    def test_get_edge_cases_sql_injection(self):
        """Test edge cases contains SQL injection attempts."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert any("DROP TABLE" in val for val in edge_cases["sql_injection"])

    def test_get_edge_cases_xss(self):
        """Test edge cases contains XSS attempts."""
        edge_cases = DICOMDictionaries.get_edge_cases()
        assert any("<script>" in val for val in edge_cases["xss"])

    def test_get_malicious_values_structure(self):
        """Test malicious values dictionary structure."""
        malicious = DICOMDictionaries.get_malicious_values()

        assert isinstance(malicious, dict)
        assert "buffer_overflow" in malicious
        assert "integer_overflow" in malicious
        assert "path_traversal" in malicious
        assert "command_injection" in malicious
        assert "format_string" in malicious
        assert "null_dereference" in malicious

    def test_get_malicious_values_buffer_overflow(self):
        """Test malicious values contains buffer overflow attempts."""
        malicious = DICOMDictionaries.get_malicious_values()
        assert any(len(s) >= 1024 for s in malicious["buffer_overflow"])

    def test_get_malicious_values_integer_overflow(self):
        """Test malicious values contains integer overflow attempts."""
        malicious = DICOMDictionaries.get_malicious_values()
        assert "2147483647" in malicious["integer_overflow"]  # INT_MAX

    def test_get_malicious_values_path_traversal(self):
        """Test malicious values contains path traversal attempts."""
        malicious = DICOMDictionaries.get_malicious_values()
        assert any("../" in val for val in malicious["path_traversal"])

    def test_get_malicious_values_command_injection(self):
        """Test malicious values contains command injection attempts."""
        malicious = DICOMDictionaries.get_malicious_values()
        assert any(";" in val or "|" in val for val in malicious["command_injection"])


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_iterate_all_dictionaries(self):
        """Test iterating through all dictionaries."""
        all_names = DICOMDictionaries.get_all_dictionary_names()

        for name in all_names:
            dictionary = DICOMDictionaries.get_dictionary(name)
            assert len(dictionary) > 0

    def test_generate_multiple_uids(self):
        """Test generating multiple UIDs with different roots."""
        roots = ["1.2.3", "1.2.840.10008", "9.9.9.9"]

        for root in roots:
            uid = DICOMDictionaries.generate_random_uid(root=root)
            assert uid.startswith(root)

    def test_random_value_from_each_dictionary(self):
        """Test getting random values from each dictionary."""
        all_names = DICOMDictionaries.get_all_dictionary_names()

        for name in all_names:
            value = DICOMDictionaries.get_random_value(name)
            # Value should be in the original dictionary
            original = DICOMDictionaries.get_dictionary(name)
            assert value in original

    def test_edge_cases_comprehensive(self):
        """Test that edge cases cover major vulnerability categories."""
        edge_cases = DICOMDictionaries.get_edge_cases()

        # Should have multiple categories
        assert len(edge_cases) >= 10

        # Each category should have values
        for category, values in edge_cases.items():
            assert len(values) > 0, f"Category {category} is empty"

    def test_malicious_values_comprehensive(self):
        """Test that malicious values cover major attack vectors."""
        malicious = DICOMDictionaries.get_malicious_values()

        # Should have multiple attack categories
        assert len(malicious) >= 6

        # Each category should have values
        for category, values in malicious.items():
            assert len(values) > 0, f"Category {category} is empty"

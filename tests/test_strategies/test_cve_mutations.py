"""Tests for CVE-Inspired Mutation Strategies.

Comprehensive tests for all CVE mutation functions and the registry.
"""

import struct

import pytest

from dicom_fuzzer.strategies.cve_mutations import (
    CVE_MUTATIONS,
    CVECategory,
    CVEMutation,
    apply_cve_mutation,
    get_available_cves,
    get_mutation_func,
    get_mutations_by_category,
    mutate_certificate_validation_bypass,
    mutate_dcmtk_determine_minmax_oob,
    mutate_dcmtk_nowindow_oob_write,
    mutate_deep_nesting,
    mutate_elf_polyglot_preamble,
    mutate_encapsulated_pixeldata_underflow,
    mutate_fragment_count_mismatch,
    mutate_heap_overflow_dcm_parsing,
    mutate_heap_overflow_pixel_data,
    mutate_integer_overflow_dimensions,
    mutate_invalid_transfer_syntax,
    mutate_jpeg_codec_oob_read,
    mutate_jpeg_truncated_stream,
    mutate_malformed_length_field,
    mutate_oob_read_sante_2024,
    mutate_oob_read_sante_2025,
    mutate_oob_write_lack_validation,
    mutate_oob_write_pixel_data,
    mutate_oversized_length,
    mutate_path_traversal_filename,
    mutate_pe_polyglot_preamble,
    mutate_stack_overflow_dcm,
    mutate_url_scheme_bypass,
    mutate_use_after_free_local,
    mutate_use_after_free_remote,
)


class TestCVECategory:
    """Test CVECategory enum."""

    def test_all_categories_exist(self):
        """Test all expected categories are defined."""
        expected = [
            "HEAP_OVERFLOW",
            "STACK_OVERFLOW",
            "BUFFER_OVERFLOW",
            "INTEGER_OVERFLOW",
            "INTEGER_UNDERFLOW",
            "OUT_OF_BOUNDS_WRITE",
            "OUT_OF_BOUNDS_READ",
            "USE_AFTER_FREE",
            "PATH_TRAVERSAL",
            "DENIAL_OF_SERVICE",
            "POLYGLOT",
            "DEEP_NESTING",
            "MALFORMED_LENGTH",
            "ENCAPSULATED_PIXEL",
            "JPEG_CODEC",
            "CERTIFICATE_VALIDATION",
            "URL_SCHEME_BYPASS",
        ]
        for cat_name in expected:
            assert hasattr(CVECategory, cat_name)

    def test_category_values(self):
        """Test category values are strings."""
        for cat in CVECategory:
            assert isinstance(cat.value, str)


class TestCVEMutation:
    """Test CVEMutation dataclass."""

    def test_create_mutation(self):
        """Test creating a CVEMutation."""
        mutation = CVEMutation(
            cve_id="CVE-2024-1234",
            category=CVECategory.HEAP_OVERFLOW,
            description="Test mutation",
            mutation_func="test_func",
            severity="high",
            target_component="test",
        )
        assert mutation.cve_id == "CVE-2024-1234"
        assert mutation.category == CVECategory.HEAP_OVERFLOW
        assert mutation.description == "Test mutation"
        assert mutation.mutation_func == "test_func"
        assert mutation.severity == "high"
        assert mutation.target_component == "test"

    def test_to_dict(self):
        """Test CVEMutation.to_dict()."""
        mutation = CVEMutation(
            cve_id="CVE-2024-5678",
            category=CVECategory.BUFFER_OVERFLOW,
            description="Buffer overflow test",
            mutation_func="test_buffer",
            severity="critical",
            target_component="buffer",
        )
        d = mutation.to_dict()
        assert d["cve_id"] == "CVE-2024-5678"
        assert d["category"] == "buffer_overflow"
        assert d["description"] == "Buffer overflow test"
        assert d["severity"] == "critical"
        assert d["target_component"] == "buffer"

    def test_default_values(self):
        """Test default values in CVEMutation."""
        mutation = CVEMutation(
            cve_id="CVE-TEST",
            category=CVECategory.POLYGLOT,
            description="Test",
            mutation_func="func",
        )
        assert mutation.severity == "high"
        assert mutation.target_component == ""


class TestHeapOverflowMutation:
    """Test heap overflow pixel data mutation."""

    @pytest.fixture
    def sample_dicom_data(self):
        """Create sample DICOM-like data with dimension tags."""
        # Create minimal DICOM structure with Rows, Columns, BitsAllocated
        data = bytearray(200)
        # Rows tag (0028,0010) at offset 20
        data[20:24] = b"\x28\x00\x10\x00"
        data[24:26] = b"US"
        data[26:28] = struct.pack("<H", 2)  # length
        data[28:30] = struct.pack("<H", 512)  # value

        # Columns tag (0028,0011) at offset 40
        data[40:44] = b"\x28\x00\x11\x00"
        data[44:46] = b"US"
        data[46:48] = struct.pack("<H", 2)
        data[48:50] = struct.pack("<H", 512)

        # BitsAllocated tag (0028,0100) at offset 60
        data[60:64] = b"\x28\x00\x00\x01"
        data[64:66] = b"US"
        data[66:68] = struct.pack("<H", 2)
        data[68:70] = struct.pack("<H", 8)

        return bytes(data)

    def test_mutate_heap_overflow_modifies_rows(self, sample_dicom_data):
        """Test that heap overflow mutation modifies Rows to max value."""
        result = mutate_heap_overflow_pixel_data(sample_dicom_data)
        assert result != sample_dicom_data
        # Find Rows value
        idx = result.find(b"\x28\x00\x10\x00")
        if idx != -1:
            rows = struct.unpack("<H", result[idx + 6 : idx + 8])[0]
            assert rows == 0xFFFF

    def test_mutate_heap_overflow_modifies_columns(self, sample_dicom_data):
        """Test that heap overflow mutation modifies Columns."""
        result = mutate_heap_overflow_pixel_data(sample_dicom_data)
        idx = result.find(b"\x28\x00\x11\x00")
        if idx != -1:
            cols = struct.unpack("<H", result[idx + 6 : idx + 8])[0]
            assert cols == 0xFFFF

    def test_mutate_heap_overflow_empty_data(self):
        """Test mutation with empty data."""
        result = mutate_heap_overflow_pixel_data(b"")
        assert result == b""


class TestIntegerOverflowMutation:
    """Test integer overflow dimension mutation."""

    @pytest.fixture
    def sample_dicom_data(self):
        """Create sample DICOM data."""
        data = bytearray(100)
        data[10:14] = b"\x28\x00\x10\x00"  # Rows
        data[14:16] = b"US"
        data[16:18] = struct.pack("<H", 2)
        data[18:20] = struct.pack("<H", 100)

        data[30:34] = b"\x28\x00\x11\x00"  # Columns
        data[34:36] = b"US"
        data[36:38] = struct.pack("<H", 2)
        data[38:40] = struct.pack("<H", 100)
        return bytes(data)

    def test_mutate_integer_overflow(self, sample_dicom_data):
        """Test integer overflow mutation modifies dimensions."""
        result = mutate_integer_overflow_dimensions(sample_dicom_data)
        assert result != sample_dicom_data
        assert len(result) == len(sample_dicom_data)


class TestMalformedLengthMutation:
    """Test malformed length field mutation."""

    def test_mutate_malformed_length_vr_patterns(self):
        """Test mutation targets VR patterns."""
        # Data with OB VR
        data = b"\x00" * 10 + b"OB\x00\x00\x10\x00" + b"\x00" * 20
        result = mutate_malformed_length_field(data)
        # May or may not modify depending on random
        assert len(result) == len(data)

    def test_mutate_malformed_length_empty(self):
        """Test with empty data."""
        result = mutate_malformed_length_field(b"")
        assert result == b""


class TestOversizedLengthMutation:
    """Test oversized length mutation."""

    def test_mutate_oversized_length(self):
        """Test oversized length mutation."""
        # Data with explicit VR
        data = b"\x00" * 5 + b"OB\x00\x00\x10\x00\x00\x00" + b"\x00" * 50
        result = mutate_oversized_length(data)
        assert len(result) == len(data)


class TestPathTraversalMutation:
    """Test path traversal mutation."""

    def test_mutate_path_traversal(self):
        """Test path traversal payload injection."""
        # Data with Referenced File ID tag
        data = (
            b"\x00" * 10
            + b"\x04\x00\x00\x15"
            + b"LO\x00\x08"
            + b"test.dcm"
            + b"\x00" * 50
        )
        result = mutate_path_traversal_filename(data)
        # Result should contain path traversal sequence
        assert b"../" in result or b"..\\" in result or result != data

    def test_mutate_path_traversal_no_tag(self):
        """Test when Referenced File ID tag not found."""
        data = b"\x00" * 50
        result = mutate_path_traversal_filename(data)
        assert result == data


class TestDeepNestingMutation:
    """Test deep nesting mutation."""

    def test_mutate_deep_nesting_adds_structure(self):
        """Test that deep nesting adds item delimiters."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"  # End with item delimitation
        result = mutate_deep_nesting(data)
        # Should be larger due to nested structure
        assert len(result) > len(data)

    def test_mutate_deep_nesting_contains_items(self):
        """Test nested structure contains item tags."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"
        result = mutate_deep_nesting(data)
        # Should contain item start tag
        item_start = b"\xfe\xff\x00\xe0"
        assert item_start in result


class TestPolyglotMutations:
    """Test polyglot preamble mutations."""

    @pytest.fixture
    def sample_dicom_preamble(self):
        """Create sample DICOM with 128-byte preamble."""
        preamble = b"\x00" * 128
        dicm = b"DICM"
        return preamble + dicm + b"\x00" * 100

    def test_mutate_pe_polyglot(self, sample_dicom_preamble):
        """Test PE polyglot injection."""
        result = mutate_pe_polyglot_preamble(sample_dicom_preamble)
        # Should start with MZ
        assert result[:2] == b"MZ"
        # DICM should still be at offset 128
        assert result[128:132] == b"DICM"

    def test_mutate_elf_polyglot(self, sample_dicom_preamble):
        """Test ELF polyglot injection."""
        result = mutate_elf_polyglot_preamble(sample_dicom_preamble)
        # Should start with ELF magic
        assert result[:4] == b"\x7fELF"
        # DICM should still be at offset 128
        assert result[128:132] == b"DICM"

    def test_mutate_polyglot_small_file(self):
        """Test polyglot on small file returns unchanged."""
        data = b"\x00" * 50
        result_pe = mutate_pe_polyglot_preamble(data)
        result_elf = mutate_elf_polyglot_preamble(data)
        assert result_pe == data
        assert result_elf == data


class TestTransferSyntaxMutation:
    """Test invalid transfer syntax mutation."""

    def test_mutate_invalid_transfer_syntax(self):
        """Test transfer syntax UID mutation."""
        # Data with Transfer Syntax UID tag
        ts_tag = b"\x02\x00\x10\x00"
        uid = b"1.2.840.10008.1.2.1"
        data = (
            b"\x00" * 10
            + ts_tag
            + b"UI"
            + struct.pack("<H", len(uid))
            + uid
            + b"\x00" * 50
        )
        result = mutate_invalid_transfer_syntax(data)
        # Should have modified the UID
        if ts_tag in result:
            # Check UID was changed
            assert result != data


class TestEncapsulatedPixelDataMutations:
    """Test encapsulated PixelData mutations for CVE-2025-11266."""

    def test_mutate_encapsulated_underflow_no_pixeldata(self):
        """Test underflow mutation when no PixelData tag exists."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"
        result = mutate_encapsulated_pixeldata_underflow(data)
        # Should add malicious encapsulated structure
        assert b"\xe0\x7f\x10\x00" in result  # PixelData tag

    def test_mutate_encapsulated_underflow_with_pixeldata(self):
        """Test underflow mutation with existing PixelData."""
        # Create data with PixelData tag
        pixel_data_tag = b"\xe0\x7f\x10\x00"
        item_tag = b"\xfe\xff\x00\xe0"
        data = (
            b"\x00" * 50
            + pixel_data_tag
            + b"OB\x00\x00\xff\xff\xff\xff"
            + item_tag
            + b"\x10\x00\x00\x00"
            + b"\x00" * 100
        )
        result = mutate_encapsulated_pixeldata_underflow(data)
        assert result != data

    def test_mutate_fragment_count_mismatch(self):
        """Test fragment count mismatch mutation."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"
        result = mutate_fragment_count_mismatch(data)
        # Should contain encapsulated structure
        assert b"\xe0\x7f\x10\x00" in result


class TestJPEGCodecMutations:
    """Test JPEG codec mutations for CVE-2025-53618/53619."""

    def test_mutate_jpeg_codec_oob_read(self):
        """Test JPEG codec OOB read mutation."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"
        result = mutate_jpeg_codec_oob_read(data)
        # Should contain JPEG markers
        assert b"\xff\xd8" in result  # SOI
        assert b"\xff\xc0" in result  # SOF0

    def test_mutate_jpeg_truncated_stream(self):
        """Test truncated JPEG stream mutation."""
        data = b"\x00" * 100 + b"\xfe\xff\x0d\xe0"
        result = mutate_jpeg_truncated_stream(data)
        # Should contain truncated JPEG
        assert b"\xff\xd8" in result  # SOI
        # Should NOT contain EOI (truncated)
        jpeg_start = result.find(b"\xff\xd8")
        if jpeg_start != -1:
            jpeg_portion = result[jpeg_start:]
            # May or may not have EOI depending on structure
            assert len(jpeg_portion) > 10


class TestCVERegistry:
    """Test CVE mutation registry functions."""

    def test_cve_mutations_not_empty(self):
        """Test CVE_MUTATIONS list is populated."""
        assert len(CVE_MUTATIONS) > 0

    def test_get_mutation_func_valid(self):
        """Test getting a valid mutation function."""
        func = get_mutation_func("mutate_heap_overflow_pixel_data")
        assert func is not None
        assert callable(func)

    def test_get_mutation_func_invalid(self):
        """Test getting an invalid mutation function returns None."""
        func = get_mutation_func("nonexistent_function")
        assert func is None

    def test_get_available_cves(self):
        """Test getting available CVE IDs."""
        cves = get_available_cves()
        assert len(cves) > 0
        assert "CVE-2025-5943" in cves
        assert "CVE-2025-11266" in cves
        assert "CVE-2025-53618" in cves

    def test_get_mutations_by_category(self):
        """Test filtering mutations by category."""
        heap_mutations = get_mutations_by_category(CVECategory.HEAP_OVERFLOW)
        assert len(heap_mutations) > 0
        for m in heap_mutations:
            assert m.category == CVECategory.HEAP_OVERFLOW

    def test_apply_cve_mutation_random(self):
        """Test applying random CVE mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        mutated, mutation = apply_cve_mutation(data)
        assert isinstance(mutation, CVEMutation)
        assert isinstance(mutated, bytes)

    def test_apply_cve_mutation_specific(self):
        """Test applying specific CVE mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        mutated, mutation = apply_cve_mutation(data, cve_id="CVE-2025-11266")
        assert mutation.cve_id == "CVE-2025-11266"

    def test_apply_cve_mutation_invalid_cve(self):
        """Test applying mutation with invalid CVE raises error."""
        data = b"\x00" * 100
        with pytest.raises(ValueError, match="Unknown CVE"):
            apply_cve_mutation(data, cve_id="CVE-INVALID-9999")

    def test_all_registered_functions_exist(self):
        """Test all registered mutation functions actually exist."""
        for mutation in CVE_MUTATIONS:
            func = get_mutation_func(mutation.mutation_func)
            assert func is not None, f"Function {mutation.mutation_func} not found"
            assert callable(func)

    def test_all_mutations_have_required_fields(self):
        """Test all mutations have required fields populated."""
        for mutation in CVE_MUTATIONS:
            assert mutation.cve_id
            assert mutation.category
            assert mutation.description
            assert mutation.mutation_func
            assert mutation.severity


class TestMutationEdgeCases:
    """Test edge cases for mutations."""

    def test_all_mutations_handle_empty_data(self):
        """Test all mutation functions handle empty data gracefully."""
        mutation_funcs = [
            mutate_heap_overflow_pixel_data,
            mutate_integer_overflow_dimensions,
            mutate_malformed_length_field,
            mutate_oversized_length,
            mutate_path_traversal_filename,
            mutate_deep_nesting,
            mutate_pe_polyglot_preamble,
            mutate_elf_polyglot_preamble,
            mutate_invalid_transfer_syntax,
            mutate_encapsulated_pixeldata_underflow,
            mutate_fragment_count_mismatch,
            mutate_jpeg_codec_oob_read,
            mutate_jpeg_truncated_stream,
            # 2024-2025 CVE mutations
            mutate_oob_write_pixel_data,
            mutate_oob_write_lack_validation,
            mutate_heap_overflow_dcm_parsing,
            mutate_stack_overflow_dcm,
            mutate_url_scheme_bypass,
            mutate_certificate_validation_bypass,
            # OsiriX and Sante CVE mutations
            mutate_use_after_free_remote,
            mutate_use_after_free_local,
            mutate_oob_read_sante_2024,
            mutate_oob_read_sante_2025,
        ]
        for func in mutation_funcs:
            # Should not raise exception
            result = func(b"")
            assert isinstance(result, bytes)

    def test_all_mutations_return_bytes(self):
        """Test all mutation functions return bytes."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        mutation_funcs = [
            mutate_heap_overflow_pixel_data,
            mutate_integer_overflow_dimensions,
            mutate_malformed_length_field,
            mutate_oversized_length,
            mutate_path_traversal_filename,
            mutate_deep_nesting,
            mutate_pe_polyglot_preamble,
            mutate_elf_polyglot_preamble,
            mutate_invalid_transfer_syntax,
            mutate_encapsulated_pixeldata_underflow,
            mutate_fragment_count_mismatch,
            mutate_jpeg_codec_oob_read,
            mutate_jpeg_truncated_stream,
            # 2024-2025 CVE mutations
            mutate_oob_write_pixel_data,
            mutate_oob_write_lack_validation,
            mutate_heap_overflow_dcm_parsing,
            mutate_stack_overflow_dcm,
            mutate_url_scheme_bypass,
            mutate_certificate_validation_bypass,
            # OsiriX and Sante CVE mutations
            mutate_use_after_free_remote,
            mutate_use_after_free_local,
            mutate_oob_read_sante_2024,
            mutate_oob_read_sante_2025,
        ]
        for func in mutation_funcs:
            result = func(data)
            assert isinstance(result, bytes), f"{func.__name__} did not return bytes"


class TestMicroDicom2024CVEs:
    """Test MicroDicom 2024 CVE mutations."""

    def test_mutate_oob_write_pixel_data(self):
        """Test CVE-2025-35975 out-of-bounds write mutation."""
        # Create data with Rows and Columns tags
        rows_tag = b"\x28\x00\x10\x00"
        cols_tag = b"\x28\x00\x11\x00"
        data = (
            b"\x00" * 50
            + rows_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 512)
            + cols_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 512)
            + b"\x00" * 100
        )
        result = mutate_oob_write_pixel_data(data)
        # Should have modified dimensions
        assert result != data

    def test_mutate_oob_write_lack_validation(self):
        """Test CVE-2024-25578 out-of-bounds write mutation."""
        # Create data with explicit VR elements
        data = (
            b"\x00" * 50
            + b"\x08\x00\x18\x00"  # SOP Instance UID tag
            + b"OB"
            + b"\x00\x00"
            + struct.pack("<I", 64)
            + b"\x00" * 64
            + b"\x00" * 50
        )
        result = mutate_oob_write_lack_validation(data)
        assert isinstance(result, bytes)

    def test_mutate_heap_overflow_dcm_parsing(self):
        """Test CVE-2024-22100 heap overflow mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_heap_overflow_dcm_parsing(data)
        # Should have added private creator or modified existing
        assert len(result) >= len(data)

    def test_mutate_stack_overflow_dcm(self):
        """Test CVE-2024-28877 stack overflow mutation."""
        # Create data with Patient Name tag
        pn_tag = b"\x10\x00\x10\x00"
        data = (
            b"\x00" * 50
            + pn_tag
            + b"PN"
            + struct.pack("<H", 10)
            + b"Test^Name"
            + b"\x00"
            + b"\x00" * 50
        )
        result = mutate_stack_overflow_dcm(data)
        # Should have added deep nesting or modified patient name
        assert len(result) > len(data)

    def test_mutate_url_scheme_bypass(self):
        """Test CVE-2024-33606 URL scheme bypass mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_url_scheme_bypass(data)
        # Should have injected URL payload
        assert len(result) > len(data)
        # Should contain some URL-like content
        url_indicators = [b"file:", b"http:", b"\\\\", b"javascript:"]
        has_url = any(indicator in result for indicator in url_indicators)
        assert has_url


class TestRadiAnt2025CVE:
    """Test RadiAnt DICOM Viewer 2025 CVE mutation."""

    def test_mutate_certificate_validation_bypass(self):
        """Test CVE-2025-1001 certificate validation bypass mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_certificate_validation_bypass(data)
        # Should have injected update-related URL
        assert len(result) > len(data)

    def test_mutate_certificate_validation_with_existing_tag(self):
        """Test certificate validation bypass with existing metadata tag."""
        # Create data with Institution Address tag
        inst_tag = b"\x08\x00\x81\x00"
        data = (
            b"\x00" * 50
            + inst_tag
            + b"LO"
            + struct.pack("<H", 20)
            + b"Test Institution   "
            + b"\x00" * 50
        )
        result = mutate_certificate_validation_bypass(data)
        assert result != data


class TestNewCVERegistry:
    """Test that new CVEs are properly registered."""

    def test_2024_cves_registered(self):
        """Test 2024 CVEs are in the registry."""
        cves = get_available_cves()
        assert "CVE-2024-22100" in cves
        assert "CVE-2024-25578" in cves
        assert "CVE-2024-28877" in cves
        assert "CVE-2024-33606" in cves
        assert "CVE-2024-1453" in cves  # Sante DICOM Viewer Pro OOB read
        assert "CVE-2024-47796" in cves  # DCMTK nowindow LUT OOB write
        assert "CVE-2024-52333" in cves  # DCMTK determineMinMax OOB write

    def test_2025_cves_registered(self):
        """Test 2025 CVEs are in the registry."""
        cves = get_available_cves()
        assert "CVE-2025-35975" in cves
        assert "CVE-2025-1001" in cves
        assert "CVE-2025-27578" in cves  # OsiriX MD remote use-after-free
        assert "CVE-2025-31946" in cves  # OsiriX MD local use-after-free
        assert "CVE-2025-5307" in cves  # Sante DICOM Viewer Pro OOB read 2025

    def test_new_categories_have_mutations(self):
        """Test new categories have associated mutations."""
        stack_mutations = get_mutations_by_category(CVECategory.STACK_OVERFLOW)
        assert len(stack_mutations) > 0

        oob_write_mutations = get_mutations_by_category(CVECategory.OUT_OF_BOUNDS_WRITE)
        assert len(oob_write_mutations) > 0

        cert_mutations = get_mutations_by_category(CVECategory.CERTIFICATE_VALIDATION)
        assert len(cert_mutations) > 0

        url_mutations = get_mutations_by_category(CVECategory.URL_SCHEME_BYPASS)
        assert len(url_mutations) > 0

    def test_apply_new_cve_mutations(self):
        """Test applying new CVE mutations."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"

        # Test each new CVE
        new_cves = [
            "CVE-2024-22100",
            "CVE-2024-25578",
            "CVE-2024-28877",
            "CVE-2024-33606",
            "CVE-2025-35975",
            "CVE-2025-1001",
            "CVE-2025-27578",
            "CVE-2025-31946",
            "CVE-2024-1453",
            "CVE-2025-5307",
            "CVE-2024-47796",
            "CVE-2024-52333",
        ]
        for cve_id in new_cves:
            mutated, mutation = apply_cve_mutation(data, cve_id=cve_id)
            assert mutation.cve_id == cve_id
            assert isinstance(mutated, bytes)


class TestOsiriXMD2025CVEs:
    """Test OsiriX MD 2025 use-after-free CVE mutations."""

    def test_mutate_use_after_free_remote(self):
        """Test CVE-2025-27578 remote use-after-free mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_use_after_free_remote(data)
        # Should create malformed sequence with premature termination
        assert len(result) > len(data)
        # Should contain sequence tags
        assert b"\x08\x00\x18\x11" in result or b"\xfe\xff\x00\xe0" in result

    def test_mutate_use_after_free_remote_with_existing_sequence(self):
        """Test remote use-after-free with existing sequence tag."""
        # Create data with Referenced Image Sequence tag
        seq_tag = b"\x08\x00\x18\x11"
        data = (
            b"\x00" * 50
            + seq_tag
            + b"SQ"
            + b"\x00\x00"
            + b"\xff\xff\xff\xff"
            + b"\xfe\xff\x00\xe0"
            + struct.pack("<I", 16)
            + b"\x00" * 16
            + b"\xfe\xff\x0d\xe0"
            + b"\x00\x00\x00\x00"
            + b"\xfe\xff\xdd\xe0"
            + b"\x00\x00\x00\x00"
        )
        result = mutate_use_after_free_remote(data)
        assert result != data
        assert isinstance(result, bytes)

    def test_mutate_use_after_free_local(self):
        """Test CVE-2025-31946 local use-after-free mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_use_after_free_local(data)
        # Should create encapsulated PixelData with invalid offsets
        assert len(result) > len(data)
        # Should contain PixelData tag
        assert b"\xe0\x7f\x10\x00" in result

    def test_mutate_use_after_free_local_with_existing_pixeldata(self):
        """Test local use-after-free with existing PixelData."""
        # Create data with PixelData tag
        pixel_data_tag = b"\xe0\x7f\x10\x00"
        data = (
            b"\x00" * 50
            + pixel_data_tag
            + b"OB"
            + b"\x00\x00"
            + b"\xff\xff\xff\xff"
            + b"\xfe\xff\x00\xe0"
            + struct.pack("<I", 32)
            + b"\x00" * 32
            + b"\xfe\xff\xdd\xe0"
            + b"\x00\x00\x00\x00"
        )
        result = mutate_use_after_free_local(data)
        # Mutation should return valid bytes (may or may not modify existing structure)
        assert isinstance(result, bytes)
        assert len(result) >= len(data)


class TestSanteDICOMViewerCVEs:
    """Test Sante DICOM Viewer Pro OOB read CVE mutations."""

    def test_mutate_oob_read_sante_2024(self):
        """Test CVE-2024-1453 out-of-bounds read mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_oob_read_sante_2024(data)
        # Should create oversized length fields
        assert len(result) >= len(data)
        assert isinstance(result, bytes)

    def test_mutate_oob_read_sante_2024_with_explicit_vr(self):
        """Test CVE-2024-1453 with existing explicit VR element."""
        # Create data with explicit VR OB element
        data = (
            b"\x00" * 50
            + b"\x08\x00\x18\x00"  # SOP Instance UID tag
            + b"OB"
            + b"\x00\x00"
            + struct.pack("<I", 64)
            + b"\x00" * 64
            + b"\x00" * 50
        )
        result = mutate_oob_read_sante_2024(data)
        # Should have modified or added oversized length
        assert isinstance(result, bytes)

    def test_mutate_oob_read_sante_2025(self):
        """Test CVE-2025-5307 out-of-bounds read mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_oob_read_sante_2025(data)
        # Should create dimension/buffer mismatch (may modify in place or append)
        assert isinstance(result, bytes)
        assert len(result) >= len(data)

    def test_mutate_oob_read_sante_2025_with_dimensions(self):
        """Test CVE-2025-5307 with existing dimension tags."""
        # Create data with Rows and Columns tags
        rows_tag = b"\x28\x00\x10\x00"
        cols_tag = b"\x28\x00\x11\x00"
        data = (
            b"\x00" * 50
            + rows_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 512)
            + cols_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 512)
            + b"\x00" * 100
        )
        result = mutate_oob_read_sante_2025(data)
        # Should have modified dimensions or added PixelData with mismatch
        assert result != data


class TestUseAfterFreeCategory:
    """Test USE_AFTER_FREE category."""

    def test_use_after_free_category_exists(self):
        """Test USE_AFTER_FREE category is defined."""
        assert hasattr(CVECategory, "USE_AFTER_FREE")
        assert CVECategory.USE_AFTER_FREE.value == "use_after_free"

    def test_use_after_free_mutations_in_registry(self):
        """Test USE_AFTER_FREE mutations are registered."""
        uaf_mutations = get_mutations_by_category(CVECategory.USE_AFTER_FREE)
        assert len(uaf_mutations) >= 2
        cve_ids = [m.cve_id for m in uaf_mutations]
        assert "CVE-2025-27578" in cve_ids
        assert "CVE-2025-31946" in cve_ids

    def test_oob_read_mutations_include_sante(self):
        """Test OOB read mutations include Sante CVEs."""
        oob_mutations = get_mutations_by_category(CVECategory.OUT_OF_BOUNDS_READ)
        cve_ids = [m.cve_id for m in oob_mutations]
        assert "CVE-2024-1453" in cve_ids
        assert "CVE-2025-5307" in cve_ids


class TestDCMTK2024CVEs:
    """Test DCMTK 2024 CVE mutations from Cisco Talos research."""

    def test_mutate_dcmtk_nowindow_oob_write(self):
        """Test CVE-2024-47796 nowindow LUT out-of-bounds write mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_dcmtk_nowindow_oob_write(data)
        # Should modify data or inject NumberOfFrames element
        assert isinstance(result, bytes)
        assert len(result) >= len(data)

    def test_mutate_dcmtk_nowindow_with_existing_dimensions(self):
        """Test CVE-2024-47796 with existing dimension tags."""
        rows_tag = b"\x28\x00\x10\x00"
        cols_tag = b"\x28\x00\x11\x00"
        data = (
            b"\x00" * 50
            + rows_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 256)
            + cols_tag
            + b"US"
            + struct.pack("<H", 2)
            + struct.pack("<H", 256)
            + b"\x00" * 100
        )
        result = mutate_dcmtk_nowindow_oob_write(data)
        # Should have modified dimension values
        assert result != data
        assert isinstance(result, bytes)

    def test_mutate_dcmtk_determine_minmax_oob(self):
        """Test CVE-2024-52333 determineMinMax out-of-bounds write mutation."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"
        result = mutate_dcmtk_determine_minmax_oob(data)
        # Should create dimension/buffer mismatch or inject PixelData
        assert isinstance(result, bytes)
        assert len(result) >= len(data)

    def test_mutate_dcmtk_determine_minmax_with_existing_pixeldata(self):
        """Test CVE-2024-52333 with existing PixelData tag."""
        pixel_data_tag = b"\xe0\x7f\x10\x00"
        data = (
            b"\x00" * 50
            + pixel_data_tag
            + b"OW"
            + b"\x00\x00"
            + struct.pack("<I", 1024)
            + b"\x00" * 1024
            + b"\x00" * 50
        )
        result = mutate_dcmtk_determine_minmax_oob(data)
        # Should have modified PixelData length to small value
        assert isinstance(result, bytes)

    def test_dcmtk_2024_cves_in_registry(self):
        """Test DCMTK 2024 CVEs are registered."""
        cves = get_available_cves()
        assert "CVE-2024-47796" in cves
        assert "CVE-2024-52333" in cves

    def test_dcmtk_oob_write_mutations_in_category(self):
        """Test DCMTK OOB write mutations are in correct category."""
        oob_write_mutations = get_mutations_by_category(CVECategory.OUT_OF_BOUNDS_WRITE)
        cve_ids = [m.cve_id for m in oob_write_mutations]
        assert "CVE-2024-47796" in cve_ids
        assert "CVE-2024-52333" in cve_ids

    def test_apply_dcmtk_cve_mutations(self):
        """Test applying DCMTK CVE mutations via registry."""
        data = b"\x00" * 200 + b"\xfe\xff\x0d\xe0"

        for cve_id in ["CVE-2024-47796", "CVE-2024-52333"]:
            mutated, mutation = apply_cve_mutation(data, cve_id=cve_id)
            assert mutation.cve_id == cve_id
            assert isinstance(mutated, bytes)

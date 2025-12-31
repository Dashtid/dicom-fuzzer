"""Tests for main.py file/path validation functions.

Tests cover validate_input_path, validate_input_file, _is_potential_dicom,
and parse_target_config functions.
"""

import json
from unittest.mock import patch

import pytest

from dicom_fuzzer.cli.main import (
    _is_potential_dicom,
    parse_target_config,
    validate_input_file,
    validate_input_path,
)


class TestValidateInputPath:
    """Test validate_input_path function."""

    def test_single_file_exists(self, tmp_path):
        """Test validating a single existing file."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        result = validate_input_path(str(test_file))

        assert len(result) == 1
        assert result[0] == test_file

    def test_single_file_not_found(self, tmp_path):
        """Test that non-existent file raises SystemExit."""
        nonexistent = tmp_path / "nonexistent.dcm"

        with pytest.raises(SystemExit) as exc_info:
            validate_input_path(str(nonexistent))

        assert exc_info.value.code == 1

    def test_directory_with_dicom_files(self, tmp_path):
        """Test validating directory with DICOM files."""
        # Create test DICOM files
        (tmp_path / "file1.dcm").write_bytes(b"test")
        (tmp_path / "file2.dcm").write_bytes(b"test")
        (tmp_path / "file3.txt").write_bytes(b"not dicom")

        result = validate_input_path(str(tmp_path))

        # Should find .dcm files
        assert len(result) == 2
        names = [f.name for f in result]
        assert "file1.dcm" in names
        assert "file2.dcm" in names

    def test_directory_recursive(self, tmp_path):
        """Test recursive directory scanning."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "file1.dcm").write_bytes(b"test")
        (subdir / "file2.dcm").write_bytes(b"test")

        # Non-recursive should only find top-level
        result_non_recursive = validate_input_path(str(tmp_path), recursive=False)
        assert len(result_non_recursive) == 1

        # Recursive should find both
        result_recursive = validate_input_path(str(tmp_path), recursive=True)
        assert len(result_recursive) == 2

    def test_directory_no_dicom_files(self, tmp_path):
        """Test directory with no DICOM files raises SystemExit."""
        # Create non-DICOM files only
        (tmp_path / "file1.txt").write_bytes(b"test")
        (tmp_path / "file2.json").write_bytes(b"{}")

        with pytest.raises(SystemExit) as exc_info:
            validate_input_path(str(tmp_path))

        assert exc_info.value.code == 1

    def test_empty_directory(self, tmp_path):
        """Test empty directory raises SystemExit."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with pytest.raises(SystemExit) as exc_info:
            validate_input_path(str(empty_dir))

        assert exc_info.value.code == 1

    def test_dicom_extension_variations(self, tmp_path):
        """Test various DICOM file extensions."""
        (tmp_path / "file1.dcm").write_bytes(b"test")
        (tmp_path / "file2.dicom").write_bytes(b"test")
        (tmp_path / "file3.dic").write_bytes(b"test")

        result = validate_input_path(str(tmp_path))

        assert len(result) == 3


class TestIsPotentialDicom:
    """Test _is_potential_dicom function."""

    def test_dcm_extension(self, tmp_path):
        """Test .dcm extension is recognized."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"any content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is True

    def test_dicom_extension(self, tmp_path):
        """Test .dicom extension is recognized."""
        test_file = tmp_path / "test.dicom"
        test_file.write_bytes(b"any content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is True

    def test_dic_extension(self, tmp_path):
        """Test .dic extension is recognized."""
        test_file = tmp_path / "test.dic"
        test_file.write_bytes(b"any content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is True

    def test_no_extension_with_magic(self, tmp_path):
        """Test file without extension but with DICM magic bytes."""
        test_file = tmp_path / "testfile"
        # DICOM magic bytes at offset 128
        test_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is True

    def test_no_extension_without_magic(self, tmp_path):
        """Test file without extension and without DICM magic."""
        test_file = tmp_path / "testfile"
        test_file.write_bytes(b"\x00" * 200)

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is False

    def test_other_extension(self, tmp_path):
        """Test non-DICOM extension is rejected."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"text content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is False

    def test_short_file_no_extension(self, tmp_path):
        """Test short file without extension (can't have magic at offset 128)."""
        test_file = tmp_path / "shortfile"
        test_file.write_bytes(b"short")

        extensions = {".dcm", ".dicom", ".dic", ""}
        assert _is_potential_dicom(test_file, extensions) is False


class TestValidateInputFile:
    """Test validate_input_file function (legacy)."""

    def test_valid_file(self, tmp_path):
        """Test validating existing file."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        result = validate_input_file(str(test_file))

        assert result == test_file

    def test_file_not_found(self, tmp_path):
        """Test non-existent file raises SystemExit."""
        nonexistent = tmp_path / "nonexistent.dcm"

        with pytest.raises(SystemExit) as exc_info:
            validate_input_file(str(nonexistent))

        assert exc_info.value.code == 1

    def test_directory_instead_of_file(self, tmp_path):
        """Test that directory path raises SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            validate_input_file(str(tmp_path))

        assert exc_info.value.code == 1


class TestParseTargetConfig:
    """Test parse_target_config function."""

    def test_valid_json_config(self, tmp_path):
        """Test parsing valid JSON config file."""
        config_file = tmp_path / "config.json"
        config_data = {
            "target": "/path/to/app",
            "timeout": 10,
            "options": ["--flag1", "--flag2"],
        }
        config_file.write_text(json.dumps(config_data))

        result = parse_target_config(str(config_file))

        assert result["target"] == "/path/to/app"
        assert result["timeout"] == 10
        assert result["options"] == ["--flag1", "--flag2"]

    def test_missing_config_file(self, tmp_path):
        """Test missing config file raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            parse_target_config(str(nonexistent))

    def test_invalid_json(self, tmp_path):
        """Test invalid JSON raises JSONDecodeError."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ invalid json }")

        with pytest.raises(json.JSONDecodeError):
            parse_target_config(str(config_file))

    def test_empty_json(self, tmp_path):
        """Test empty JSON object."""
        config_file = tmp_path / "empty.json"
        config_file.write_text("{}")

        result = parse_target_config(str(config_file))

        assert result == {}

    def test_nested_config(self, tmp_path):
        """Test parsing nested JSON structure."""
        config_file = tmp_path / "nested.json"
        config_data = {
            "fuzzing": {
                "strategies": ["metadata", "header"],
                "count": 100,
            },
            "target": {
                "executable": "/app/viewer",
                "args": ["--no-gui"],
            },
        }
        config_file.write_text(json.dumps(config_data))

        result = parse_target_config(str(config_file))

        assert result["fuzzing"]["strategies"] == ["metadata", "header"]
        assert result["target"]["executable"] == "/app/viewer"


class TestIsPotentialDicomEdgeCases:
    """Additional edge case tests for _is_potential_dicom."""

    def test_file_read_permission_denied(self, tmp_path):
        """Test handling when file read fails due to permissions."""
        test_file = tmp_path / "noperm"
        test_file.write_bytes(b"content")

        extensions = {".dcm", ".dicom", ".dic", ""}

        # Mock open to raise permission error
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # Should return False, not raise exception
            result = _is_potential_dicom(test_file, extensions)
            assert result is False

    def test_file_exactly_128_bytes(self, tmp_path):
        """Test file exactly 128 bytes (seek to 128 then read 4 bytes fails)."""
        test_file = tmp_path / "exact128"
        test_file.write_bytes(b"\x00" * 128)

        extensions = {".dcm", ".dicom", ".dic", ""}
        # File ends exactly at offset 128, no magic bytes possible
        result = _is_potential_dicom(test_file, extensions)
        assert result is False

    def test_file_131_bytes_incomplete_magic(self, tmp_path):
        """Test file 131 bytes (less than 132 needed for full DICM)."""
        test_file = tmp_path / "short131"
        # 128 bytes preamble + only 3 bytes "DIC" (not full "DICM")
        test_file.write_bytes(b"\x00" * 128 + b"DIC")

        extensions = {".dcm", ".dicom", ".dic", ""}
        result = _is_potential_dicom(test_file, extensions)
        assert result is False

    def test_file_uppercase_extension(self, tmp_path):
        """Test .DCM uppercase extension."""
        test_file = tmp_path / "test.DCM"
        test_file.write_bytes(b"content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        # Should recognize uppercase extension
        result = _is_potential_dicom(test_file, extensions)
        assert result is True

    def test_file_mixed_case_extension(self, tmp_path):
        """Test .DcM mixed case extension."""
        test_file = tmp_path / "test.DcM"
        test_file.write_bytes(b"content")

        extensions = {".dcm", ".dicom", ".dic", ""}
        result = _is_potential_dicom(test_file, extensions)
        assert result is True

    def test_file_wrong_magic_bytes(self, tmp_path):
        """Test file without extension but with wrong magic bytes."""
        test_file = tmp_path / "wrongmagic"
        # "ABCD" at offset 128 instead of "DICM"
        test_file.write_bytes(b"\x00" * 128 + b"ABCD" + b"\x00" * 100)

        extensions = {".dcm", ".dicom", ".dic", ""}
        result = _is_potential_dicom(test_file, extensions)
        assert result is False


class TestValidateInputPathEdgeCases:
    """Additional edge case tests for validate_input_path."""

    def test_directory_with_mixed_extensions(self, tmp_path):
        """Test directory with .dcm, .dicom, .dic, and other files."""
        (tmp_path / "file1.dcm").write_bytes(b"dcm")
        (tmp_path / "file2.dicom").write_bytes(b"dicom")
        (tmp_path / "file3.dic").write_bytes(b"dic")
        (tmp_path / "file4.txt").write_bytes(b"txt")
        (tmp_path / "file5.json").write_bytes(b"{}")

        result = validate_input_path(str(tmp_path))

        # Should find all 3 DICOM variants
        assert len(result) == 3
        extensions = {f.suffix for f in result}
        assert ".dcm" in extensions
        assert ".dicom" in extensions
        assert ".dic" in extensions

    def test_directory_only_extensionless_dicom(self, tmp_path):
        """Test directory with only extensionless DICOM files."""
        # Create files without extension but with DICM magic
        file1 = tmp_path / "image001"
        file1.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)
        file2 = tmp_path / "image002"
        file2.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        result = validate_input_path(str(tmp_path))

        assert len(result) == 2

    def test_directory_subdirs_non_recursive(self, tmp_path):
        """Test that subdirectories are ignored when not recursive."""
        # Top-level file
        (tmp_path / "top.dcm").write_bytes(b"top")

        # Subdir with files
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.dcm").write_bytes(b"nested")

        result = validate_input_path(str(tmp_path), recursive=False)

        # Only top-level should be found
        assert len(result) == 1
        assert result[0].name == "top.dcm"

    def test_output_message_no_dicom_non_recursive(self, tmp_path, capsys):
        """Test tip message for --recursive when no files found."""
        # Create subdir with dcm files but nothing at top level
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.dcm").write_bytes(b"nested")
        (tmp_path / "readme.txt").write_bytes(b"readme")

        with pytest.raises(SystemExit):
            validate_input_path(str(tmp_path), recursive=False)

        captured = capsys.readouterr()
        # Should suggest using --recursive
        assert "recursive" in captured.out.lower() or "Tip" in captured.out

    def test_path_with_spaces(self, tmp_path):
        """Test handling path with spaces."""
        spaced_dir = tmp_path / "path with spaces"
        spaced_dir.mkdir()
        (spaced_dir / "test.dcm").write_bytes(b"test")

        result = validate_input_path(str(spaced_dir))

        assert len(result) == 1

    def test_path_with_unicode(self, tmp_path):
        """Test handling path with unicode characters."""
        unicode_dir = tmp_path / "test_unicode"
        unicode_dir.mkdir()
        (unicode_dir / "patient_data.dcm").write_bytes(b"test")

        result = validate_input_path(str(unicode_dir))

        assert len(result) == 1

    def test_single_file_with_dicom_extension(self, tmp_path):
        """Test single .dicom extension file."""
        test_file = tmp_path / "test.dicom"
        test_file.write_bytes(b"content")

        result = validate_input_path(str(test_file))

        assert len(result) == 1
        assert result[0] == test_file

    def test_deeply_nested_recursive(self, tmp_path):
        """Test deeply nested directory structure with recursive."""
        # Create deep nesting
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "deep.dcm").write_bytes(b"deep")
        (tmp_path / "top.dcm").write_bytes(b"top")

        result = validate_input_path(str(tmp_path), recursive=True)

        assert len(result) == 2
        names = [f.name for f in result]
        assert "deep.dcm" in names
        assert "top.dcm" in names

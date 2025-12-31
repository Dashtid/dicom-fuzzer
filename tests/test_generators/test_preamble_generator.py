"""Tests for preamble_attacks/generator.py - PE/DICOM and ELF/DICOM Polyglot Generator.

Tests cover PE header creation, ELF header creation, polyglot validation, and sanitization.
"""

from unittest.mock import patch

from dicom_fuzzer.generators.preamble_attacks.generator import (
    ELFHeader,
    PEHeader,
    PreambleAttackGenerator,
    main,
)


class TestPEHeader:
    """Test PEHeader dataclass."""

    def test_default_values(self):
        """Test default PE header values."""
        header = PEHeader()
        assert header.e_magic == b"MZ"
        assert header.e_lfanew == 0x80

    def test_to_bytes(self):
        """Test to_bytes generates valid DOS header."""
        header = PEHeader()
        data = header.to_bytes()

        assert len(data) == 64
        assert data[:2] == b"MZ"

    def test_custom_lfanew(self):
        """Test custom e_lfanew value."""
        header = PEHeader(e_lfanew=0x100)
        data = header.to_bytes()

        import struct

        lfanew = struct.unpack_from("<I", data, 60)[0]
        assert lfanew == 0x100


class TestELFHeader:
    """Test ELFHeader dataclass."""

    def test_default_values(self):
        """Test default ELF header values."""
        header = ELFHeader()
        assert header.ei_class == 1  # 32-bit
        assert header.ei_data == 1  # Little endian
        assert header.e_type == 2  # ET_EXEC

    def test_to_bytes(self):
        """Test to_bytes generates valid ELF header."""
        header = ELFHeader()
        data = header.to_bytes()

        assert len(data) == 128
        assert data[:4] == b"\x7fELF"

    def test_to_bytes_elf_class(self):
        """Test ELF class is written correctly."""
        header = ELFHeader(ei_class=2)  # 64-bit
        data = header.to_bytes()

        assert data[4] == 2


class TestPreambleAttackGeneratorInit:
    """Test PreambleAttackGenerator initialization."""

    def test_init_succeeds(self):
        """Test generator can be initialized."""
        generator = PreambleAttackGenerator()
        assert generator is not None


class TestCreateMinimalDicom:
    """Test create_minimal_dicom method."""

    def test_creates_valid_dataset(self):
        """Test that minimal DICOM is valid."""
        generator = PreambleAttackGenerator()
        ds = generator.create_minimal_dicom()

        assert ds.PatientName == "POLYGLOT^TEST"
        assert ds.PatientID == "SECURITY-TEST-001"
        assert ds.Modality == "OT"
        assert ds.Rows == 8
        assert ds.Columns == 8


class TestCreatePeDicom:
    """Test create_pe_dicom method."""

    def test_creates_polyglot(self, tmp_path):
        """Test that PE/DICOM polyglot is created."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "pe_dicom.dcm"

        path = generator.create_pe_dicom(output)

        assert path.exists()

    def test_has_mz_header(self, tmp_path):
        """Test that file has MZ header."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "pe_dicom.dcm"

        path = generator.create_pe_dicom(output)

        with open(path, "rb") as f:
            magic = f.read(2)

        assert magic == b"MZ"

    def test_has_dicm_marker(self, tmp_path):
        """Test that file has DICM marker."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "pe_dicom.dcm"

        path = generator.create_pe_dicom(output)

        with open(path, "rb") as f:
            f.seek(128)
            dicm = f.read(4)

        assert dicm == b"DICM"

    def test_with_template(self, tmp_path):
        """Test creating polyglot with template dataset."""
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, generate_uid

        # Create template
        template = Dataset()
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        template.file_meta = file_meta
        template.PatientName = "TEMPLATE^TEST"
        template.PatientID = "TEMPLATE-001"
        template.SOPClassUID = file_meta.MediaStorageSOPClassUID
        template.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        template.Rows = 16
        template.Columns = 16
        template.BitsAllocated = 8
        template.BitsStored = 8
        template.HighBit = 7
        template.PixelRepresentation = 0
        template.SamplesPerPixel = 1
        template.PhotometricInterpretation = "MONOCHROME2"
        template.PixelData = bytes([128] * 256)

        generator = PreambleAttackGenerator()
        output = tmp_path / "pe_template.dcm"

        path = generator.create_pe_dicom(output, dicom_template=template)
        assert path.exists()


class TestCreateElfDicom:
    """Test create_elf_dicom method."""

    def test_creates_polyglot(self, tmp_path):
        """Test that ELF/DICOM polyglot is created."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "elf_dicom.dcm"

        path = generator.create_elf_dicom(output)

        assert path.exists()

    def test_has_elf_header(self, tmp_path):
        """Test that file has ELF header."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "elf_dicom.dcm"

        path = generator.create_elf_dicom(output)

        with open(path, "rb") as f:
            magic = f.read(4)

        assert magic == b"\x7fELF"

    def test_has_dicm_marker(self, tmp_path):
        """Test that file has DICM marker."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "elf_dicom.dcm"

        path = generator.create_elf_dicom(output)

        with open(path, "rb") as f:
            f.seek(128)
            dicm = f.read(4)

        assert dicm == b"DICM"


class TestValidatePolyglot:
    """Test validate_polyglot method."""

    def test_validates_pe_dicom(self, tmp_path):
        """Test validation of PE/DICOM polyglot."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "pe_dicom.dcm"
        generator.create_pe_dicom(output)

        results = generator.validate_polyglot(output)

        assert results["is_dicom"] is True
        assert results["is_pe"] is True
        assert results["preamble_type"] == "PE (Windows)"
        assert results["is_polyglot"] is True

    def test_validates_elf_dicom(self, tmp_path):
        """Test validation of ELF/DICOM polyglot."""
        generator = PreambleAttackGenerator()
        output = tmp_path / "elf_dicom.dcm"
        generator.create_elf_dicom(output)

        results = generator.validate_polyglot(output)

        assert results["is_dicom"] is True
        assert results["is_elf"] is True
        assert results["preamble_type"] == "ELF (Linux)"
        assert results["is_polyglot"] is True


class TestSanitizePreamble:
    """Test sanitize_preamble static method."""

    def test_sanitizes_pe_polyglot(self, tmp_path):
        """Test sanitization removes PE header."""
        generator = PreambleAttackGenerator()
        polyglot = tmp_path / "pe_dicom.dcm"
        sanitized = tmp_path / "sanitized.dcm"

        generator.create_pe_dicom(polyglot)
        PreambleAttackGenerator.sanitize_preamble(polyglot, sanitized)

        with open(sanitized, "rb") as f:
            preamble = f.read(128)

        # Preamble should be all nulls
        assert preamble == b"\x00" * 128

    def test_sanitized_file_is_valid_dicom(self, tmp_path):
        """Test that sanitized file is still valid DICOM."""
        import pydicom

        generator = PreambleAttackGenerator()
        polyglot = tmp_path / "pe_dicom.dcm"
        sanitized = tmp_path / "sanitized.dcm"

        generator.create_pe_dicom(polyglot)
        PreambleAttackGenerator.sanitize_preamble(polyglot, sanitized)

        # Should be readable as DICOM
        ds = pydicom.dcmread(sanitized)
        assert ds.PatientName == "POLYGLOT^TEST"


class TestMain:
    """Test main CLI function."""

    def test_main_pe_command(self, tmp_path, capsys):
        """Test PE subcommand."""
        output = tmp_path / "pe_test.dcm"

        with patch("sys.argv", ["generator", "pe", str(output)]):
            main()

        assert output.exists()
        captured = capsys.readouterr()
        assert "Created PE/DICOM polyglot" in captured.out

    def test_main_elf_command(self, tmp_path, capsys):
        """Test ELF subcommand."""
        output = tmp_path / "elf_test.dcm"

        with patch("sys.argv", ["generator", "elf", str(output)]):
            main()

        assert output.exists()
        captured = capsys.readouterr()
        assert "Created ELF/DICOM polyglot" in captured.out

    def test_main_validate_command(self, tmp_path, capsys):
        """Test validate subcommand."""
        generator = PreambleAttackGenerator()
        polyglot = tmp_path / "test.dcm"
        generator.create_pe_dicom(polyglot)

        with patch("sys.argv", ["generator", "validate", str(polyglot)]):
            main()

        captured = capsys.readouterr()
        assert "Is DICOM: True" in captured.out
        assert "Is PE: True" in captured.out

    def test_main_sanitize_command(self, tmp_path, capsys):
        """Test sanitize subcommand."""
        generator = PreambleAttackGenerator()
        polyglot = tmp_path / "polyglot.dcm"
        sanitized = tmp_path / "clean.dcm"
        generator.create_pe_dicom(polyglot)

        with patch(
            "sys.argv", ["generator", "sanitize", str(polyglot), str(sanitized)]
        ):
            main()

        assert sanitized.exists()
        captured = capsys.readouterr()
        assert "Sanitized file saved" in captured.out

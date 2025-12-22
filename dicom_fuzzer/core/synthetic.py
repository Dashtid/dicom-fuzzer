"""Synthetic DICOM File Generator.

Generates valid DICOM files with completely fabricated (synthetic) patient data.
All data is fake - no PHI concerns. Useful for fuzzing without needing real data.
"""

import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import UID, generate_uid

# Standard Transfer Syntax UIDs
IMPLICIT_VR_LITTLE_ENDIAN = "1.2.840.10008.1.2"
EXPLICIT_VR_LITTLE_ENDIAN = "1.2.840.10008.1.2.1"
EXPLICIT_VR_BIG_ENDIAN = "1.2.840.10008.1.2.2"

# SOP Class UIDs for common modalities
SOP_CLASS_UIDS = {
    "CT": "1.2.840.10008.5.1.4.1.1.2",
    "MR": "1.2.840.10008.5.1.4.1.1.4",
    "US": "1.2.840.10008.5.1.4.1.1.6.1",
    "CR": "1.2.840.10008.5.1.4.1.1.1",
    "DX": "1.2.840.10008.5.1.4.1.1.1.1",
    "PT": "1.2.840.10008.5.1.4.1.1.128",
    "NM": "1.2.840.10008.5.1.4.1.1.20",
    "XA": "1.2.840.10008.5.1.4.1.1.12.1",
    "RF": "1.2.840.10008.5.1.4.1.1.12.2",
    "SC": "1.2.840.10008.5.1.4.1.1.7",
}

# Photometric interpretation by modality
PHOTOMETRIC_INTERPRETATION = {
    "CT": "MONOCHROME2",
    "MR": "MONOCHROME2",
    "US": "RGB",
    "CR": "MONOCHROME2",
    "DX": "MONOCHROME2",
    "PT": "MONOCHROME2",
    "NM": "MONOCHROME2",
    "XA": "MONOCHROME2",
    "RF": "MONOCHROME2",
    "SC": "MONOCHROME2",
}


# Fake name components for generating synthetic patient names
FIRST_NAMES = [
    "John",
    "Jane",
    "Robert",
    "Emily",
    "Michael",
    "Sarah",
    "David",
    "Jennifer",
    "James",
    "Lisa",
    "William",
    "Maria",
    "Richard",
    "Susan",
    "Joseph",
    "Karen",
    "Thomas",
    "Nancy",
    "Charles",
    "Margaret",
    "Daniel",
    "Betty",
    "Matthew",
    "Sandra",
    "Anthony",
    "Ashley",
    "Mark",
    "Dorothy",
    "Donald",
    "Kimberly",
    "Steven",
    "Helen",
]

LAST_NAMES = [
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Perez",
    "Thompson",
    "White",
    "Harris",
    "Sanchez",
    "Clark",
    "Ramirez",
    "Lewis",
    "Robinson",
    "Walker",
]


@dataclass
class SyntheticPatient:
    """Synthetic patient data for DICOM generation."""

    name: str
    patient_id: str
    birth_date: str
    sex: str
    age: str


@dataclass
class SyntheticStudy:
    """Synthetic study data for DICOM generation."""

    study_instance_uid: str
    study_date: str
    study_time: str
    study_description: str
    accession_number: str
    referring_physician: str


@dataclass
class SyntheticSeries:
    """Synthetic series data for DICOM generation."""

    series_instance_uid: str
    series_number: int
    series_description: str
    modality: str
    body_part: str
    patient_position: str


class SyntheticDataGenerator:
    """Generate synthetic patient, study, and series data."""

    def __init__(self, seed: int | None = None) -> None:
        """Initialize with optional random seed for reproducibility."""
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

    def generate_patient(self) -> SyntheticPatient:
        """Generate a synthetic patient."""
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)
        name = f"{last_name}^{first_name}"

        patient_id = "".join(random.choices(string.digits, k=8))

        # Generate birth date (20-80 years ago)
        days_ago = random.randint(20 * 365, 80 * 365)
        birth_date = datetime.now() - timedelta(days=days_ago)
        birth_date_str = birth_date.strftime("%Y%m%d")

        sex = random.choice(["M", "F", "O"])

        age_years = days_ago // 365
        age = f"{age_years:03d}Y"

        return SyntheticPatient(
            name=name,
            patient_id=patient_id,
            birth_date=birth_date_str,
            sex=sex,
            age=age,
        )

    def generate_study(self) -> SyntheticStudy:
        """Generate a synthetic study."""
        # Generate study date (within last 2 years)
        days_ago = random.randint(0, 730)
        study_date = datetime.now() - timedelta(days=days_ago)
        study_date_str = study_date.strftime("%Y%m%d")
        study_time_str = f"{random.randint(6, 22):02d}{random.randint(0, 59):02d}{random.randint(0, 59):02d}"

        descriptions = [
            "Routine Examination",
            "Follow-up Study",
            "Initial Assessment",
            "Pre-operative",
            "Post-operative",
            "Screening",
            "Diagnostic",
            "Emergency",
        ]

        referring = f"{random.choice(LAST_NAMES)}^{random.choice(FIRST_NAMES)[0]}"
        accession = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=10)
        )

        return SyntheticStudy(
            study_instance_uid=generate_uid(),
            study_date=study_date_str,
            study_time=study_time_str,
            study_description=random.choice(descriptions),
            accession_number=accession,
            referring_physician=referring,
        )

    def generate_series(self, modality: str | None = None) -> SyntheticSeries:
        """Generate a synthetic series for the given modality."""
        if modality is None:
            modality = random.choice(list(SOP_CLASS_UIDS.keys()))

        body_parts = {
            "CT": ["HEAD", "CHEST", "ABDOMEN", "PELVIS", "SPINE", "EXTREMITY"],
            "MR": ["HEAD", "BRAIN", "SPINE", "KNEE", "SHOULDER", "ABDOMEN"],
            "US": ["ABDOMEN", "PELVIS", "THYROID", "BREAST", "HEART"],
            "CR": ["CHEST", "HAND", "FOOT", "KNEE", "SPINE"],
            "DX": ["CHEST", "HAND", "FOOT", "KNEE", "SPINE"],
            "PT": ["WHOLEBODY", "CHEST", "HEAD", "BRAIN"],
            "NM": ["WHOLEBODY", "BONE", "THYROID", "HEART"],
            "XA": ["HEART", "VESSEL"],
            "RF": ["CHEST", "ABDOMEN", "GI TRACT"],
            "SC": ["WHOLEBODY"],
        }

        positions = ["HFS", "HFP", "FFS", "FFP", "HFDR", "HFDL", "FFDR", "FFDL"]

        series_descriptions = {
            "CT": ["Axial", "Helical", "Scout", "Contrast", "Non-contrast"],
            "MR": ["T1", "T2", "FLAIR", "DWI", "ADC", "Post-contrast"],
            "US": ["B-mode", "Doppler", "M-mode"],
            "CR": ["PA", "Lateral", "AP", "Oblique"],
            "DX": ["PA", "Lateral", "AP", "Oblique"],
            "PT": ["Static", "Whole Body", "Dynamic"],
            "NM": ["Static", "Whole Body", "SPECT"],
            "XA": ["Angiography", "Fluoroscopy"],
            "RF": ["Fluoroscopy", "Spot"],
            "SC": ["Secondary Capture"],
        }

        return SyntheticSeries(
            series_instance_uid=generate_uid(),
            series_number=random.randint(1, 10),
            series_description=random.choice(
                series_descriptions.get(modality, ["Series"])
            ),
            modality=modality,
            body_part=random.choice(body_parts.get(modality, ["UNKNOWN"])),
            patient_position=random.choice(positions),
        )


class SyntheticDicomGenerator:
    """Generate complete synthetic DICOM files."""

    def __init__(
        self,
        output_dir: str | Path = "./synthetic_dicoms",
        seed: int | None = None,
    ) -> None:
        """Initialize the generator.

        Args:
            output_dir: Directory to save generated files
            seed: Random seed for reproducibility

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data_gen = SyntheticDataGenerator(seed)

    def generate_file(
        self,
        modality: str = "CT",
        rows: int = 256,
        columns: int = 256,
        filename: str | None = None,
        patient: SyntheticPatient | None = None,
        study: SyntheticStudy | None = None,
        series: SyntheticSeries | None = None,
        extra_tags: dict[str, Any] | None = None,
    ) -> Path:
        """Generate a single synthetic DICOM file.

        Args:
            modality: DICOM modality (CT, MR, US, CR, etc.)
            rows: Image rows
            columns: Image columns
            filename: Output filename (auto-generated if None)
            patient: Patient data (auto-generated if None)
            study: Study data (auto-generated if None)
            series: Series data (auto-generated if None)
            extra_tags: Additional DICOM tags to set

        Returns:
            Path to the generated file

        """
        # Generate synthetic data if not provided
        if patient is None:
            patient = self.data_gen.generate_patient()
        if study is None:
            study = self.data_gen.generate_study()
        if series is None:
            series = self.data_gen.generate_series(modality)

        # Generate filename if not provided
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            random_suffix = "".join(random.choices(string.ascii_lowercase, k=4))
            filename = f"synthetic_{modality}_{timestamp}_{random_suffix}.dcm"

        output_path = self.output_dir / filename

        # Create file metadata
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = UID(
            SOP_CLASS_UIDS.get(modality, SOP_CLASS_UIDS["CT"])
        )
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = UID(EXPLICIT_VR_LITTLE_ENDIAN)
        file_meta.ImplementationClassUID = generate_uid()
        file_meta.ImplementationVersionName = "DICOM_FUZZER_1.0"

        # Create dataset
        ds = FileDataset(
            str(output_path),
            {},
            file_meta=file_meta,
            preamble=b"\x00" * 128,
        )

        # Set SOP class and instance
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID

        # Set patient information
        ds.PatientName = patient.name
        ds.PatientID = patient.patient_id
        ds.PatientBirthDate = patient.birth_date
        ds.PatientSex = patient.sex
        ds.PatientAge = patient.age

        # Set study information
        ds.StudyInstanceUID = study.study_instance_uid
        ds.StudyDate = study.study_date
        ds.StudyTime = study.study_time
        ds.StudyDescription = study.study_description
        ds.AccessionNumber = study.accession_number
        ds.ReferringPhysicianName = study.referring_physician
        ds.StudyID = "".join(random.choices(string.digits, k=6))

        # Set series information
        ds.SeriesInstanceUID = series.series_instance_uid
        ds.SeriesNumber = series.series_number
        ds.SeriesDescription = series.series_description
        ds.Modality = series.modality
        ds.BodyPartExamined = series.body_part
        ds.PatientPosition = series.patient_position

        # Set instance information
        ds.InstanceNumber = random.randint(1, 100)
        ds.ContentDate = study.study_date
        ds.ContentTime = study.study_time

        # Set image parameters
        ds.Rows = rows
        ds.Columns = columns
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.HighBit = 11
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1

        # Modality-specific settings
        photometric = PHOTOMETRIC_INTERPRETATION.get(modality, "MONOCHROME2")
        ds.PhotometricInterpretation = photometric

        if photometric == "RGB":
            ds.SamplesPerPixel = 3
            ds.PlanarConfiguration = 0

        # Generate synthetic pixel data
        ds.PixelData = self._generate_pixel_data(rows, columns, modality, photometric)

        # Add modality-specific tags
        self._add_modality_tags(ds, modality)

        # Apply extra tags if provided
        if extra_tags:
            for key, value in extra_tags.items():
                if hasattr(ds, key):
                    setattr(ds, key, value)

        # Save the file
        ds.save_as(str(output_path), write_like_original=False)

        return output_path

    def generate_batch(
        self,
        count: int = 10,
        modality: str | None = None,
        modalities: list[str] | None = None,
        rows: int = 256,
        columns: int = 256,
    ) -> list[Path]:
        """Generate a batch of synthetic DICOM files.

        Args:
            count: Number of files to generate
            modality: Single modality for all files (overrides modalities)
            modalities: List of modalities to choose from
            rows: Image rows
            columns: Image columns

        Returns:
            List of paths to generated files

        """
        if modalities is None:
            modalities = list(SOP_CLASS_UIDS.keys())

        generated = []
        for _ in range(count):
            mod = modality if modality else random.choice(modalities)
            path = self.generate_file(modality=mod, rows=rows, columns=columns)
            generated.append(path)

        return generated

    def generate_series(
        self,
        count: int = 10,
        modality: str = "CT",
        rows: int = 256,
        columns: int = 256,
    ) -> list[Path]:
        """Generate a series of synthetic DICOM files with consistent UIDs.

        All files share the same patient, study, and series information,
        simulating a real DICOM series (like CT slices).

        Args:
            count: Number of slices/images in the series
            modality: DICOM modality
            rows: Image rows
            columns: Image columns

        Returns:
            List of paths to generated files

        """
        # Generate shared data for the series
        patient = self.data_gen.generate_patient()
        study = self.data_gen.generate_study()
        series = self.data_gen.generate_series(modality)

        generated = []
        for i in range(count):
            # Generate unique instance but keep patient/study/series same
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"synthetic_{modality}_series_{i:04d}_{timestamp}.dcm"

            extra_tags = {
                "InstanceNumber": i + 1,
                "SliceLocation": float(i * 2.5),  # 2.5mm spacing
                "ImagePositionPatient": [0.0, 0.0, float(i * 2.5)],
                "ImageOrientationPatient": [1.0, 0.0, 0.0, 0.0, 1.0, 0.0],
                "SliceThickness": 2.5,
                "SpacingBetweenSlices": 2.5,
            }

            path = self.generate_file(
                modality=modality,
                rows=rows,
                columns=columns,
                filename=filename,
                patient=patient,
                study=study,
                series=series,
                extra_tags=extra_tags,
            )
            generated.append(path)

        return generated

    def _generate_pixel_data(
        self,
        rows: int,
        columns: int,
        modality: str,
        photometric: str,
    ) -> bytes:
        """Generate synthetic pixel data with realistic patterns."""
        if photometric == "RGB":
            # Generate color image for ultrasound, etc.
            pixels = np.zeros((rows, columns, 3), dtype=np.uint8)

            # Add some structure (circles, gradients)
            center_y, center_x = rows // 2, columns // 2
            y, x = np.ogrid[:rows, :columns]
            radius = min(rows, columns) // 3

            # Create circular pattern
            dist = np.sqrt((x - center_x) ** 2 + (y - center_y) ** 2)
            mask = dist < radius

            # Add gradient inside circle
            pixels[mask, 0] = np.clip(128 + (dist[mask] / radius * 100), 0, 255).astype(
                np.uint8
            )
            pixels[mask, 1] = np.clip(64 + (dist[mask] / radius * 50), 0, 255).astype(
                np.uint8
            )
            pixels[mask, 2] = np.clip(180 - (dist[mask] / radius * 80), 0, 255).astype(
                np.uint8
            )

            return bytes(pixels.tobytes())
        # Generate grayscale image
        grayscale_pixels: np.ndarray[tuple[int, int], np.dtype[np.uint16]]

        # Add modality-appropriate patterns
        if modality in ["CT", "MR"]:
            # Add anatomical-like structure (ellipse + noise)
            grayscale_pixels = np.zeros((rows, columns), dtype=np.uint16)
            center_y, center_x = rows // 2, columns // 2
            y, x = np.ogrid[:rows, :columns]

            # Outer ellipse (body outline)
            outer = ((x - center_x) / (columns * 0.4)) ** 2 + (
                (y - center_y) / (rows * 0.35)
            ) ** 2 < 1
            grayscale_pixels[outer] = 800 + np.random.randint(
                -50, 50, size=int(np.sum(outer))
            )

            # Inner structures
            inner = ((x - center_x) / (columns * 0.15)) ** 2 + (
                (y - center_y) / (rows * 0.12)
            ) ** 2 < 1
            grayscale_pixels[inner] = 1500 + np.random.randint(
                -100, 100, size=int(np.sum(inner))
            )

            # Add noise
            pixels_float = grayscale_pixels.astype(np.float64)
            pixels_float = pixels_float + np.random.normal(0, 30, pixels_float.shape)
            grayscale_pixels = np.clip(pixels_float, 0, 4095).astype(np.uint16)

        elif modality in ["CR", "DX"]:
            # Add X-ray like pattern (higher values = more absorption)
            gradient = np.linspace(500, 2000, columns)
            grayscale_pixels = np.tile(gradient, (rows, 1)).astype(np.uint16)
            grayscale_pixels = grayscale_pixels + np.random.randint(
                0, 200, grayscale_pixels.shape
            ).astype(np.uint16)

        else:
            # Generic pattern
            grayscale_pixels = np.random.randint(
                0, 4095, (rows, columns), dtype=np.uint16
            )

        return bytes(grayscale_pixels.tobytes())

    def _add_modality_tags(self, ds: Dataset, modality: str) -> None:
        """Add modality-specific DICOM tags."""
        if modality == "CT":
            ds.KVP = random.choice([80, 100, 120, 140])
            ds.ExposureTime = random.randint(500, 2000)
            ds.XRayTubeCurrent = random.randint(100, 400)
            ds.SliceThickness = random.choice([0.625, 1.0, 1.25, 2.5, 5.0])
            ds.ConvolutionKernel = random.choice(["STANDARD", "BONE", "SOFT"])
            ds.ReconstructionDiameter = 350.0
            ds.WindowCenter = random.choice([40, 400, 600])
            ds.WindowWidth = random.choice([400, 1500, 2000])

        elif modality == "MR":
            ds.MagneticFieldStrength = random.choice([1.5, 3.0])
            ds.RepetitionTime = random.randint(500, 5000)
            ds.EchoTime = random.randint(10, 150)
            ds.FlipAngle = random.choice([15, 30, 60, 90])
            ds.SliceThickness = random.choice([1.0, 2.0, 3.0, 5.0])
            ds.SpacingBetweenSlices = random.choice([1.0, 2.0, 3.0, 5.0])

        elif modality == "US":
            ds.TransducerType = random.choice(["LINEAR", "CURVED", "PHASED"])
            ds.MechanicalIndex = round(random.uniform(0.1, 1.2), 2)
            ds.ThermalIndex = round(random.uniform(0.1, 2.0), 2)

        elif modality in ["CR", "DX"]:
            ds.KVP = random.choice([60, 80, 100, 120])
            ds.ExposureTime = random.randint(10, 100)
            ds.Exposure = random.randint(1, 10)
            ds.DistanceSourceToDetector = 1000.0
            ds.DistanceSourceToPatient = 900.0

        elif modality == "PT":
            ds.RadiopharmaceuticalInformationSequence = []
            ds.Units = "BQML"
            ds.DecayCorrection = "START"
            ds.AttenuationCorrectionMethod = "measured"

        elif modality == "NM":
            ds.RadiopharmaceuticalInformationSequence = []
            ds.NumberOfFrames = 1
            ds.EnergyWindowInformationSequence = []


def generate_sample_files(
    output_dir: str | Path,
    count: int = 10,
    modalities: list[str] | None = None,
) -> list[Path]:
    """Convenience function to generate sample synthetic DICOM files.

    Args:
        output_dir: Directory to save files
        count: Number of files to generate
        modalities: List of modalities (None = all supported)

    Returns:
        List of paths to generated files

    """
    generator = SyntheticDicomGenerator(output_dir)
    return generator.generate_batch(count=count, modalities=modalities)

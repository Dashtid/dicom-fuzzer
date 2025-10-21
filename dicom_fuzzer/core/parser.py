"""DICOM file parsing module with comprehensive validation and security features.

This module provides secure parsing capabilities for DICOM files,
with extensive validation, error handling, and security considerations.
"""

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional, Union

import numpy as np
import pydicom
from pydicom.dataset import Dataset
from pydicom.tag import Tag

from .exceptions import ParsingError, SecurityViolationError, ValidationError

logger = logging.getLogger(__name__)


class DicomParser:
    """Professional DICOM parser with comprehensive validation and security features.

    This parser provides secure DICOM file parsing with extensive validation,
    error handling, and security checks to prevent malicious input exploitation.

    Attributes:
        file_path: Path to the DICOM file
        dataset: Parsed DICOM dataset
        metadata_cache: Cached metadata for performance
        security_checks_enabled: Whether to perform security validation
    """

    # Critical DICOM tags that should never be mutated for safety
    CRITICAL_TAGS = {
        Tag(0x0008, 0x0016),  # SOPClassUID
        Tag(0x0008, 0x0018),  # SOPInstanceUID
        Tag(0x0020, 0x000D),  # StudyInstanceUID
        Tag(0x0020, 0x000E),  # SeriesInstanceUID
    }

    # Maximum safe file size (100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    def __init__(
        self,
        file_path: Union[str, Path],
        security_checks: bool = True,
        max_file_size: Optional[int] = None,
    ) -> None:
        """Initialize DICOM parser with security validation.

        Args:
            file_path: Path to DICOM file to parse
            security_checks: Enable security validation checks
            max_file_size: Maximum allowed file size in bytes

        Raises:
            ParsingError: If file cannot be parsed
            SecurityViolationError: If security checks fail
            ValidationError: If file validation fails
        """
        self.file_path = Path(file_path)
        self.security_checks_enabled = security_checks
        self.max_file_size = max_file_size or self.MAX_FILE_SIZE
        self._metadata_cache: Optional[Dict[str, Any]] = None
        self._dataset: Optional[Dataset] = None

        # Validate file before parsing
        if self.security_checks_enabled:
            self._perform_security_checks()

        try:
            self._parse_dicom_file()
        except Exception as e:
            logger.error(f"Failed to parse DICOM file {self.file_path}: {e}")
            raise ParsingError(
                f"Failed to parse DICOM file: {e}",
                error_code="PARSE_FAILED",
                context={"file_path": str(self.file_path)},
            )

    def _perform_security_checks(self) -> None:
        """Perform comprehensive security validation on the DICOM file.

        Raises:
            SecurityViolationError: If security checks fail
        """
        # Check file existence and permissions
        if not self.file_path.exists():
            raise SecurityViolationError(
                f"File does not exist: {self.file_path}", error_code="FILE_NOT_FOUND"
            )

        if not self.file_path.is_file():
            raise SecurityViolationError(
                f"Path is not a regular file: {self.file_path}",
                error_code="INVALID_FILE_TYPE",
            )

        # Check file size
        file_size = self.file_path.stat().st_size
        if file_size > self.max_file_size:
            raise SecurityViolationError(
                f"File size {file_size} exceeds maximum {self.max_file_size}",
                error_code="FILE_TOO_LARGE",
                context={"file_size": file_size, "max_size": self.max_file_size},
            )

        # Check for suspicious file extensions
        if self.file_path.suffix.lower() not in {".dcm", ".dicom", ""}:
            logger.warning(f"Unusual file extension: {self.file_path.suffix}")

    def _parse_dicom_file(self) -> None:
        """Parse the DICOM file with comprehensive error handling."""
        try:
            # Use force=True to handle non-standard DICOM files
            self._dataset = pydicom.dcmread(
                str(self.file_path), force=True, stop_before_pixels=False
            )

            # Validate dataset structure
            self._validate_dataset()

        except (pydicom.errors.InvalidDicomError, IOError) as e:
            raise ParsingError(
                f"Invalid DICOM file format: {e}", error_code="INVALID_DICOM_FORMAT"
            )

    def _validate_dataset(self) -> None:
        """Validate the parsed DICOM dataset structure.

        Raises:
            ValidationError: If dataset validation fails
        """
        if self._dataset is None:
            raise ValidationError("Dataset is None after parsing")

        # Check for required elements
        required_elements = [
            Tag(0x0008, 0x0016),  # SOPClassUID
            Tag(0x0008, 0x0018),  # SOPInstanceUID
        ]

        missing_elements = []
        for tag in required_elements:
            if tag not in self._dataset:
                missing_elements.append(str(tag))

        if missing_elements:
            raise ValidationError(
                f"Missing required DICOM elements: {missing_elements}",
                error_code="MISSING_REQUIRED_ELEMENTS",
                context={"missing_elements": missing_elements},
            )

    @property
    def dataset(self) -> Dataset:
        """Get the parsed DICOM dataset.

        Returns:
            The parsed pydicom Dataset object

        Raises:
            ParsingError: If dataset is not available
        """
        if self._dataset is None:
            raise ParsingError("Dataset not available - parsing may have failed")
        return self._dataset

    def extract_metadata(self, include_private: bool = False) -> Dict[str, Any]:
        """Extract comprehensive metadata from the DICOM file.

        Args:
            include_private: Whether to include private tags in metadata

        Returns:
            Dictionary containing extracted metadata

        Security:
            Private tags may contain sensitive information and should be
            handled with care in production environments.
        """
        if self._metadata_cache is not None:
            return self._metadata_cache

        metadata = {}

        # Standard metadata extraction with error handling
        metadata_fields = {
            "patient_id": (Tag(0x0010, 0x0020), "PatientID"),
            "patient_name": (Tag(0x0010, 0x0010), "PatientName"),
            "patient_birth_date": (Tag(0x0010, 0x0030), "PatientBirthDate"),
            "patient_sex": (Tag(0x0010, 0x0040), "PatientSex"),
            "study_date": (Tag(0x0008, 0x0020), "StudyDate"),
            "study_time": (Tag(0x0008, 0x0030), "StudyTime"),
            "study_description": (Tag(0x0008, 0x1030), "StudyDescription"),
            "modality": (Tag(0x0008, 0x0060), "Modality"),
            "institution_name": (Tag(0x0008, 0x0080), "InstitutionName"),
            "manufacturer": (Tag(0x0008, 0x0070), "Manufacturer"),
            "manufacturer_model": (Tag(0x0008, 0x1090), "ManufacturerModelName"),
            "software_version": (Tag(0x0018, 0x1020), "SoftwareVersions"),
            "sop_class_uid": (Tag(0x0008, 0x0016), "SOPClassUID"),
            "sop_instance_uid": (Tag(0x0008, 0x0018), "SOPInstanceUID"),
            "study_instance_uid": (Tag(0x0020, 0x000D), "StudyInstanceUID"),
            "series_instance_uid": (Tag(0x0020, 0x000E), "SeriesInstanceUID"),
        }

        for field_name, (tag, keyword) in metadata_fields.items():
            try:
                value = self.dataset.get(tag, None)
                if value is not None:
                    # Convert to string and sanitize
                    metadata[field_name] = str(value).strip()
                else:
                    metadata[field_name] = ""
            except Exception as e:
                logger.warning(f"Failed to extract {field_name}: {e}")
                metadata[field_name] = ""

        # Add image-specific metadata if present
        # Check for PixelData tag instead of pixel_array property
        try:
            if "PixelData" in self.dataset:
                try:
                    pixel_array = self.dataset.pixel_array
                    metadata.update(
                        {
                            "has_pixel_data": True,
                            "image_shape": pixel_array.shape,
                            "image_dtype": str(pixel_array.dtype),
                            "rows": getattr(self.dataset, "Rows", None),
                            "columns": getattr(self.dataset, "Columns", None),
                            "bits_allocated": getattr(
                                self.dataset, "BitsAllocated", None
                            ),
                            "bits_stored": getattr(self.dataset, "BitsStored", None),
                            "samples_per_pixel": getattr(
                                self.dataset, "SamplesPerPixel", None
                            ),
                        }
                    )
                except Exception as e:
                    # PixelData exists but can't be decoded
                    logger.warning(f"PixelData exists but can't be decoded: {e}")
                    metadata["has_pixel_data"] = True
                    metadata["rows"] = getattr(self.dataset, "Rows", None)
                    metadata["columns"] = getattr(self.dataset, "Columns", None)
                    metadata["bits_allocated"] = getattr(
                        self.dataset, "BitsAllocated", None
                    )
                    metadata["bits_stored"] = getattr(self.dataset, "BitsStored", None)
                    metadata["samples_per_pixel"] = getattr(
                        self.dataset, "SamplesPerPixel", None
                    )
            else:
                metadata["has_pixel_data"] = False
        except Exception as e:
            logger.warning(f"Failed to extract pixel metadata: {e}")
            metadata["has_pixel_data"] = False

        # Include private tags if requested
        if include_private:
            metadata["private_tags"] = self._extract_private_tags()

        self._metadata_cache = metadata
        return metadata

    def _extract_private_tags(self) -> Dict[str, Any]:
        """Extract private DICOM tags.

        Returns:
            Dictionary of private tags

        Security:
            Private tags may contain sensitive or proprietary information.
        """
        private_tags = {}

        for tag, element in self.dataset.items():
            if tag.is_private:
                try:
                    private_tags[str(tag)] = {
                        "value": str(element.value) if element.value else "",
                        "vr": element.VR if hasattr(element, "VR") else "UN",
                        "keyword": (
                            element.keyword if hasattr(element, "keyword") else ""
                        ),
                    }
                except Exception as e:
                    logger.warning(f"Failed to extract private tag {tag}: {e}")

        return private_tags

    def get_pixel_data(self, validate: bool = True) -> Optional[np.ndarray]:
        """Extract pixel array with validation.

        Args:
            validate: Whether to validate pixel data integrity

        Returns:
            Numpy array of pixel data or None if not present

        Raises:
            ValidationError: If pixel data validation fails
        """
        try:
            if not hasattr(self.dataset, "pixel_array"):
                return None

            pixel_array = self.dataset.pixel_array

            if validate:
                self._validate_pixel_data(pixel_array)

            return pixel_array

        except Exception as e:
            logger.error(f"Failed to extract pixel data: {e}")
            if validate:
                raise ValidationError(
                    f"Pixel data validation failed: {e}",
                    error_code="PIXEL_DATA_INVALID",
                )
            return None

    def _validate_pixel_data(self, pixel_array: np.ndarray) -> None:
        """Validate pixel data integrity and safety.

        Args:
            pixel_array: Pixel data to validate

        Raises:
            ValidationError: If validation fails
        """
        # Check array properties
        if pixel_array.size == 0:
            raise ValidationError("Pixel array is empty")

        # Check for reasonable image dimensions
        if pixel_array.ndim not in {2, 3, 4}:
            raise ValidationError(f"Invalid pixel array dimensions: {pixel_array.ndim}")

        # Check for excessive memory usage (>500MB)
        memory_size = pixel_array.nbytes
        max_memory = 500 * 1024 * 1024
        if memory_size > max_memory:
            raise ValidationError(
                f"Pixel data too large: {memory_size} bytes",
                error_code="PIXEL_DATA_TOO_LARGE",
            )

    def get_transfer_syntax(self) -> Optional[str]:
        """Get the transfer syntax of the DICOM file.

        Returns:
            Transfer syntax UID or None if not available
        """
        try:
            return getattr(self.dataset, "file_meta", {}).get("TransferSyntaxUID", None)
        except Exception as e:
            logger.warning(f"Failed to get transfer syntax: {e}")
            return None

    def is_compressed(self) -> bool:
        """Check if the DICOM file uses compressed transfer syntax.

        Returns:
            True if compressed, False otherwise
        """
        transfer_syntax = self.get_transfer_syntax()
        if not transfer_syntax:
            return False

        # Common compressed transfer syntaxes
        compressed_syntaxes = {
            "1.2.840.10008.1.2.4.50",  # JPEG Baseline
            "1.2.840.10008.1.2.4.51",  # JPEG Extended
            "1.2.840.10008.1.2.4.57",  # JPEG Lossless
            "1.2.840.10008.1.2.4.70",  # JPEG Lossless SV1
            "1.2.840.10008.1.2.4.80",  # JPEG-LS Lossless
            "1.2.840.10008.1.2.4.81",  # JPEG-LS Lossy
            "1.2.840.10008.1.2.4.90",  # JPEG 2000 Lossless
            "1.2.840.10008.1.2.4.91",  # JPEG 2000
            "1.2.840.10008.1.2.5",  # RLE Lossless
        }

        return transfer_syntax in compressed_syntaxes

    def get_critical_tags(self) -> Dict[str, Any]:
        """Extract critical DICOM tags that should not be mutated.

        Returns:
            Dictionary of critical tag values

        Security:
            These tags are essential for DICOM functionality and should
            be preserved during fuzzing operations.
        """
        critical_data = {}

        for tag in self.CRITICAL_TAGS:
            try:
                if tag in self.dataset:
                    critical_data[str(tag)] = str(self.dataset[tag].value)
            except Exception as e:
                logger.warning(f"Failed to extract critical tag {tag}: {e}")

        return critical_data

    @contextmanager
    def temporary_mutation(self):
        """Context manager for temporary dataset mutations.

        This allows safe temporary modifications that are automatically
        reverted when the context exits.

        Yields:
            The dataset for temporary modification
        """
        # Create a deep copy for mutation
        original_state = self.dataset.copy()

        try:
            yield self.dataset
        finally:
            # Restore original state
            self._dataset = original_state
            # Clear metadata cache
            self._metadata_cache = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        # Clear caches and references
        self._metadata_cache = None
        self._dataset = None

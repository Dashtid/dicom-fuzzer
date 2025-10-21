"""
DICOM Validator Module

LEARNING OBJECTIVE: This module demonstrates data validation, error handling,
and defensive programming patterns essential for security-critical applications.

CONCEPT: The validator acts as a "quality control inspector" that checks DICOM
files for correctness, compliance, and security issues.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import SecurityEventLogger, get_logger

# Get logger for this module
logger = get_logger(__name__)
security_logger = SecurityEventLogger(logger)


class ValidationResult:
    """
    LEARNING: This class encapsulates validation results with details.

    CONCEPT: Rather than just returning True/False, we return detailed
    information about what passed and what failed.
    """

    def __init__(self, is_valid: bool = True):
        """Initialize validation result.

        Args:
            is_valid: Whether validation passed overall
        """
        self.is_valid = is_valid
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: Dict[str, Any] = {}

    def add_error(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Add an error message to the result.

        Args:
            message: Error description
            context: Additional context information
        """
        self.errors.append(message)
        self.is_valid = False
        if context:
            self.info[message] = context

    def add_warning(
        self, message: str, context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a warning message to the result.

        Args:
            message: Warning description
            context: Additional context information
        """
        self.warnings.append(message)
        if context:
            self.info[message] = context

    def __bool__(self) -> bool:
        """Allow using result in boolean context.

        Returns:
            bool: Whether validation passed

        Example:
            >>> result = ValidationResult()
            >>> if result:
            ...     print("Valid!")
        """
        return self.is_valid

    def __str__(self) -> str:
        """Get string representation of validation result.

        Returns:
            str: Human-readable summary
        """
        if self.is_valid and not self.warnings:
            return "[PASS] Validation passed"

        lines = []
        if not self.is_valid:
            lines.append(f"[FAIL] Validation failed with {len(self.errors)} error(s)")
            for error in self.errors:
                lines.append(f"  - {error}")  # noqa: E221

        if self.warnings:
            lines.append(f"[WARN] {len(self.warnings)} warning(s)")
            for warning in self.warnings:
                lines.append(f"  - {warning}")  # noqa: E221

        return "\n".join(lines)


class DicomValidator:
    """
    LEARNING: This class validates DICOM files for correctness and compliance.

    CONCEPT: Validation ensures that generated/mutated DICOM files are:
    1. Structurally correct (proper format)
    2. Compliant with DICOM standards
    3. Secure (no malicious content)
    4. Parseable by target systems
    """

    # LEARNING: Class variables define required tags for different modalities
    REQUIRED_TAGS = {
        "Patient": [
            Tag(0x0010, 0x0010),  # Patient's Name
            Tag(0x0010, 0x0020),  # Patient ID
        ],
        "Study": [
            Tag(0x0020, 0x000D),  # Study Instance UID
            Tag(0x0008, 0x0020),  # Study Date
        ],
        "Series": [
            Tag(0x0020, 0x000E),  # Series Instance UID
            Tag(0x0008, 0x0060),  # Modality
        ],
        "Image": [
            Tag(0x0008, 0x0016),  # SOP Class UID
            Tag(0x0008, 0x0018),  # SOP Instance UID
        ],
    }

    def __init__(
        self, strict_mode: bool = False, max_file_size: int = 100 * 1024 * 1024
    ):
        """Initialize DICOM validator.

        Args:
            strict_mode: Whether to enforce strict DICOM compliance
            max_file_size: Maximum allowed file size in bytes (default 100MB)
        """
        self.strict_mode = strict_mode
        self.max_file_size = max_file_size

        logger.info(
            "DicomValidator initialized",
            strict_mode=strict_mode,
            max_file_size_mb=max_file_size / (1024 * 1024),
        )

    def validate(
        self,
        dataset: Dataset,
        check_required_tags: bool = True,
        check_values: bool = True,
        check_security: bool = True,
    ) -> ValidationResult:
        """Validate DICOM dataset comprehensively.

        LEARNING: This method orchestrates multiple validation checks.

        Args:
            dataset: DICOM dataset to validate
            check_required_tags: Whether to check for required tags
            check_values: Whether to validate tag values
            check_security: Whether to perform security checks

        Returns:
            ValidationResult: Detailed validation results
        """
        result = ValidationResult()

        # Check basic structure
        if not self._validate_structure(dataset, result):
            # If structure is invalid, skip other checks
            logger.warning("Structure validation failed, skipping further checks")
            return result

        # Check required tags
        if check_required_tags:
            self._validate_required_tags(dataset, result)

        # Check tag values
        if check_values:
            self._validate_tag_values(dataset, result)

        # Security validation
        if check_security:
            self._validate_security(dataset, result)

        # Log validation summary
        if result.is_valid:
            logger.info("Validation passed", warnings=len(result.warnings))
        else:
            logger.error(
                "Validation failed",
                errors=len(result.errors),
                warnings=len(result.warnings),
            )
            security_logger.log_validation_failure(
                file_path="dataset",
                reason=f"{len(result.errors)} validation error(s)",
                details={"errors": result.errors[:5]},  # First 5 errors
            )

        return result

    def validate_file(
        self, file_path: Path, parse_dataset: bool = True
    ) -> Tuple[ValidationResult, Optional[Dataset]]:
        """Validate DICOM file from disk.

        Args:
            file_path: Path to DICOM file
            parse_dataset: Whether to parse and validate the dataset

        Returns:
            Tuple of (ValidationResult, Optional[Dataset])
        """
        result = ValidationResult()
        dataset = None

        # Check file exists
        file_path = Path(file_path)
        if not file_path.exists():
            result.add_error(f"File does not exist: {file_path}")
            return result, None

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            result.add_error(
                f"File size {file_size} exceeds maximum {self.max_file_size}",
                context={"file_size": file_size, "max_size": self.max_file_size},
            )
            return result, None

        if file_size == 0:
            result.add_error("File is empty")
            return result, None

        # Try to parse the file
        if parse_dataset:
            try:
                import pydicom

                dataset = pydicom.dcmread(file_path, force=True)

                # Check if file has valid DICOM structure (preamble + file_meta)
                # force=True allows reading malformed DICOM, but completely invalid files
                # will have no preamble and empty file_meta
                if not hasattr(dataset, "preamble") or dataset.preamble is None:
                    if not hasattr(dataset, "file_meta") or len(dataset.file_meta) == 0:
                        result.add_error(
                            "File does not appear to be valid DICOM format "
                            "(missing DICOM preamble and file meta information)"
                        )
                        return result, dataset

                # Validate the parsed dataset
                validation_result = self.validate(dataset)
                result.errors.extend(validation_result.errors)
                result.warnings.extend(validation_result.warnings)
                result.is_valid = validation_result.is_valid

            except Exception as e:
                result.add_error(
                    f"Failed to parse DICOM file: {e}", context={"exception": str(e)}
                )
                return result, None

        return result, dataset

    def _validate_structure(self, dataset: Dataset, result: ValidationResult) -> bool:
        """Validate basic DICOM structure.

        LEARNING: This checks fundamental DICOM requirements.

        Args:
            dataset: DICOM dataset
            result: Validation result to update

        Returns:
            bool: Whether structure is valid (continue validation)
        """
        # Check that dataset is not None
        if dataset is None:
            result.add_error("Dataset is None")
            return False

        # Check that dataset has some elements
        if len(dataset) == 0:
            result.add_error("Dataset is empty")
            return False

        # Check for DICOM file meta information
        if not hasattr(dataset, "file_meta") or dataset.file_meta is None:
            result.add_warning("No file meta information present")

        return True

    def _validate_required_tags(
        self, dataset: Dataset, result: ValidationResult
    ) -> None:
        """Validate that required tags are present.

        Args:
            dataset: DICOM dataset
            result: Validation result to update
        """
        # Check each category of required tags
        for category, tags in self.REQUIRED_TAGS.items():
            for tag in tags:
                if tag not in dataset:
                    if self.strict_mode:
                        result.add_error(
                            f"Required {category} tag missing: {tag}",
                            context={"category": category, "tag": str(tag)},
                        )
                    else:
                        result.add_warning(
                            f"Required {category} tag missing: {tag}",
                            context={"category": category, "tag": str(tag)},
                        )

    def _validate_tag_values(self, dataset: Dataset, result: ValidationResult) -> None:
        """Validate DICOM tag values for correctness.

        Args:
            dataset: DICOM dataset
            result: Validation result to update
        """
        for elem in dataset:
            # Skip empty or undefined values
            if elem.value is None or elem.value == "":
                continue

            # Convert pydicom value types to string for checking
            # (pydicom uses PersonName, etc. which are not str instances)
            str_value = str(elem.value) if not isinstance(elem.value, bytes) else None

            if str_value is None:
                continue

            # Check for extremely long strings (potential attack)
            if len(str_value) > 10000:
                result.add_warning(
                    f"Tag {elem.tag} has extremely long value: {len(str_value)} chars",
                    context={"tag": str(elem.tag), "length": len(str_value)},
                )

    def _validate_security(self, dataset: Dataset, result: ValidationResult) -> None:
        """Perform security-focused validation.

        LEARNING: Security validation checks for potential attacks or exploits.

        Args:
            dataset: DICOM dataset
            result: Validation result to update
        """
        # Check for suspiciously large number of elements
        if len(dataset) > 10000:
            msg = f"Dataset has unusually large number of elements: {len(dataset)}"
            ctx = {"element_count": len(dataset)}
            if self.strict_mode:
                result.add_error(msg, context=ctx)
            else:
                result.add_warning(msg, context=ctx)

        # Check for deeply nested sequences
        max_depth = self._check_sequence_depth(dataset)
        if max_depth > 10:
            msg = f"Dataset has deeply nested sequences: depth {max_depth}"
            ctx = {"max_depth": max_depth}
            if self.strict_mode:
                result.add_error(msg, context=ctx)
            else:
                result.add_warning(msg, context=ctx)

        # Check for null bytes in string values (potential attack)
        for elem in dataset:
            # Skip empty or undefined values
            if elem.value is None or elem.value == "":
                continue

            # Convert to string for checking
            str_value = str(elem.value) if not isinstance(elem.value, bytes) else None

            if str_value is None:
                continue

            # Check for null bytes (allow single trailing null for DICOM padding)
            if "\x00" in str_value[:-1]:
                result.add_error(
                    f"Tag {elem.tag} contains null bytes (potential attack)",
                    context={"tag": str(elem.tag)},
                )

        # Check for private tags with suspicious patterns
        self._check_private_tags(dataset, result)

    def _check_sequence_depth(self, dataset: Dataset, current_depth: int = 0) -> int:
        """Recursively check depth of nested sequences.

        Args:
            dataset: DICOM dataset
            current_depth: Current nesting depth

        Returns:
            int: Maximum depth found
        """
        max_depth = current_depth

        for elem in dataset:
            if elem.VR == "SQ":  # Sequence
                for item in elem.value:
                    depth = self._check_sequence_depth(item, current_depth + 1)
                    max_depth = max(max_depth, depth)

        return max_depth

    def _check_private_tags(self, dataset: Dataset, result: ValidationResult) -> None:
        """Check private tags for suspicious patterns.

        Args:
            dataset: DICOM dataset
            result: Validation result to update
        """
        private_tag_count = 0

        for elem in dataset:
            # Private tags have odd group numbers
            if elem.tag.group % 2 == 1:
                private_tag_count += 1

                # Check for suspiciously large private data
                if hasattr(elem, "value") and isinstance(elem.value, bytes):
                    if len(elem.value) > 1024 * 1024:  # > 1MB
                        msg = f"Private tag {elem.tag} contains large data: {len(elem.value)} bytes"
                        ctx = {"tag": str(elem.tag), "size": len(elem.value)}
                        if self.strict_mode:
                            result.add_error(msg, context=ctx)
                        else:
                            result.add_warning(msg, context=ctx)

        # Too many private tags might indicate data exfiltration attempt
        if private_tag_count > 100:
            msg = f"Dataset contains many private tags: {private_tag_count}"
            ctx = {"private_tag_count": private_tag_count}
            if self.strict_mode:
                result.add_error(msg, context=ctx)
            else:
                result.add_warning(msg, context=ctx)

    def validate_batch(
        self, datasets: List[Dataset], stop_on_first_error: bool = False
    ) -> List[ValidationResult]:
        """Validate multiple DICOM datasets.

        Args:
            datasets: List of DICOM datasets to validate
            stop_on_first_error: Whether to stop on first error

        Returns:
            List[ValidationResult]: Results for each dataset
        """
        results = []

        for i, dataset in enumerate(datasets):
            logger.debug(f"Validating dataset {i + 1}/{len(datasets)}")
            result = self.validate(dataset)
            results.append(result)

            if stop_on_first_error and not result.is_valid:
                logger.warning(f"Stopping validation at dataset {i + 1} due to error")
                break

        # Summary statistics
        valid_count = sum(1 for r in results if r.is_valid)
        logger.info(
            f"Batch validation complete: {valid_count}/{len(results)} valid",
            valid=valid_count,
            total=len(results),
            success_rate=valid_count / len(results) if results else 0,
        )

        return results


if __name__ == "__main__":
    """Test the validator functionality."""
    print("Testing DICOM Validator...\n")

    # Create validator
    validator = DicomValidator(strict_mode=False)
    print(f"Created validator: strict_mode={validator.strict_mode}\n")

    # Create minimal test dataset
    from pydicom.dataset import Dataset

    test_dataset = Dataset()
    test_dataset.PatientName = "Test^Patient"
    test_dataset.PatientID = "TEST001"
    test_dataset.StudyInstanceUID = "1.2.3.4.5"
    test_dataset.StudyDate = "20250930"
    test_dataset.SeriesInstanceUID = "1.2.3.4.5.6"
    test_dataset.Modality = "CT"
    test_dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    test_dataset.SOPInstanceUID = "1.2.3.4.5.6.7"

    # Validate
    result = validator.validate(test_dataset)
    print("Validation Result:")
    print(result)

    print("\nValidator testing complete!")

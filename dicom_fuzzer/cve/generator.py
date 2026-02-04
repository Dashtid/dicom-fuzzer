"""CVE Generator - Deterministic DICOM CVE file generation.

This module provides the main API for generating DICOM files that replicate
known CVEs. Output is deterministic - the same CVE and template always produces
the same output files.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .payloads import CVE_MUTATIONS
from .registry import CVE_REGISTRY, CVEInfo, get_cve_info

if TYPE_CHECKING:
    pass


@dataclass
class CVEFile:
    """A generated CVE replication file.

    Attributes:
        cve_id: The CVE being replicated
        variant: Name of the specific attack variant
        data: The mutated DICOM bytes
        info: Metadata about the CVE
    """

    cve_id: str
    variant: str
    data: bytes
    info: CVEInfo

    @property
    def filename(self) -> str:
        """Generate a descriptive filename for this CVE file."""
        return f"{self.cve_id}_{self.variant}.dcm"

    def save(self, output_dir: str | Path) -> Path:
        """Save the CVE file to a directory.

        Args:
            output_dir: Directory to save the file in

        Returns:
            Path to the saved file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        file_path = output_path / self.filename
        file_path.write_bytes(self.data)
        return file_path


class CVEGenerator:
    """Generator for CVE replication DICOM files.

    This class provides methods to generate DICOM files that replicate
    known CVEs for security validation testing.

    Example:
        generator = CVEGenerator()

        # Generate all variants for a specific CVE
        files = generator.generate("CVE-2025-5943", template_bytes)

        # Generate first variant only
        file = generator.generate_one("CVE-2025-5943", template_bytes)

        # Generate all CVEs
        all_files = generator.generate_all(template_bytes)
    """

    def __init__(self) -> None:
        """Initialize the CVE generator."""
        self._mutations = CVE_MUTATIONS
        self._registry = CVE_REGISTRY

    @property
    def available_cves(self) -> list[str]:
        """Get list of available CVE IDs."""
        return sorted(self._registry.keys())

    def get_info(self, cve_id: str) -> CVEInfo | None:
        """Get information about a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2025-5943")

        Returns:
            CVEInfo object or None if CVE not found
        """
        return get_cve_info(cve_id)

    def generate(self, cve_id: str, template: bytes) -> list[CVEFile]:
        """Generate all variants for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2025-5943")
            template: Template DICOM file bytes to mutate

        Returns:
            List of CVEFile objects, one per variant

        Raises:
            ValueError: If CVE ID is not recognized
        """
        cve_id = cve_id.upper()

        if cve_id not in self._mutations:
            available = ", ".join(sorted(self._mutations.keys())[:5])
            raise ValueError(
                f"Unknown CVE: {cve_id}. Available CVEs include: {available}..."
            )

        info = self._registry.get(cve_id)
        if info is None:
            raise ValueError(f"CVE {cve_id} has no registry entry")

        mutation_func = self._mutations[cve_id]
        variants = mutation_func(template)

        return [
            CVEFile(
                cve_id=cve_id,
                variant=variant_name,
                data=mutated_data,
                info=info,
            )
            for variant_name, mutated_data in variants
        ]

    def generate_one(self, cve_id: str, template: bytes) -> CVEFile:
        """Generate the first (primary) variant for a CVE.

        Use this when you only need one file per CVE rather than all variants.

        Args:
            cve_id: CVE identifier
            template: Template DICOM file bytes

        Returns:
            Single CVEFile object

        Raises:
            ValueError: If CVE ID is not recognized
        """
        files = self.generate(cve_id, template)
        return files[0]

    def generate_all(self, template: bytes) -> dict[str, list[CVEFile]]:
        """Generate files for all known CVEs.

        Args:
            template: Template DICOM file bytes to mutate

        Returns:
            Dictionary mapping CVE ID to list of CVEFile objects
        """
        results = {}
        for cve_id in self._mutations:
            results[cve_id] = self.generate(cve_id, template)
        return results

    def generate_by_category(
        self, category: str, template: bytes
    ) -> dict[str, list[CVEFile]]:
        """Generate files for all CVEs in a category.

        Args:
            category: Category name (e.g., "heap_overflow", "path_traversal")
            template: Template DICOM file bytes

        Returns:
            Dictionary mapping CVE ID to list of CVEFile objects
        """
        results = {}
        for cve_id, info in self._registry.items():
            if info.category.value == category:
                if cve_id in self._mutations:
                    results[cve_id] = self.generate(cve_id, template)
        return results

    def generate_by_product(
        self, product: str, template: bytes
    ) -> dict[str, list[CVEFile]]:
        """Generate files for all CVEs affecting a specific product.

        Args:
            product: Product name (e.g., "MicroDicom", "GDCM")
            template: Template DICOM file bytes

        Returns:
            Dictionary mapping CVE ID to list of CVEFile objects
        """
        results = {}
        product_lower = product.lower()
        for cve_id, info in self._registry.items():
            if product_lower in info.affected_product.lower():
                if cve_id in self._mutations:
                    results[cve_id] = self.generate(cve_id, template)
        return results

    def save_all(
        self, template: bytes, output_dir: str | Path, flat: bool = False
    ) -> list[Path]:
        """Generate and save all CVE files.

        Args:
            template: Template DICOM file bytes
            output_dir: Directory to save files in
            flat: If True, save all files in output_dir directly.
                  If False (default), create subdirectories per CVE.

        Returns:
            List of paths to saved files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        saved_paths = []
        all_files = self.generate_all(template)

        for cve_id, files in all_files.items():
            if flat:
                for cve_file in files:
                    file_path = output_path / cve_file.filename
                    file_path.write_bytes(cve_file.data)
                    saved_paths.append(file_path)
            else:
                cve_dir = output_path / cve_id
                cve_dir.mkdir(parents=True, exist_ok=True)
                for cve_file in files:
                    file_path = cve_dir / f"{cve_file.variant}.dcm"
                    file_path.write_bytes(cve_file.data)
                    saved_paths.append(file_path)

        return saved_paths

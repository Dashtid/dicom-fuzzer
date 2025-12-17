"""Software Bill of Materials (SBOM) Generator.

Generates FDA-compliant SBOMs in CycloneDX and SPDX formats for medical device
premarket submissions per the June 2025 FDA Cybersecurity Guidance.

SBOM requirements per FDA guidance:
- Machine-readable format (CycloneDX or SPDX preferred)
- Include all software components and dependencies
- Version information for all components
- License information where available
- Vulnerability database identifiers (CPE, PURL)

NTIA Minimum Elements (July 2021) - 7 Required Fields:
1. Supplier Name - Entity that creates/defines/identifies components
2. Component Name - Designation assigned to a unit of software
3. Version of the Component - Identifier for version changes
4. Other Unique Identifiers - CPE, PURL, SWID tag
5. Dependency Relationship - Upstream component relationships
6. Author of SBOM Data - Entity that creates the SBOM
7. Timestamp - Date/time of SBOM data assembly

References:
- FDA Cybersecurity Guidance (June 2025)
- NTIA SBOM Minimum Elements (July 2021)
- CycloneDX Specification v1.5
- SPDX Specification v2.3

"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

import dicom_fuzzer


class DependencyRelationship(Enum):
    """NTIA dependency relationship types."""

    DEPENDS_ON = "depends_on"
    DEPENDENCY_OF = "dependency_of"
    DEV_DEPENDENCY_OF = "dev_dependency_of"
    OPTIONAL_DEPENDENCY_OF = "optional_dependency_of"
    PROVIDED_BY = "provided_by"
    CONTAINS = "contains"
    CONTAINED_BY = "contained_by"
    GENERATES = "generates"
    GENERATED_FROM = "generated_from"
    ANCESTOR_OF = "ancestor_of"
    DESCENDANT_OF = "descendant_of"
    VARIANT_OF = "variant_of"
    BUILD_TOOL_OF = "build_tool_of"
    DEV_TOOL_OF = "dev_tool_of"
    TEST_TOOL_OF = "test_tool_of"
    DOCUMENTATION_OF = "documentation_of"
    PACKAGE_OF = "package_of"
    RUNTIME_DEPENDENCY_OF = "runtime_dependency_of"


@dataclass
class NTIACompliance:
    """NTIA baseline compliance validation results."""

    is_compliant: bool = False
    has_supplier_name: bool = False
    has_component_name: bool = False
    has_version: bool = False
    has_unique_identifier: bool = False
    has_dependency_relationship: bool = False
    has_sbom_author: bool = False
    has_timestamp: bool = False
    missing_fields: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._update_compliance()

    def _update_compliance(self) -> None:
        """Update overall compliance based on individual fields."""
        self.missing_fields = []
        if not self.has_supplier_name:
            self.missing_fields.append("Supplier Name")
        if not self.has_component_name:
            self.missing_fields.append("Component Name")
        if not self.has_version:
            self.missing_fields.append("Version")
        if not self.has_unique_identifier:
            self.missing_fields.append("Unique Identifier (CPE/PURL/SWID)")
        if not self.has_dependency_relationship:
            self.missing_fields.append("Dependency Relationship")
        if not self.has_sbom_author:
            self.missing_fields.append("SBOM Author")
        if not self.has_timestamp:
            self.missing_fields.append("Timestamp")

        self.is_compliant = len(self.missing_fields) == 0


@dataclass
class SBOMComponent:
    """Individual software component in the SBOM.

    NTIA Minimum Elements supported:
    - name: Component Name (required)
    - version: Version of the Component (required)
    - supplier/supplier_url: Supplier Name (required)
    - purl/cpe/swid: Other Unique Identifiers (required)
    - relationships: Dependency Relationship (required at SBOM level)
    """

    name: str
    version: str
    purl: str = ""
    cpe: str = ""
    swid: str = ""  # NTIA: Software Identification tag
    license_id: str = ""
    license_name: str = ""
    supplier: str = ""  # NTIA: Supplier Name (required)
    supplier_url: str = ""  # Supplier website/repository
    author: str = ""  # Original author if different from supplier
    description: str = ""
    hashes: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    relationships: list[tuple[str, DependencyRelationship]] = field(
        default_factory=list
    )  # NTIA: (target_purl, relationship_type)
    external_references: list[dict[str, str]] = field(default_factory=list)
    # Additional NTIA-recommended fields
    download_location: str = ""
    file_verified: bool = False
    files_analyzed: bool = False
    homepage: str = ""

    def __post_init__(self) -> None:
        if not self.purl:
            self.purl = f"pkg:pypi/{self.name}@{self.version}"
        if not self.cpe:
            self.cpe = self._generate_cpe()
        if not self.swid:
            self.swid = self._generate_swid()

    def _generate_cpe(self) -> str:
        """Generate CPE 2.3 identifier for the component."""
        # CPE 2.3 format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        vendor = self.supplier.lower().replace(" ", "_") if self.supplier else "*"
        product = self.name.lower().replace("-", "_").replace(" ", "_")
        version = self.version.replace("-", ".") if self.version else "*"
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def _generate_swid(self) -> str:
        """Generate SWID tag ID for the component."""
        # SWID tag format: urn:swid:<regid>/<tagID>
        tag_id = f"{self.name}-{self.version}"
        # Use supplier domain or default
        regid = "github.com/Dashtid"
        return f"urn:swid:{regid}/{tag_id}"

    def add_relationship(
        self, target_purl: str, relationship: DependencyRelationship
    ) -> None:
        """Add a dependency relationship to another component."""
        self.relationships.append((target_purl, relationship))

    def validate_ntia_fields(self) -> NTIACompliance:
        """Validate NTIA minimum element compliance for this component."""
        compliance = NTIACompliance(
            has_component_name=bool(self.name),
            has_version=bool(self.version),
            has_supplier_name=bool(self.supplier),
            has_unique_identifier=bool(self.purl or self.cpe or self.swid),
            has_dependency_relationship=True,  # Validated at SBOM level
            has_sbom_author=True,  # Validated at SBOM level
            has_timestamp=True,  # Validated at SBOM level
        )
        compliance._update_compliance()

        # Add warnings for recommended fields
        if not self.license_id and not self.license_name:
            compliance.warnings.append(f"{self.name}: Missing license information")
        if not self.download_location:
            compliance.warnings.append(f"{self.name}: Missing download location")

        return compliance


@dataclass
class SBOMMetadata:
    """SBOM document metadata.

    NTIA Minimum Elements:
    - sbom_author: Author of SBOM Data (required)
    - creation_time: Timestamp (required)
    """

    document_id: str = ""
    document_name: str = ""
    document_namespace: str = ""
    creation_time: str = ""  # NTIA: Timestamp (required)
    creator_tool: str = ""
    creator_organization: str = ""
    sbom_author: str = ""  # NTIA: Author of SBOM Data (required)
    sbom_author_email: str = ""
    spec_version: str = ""
    # NTIA automation support fields
    data_license: str = "CC0-1.0"
    sbom_format: str = ""  # cyclonedx, spdx
    sbom_version: int = 1

    def __post_init__(self) -> None:
        if not self.document_id:
            self.document_id = f"urn:uuid:{uuid4()}"
        if not self.creation_time:
            self.creation_time = datetime.now(UTC).isoformat()
        if not self.creator_tool:
            version = getattr(dicom_fuzzer, "__version__", "1.4.0")
            self.creator_tool = f"DICOM-Fuzzer-{version}"
        if not self.sbom_author:
            self.sbom_author = self.creator_organization or self.creator_tool


@dataclass
class SBOM:
    """Complete Software Bill of Materials.

    Implements NTIA Minimum Elements for SBOM:
    - All 7 required fields tracked and validated
    - Support for CycloneDX and SPDX export formats
    - Dependency relationship graph
    """

    metadata: SBOMMetadata = field(default_factory=SBOMMetadata)
    components: list[SBOMComponent] = field(default_factory=list)
    root_component: SBOMComponent | None = None
    # NTIA: Dependency relationships tracked at SBOM level
    dependency_graph: dict[str, list[str]] = field(default_factory=dict)

    def validate_ntia_compliance(self) -> NTIACompliance:
        """Validate NTIA minimum element compliance for the entire SBOM."""
        compliance = NTIACompliance(
            has_sbom_author=bool(self.metadata.sbom_author),
            has_timestamp=bool(self.metadata.creation_time),
            has_dependency_relationship=bool(self.dependency_graph)
            or any(c.relationships for c in self.components),
        )

        # Check all components
        all_have_supplier = True
        all_have_name = True
        all_have_version = True
        all_have_unique_id = True

        for comp in self.components:
            if not comp.supplier:
                all_have_supplier = False
                compliance.warnings.append(f"Component '{comp.name}' missing supplier")
            if not comp.name:
                all_have_name = False
            if not comp.version:
                all_have_version = False
                compliance.warnings.append(f"Component '{comp.name}' missing version")
            if not (comp.purl or comp.cpe or comp.swid):
                all_have_unique_id = False
                compliance.warnings.append(
                    f"Component '{comp.name}' missing unique identifier"
                )

        if self.root_component:
            if not self.root_component.supplier:
                all_have_supplier = False
                compliance.warnings.append("Root component missing supplier")

        compliance.has_supplier_name = all_have_supplier
        compliance.has_component_name = all_have_name
        compliance.has_version = all_have_version
        compliance.has_unique_identifier = all_have_unique_id

        compliance._update_compliance()
        return compliance

    def get_component_by_purl(self, purl: str) -> SBOMComponent | None:
        """Find a component by its PURL."""
        for comp in self.components:
            if comp.purl == purl:
                return comp
        if self.root_component and self.root_component.purl == purl:
            return self.root_component
        return None

    def add_dependency(self, source_purl: str, target_purl: str) -> None:
        """Add a dependency relationship to the graph."""
        if source_purl not in self.dependency_graph:
            self.dependency_graph[source_purl] = []
        if target_purl not in self.dependency_graph[source_purl]:
            self.dependency_graph[source_purl].append(target_purl)


class SBOMGenerator:
    """Generate SBOMs from Python project files.

    Parses pyproject.toml and uv.lock to extract dependency information
    and generate machine-readable SBOMs in FDA-accepted formats.

    NTIA Compliance:
    - Automatically populates supplier information from known package database
    - Generates CPE and SWID identifiers for all components
    - Tracks dependency relationships in the SBOM
    - Validates all 7 NTIA minimum elements
    """

    # Known PyPI package suppliers for NTIA compliance
    KNOWN_SUPPLIERS: dict[str, tuple[str, str]] = {
        # Package name: (supplier_name, supplier_url)
        "pydicom": ("pydicom Contributors", "https://github.com/pydicom/pydicom"),
        "pillow": ("Jeffrey A. Clark (Alex)", "https://python-pillow.org/"),
        "numpy": ("NumPy Developers", "https://numpy.org/"),
        "requests": ("Kenneth Reitz", "https://requests.readthedocs.io/"),
        "click": ("Pallets", "https://palletsprojects.com/"),
        "pytest": ("pytest-dev", "https://pytest.org/"),
        "rich": ("Will McGugan", "https://github.com/Textualize/rich"),
        "pydantic": ("Samuel Colvin", "https://pydantic.dev/"),
        "typer": ("Tiangolo", "https://typer.tiangolo.com/"),
        "httpx": ("Encode", "https://www.python-httpx.org/"),
        "aiohttp": ("aio-libs", "https://aiohttp.readthedocs.io/"),
        "cryptography": ("Python Cryptographic Authority", "https://cryptography.io/"),
        "pyyaml": ("YAML community", "https://pyyaml.org/"),
        "toml": ("Uiri Noyb", "https://github.com/uiri/toml"),
        "jinja2": ("Pallets", "https://palletsprojects.com/"),
        "flask": ("Pallets", "https://palletsprojects.com/"),
        "django": ("Django Software Foundation", "https://djangoproject.com/"),
        "sqlalchemy": ("SQLAlchemy Authors", "https://www.sqlalchemy.org/"),
        "pandas": ("pandas Development Team", "https://pandas.pydata.org/"),
        "scipy": ("SciPy Developers", "https://scipy.org/"),
        "matplotlib": ("Matplotlib Development Team", "https://matplotlib.org/"),
        "scikit-learn": ("scikit-learn Developers", "https://scikit-learn.org/"),
        "tensorflow": ("Google", "https://tensorflow.org/"),
        "torch": ("Meta AI", "https://pytorch.org/"),
        "opencv-python": ("OpenCV", "https://opencv.org/"),
        "gdcm": ("GDCM Contributors", "https://github.com/malaterre/GDCM"),
    }

    def __init__(
        self,
        project_dir: Path | str | None = None,
        organization: str = "",
        device_name: str = "",
        sbom_author: str = "",
        sbom_author_email: str = "",
    ) -> None:
        self.project_dir = Path(project_dir) if project_dir else Path.cwd()
        self.organization = organization
        self.device_name = device_name
        self.sbom_author = sbom_author or organization
        self.sbom_author_email = sbom_author_email
        self.sbom = SBOM()

    def parse_pyproject(self) -> dict[str, Any]:
        """Parse pyproject.toml for project metadata and dependencies."""
        pyproject_path = self.project_dir / "pyproject.toml"
        if not pyproject_path.exists():
            return {}

        with open(pyproject_path, "rb") as f:
            return tomllib.load(f)

    def parse_uv_lock(self) -> list[dict[str, Any]]:
        """Parse uv.lock for resolved dependency versions and hashes."""
        lock_path = self.project_dir / "uv.lock"
        if not lock_path.exists():
            return []

        packages: list[dict[str, Any]] = []

        with open(lock_path, encoding="utf-8") as f:
            content = f.read()

        # Parse TOML-like structure of uv.lock
        # Using regex for simple parsing since tomllib expects valid TOML
        package_pattern = re.compile(
            r"\[\[package\]\]\s*\n"
            r'name\s*=\s*"([^"]+)"\s*\n'
            r'version\s*=\s*"([^"]+)"',
            re.MULTILINE,
        )

        for match in package_pattern.finditer(content):
            packages.append(
                {
                    "name": match.group(1),
                    "version": match.group(2),
                }
            )

        return packages

    def generate(self) -> SBOM:
        """Generate SBOM from project files with NTIA compliance."""
        pyproject = self.parse_pyproject()
        lock_packages = self.parse_uv_lock()

        # Set metadata with NTIA required fields
        project_info = pyproject.get("project", {})
        project_name = project_info.get("name", "unknown")
        project_version = project_info.get("version", "0.0.0")

        self.sbom.metadata = SBOMMetadata(
            document_name=f"SBOM for {self.device_name or project_name}",
            document_namespace=f"https://github.com/Dashtid/dicom-fuzzer/sbom/{project_version}",
            creator_organization=self.organization,
            sbom_author=self.sbom_author,
            sbom_author_email=self.sbom_author_email,
            spec_version="1.5",  # CycloneDX 1.5
        )

        # Create root component with NTIA fields
        self.sbom.root_component = SBOMComponent(
            name=project_name,
            version=project_version,
            description=project_info.get("description", ""),
            license_id=self._extract_license(project_info),
            supplier=self.organization or "DICOM Fuzzer Project",
            supplier_url="https://github.com/Dashtid/dicom-fuzzer",
            download_location="https://github.com/Dashtid/dicom-fuzzer",
        )

        # Add dependencies from lock file with supplier info
        for pkg in lock_packages:
            supplier_name, supplier_url = self._get_supplier_info(pkg["name"])
            component = SBOMComponent(
                name=pkg["name"],
                version=pkg["version"],
                supplier=supplier_name,
                supplier_url=supplier_url,
                download_location=f"https://pypi.org/project/{pkg['name']}/{pkg['version']}/",
            )
            self.sbom.components.append(component)
            # NTIA: Track dependency relationship
            if self.sbom.root_component:
                self.sbom.add_dependency(self.sbom.root_component.purl, component.purl)

        # If no lock file, fall back to pyproject.toml dependencies
        if not lock_packages:
            deps = project_info.get("dependencies", [])
            for dep in deps:
                name, version = self._parse_dependency_spec(dep)
                supplier_name, supplier_url = self._get_supplier_info(name)
                component = SBOMComponent(
                    name=name,
                    version=version,
                    supplier=supplier_name,
                    supplier_url=supplier_url,
                    download_location=f"https://pypi.org/project/{name}/",
                )
                self.sbom.components.append(component)
                if self.sbom.root_component:
                    self.sbom.add_dependency(
                        self.sbom.root_component.purl, component.purl
                    )

        return self.sbom

    def _get_supplier_info(self, package_name: str) -> tuple[str, str]:
        """Get supplier information for a package from known suppliers database."""
        # Normalize package name for lookup
        normalized = package_name.lower().replace("_", "-")
        if normalized in self.KNOWN_SUPPLIERS:
            return self.KNOWN_SUPPLIERS[normalized]
        # Default to PyPI as supplier for unknown packages
        return ("PyPI", f"https://pypi.org/project/{package_name}/")

    def _extract_license(self, project_info: dict[str, Any]) -> str:
        """Extract license identifier from project info."""
        license_info = project_info.get("license", {})
        if isinstance(license_info, dict):
            text = license_info.get("text", "")
            return str(text) if text else ""
        return str(license_info) if license_info else ""

    def _parse_dependency_spec(self, spec: str) -> tuple[str, str]:
        """Parse a dependency specification like 'package>=1.0.0'."""
        # Match package name and optional version specifier
        match = re.match(r"([a-zA-Z0-9_-]+)(.*)$", spec)
        if match:
            name = match.group(1)
            version_spec = match.group(2).strip()
            # Extract version from spec (e.g., ">=1.0.0" -> "1.0.0+")
            version_match = re.search(r"[\d.]+", version_spec)
            version = version_match.group(0) if version_match else "unspecified"
            return name, version
        return spec, "unspecified"

    def to_cyclonedx(self) -> dict[str, Any]:
        """Generate CycloneDX 1.5 format SBOM with NTIA compliance."""
        if not self.sbom.components:
            self.generate()

        # CycloneDX 1.5 JSON structure
        cdx: dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": self.sbom.metadata.document_id,
            "version": self.sbom.metadata.sbom_version,
            "metadata": {
                "timestamp": self.sbom.metadata.creation_time,  # NTIA: Timestamp
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "DICOM Fuzzer SBOM Generator",
                            "version": getattr(dicom_fuzzer, "__version__", "1.4.0"),
                            "publisher": "DICOM Fuzzer Project",
                        }
                    ]
                },
                "authors": [],  # NTIA: Author of SBOM Data
                "component": None,
            },
            "components": [],
            "dependencies": [],  # NTIA: Dependency Relationship
        }

        # NTIA: Add SBOM author (required)
        if self.sbom.metadata.sbom_author:
            author_entry: dict[str, str] = {"name": self.sbom.metadata.sbom_author}
            if self.sbom.metadata.sbom_author_email:
                author_entry["email"] = self.sbom.metadata.sbom_author_email
            cdx["metadata"]["authors"].append(author_entry)
        elif self.sbom.metadata.creator_organization:
            cdx["metadata"]["authors"].append(
                {"name": self.sbom.metadata.creator_organization}
            )

        # Add root component with NTIA fields
        if self.sbom.root_component:
            root_comp = self._format_cdx_component(
                self.sbom.root_component, comp_type="application"
            )
            cdx["metadata"]["component"] = root_comp

        # Add components with NTIA fields
        for comp in self.sbom.components:
            cdx_comp = self._format_cdx_component(comp, comp_type="library")
            cdx["components"].append(cdx_comp)

        # NTIA: Add dependency graph
        for source_purl, target_purls in self.sbom.dependency_graph.items():
            cdx["dependencies"].append(
                {
                    "ref": source_purl,
                    "dependsOn": target_purls,
                }
            )

        # Fallback if no dependency graph but has components
        if not self.sbom.dependency_graph and self.sbom.root_component:
            cdx["dependencies"].append(
                {
                    "ref": self.sbom.root_component.purl,
                    "dependsOn": [c.purl for c in self.sbom.components],
                }
            )

        return cdx

    def _format_cdx_component(
        self, comp: SBOMComponent, comp_type: str = "library"
    ) -> dict[str, Any]:
        """Format a component for CycloneDX with NTIA fields."""
        cdx_comp: dict[str, Any] = {
            "type": comp_type,
            "bom-ref": comp.purl,
            "name": comp.name,  # NTIA: Component Name
            "version": comp.version,  # NTIA: Version
            "purl": comp.purl,  # NTIA: Unique Identifier
        }

        # NTIA: Supplier Name (required)
        if comp.supplier:
            cdx_comp["supplier"] = {"name": comp.supplier}
            if comp.supplier_url:
                cdx_comp["supplier"]["url"] = [comp.supplier_url]

        # NTIA: Other Unique Identifiers (CPE, SWID)
        if comp.cpe:
            cdx_comp["cpe"] = comp.cpe
        if comp.swid:
            cdx_comp["swid"] = {"tagId": comp.swid, "name": comp.name}

        # Optional fields
        if comp.description:
            cdx_comp["description"] = comp.description
        if comp.license_id or comp.license_name:
            cdx_comp["licenses"] = self._format_cdx_licenses(comp)
        if comp.author:
            cdx_comp["author"] = comp.author
        if comp.hashes:
            cdx_comp["hashes"] = [
                {"alg": alg.upper(), "content": h} for alg, h in comp.hashes.items()
            ]
        if comp.external_references:
            cdx_comp["externalReferences"] = comp.external_references

        return cdx_comp

    def _format_cdx_licenses(self, comp: SBOMComponent) -> list[dict[str, Any]]:
        """Format licenses for CycloneDX."""
        licenses: list[dict[str, Any]] = []
        if comp.license_id:
            licenses.append({"license": {"id": comp.license_id}})
        elif comp.license_name:
            licenses.append({"license": {"name": comp.license_name}})
        return licenses

    def to_spdx(self) -> dict[str, Any]:
        """Generate SPDX 2.3 format SBOM with NTIA compliance."""
        if not self.sbom.components:
            self.generate()

        # SPDX 2.3 JSON structure
        spdx: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": self.sbom.metadata.data_license,
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.sbom.metadata.document_name,
            "documentNamespace": self.sbom.metadata.document_namespace,
            "creationInfo": {
                "created": self.sbom.metadata.creation_time,  # NTIA: Timestamp
                "creators": [
                    f"Tool: {self.sbom.metadata.creator_tool}",
                ],
            },
            "packages": [],
            "relationships": [],  # NTIA: Dependency Relationship
        }

        # NTIA: Add SBOM author (required)
        if self.sbom.metadata.sbom_author:
            spdx["creationInfo"]["creators"].append(
                f"Person: {self.sbom.metadata.sbom_author}"
            )
        if self.sbom.metadata.creator_organization:
            spdx["creationInfo"]["creators"].append(
                f"Organization: {self.sbom.metadata.creator_organization}"
            )

        # Add root package with NTIA fields
        if self.sbom.root_component:
            root_spdx_id = f"SPDXRef-Package-{self._sanitize_spdx_id(self.sbom.root_component.name)}"
            root_pkg = self._format_spdx_package(self.sbom.root_component, root_spdx_id)
            spdx["packages"].append(root_pkg)

            # Document describes root package
            spdx["relationships"].append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": root_spdx_id,
                }
            )

        # Add component packages with NTIA fields
        for comp in self.sbom.components:
            spdx_id = f"SPDXRef-Package-{self._sanitize_spdx_id(comp.name)}"
            pkg = self._format_spdx_package(comp, spdx_id)
            spdx["packages"].append(pkg)

            # NTIA: Root depends on component
            if self.sbom.root_component:
                root_spdx_id = f"SPDXRef-Package-{self._sanitize_spdx_id(self.sbom.root_component.name)}"
                spdx["relationships"].append(
                    {
                        "spdxElementId": root_spdx_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": spdx_id,
                    }
                )

        return spdx

    def _format_spdx_package(self, comp: SBOMComponent, spdx_id: str) -> dict[str, Any]:
        """Format a component as SPDX package with NTIA fields."""
        pkg: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": comp.name,  # NTIA: Component Name
            "versionInfo": comp.version,  # NTIA: Version
            "downloadLocation": comp.download_location or "NOASSERTION",
            "filesAnalyzed": comp.files_analyzed,
            "licenseDeclared": comp.license_id or "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [],
        }

        # NTIA: Supplier Name (required)
        if comp.supplier:
            pkg["supplier"] = f"Organization: {comp.supplier}"
            if comp.supplier_url:
                pkg["homepage"] = comp.supplier_url

        # Optional description
        if comp.description:
            pkg["description"] = comp.description

        # NTIA: Unique Identifiers (PURL, CPE, SWID)
        if comp.purl:
            pkg["externalRefs"].append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }
            )
        if comp.cpe:
            pkg["externalRefs"].append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": comp.cpe,
                }
            )
        if comp.swid:
            pkg["externalRefs"].append(
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "swid",
                    "referenceLocator": comp.swid,
                }
            )

        # File hashes if available
        if comp.hashes:
            pkg["checksums"] = [
                {"algorithm": alg.upper(), "checksumValue": h}
                for alg, h in comp.hashes.items()
            ]

        return pkg

    def _sanitize_spdx_id(self, name: str) -> str:
        """Sanitize name for use in SPDX ID."""
        return re.sub(r"[^a-zA-Z0-9.-]", "-", name)

    def save_cyclonedx(self, path: Path | str) -> Path:
        """Save SBOM in CycloneDX JSON format."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_cyclonedx(), f, indent=2)
        return path

    def save_spdx(self, path: Path | str) -> Path:
        """Save SBOM in SPDX JSON format."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_spdx(), f, indent=2)
        return path

    def generate_summary(self) -> str:
        """Generate a human-readable SBOM summary with NTIA compliance status."""
        if not self.sbom.components:
            self.generate()

        # Validate NTIA compliance
        compliance = self.sbom.validate_ntia_compliance()

        lines = [
            "# Software Bill of Materials Summary",
            "",
            "## Document Information",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Document ID | {self.sbom.metadata.document_id} |",
            f"| Created | {self.sbom.metadata.creation_time} |",
            f"| Generator | {self.sbom.metadata.creator_tool} |",
            f"| SBOM Author | {self.sbom.metadata.sbom_author or 'N/A'} |",
            f"| Organization | {self.sbom.metadata.creator_organization or 'N/A'} |",
            "",
            "## NTIA Minimum Elements Compliance",
            "",
            f"**Status: {'COMPLIANT' if compliance.is_compliant else 'NON-COMPLIANT'}**",
            "",
            "| Element | Status |",
            "|---------|--------|",
            f"| Supplier Name | {'[+]' if compliance.has_supplier_name else '[-]'} |",
            f"| Component Name | {'[+]' if compliance.has_component_name else '[-]'} |",
            f"| Version | {'[+]' if compliance.has_version else '[-]'} |",
            f"| Unique Identifier | {'[+]' if compliance.has_unique_identifier else '[-]'} |",
            f"| Dependency Relationship | {'[+]' if compliance.has_dependency_relationship else '[-]'} |",
            f"| SBOM Author | {'[+]' if compliance.has_sbom_author else '[-]'} |",
            f"| Timestamp | {'[+]' if compliance.has_timestamp else '[-]'} |",
            "",
        ]

        if compliance.missing_fields:
            lines.extend(
                [
                    "### Missing Fields",
                    "",
                ]
            )
            for field in compliance.missing_fields:
                lines.append(f"- {field}")
            lines.append("")

        if compliance.warnings:
            lines.extend(
                [
                    "### Warnings",
                    "",
                ]
            )
            for warning in compliance.warnings[:10]:  # Limit to first 10
                lines.append(f"- {warning}")
            if len(compliance.warnings) > 10:
                lines.append(f"- ... and {len(compliance.warnings) - 10} more")
            lines.append("")

        if self.sbom.root_component:
            lines.extend(
                [
                    "## Primary Component",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| Name | {self.sbom.root_component.name} |",
                    f"| Version | {self.sbom.root_component.version} |",
                    f"| Supplier | {self.sbom.root_component.supplier or 'N/A'} |",
                    f"| License | {self.sbom.root_component.license_id or 'N/A'} |",
                    f"| PURL | {self.sbom.root_component.purl} |",
                    f"| CPE | {self.sbom.root_component.cpe} |",
                    "",
                ]
            )

        lines.extend(
            [
                "## Dependencies",
                "",
                f"Total components: {len(self.sbom.components)}",
                "",
                "| Package | Version | Supplier | PURL |",
                "|---------|---------|----------|------|",
            ]
        )

        for comp in sorted(self.sbom.components, key=lambda c: c.name):
            supplier = (
                comp.supplier[:20] + "..." if len(comp.supplier) > 20 else comp.supplier
            )
            lines.append(
                f"| {comp.name} | {comp.version} | {supplier or 'N/A'} | {comp.purl} |"
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "*Generated for FDA premarket cybersecurity submission per June 2025 guidance.*",
                "*NTIA SBOM Minimum Elements (July 2021) compliance validated.*",
            ]
        )

        return "\n".join(lines)

    def generate_ntia_compliance_report(self) -> str:
        """Generate detailed NTIA compliance report."""
        if not self.sbom.components:
            self.generate()

        compliance = self.sbom.validate_ntia_compliance()

        lines = [
            "# NTIA SBOM Minimum Elements Compliance Report",
            "",
            f"Generated: {self.sbom.metadata.creation_time}",
            f"Document: {self.sbom.metadata.document_name}",
            "",
            "## Overall Compliance Status",
            "",
            f"**{'COMPLIANT' if compliance.is_compliant else 'NON-COMPLIANT'}** with NTIA Minimum Elements (July 2021)",
            "",
            "## Required Elements Assessment",
            "",
            "| # | Element | Requirement | Status | Details |",
            "|---|---------|-------------|--------|---------|",
            f"| 1 | Supplier Name | Required | {'[+] PASS' if compliance.has_supplier_name else '[-] FAIL'} | Entity that creates/defines components |",
            f"| 2 | Component Name | Required | {'[+] PASS' if compliance.has_component_name else '[-] FAIL'} | Designation assigned to software unit |",
            f"| 3 | Version | Required | {'[+] PASS' if compliance.has_version else '[-] FAIL'} | Change identifier from previous version |",
            f"| 4 | Unique Identifier | Required | {'[+] PASS' if compliance.has_unique_identifier else '[-] FAIL'} | CPE, PURL, or SWID tag |",
            f"| 5 | Dependency Relationship | Required | {'[+] PASS' if compliance.has_dependency_relationship else '[-] FAIL'} | Upstream component relationships |",
            f"| 6 | SBOM Author | Required | {'[+] PASS' if compliance.has_sbom_author else '[-] FAIL'} | Entity creating SBOM data |",
            f"| 7 | Timestamp | Required | {'[+] PASS' if compliance.has_timestamp else '[-] FAIL'} | Date/time of SBOM assembly |",
            "",
            f"**Compliance Score: {7 - len(compliance.missing_fields)}/7 elements**",
            "",
        ]

        if compliance.missing_fields:
            lines.extend(
                [
                    "## Remediation Required",
                    "",
                    "The following NTIA minimum elements are missing:",
                    "",
                ]
            )
            for field in compliance.missing_fields:
                lines.append(f"- **{field}**: Must be provided for compliance")
            lines.append("")

        # Component-level compliance
        lines.extend(
            [
                "## Component-Level Compliance",
                "",
                f"Total components analyzed: {len(self.sbom.components) + (1 if self.sbom.root_component else 0)}",
                "",
            ]
        )

        # Count components with issues
        components_without_supplier = sum(
            1 for c in self.sbom.components if not c.supplier
        )
        if self.sbom.root_component and not self.sbom.root_component.supplier:
            components_without_supplier += 1

        if components_without_supplier > 0:
            lines.extend(
                [
                    f"[!] {components_without_supplier} component(s) missing supplier information",
                    "",
                ]
            )

        if compliance.warnings:
            lines.extend(
                [
                    "## Warnings",
                    "",
                ]
            )
            for warning in compliance.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        lines.extend(
            [
                "## Automation Support Fields",
                "",
                "| Field | Value |",
                "|-------|-------|",
                "| Format | CycloneDX 1.5 / SPDX 2.3 |",
                f"| Data License | {self.sbom.metadata.data_license} |",
                "| Machine Readable | Yes |",
                "",
                "## References",
                "",
                "- NTIA: The Minimum Elements For a Software Bill of Materials (July 2021)",
                "- FDA: Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions (June 2025)",
                "- CycloneDX Specification v1.5",
                "- SPDX Specification v2.3",
                "",
            ]
        )

        return "\n".join(lines)

    def save_ntia_compliance_report(self, path: Path | str) -> Path:
        """Save NTIA compliance report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_ntia_compliance_report())
        return path

    def save_summary(self, path: Path | str) -> Path:
        """Save human-readable SBOM summary."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_summary())
        return path


def generate_sbom(
    project_dir: Path | str | None = None,
    output_dir: Path | str | None = None,
    organization: str = "",
    device_name: str = "",
    sbom_author: str = "",
    sbom_author_email: str = "",
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Generate SBOM in multiple formats with NTIA compliance.

    Args:
        project_dir: Project directory containing pyproject.toml/uv.lock
        output_dir: Output directory for SBOM files
        organization: Organization name for SBOM metadata
        device_name: Device name for SBOM metadata
        sbom_author: NTIA required - Author of SBOM data
        sbom_author_email: Email of SBOM author
        formats: List of formats to generate:
            - 'cyclonedx': CycloneDX 1.5 JSON
            - 'spdx': SPDX 2.3 JSON
            - 'summary': Human-readable markdown summary
            - 'ntia': NTIA compliance report

    Returns:
        Dictionary mapping format names to output file paths

    """
    if formats is None:
        formats = ["cyclonedx", "spdx", "summary", "ntia"]

    if output_dir is None:
        output_dir = Path.cwd() / "output" / "sbom"
    else:
        output_dir = Path(output_dir)

    generator = SBOMGenerator(
        project_dir=project_dir,
        organization=organization,
        device_name=device_name,
        sbom_author=sbom_author,
        sbom_author_email=sbom_author_email,
    )
    generator.generate()

    outputs: dict[str, Path] = {}

    if "cyclonedx" in formats:
        outputs["cyclonedx"] = generator.save_cyclonedx(
            output_dir / "sbom-cyclonedx.json"
        )

    if "spdx" in formats:
        outputs["spdx"] = generator.save_spdx(output_dir / "sbom-spdx.json")

    if "summary" in formats:
        outputs["summary"] = generator.save_summary(output_dir / "sbom-summary.md")

    if "ntia" in formats:
        outputs["ntia"] = generator.save_ntia_compliance_report(
            output_dir / "sbom-ntia-compliance.md"
        )

    return outputs


def validate_sbom_ntia_compliance(
    project_dir: Path | str | None = None,
    organization: str = "",
    sbom_author: str = "",
) -> NTIACompliance:
    """Validate SBOM against NTIA minimum elements.

    Args:
        project_dir: Project directory to analyze
        organization: Organization name (NTIA: Supplier Name)
        sbom_author: SBOM author name (NTIA: Author of SBOM Data)

    Returns:
        NTIACompliance object with validation results

    """
    generator = SBOMGenerator(
        project_dir=project_dir,
        organization=organization,
        sbom_author=sbom_author,
    )
    generator.generate()
    return generator.sbom.validate_ntia_compliance()


if __name__ == "__main__":
    # Generate SBOM for the current project
    outputs = generate_sbom(
        organization="DICOM Fuzzer Project",
        device_name="DICOM Fuzzer",
        sbom_author="DICOM Fuzzer Team",
    )
    for fmt, path in outputs.items():
        print(f"[+] Generated {fmt}: {path}")

    # Validate NTIA compliance
    compliance = validate_sbom_ntia_compliance(
        organization="DICOM Fuzzer Project",
        sbom_author="DICOM Fuzzer Team",
    )
    print(f"\n[i] NTIA Compliance: {'PASS' if compliance.is_compliant else 'FAIL'}")
    if compliance.missing_fields:
        print(f"[-] Missing fields: {', '.join(compliance.missing_fields)}")

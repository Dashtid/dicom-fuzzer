"""CVE Registry - Metadata for all supported CVEs.

Contains information about each CVE including:
- CVE ID and description
- Affected products and versions
- Vulnerability category
- Severity rating
- References
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CVECategory(Enum):
    """Categories of DICOM vulnerabilities."""

    HEAP_OVERFLOW = "heap_overflow"
    STACK_OVERFLOW = "stack_overflow"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    USE_AFTER_FREE = "use_after_free"
    PATH_TRAVERSAL = "path_traversal"
    DENIAL_OF_SERVICE = "denial_of_service"
    POLYGLOT = "polyglot"
    DEEP_NESTING = "deep_nesting"
    MALFORMED_LENGTH = "malformed_length"
    ENCAPSULATED_PIXEL = "encapsulated_pixel"
    JPEG_CODEC = "jpeg_codec"
    CERTIFICATE_VALIDATION = "certificate_validation"
    URL_SCHEME_BYPASS = "url_scheme_bypass"


@dataclass
class CVEInfo:
    """Information about a specific CVE.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2025-5943")
        description: Human-readable description
        category: Type of vulnerability
        severity: CVSS severity (critical, high, medium, low)
        cvss_score: CVSS v3 score if available
        affected_product: Product name (e.g., "MicroDicom")
        affected_versions: Version string (e.g., "< 2024.1")
        target_component: DICOM component targeted
        references: List of reference URLs
        variants: Number of attack variants available

    """

    cve_id: str
    description: str
    category: CVECategory
    severity: str
    affected_product: str
    target_component: str
    cvss_score: float | None = None
    affected_versions: str = ""
    references: list[str] = field(default_factory=list)
    variants: int = 1

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_product": self.affected_product,
            "affected_versions": self.affected_versions,
            "target_component": self.target_component,
            "references": self.references,
            "variants": self.variants,
        }


# Registry of all supported CVEs
CVE_REGISTRY: dict[str, CVEInfo] = {
    # === 2025 CVEs ===
    "CVE-2025-5943": CVEInfo(
        cve_id="CVE-2025-5943",
        description="MicroDicom heap buffer overflow in pixel data parsing",
        category=CVECategory.HEAP_OVERFLOW,
        severity="critical",
        cvss_score=9.8,
        affected_product="MicroDicom",
        affected_versions="< 2024.2",
        target_component="pixel_data",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-037-01"
        ],
        variants=2,  # heap_overflow + integer_overflow
    ),
    "CVE-2025-35975": CVEInfo(
        cve_id="CVE-2025-35975",
        description="MicroDicom out-of-bounds write via pixel data dimension mismatch",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        severity="critical",
        cvss_score=9.8,
        affected_product="MicroDicom",
        affected_versions="< 2024.2",
        target_component="pixel_data",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01"
        ],
        variants=4,  # Different dimension combinations
    ),
    "CVE-2025-36521": CVEInfo(
        cve_id="CVE-2025-36521",
        description="MicroDicom out-of-bounds read via dimension/buffer mismatch",
        category=CVECategory.OUT_OF_BOUNDS_READ,
        severity="high",
        cvss_score=8.8,
        affected_product="MicroDicom",
        affected_versions="< 2024.2",
        target_component="pixel_data",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01"
        ],
        variants=5,  # Different dimension triggers
    ),
    "CVE-2025-11266": CVEInfo(
        cve_id="CVE-2025-11266",
        description="GDCM integer underflow in encapsulated PixelData fragments",
        category=CVECategory.INTEGER_UNDERFLOW,
        severity="high",
        cvss_score=8.1,
        affected_product="GDCM",
        affected_versions="< 3.0.24",
        target_component="encapsulated_pixel_data",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01"
        ],
        variants=2,  # underflow + fragment_count_mismatch
    ),
    "CVE-2025-53618": CVEInfo(
        cve_id="CVE-2025-53618",
        description="GDCM JPEG codec OOB read via malformed Huffman tables",
        category=CVECategory.OUT_OF_BOUNDS_READ,
        severity="high",
        cvss_score=7.5,
        affected_product="GDCM",
        affected_versions="< 3.0.24",
        target_component="jpeg_codec",
        references=[
            "https://claroty.com/team82/research/dicom-demystified-exploring-the-underbelly-of-medical-imaging"
        ],
        variants=1,
    ),
    "CVE-2025-53619": CVEInfo(
        cve_id="CVE-2025-53619",
        description="GDCM JPEG stream truncation causing OOB read",
        category=CVECategory.JPEG_CODEC,
        severity="high",
        cvss_score=7.5,
        affected_product="GDCM",
        affected_versions="< 3.0.24",
        target_component="jpeg_codec",
        references=[
            "https://claroty.com/team82/research/dicom-demystified-exploring-the-underbelly-of-medical-imaging"
        ],
        variants=1,
    ),
    "CVE-2025-1001": CVEInfo(
        cve_id="CVE-2025-1001",
        description="RadiAnt certificate validation bypass (MITM)",
        category=CVECategory.CERTIFICATE_VALIDATION,
        severity="medium",
        cvss_score=5.7,
        affected_product="RadiAnt DICOM Viewer",
        affected_versions="< 2024.1",
        target_component="metadata",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-051-01"
        ],
        variants=5,  # Different URL payloads
    ),
    "CVE-2025-1002": CVEInfo(
        cve_id="CVE-2025-1002",
        description="MicroDicom certificate verification bypass (MITM)",
        category=CVECategory.CERTIFICATE_VALIDATION,
        severity="medium",
        cvss_score=5.7,
        affected_product="MicroDicom",
        affected_versions="< 2024.2",
        target_component="metadata",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01"
        ],
        variants=7,  # Different MITM URL payloads
    ),
    "CVE-2025-27578": CVEInfo(
        cve_id="CVE-2025-27578",
        description="OsiriX MD use-after-free via DICOM upload",
        category=CVECategory.USE_AFTER_FREE,
        severity="critical",
        cvss_score=9.8,
        affected_product="OsiriX MD",
        affected_versions="< 13.0.2",
        target_component="sequence",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-128-01"
        ],
        variants=1,
    ),
    "CVE-2025-31946": CVEInfo(
        cve_id="CVE-2025-31946",
        description="OsiriX MD local use-after-free via import",
        category=CVECategory.USE_AFTER_FREE,
        severity="high",
        cvss_score=7.8,
        affected_product="OsiriX MD",
        affected_versions="< 13.0.2",
        target_component="pixel_data",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-128-01"
        ],
        variants=1,
    ),
    "CVE-2025-5307": CVEInfo(
        cve_id="CVE-2025-5307",
        description="Sante DICOM Viewer Pro out-of-bounds read",
        category=CVECategory.OUT_OF_BOUNDS_READ,
        severity="high",
        cvss_score=7.8,
        affected_product="Sante DICOM Viewer Pro",
        affected_versions="< 14.2.2",
        target_component="pixel_data",
        references=[],
        variants=4,  # Different dimension configurations
    ),
    # === 2024 CVEs ===
    "CVE-2024-22100": CVEInfo(
        cve_id="CVE-2024-22100",
        description="MicroDicom heap-based buffer overflow in DCM parsing",
        category=CVECategory.HEAP_OVERFLOW,
        severity="critical",
        cvss_score=9.8,
        affected_product="MicroDicom",
        affected_versions="< 2023.3",
        target_component="private_elements",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-058-01"
        ],
        variants=1,
    ),
    "CVE-2024-25578": CVEInfo(
        cve_id="CVE-2024-25578",
        description="MicroDicom out-of-bounds write due to lack of validation",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        severity="high",
        cvss_score=8.8,
        affected_product="MicroDicom",
        affected_versions="< 2023.3",
        target_component="vr_length",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-060-01"
        ],
        variants=1,
    ),
    "CVE-2024-28877": CVEInfo(
        cve_id="CVE-2024-28877",
        description="MicroDicom stack buffer overflow via nested structures",
        category=CVECategory.STACK_OVERFLOW,
        severity="critical",
        cvss_score=9.8,
        affected_product="MicroDicom",
        affected_versions="< 2023.3",
        target_component="sequence",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-058-01"
        ],
        variants=1,
    ),
    "CVE-2024-33606": CVEInfo(
        cve_id="CVE-2024-33606",
        description="MicroDicom URL scheme security bypass",
        category=CVECategory.URL_SCHEME_BYPASS,
        severity="high",
        cvss_score=8.8,
        affected_product="MicroDicom",
        affected_versions="< 2023.3",
        target_component="url_elements",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-060-01"
        ],
        variants=10,  # Different URL payloads
    ),
    "CVE-2024-1453": CVEInfo(
        cve_id="CVE-2024-1453",
        description="Sante DICOM Viewer Pro out-of-bounds read (2024)",
        category=CVECategory.OUT_OF_BOUNDS_READ,
        severity="high",
        cvss_score=7.8,
        affected_product="Sante DICOM Viewer Pro",
        affected_versions="< 14.0.4",
        target_component="string_elements",
        references=[],
        variants=5,  # Different target elements
    ),
    "CVE-2024-47796": CVEInfo(
        cve_id="CVE-2024-47796",
        description="DCMTK out-of-bounds write in nowindow LUT processing",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        severity="critical",
        cvss_score=9.8,
        affected_product="DCMTK",
        affected_versions="< 3.6.9",
        target_component="lut_data",
        references=[
            "https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122"
        ],
        variants=5,  # Different LUT overflow patterns
    ),
    "CVE-2024-52333": CVEInfo(
        cve_id="CVE-2024-52333",
        description="DCMTK out-of-bounds write in determineMinMax",
        category=CVECategory.OUT_OF_BOUNDS_WRITE,
        severity="critical",
        cvss_score=9.8,
        affected_product="DCMTK",
        affected_versions="< 3.6.9",
        target_component="pixel_data",
        references=[
            "https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121"
        ],
        variants=5,  # Different minmax overflow patterns
    ),
    # === Legacy CVEs ===
    "CVE-2022-24193": CVEInfo(
        cve_id="CVE-2022-24193",
        description="OsiriX DoS via deep sequence nesting",
        category=CVECategory.DEEP_NESTING,
        severity="medium",
        cvss_score=6.5,
        affected_product="OsiriX",
        affected_versions="< 12.0",
        target_component="sequence",
        references=[],
        variants=3,  # Different nesting depths
    ),
    "CVE-2021-41946": CVEInfo(
        cve_id="CVE-2021-41946",
        description="ClearCanvas path traversal via filename injection",
        category=CVECategory.PATH_TRAVERSAL,
        severity="high",
        cvss_score=8.1,
        affected_product="ClearCanvas",
        affected_versions="all",
        target_component="referenced_file",
        references=[],
        variants=7,  # Different path traversal payloads
    ),
    "CVE-2020-29625": CVEInfo(
        cve_id="CVE-2020-29625",
        description="DCMTK DoS via undefined length fields",
        category=CVECategory.MALFORMED_LENGTH,
        severity="high",
        cvss_score=7.5,
        affected_product="DCMTK",
        affected_versions="< 3.6.6",
        target_component="vr_length",
        references=[],
        variants=2,  # undefined_length + oversized_length
    ),
    "CVE-2019-11687": CVEInfo(
        cve_id="CVE-2019-11687",
        description="DICOM preamble polyglot (PE/ELF executable in DICOM)",
        category=CVECategory.POLYGLOT,
        severity="critical",
        cvss_score=9.8,
        affected_product="Multiple",
        affected_versions="all",
        target_component="preamble",
        references=[
            "https://marcoramilli.com/2019/02/28/dicom-dread-the-infection-is-one-click-away/"
        ],
        variants=2,  # PE polyglot + ELF polyglot
    ),
}


def list_cves() -> list[str]:
    """Get list of all available CVE IDs."""
    return sorted(CVE_REGISTRY.keys())


def get_cve_info(cve_id: str) -> CVEInfo | None:
    """Get information about a specific CVE."""
    return CVE_REGISTRY.get(cve_id)


def get_cves_by_category(category: CVECategory) -> list[CVEInfo]:
    """Get all CVEs in a specific category."""
    return [cve for cve in CVE_REGISTRY.values() if cve.category == category]


def get_cves_by_product(product: str) -> list[CVEInfo]:
    """Get all CVEs affecting a specific product."""
    product_lower = product.lower()
    return [
        cve
        for cve in CVE_REGISTRY.values()
        if product_lower in cve.affected_product.lower()
    ]

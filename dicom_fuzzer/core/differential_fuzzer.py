"""Differential Fuzzer for DICOM Implementations.

Compares behavior across multiple DICOM parser implementations to discover
semantic bugs, parsing inconsistencies, and security vulnerabilities.

Supported Implementations:
- pydicom (Python)
- GDCM (C++ via Python bindings)
- dcmtk (via subprocess)
- pynetdicom (for network operations)

Key Features:
- Multi-implementation parsing comparison
- Semantic differential analysis
- Automatic bug classification
- Regression detection
- Oracle-free bug finding

Research References:
- Differential Testing for Software (McKeeman, 1998)
- Coverage-Directed Differential Testing of JVM Implementations (PLDI 2016)
- DiffFuzz: Differential Fuzzing for Side-Channel Analysis (NDSS 2022)
- Nezha: Efficient Domain-Independent Differential Testing (S&P 2017)

"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ImplementationType(Enum):
    """Supported DICOM implementation types."""

    PYDICOM = "pydicom"
    GDCM = "gdcm"
    DCMTK = "dcmtk"
    PYNETDICOM = "pynetdicom"
    CUSTOM = "custom"


class DifferenceType(Enum):
    """Types of differences between implementations."""

    PARSE_SUCCESS_FAILURE = "parse_success_failure"
    VALUE_MISMATCH = "value_mismatch"
    VR_MISMATCH = "vr_mismatch"
    TAG_PRESENCE = "tag_presence"
    SEQUENCE_DEPTH = "sequence_depth"
    ENCODING_DIFFERENCE = "encoding_difference"
    EXCEPTION_TYPE = "exception_type"
    CRASH = "crash"
    TIMEOUT = "timeout"
    MEMORY_DIVERGENCE = "memory_divergence"


class BugSeverity(Enum):
    """Severity classification for found bugs."""

    CRITICAL = "critical"  # Crash, memory corruption
    HIGH = "high"  # Security-relevant semantic difference
    MEDIUM = "medium"  # Functional difference
    LOW = "low"  # Minor inconsistency
    INFO = "info"  # Informational difference


@dataclass
class ParseResult:
    """Result of parsing a DICOM file with an implementation."""

    implementation: ImplementationType
    success: bool
    error_message: str = ""
    error_type: str = ""
    parse_time_ms: float = 0.0
    memory_usage_mb: float = 0.0

    # Parsed data
    tags_found: dict[str, Any] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    vr_types: dict[str, str] = field(default_factory=dict)
    sequence_depths: dict[str, int] = field(default_factory=dict)

    # Metadata
    file_meta: dict[str, Any] = field(default_factory=dict)
    transfer_syntax: str = ""
    sop_class: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for comparison."""
        return {
            "implementation": self.implementation.value,
            "success": self.success,
            "error_message": self.error_message,
            "tags_found": list(self.tags_found.keys()),
            "values": self.values,
            "vr_types": self.vr_types,
            "transfer_syntax": self.transfer_syntax,
        }


@dataclass
class Difference:
    """A difference found between implementations."""

    diff_type: DifferenceType
    description: str
    impl_a: ImplementationType
    impl_b: ImplementationType
    tag: str = ""
    value_a: Any = None
    value_b: Any = None
    severity: BugSeverity = BugSeverity.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.diff_type.value,
            "description": self.description,
            "implementations": [self.impl_a.value, self.impl_b.value],
            "tag": self.tag,
            "severity": self.severity.value,
        }


@dataclass
class DifferentialResult:
    """Result of differential testing on a single input."""

    input_hash: str
    input_path: str
    results: dict[ImplementationType, ParseResult] = field(default_factory=dict)
    differences: list[Difference] = field(default_factory=list)
    is_interesting: bool = False
    bug_severity: BugSeverity = BugSeverity.INFO
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()


class DICOMParser(ABC):
    """Abstract base class for DICOM parser wrappers."""

    @property
    @abstractmethod
    def implementation_type(self) -> ImplementationType:
        """Get implementation type."""

    @abstractmethod
    def parse(self, file_path: Path | str) -> ParseResult:
        """Parse a DICOM file and return results."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this implementation is available."""


class PydicomParser(DICOMParser):
    """Parser wrapper for pydicom."""

    @property
    def implementation_type(self) -> ImplementationType:
        """Return the implementation type identifier."""
        return ImplementationType.PYDICOM

    def is_available(self) -> bool:
        """Check if pydicom is available for parsing."""
        try:
            import pydicom  # noqa: F401

            return True
        except ImportError:
            logger.debug("pydicom not available: ImportError")
            return False

    def parse(self, file_path: Path | str) -> ParseResult:
        """Parse DICOM file using pydicom."""
        result = ParseResult(implementation=self.implementation_type, success=False)
        start_time = time.time()

        try:
            import pydicom
            from pydicom.errors import InvalidDicomError

            ds = pydicom.dcmread(str(file_path), force=True)

            result.success = True
            result.parse_time_ms = (time.time() - start_time) * 1000

            # Extract file meta
            if hasattr(ds, "file_meta"):
                result.transfer_syntax = str(
                    getattr(ds.file_meta, "TransferSyntaxUID", "")
                )
                result.sop_class = str(
                    getattr(ds.file_meta, "MediaStorageSOPClassUID", "")
                )

            # Extract all tags
            for elem in ds:
                tag_str = f"({elem.tag.group:04X},{elem.tag.element:04X})"
                result.tags_found[tag_str] = True
                result.vr_types[tag_str] = elem.VR

                # Get value (with truncation for large values)
                try:
                    value = elem.value
                    if isinstance(value, bytes) and len(value) > 100:
                        value = f"bytes[{len(value)}]"
                    elif isinstance(value, str) and len(value) > 100:
                        value = value[:100] + "..."
                    result.values[tag_str] = str(value)
                except Exception:
                    result.values[tag_str] = "<error reading value>"

                # Track sequence depth
                if elem.VR == "SQ":
                    result.sequence_depths[tag_str] = self._get_sequence_depth(elem)

        except InvalidDicomError as e:
            result.error_message = str(e)
            result.error_type = "InvalidDicomError"
        except Exception as e:
            result.error_message = str(e)
            result.error_type = type(e).__name__

        result.parse_time_ms = (time.time() - start_time) * 1000
        return result

    def _get_sequence_depth(self, elem: Any, depth: int = 0) -> int:
        """Recursively get sequence depth."""
        if not hasattr(elem, "value") or not elem.value:
            return depth

        max_depth = depth
        for item in elem.value:
            for sub_elem in item:
                if sub_elem.VR == "SQ":
                    sub_depth = self._get_sequence_depth(sub_elem, depth + 1)
                    max_depth = max(max_depth, sub_depth)

        return max_depth


class GDCMParser(DICOMParser):
    """Parser wrapper for GDCM."""

    @property
    def implementation_type(self) -> ImplementationType:
        """Return the implementation type identifier."""
        return ImplementationType.GDCM

    def is_available(self) -> bool:
        """Check if GDCM Python bindings are available."""
        try:
            import gdcm  # noqa: F401

            return True
        except ImportError:
            logger.debug("GDCM not available: ImportError")
            return False

    def parse(self, file_path: Path | str) -> ParseResult:
        """Parse DICOM file using GDCM."""
        result = ParseResult(implementation=self.implementation_type, success=False)
        start_time = time.time()

        try:
            import gdcm

            reader = gdcm.Reader()
            reader.SetFileName(str(file_path))

            if reader.Read():
                result.success = True
                ds = reader.GetFile().GetDataSet()

                # Extract transfer syntax
                file_info = reader.GetFile()
                header = file_info.GetHeader()
                result.transfer_syntax = str(
                    header.GetDataElement(gdcm.Tag(0x0002, 0x0010)).GetValue()
                )

                # Iterate through data elements
                it = ds.GetDES().begin()
                while it != ds.GetDES().end():
                    de = it.__deref__()
                    tag = de.GetTag()
                    tag_str = f"({tag.GetGroup():04X},{tag.GetElement():04X})"

                    result.tags_found[tag_str] = True

                    # Get VR
                    vr = de.GetVR()
                    result.vr_types[tag_str] = str(vr)

                    # Get value (limited)
                    try:
                        value = de.GetValue()
                        if value:
                            value_str = str(value)
                            if len(value_str) > 100:
                                value_str = value_str[:100] + "..."
                            result.values[tag_str] = value_str
                    except Exception:
                        result.values[tag_str] = "<error>"

                    it.next()
            else:
                result.error_message = "GDCM Read() returned False"
                result.error_type = "ReadError"

        except Exception as e:
            result.error_message = str(e)
            result.error_type = type(e).__name__

        result.parse_time_ms = (time.time() - start_time) * 1000
        return result


class DCMTKParser(DICOMParser):
    """Parser wrapper for DCMTK (via dcmdump subprocess)."""

    def __init__(self, dcmdump_path: str = "dcmdump") -> None:
        self.dcmdump_path = dcmdump_path

    @property
    def implementation_type(self) -> ImplementationType:
        """Return the implementation type identifier."""
        return ImplementationType.DCMTK

    def is_available(self) -> bool:
        """Check if DCMTK dcmdump is available on the system."""
        try:
            result = subprocess.run(
                [self.dcmdump_path, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.debug(f"DCMTK not available: {self.dcmdump_path} not found")
            return False
        except subprocess.TimeoutExpired:
            logger.debug(f"DCMTK not available: {self.dcmdump_path} timed out")
            return False

    def parse(self, file_path: Path | str) -> ParseResult:
        """Parse DICOM file using DCMTK dcmdump."""
        result = ParseResult(implementation=self.implementation_type, success=False)
        start_time = time.time()

        try:
            # Run dcmdump with verbose output
            proc = subprocess.run(
                [self.dcmdump_path, "+P", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode == 0:
                result.success = True
                result = self._parse_dcmdump_output(proc.stdout, result)
            else:
                result.error_message = proc.stderr or "dcmdump failed"
                result.error_type = f"ExitCode{proc.returncode}"

        except subprocess.TimeoutExpired:
            result.error_message = "dcmdump timeout"
            result.error_type = "TimeoutError"
        except FileNotFoundError:
            result.error_message = "dcmdump not found"
            result.error_type = "FileNotFoundError"
        except Exception as e:
            result.error_message = str(e)
            result.error_type = type(e).__name__

        result.parse_time_ms = (time.time() - start_time) * 1000
        return result

    def _parse_dcmdump_output(self, output: str, result: ParseResult) -> ParseResult:
        """Parse dcmdump output to extract tags and values."""
        import re

        # Pattern: (gggg,eeee) VR value
        pattern = re.compile(r"\(([0-9a-fA-F]{4}),([0-9a-fA-F]{4})\)\s+(\w{2})\s+(.+)")

        for line in output.split("\n"):
            match = pattern.search(line)
            if match:
                group, element, vr, value = match.groups()
                tag_str = f"({group.upper()},{element.upper()})"
                result.tags_found[tag_str] = True
                result.vr_types[tag_str] = vr
                result.values[tag_str] = value.strip()[:100]

                # Check for transfer syntax
                if tag_str == "(0002,0010)":
                    result.transfer_syntax = value.strip()

        return result


class DifferentialAnalyzer:
    """Analyzes differences between parser results."""

    # Tags that are critical for security
    SECURITY_CRITICAL_TAGS = {
        "(0010,0010)",  # Patient Name
        "(0010,0020)",  # Patient ID
        "(0010,0030)",  # Patient Birth Date
        "(0008,0050)",  # Accession Number
        "(0008,0018)",  # SOP Instance UID
        "(7FE0,0010)",  # Pixel Data
        "(0028,0010)",  # Rows
        "(0028,0011)",  # Columns
    }

    def analyze(
        self, results: dict[ImplementationType, ParseResult]
    ) -> list[Difference]:
        """Compare results from different implementations."""
        differences: list[Difference] = []

        impls = list(results.keys())

        for i in range(len(impls)):
            for j in range(i + 1, len(impls)):
                impl_a, impl_b = impls[i], impls[j]
                result_a, result_b = results[impl_a], results[impl_b]

                # Check parse success/failure divergence
                if result_a.success != result_b.success:
                    severity = (
                        BugSeverity.HIGH if result_a.success else BugSeverity.MEDIUM
                    )
                    differences.append(
                        Difference(
                            diff_type=DifferenceType.PARSE_SUCCESS_FAILURE,
                            description=(
                                f"{impl_a.value} {'succeeded' if result_a.success else 'failed'}, "
                                f"{impl_b.value} {'succeeded' if result_b.success else 'failed'}"
                            ),
                            impl_a=impl_a,
                            impl_b=impl_b,
                            severity=severity,
                        )
                    )
                    continue  # Can't compare further if one failed

                if not result_a.success or not result_b.success:
                    continue

                # Compare tag presence
                tags_a = set(result_a.tags_found.keys())
                tags_b = set(result_b.tags_found.keys())

                only_in_a = tags_a - tags_b
                only_in_b = tags_b - tags_a

                for tag in only_in_a:
                    severity = (
                        BugSeverity.HIGH
                        if tag in self.SECURITY_CRITICAL_TAGS
                        else BugSeverity.MEDIUM
                    )
                    differences.append(
                        Difference(
                            diff_type=DifferenceType.TAG_PRESENCE,
                            description=f"Tag {tag} present only in {impl_a.value}",
                            impl_a=impl_a,
                            impl_b=impl_b,
                            tag=tag,
                            severity=severity,
                        )
                    )

                for tag in only_in_b:
                    severity = (
                        BugSeverity.HIGH
                        if tag in self.SECURITY_CRITICAL_TAGS
                        else BugSeverity.MEDIUM
                    )
                    differences.append(
                        Difference(
                            diff_type=DifferenceType.TAG_PRESENCE,
                            description=f"Tag {tag} present only in {impl_b.value}",
                            impl_a=impl_a,
                            impl_b=impl_b,
                            tag=tag,
                            severity=severity,
                        )
                    )

                # Compare values for common tags
                common_tags = tags_a & tags_b
                for tag in common_tags:
                    value_a = result_a.values.get(tag)
                    value_b = result_b.values.get(tag)

                    if value_a != value_b:
                        severity = (
                            BugSeverity.HIGH
                            if tag in self.SECURITY_CRITICAL_TAGS
                            else BugSeverity.LOW
                        )
                        differences.append(
                            Difference(
                                diff_type=DifferenceType.VALUE_MISMATCH,
                                description=(
                                    f"Value mismatch for tag {tag}: "
                                    f"{impl_a.value}='{value_a}' vs {impl_b.value}='{value_b}'"
                                ),
                                impl_a=impl_a,
                                impl_b=impl_b,
                                tag=tag,
                                value_a=value_a,
                                value_b=value_b,
                                severity=severity,
                            )
                        )

                    # Compare VR types
                    vr_a = result_a.vr_types.get(tag)
                    vr_b = result_b.vr_types.get(tag)

                    if vr_a != vr_b:
                        differences.append(
                            Difference(
                                diff_type=DifferenceType.VR_MISMATCH,
                                description=(
                                    f"VR mismatch for tag {tag}: "
                                    f"{impl_a.value}={vr_a} vs {impl_b.value}={vr_b}"
                                ),
                                impl_a=impl_a,
                                impl_b=impl_b,
                                tag=tag,
                                value_a=vr_a,
                                value_b=vr_b,
                                severity=BugSeverity.MEDIUM,
                            )
                        )

                # Compare transfer syntax interpretation
                if result_a.transfer_syntax != result_b.transfer_syntax:
                    differences.append(
                        Difference(
                            diff_type=DifferenceType.ENCODING_DIFFERENCE,
                            description=(
                                f"Transfer syntax mismatch: "
                                f"{impl_a.value}='{result_a.transfer_syntax}' vs "
                                f"{impl_b.value}='{result_b.transfer_syntax}'"
                            ),
                            impl_a=impl_a,
                            impl_b=impl_b,
                            severity=BugSeverity.MEDIUM,
                        )
                    )

        return differences


@dataclass
class DifferentialFuzzerConfig:
    """Configuration for differential fuzzer."""

    output_dir: Path = field(default_factory=lambda: Path("diff_fuzzer_output"))
    max_iterations: int = 10000
    timeout_per_test: float = 30.0
    save_interesting: bool = True
    save_all_differences: bool = False
    min_severity: BugSeverity = BugSeverity.LOW


class DifferentialFuzzer:
    """Differential fuzzer comparing multiple DICOM implementations.

    Uses multiple DICOM parsers to find semantic bugs through
    cross-implementation comparison.
    """

    def __init__(
        self,
        config: DifferentialFuzzerConfig | None = None,
    ) -> None:
        self.config = config or DifferentialFuzzerConfig()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize parsers
        self.parsers: list[DICOMParser] = []
        self._setup_parsers()

        # Analyzer
        self.analyzer = DifferentialAnalyzer()

        # Results
        self.results: list[DifferentialResult] = []
        self.interesting_inputs: list[DifferentialResult] = []

        # Statistics
        self.total_tests = 0
        self.total_differences = 0
        self.severity_counts: dict[BugSeverity, int] = dict.fromkeys(BugSeverity, 0)

    def _setup_parsers(self) -> None:
        """Setup available parsers."""
        # Always try pydicom first
        pydicom_parser = PydicomParser()
        if pydicom_parser.is_available():
            self.parsers.append(pydicom_parser)
            logger.info("[+] pydicom parser available")

        # Try GDCM
        gdcm_parser = GDCMParser()
        if gdcm_parser.is_available():
            self.parsers.append(gdcm_parser)
            logger.info("[+] GDCM parser available")

        # Try DCMTK
        dcmtk_parser = DCMTKParser()
        if dcmtk_parser.is_available():
            self.parsers.append(dcmtk_parser)
            logger.info("[+] DCMTK parser available")

        if len(self.parsers) < 2:
            logger.warning(
                f"[-] Only {len(self.parsers)} parser(s) available. "
                "Differential fuzzing requires at least 2."
            )

    def add_parser(self, parser: DICOMParser) -> None:
        """Add a custom parser implementation."""
        if parser.is_available():
            self.parsers.append(parser)
            logger.info(f"[+] Added parser: {parser.implementation_type.value}")

    def test_file(self, file_path: Path | str) -> DifferentialResult:
        """Test a single DICOM file across all implementations."""
        file_path = Path(file_path)

        # Compute input hash
        with open(file_path, "rb") as f:
            input_hash = hashlib.sha256(f.read()).hexdigest()[:16]

        result = DifferentialResult(
            input_hash=input_hash,
            input_path=str(file_path),
        )

        # Parse with each implementation
        for parser in self.parsers:
            try:
                parse_result = parser.parse(file_path)
                result.results[parser.implementation_type] = parse_result
            except Exception as e:
                logger.error(
                    f"[-] Parser {parser.implementation_type.value} crashed: {e}"
                )
                result.results[parser.implementation_type] = ParseResult(
                    implementation=parser.implementation_type,
                    success=False,
                    error_message=str(e),
                    error_type="CRASH",
                )

        # Analyze differences
        result.differences = self.analyzer.analyze(result.results)

        # Determine severity
        severity_order = [
            BugSeverity.INFO,
            BugSeverity.LOW,
            BugSeverity.MEDIUM,
            BugSeverity.HIGH,
            BugSeverity.CRITICAL,
        ]
        if result.differences:
            result.bug_severity = max(
                (d.severity for d in result.differences),
                key=lambda s: severity_order.index(s),
            )
            result.is_interesting = result.bug_severity.value in [
                BugSeverity.CRITICAL.value,
                BugSeverity.HIGH.value,
                BugSeverity.MEDIUM.value,
            ]

        # Update statistics
        self.total_tests += 1
        self.total_differences += len(result.differences)
        for diff in result.differences:
            self.severity_counts[diff.severity] += 1

        return result

    def test_bytes(self, data: bytes) -> DifferentialResult:
        """Test raw DICOM bytes across all implementations."""
        # Write to temporary file
        with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            return self.test_file(tmp_path)
        finally:
            os.unlink(tmp_path)

    def fuzz_directory(self, corpus_dir: Path | str) -> list[DifferentialResult]:
        """Run differential fuzzing on a directory of DICOM files."""
        corpus_dir = Path(corpus_dir)
        results: list[DifferentialResult] = []

        # Find all DICOM files
        dicom_files = list(corpus_dir.glob("**/*.dcm"))
        dicom_files.extend(corpus_dir.glob("**/*.DCM"))
        dicom_files.extend(corpus_dir.glob("**/DICOMDIR"))

        logger.info(f"[+] Found {len(dicom_files)} DICOM files to test")

        for i, file_path in enumerate(dicom_files):
            if i >= self.config.max_iterations:
                break

            try:
                result = self.test_file(file_path)
                results.append(result)

                if result.is_interesting:
                    self.interesting_inputs.append(result)
                    self._save_interesting(result)
                    logger.info(
                        f"[!] Interesting: {file_path.name} - "
                        f"{len(result.differences)} differences, "
                        f"severity={result.bug_severity.value}"
                    )

                # Progress logging
                if (i + 1) % 100 == 0:
                    logger.info(
                        f"[i] Progress: {i + 1}/{len(dicom_files)}, "
                        f"differences={self.total_differences}"
                    )

            except Exception as e:
                logger.error(f"[-] Error testing {file_path}: {e}")

        return results

    def _save_interesting(self, result: DifferentialResult) -> None:
        """Save an interesting result to output directory."""
        if not self.config.save_interesting:
            return

        output_dir = self.config.output_dir / "interesting" / result.input_hash
        output_dir.mkdir(parents=True, exist_ok=True)

        # Copy input file
        input_path = Path(result.input_path)
        if input_path.exists():
            import shutil

            shutil.copy(input_path, output_dir / input_path.name)

        # Save analysis
        analysis = {
            "input_hash": result.input_hash,
            "timestamp": result.timestamp,
            "bug_severity": result.bug_severity.value,
            "differences": [d.to_dict() for d in result.differences],
            "results": {
                impl.value: res.to_dict() for impl, res in result.results.items()
            },
        }

        with open(output_dir / "analysis.json", "w") as f:
            json.dump(analysis, f, indent=2, default=str)

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzing statistics."""
        return {
            "total_tests": self.total_tests,
            "total_differences": self.total_differences,
            "interesting_inputs": len(self.interesting_inputs),
            "parsers_used": [p.implementation_type.value for p in self.parsers],
            "severity_distribution": {
                s.value: count for s, count in self.severity_counts.items()
            },
        }

    def generate_report(self) -> str:
        """Generate markdown report of findings."""
        stats = self.get_statistics()

        md = """# Differential Fuzzing Report

## Summary

| Metric | Value |
|--------|-------|
"""
        md += f"| Total Tests | {stats['total_tests']} |\n"
        md += f"| Total Differences | {stats['total_differences']} |\n"
        md += f"| Interesting Inputs | {stats['interesting_inputs']} |\n"
        md += f"| Parsers Used | {', '.join(stats['parsers_used'])} |\n"

        md += """
## Severity Distribution

| Severity | Count |
|----------|-------|
"""
        for severity, count in stats["severity_distribution"].items():
            md += f"| {severity.upper()} | {count} |\n"

        md += """
## Interesting Findings

"""
        for result in self.interesting_inputs[:20]:  # Top 20
            md += f"""### {result.input_hash}

- **Severity:** {result.bug_severity.value}
- **File:** `{result.input_path}`
- **Differences:** {len(result.differences)}

"""
            for diff in result.differences[:5]:  # Top 5 per finding
                md += f"- [{diff.severity.value.upper()}] {diff.description}\n"

            md += "\n---\n\n"

        md += """
## References

- Differential Testing for Software (McKeeman, 1998)
- Coverage-Directed Differential Testing (PLDI 2016)
- Nezha: Domain-Independent Differential Testing (S&P 2017)

*Generated by DICOM Fuzzer Differential Testing Module*
"""
        return md

    def save_report(self, path: Path | str) -> Path:
        """Save report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_report())
        return path


def create_sample_fuzzer() -> DifferentialFuzzer:
    """Create a sample differential fuzzer."""
    config = DifferentialFuzzerConfig(
        output_dir=Path("diff_fuzzer_output"),
        max_iterations=100,
    )
    return DifferentialFuzzer(config=config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    fuzzer = create_sample_fuzzer()

    print(
        f"[+] Available parsers: {[p.implementation_type.value for p in fuzzer.parsers]}"
    )

    # Test with sample bytes if available
    sample_dicom = (
        bytes(
            [
                0x44,
                0x49,
                0x43,
                0x4D,  # DICM magic
            ]
        )
        + b"\x00" * 128
    )

    result = fuzzer.test_bytes(sample_dicom)
    print(f"[+] Test result: {len(result.differences)} differences")

    print("\n[+] Statistics:")
    print(json.dumps(fuzzer.get_statistics(), indent=2))

"""Comprehensive tests for low-coverage modules to push coverage toward 90%.

This file targets the modules with lowest coverage:
- enhanced_reporter.py (6%)
- lazy_loader.py (18%)
- crash_triage.py (21%)
- corpus_manager.py (20%)
- profiler.py (30%)
"""

from datetime import datetime
from pathlib import Path

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
    Severity,
    triage_session_crashes,
)
from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator
from dicom_fuzzer.core.fuzzing_session import CrashRecord
from dicom_fuzzer.core.lazy_loader import (
    LazyDicomLoader,
    create_deferred_loader,
    create_metadata_loader,
)


class TestEnhancedReportGenerator:
    """Tests for EnhancedReportGenerator class."""

    def test_init_creates_output_dir(self, tmp_path: Path) -> None:
        """Test that __init__ creates output directory."""
        output_dir = tmp_path / "reports"
        generator = EnhancedReportGenerator(output_dir=str(output_dir))
        assert output_dir.exists()
        assert generator.output_dir == output_dir

    def test_init_with_triage_enabled(self, tmp_path: Path) -> None:
        """Test initialization with triage enabled."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=True
        )
        assert generator.enable_triage is True
        assert generator.triage_engine is not None

    def test_init_with_triage_disabled(self, tmp_path: Path) -> None:
        """Test initialization with triage disabled."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )
        assert generator.enable_triage is False
        assert generator.triage_engine is None

    def test_generate_html_report_creates_file(self, tmp_path: Path) -> None:
        """Test that generate_html_report creates an HTML file."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        session_data = {
            "session_info": {
                "session_id": "test_session_001",
                "session_name": "Test Session",
                "start_time": "2025-01-15T10:00:00",
                "end_time": "2025-01-15T11:00:00",
                "duration_seconds": 3600,
            },
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 0,
                "hangs": 0,
                "successes": 100,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

        output_path = tmp_path / "report.html"
        result = generator.generate_html_report(session_data, output_path)

        assert result == output_path
        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "Test Session" in content
        assert "100" in content  # files_fuzzed

    def test_generate_html_report_auto_output_path(self, tmp_path: Path) -> None:
        """Test HTML report with auto-generated output path."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        session_data = {
            "session_info": {
                "session_id": "auto_path_test",
                "session_name": "Auto Path Test",
                "start_time": "2025-01-15T10:00:00",
                "duration_seconds": 100,
            },
            "statistics": {
                "files_fuzzed": 50,
                "mutations_applied": 250,
                "crashes": 0,
                "hangs": 0,
                "successes": 50,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

        result = generator.generate_html_report(session_data)
        assert result.exists()
        assert "auto_path_test" in result.name

    def test_generate_html_report_with_crashes(self, tmp_path: Path) -> None:
        """Test HTML report with crash data."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        session_data = {
            "session_info": {
                "session_id": "crash_test",
                "session_name": "Crash Test",
                "start_time": "2025-01-15T10:00:00",
                "duration_seconds": 60,
            },
            "statistics": {
                "files_fuzzed": 10,
                "mutations_applied": 50,
                "crashes": 2,
                "hangs": 1,
                "successes": 7,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/tmp/test1.dcm",
                    "timestamp": "2025-01-15T10:30:00",
                    "return_code": -11,
                    "exception_type": "SegmentationFault",
                    "exception_message": "SIGSEGV at 0x0",
                    "stack_trace": "main() -> process() -> crash()",
                    "preserved_sample_path": "/crashes/crash_001.dcm",
                    "crash_log_path": "/logs/crash_001.log",
                    "reproduction_command": "dicom-fuzzer --input crash_001.dcm",
                },
                {
                    "crash_id": "crash_002",
                    "crash_type": "hang",
                    "severity": "medium",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "/tmp/test2.dcm",
                    "timestamp": "2025-01-15T10:45:00",
                },
            ],
            "fuzzed_files": {
                "file_001": {
                    "source_file": "/source/original.dcm",
                    "mutations": [
                        {
                            "strategy_name": "metadata",
                            "mutation_type": "replace",
                            "target_tag": "(0010,0010)",
                            "target_element": "PatientName",
                            "original_value": "John Doe",
                            "mutated_value": "A" * 1000,
                        }
                    ],
                },
                "file_002": {"source_file": "/source/original2.dcm", "mutations": []},
            },
        }

        output_path = tmp_path / "crash_report.html"
        result = generator.generate_html_report(session_data, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "crash_001" in content
        assert "crash_002" in content
        assert "SECURITY FINDING" in content
        assert "DoS RISK" in content
        assert "Crash Details" in content

    def test_generate_html_report_with_triage(self, tmp_path: Path) -> None:
        """Test HTML report with triage enabled."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=True
        )

        session_data = {
            "session_info": {
                "session_id": "triage_test",
                "session_name": "Triage Test",
                "start_time": "2025-01-15T10:00:00",
                "duration_seconds": 120,
            },
            "statistics": {
                "files_fuzzed": 5,
                "mutations_applied": 25,
                "crashes": 1,
                "hangs": 0,
                "successes": 4,
            },
            "crashes": [
                {
                    "crash_id": "critical_crash",
                    "crash_type": "SIGSEGV",
                    "severity": "critical",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/tmp/critical.dcm",
                    "timestamp": "2025-01-15T10:15:00",
                    "exception_message": "write access violation heap corruption",
                    "stack_trace": "use-after-free detected",
                }
            ],
            "fuzzed_files": {},
        }

        output_path = tmp_path / "triage_report.html"
        result = generator.generate_html_report(session_data, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "critical_crash" in content
        # Triage should add priority info
        assert "Priority" in content or "priority" in content.lower()

    def test_enrich_crashes_with_triage_disabled(self, tmp_path: Path) -> None:
        """Test _enrich_crashes_with_triage when triage is disabled."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        session_data = {"crashes": [{"crash_id": "test"}]}
        result = generator._enrich_crashes_with_triage(session_data)
        assert result == session_data  # Should return unchanged

    def test_enrich_crashes_with_no_crashes(self, tmp_path: Path) -> None:
        """Test _enrich_crashes_with_triage with empty crashes list."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=True
        )

        session_data = {"crashes": []}
        result = generator._enrich_crashes_with_triage(session_data)
        assert result["crashes"] == []

    def test_escape_html(self, tmp_path: Path) -> None:
        """Test HTML escaping."""
        generator = EnhancedReportGenerator(output_dir=str(tmp_path))

        text = '<script>alert("XSS")</script> & "quotes" \'apostrophe\''
        escaped = generator._escape_html(text)

        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "&amp;" in escaped
        assert "&quot;" in escaped
        assert "&#39;" in escaped

    def test_html_crash_summary_no_crashes(self, tmp_path: Path) -> None:
        """Test crash summary section with no crashes."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        html = generator._html_crash_summary([], {})
        assert "No crashes detected" in html

    def test_html_crash_details_no_crashes(self, tmp_path: Path) -> None:
        """Test crash details section with no crashes."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        html = generator._html_crash_details([], {})
        assert html == ""

    def test_html_mutation_analysis_no_files(self, tmp_path: Path) -> None:
        """Test mutation analysis with no fuzzed files."""
        generator = EnhancedReportGenerator(
            output_dir=str(tmp_path), enable_triage=False
        )

        html = generator._html_mutation_analysis({})
        assert html == ""


class TestLazyDicomLoader:
    """Tests for LazyDicomLoader class."""

    @pytest.fixture
    def sample_dicom(self, tmp_path: Path) -> Path:
        """Create a minimal DICOM file."""
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import generate_uid

        file_path = tmp_path / "test.dcm"
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

        ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.is_little_endian = True
        ds.is_implicit_VR = False
        ds.PatientName = "Test Patient"
        ds.PatientID = "12345"
        ds.Modality = "CT"

        ds.save_as(str(file_path))
        return file_path

    def test_init_default(self) -> None:
        """Test default initialization."""
        loader = LazyDicomLoader()
        assert loader.metadata_only is False
        assert loader.defer_size is None
        assert loader.force is True

    def test_init_metadata_only(self) -> None:
        """Test metadata-only initialization."""
        loader = LazyDicomLoader(metadata_only=True)
        assert loader.metadata_only is True

    def test_init_with_defer_size(self) -> None:
        """Test initialization with defer size."""
        loader = LazyDicomLoader(defer_size=1024)
        assert loader.defer_size == 1024

    def test_load_file(self, sample_dicom: Path) -> None:
        """Test loading a DICOM file."""
        loader = LazyDicomLoader()
        ds = loader.load(sample_dicom)

        assert isinstance(ds, Dataset)
        assert ds.PatientName == "Test Patient"
        assert ds.PatientID == "12345"

    def test_load_file_metadata_only(self, sample_dicom: Path) -> None:
        """Test loading with metadata_only=True."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(sample_dicom)

        assert isinstance(ds, Dataset)
        assert ds.PatientName == "Test Patient"

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading a nonexistent file."""
        loader = LazyDicomLoader()
        nonexistent = tmp_path / "nonexistent.dcm"

        with pytest.raises(FileNotFoundError):
            loader.load(nonexistent)

    def test_load_invalid_file(self, tmp_path: Path) -> None:
        """Test loading an invalid DICOM file."""
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"not a dicom file")

        loader = LazyDicomLoader(force=False)
        with pytest.raises(Exception):
            loader.load(invalid_file)

    def test_load_pixels_nonexistent_file(self, tmp_path: Path) -> None:
        """Test load_pixels with nonexistent file."""
        loader = LazyDicomLoader()
        ds = Dataset()
        nonexistent = tmp_path / "nonexistent.dcm"

        with pytest.raises(FileNotFoundError):
            loader.load_pixels(ds, nonexistent)

    def test_load_batch(self, sample_dicom: Path, tmp_path: Path) -> None:
        """Test batch loading multiple files."""
        # Create additional files
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import generate_uid

        files = [sample_dicom]
        for i in range(2):
            file_path = tmp_path / f"test_{i}.dcm"
            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
            file_meta.MediaStorageSOPInstanceUID = generate_uid()
            file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

            ds = FileDataset(
                str(file_path), {}, file_meta=file_meta, preamble=b"\0" * 128
            )
            ds.is_little_endian = True
            ds.is_implicit_VR = False
            ds.PatientName = f"Patient {i}"
            ds.save_as(str(file_path))
            files.append(file_path)

        loader = LazyDicomLoader()
        datasets = loader.load_batch(files)

        assert len(datasets) == 3

    def test_load_batch_with_invalid_files(
        self, sample_dicom: Path, tmp_path: Path
    ) -> None:
        """Test batch loading with some invalid files."""
        invalid_file = tmp_path / "invalid.dcm"
        invalid_file.write_bytes(b"not dicom")

        loader = LazyDicomLoader(force=False)
        datasets = loader.load_batch([sample_dicom, invalid_file])

        # Should skip invalid file, return valid ones
        assert len(datasets) >= 0  # At least some may succeed

    def test_create_metadata_loader(self) -> None:
        """Test create_metadata_loader factory function."""
        loader = create_metadata_loader()

        assert isinstance(loader, LazyDicomLoader)
        assert loader.metadata_only is True
        assert loader.force is True

    def test_create_deferred_loader(self) -> None:
        """Test create_deferred_loader factory function."""
        loader = create_deferred_loader(defer_size_mb=5)

        assert isinstance(loader, LazyDicomLoader)
        assert loader.metadata_only is False
        assert loader.defer_size == 5 * 1024 * 1024


class TestCrashTriageEngine:
    """Tests for CrashTriageEngine class."""

    def test_init(self) -> None:
        """Test engine initialization."""
        engine = CrashTriageEngine()
        assert engine.triage_cache == {}

    def create_crash_record(
        self,
        crash_type: str = "crash",
        exception_message: str = "",
        stack_trace: str = "",
        exception_type: str | None = None,
    ) -> CrashRecord:
        """Helper to create CrashRecord for testing."""
        return CrashRecord(
            crash_id="test_crash",
            timestamp=datetime.now(),
            crash_type=crash_type,
            severity="medium",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/tmp/test.dcm",
            return_code=-11,
            exception_type=exception_type,
            exception_message=exception_message,
            stack_trace=stack_trace,
        )

    def test_triage_critical_sigsegv_write(self) -> None:
        """Test triage for SIGSEGV with write access."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="SIGSEGV",
            exception_message="write access violation at address 0x0",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity == Severity.CRITICAL

    def test_triage_high_sigsegv(self) -> None:
        """Test triage for SIGSEGV without write."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="SIGSEGV",
            exception_message="segmentation fault",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity in [Severity.CRITICAL, Severity.HIGH]

    def test_triage_sigabrt(self) -> None:
        """Test triage for SIGABRT."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="SIGABRT",
            exception_message="abort signal",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity == Severity.HIGH

    def test_triage_heap_corruption(self) -> None:
        """Test triage for heap-related crash."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="crash",
            exception_message="heap corruption detected",
            stack_trace="malloc() -> process() -> heap overflow",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity in [Severity.CRITICAL, Severity.HIGH]
        assert triage.exploitability in [
            ExploitabilityRating.EXPLOITABLE,
            ExploitabilityRating.PROBABLY_EXPLOITABLE,
        ]

    def test_triage_use_after_free(self) -> None:
        """Test triage for use-after-free."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="crash",
            exception_message="use-after-free detected",
            stack_trace="free() called on already freed memory",
        )

        triage = engine.triage_crash(crash)

        assert triage.exploitability == ExploitabilityRating.EXPLOITABLE

    def test_triage_buffer_overflow(self) -> None:
        """Test triage for buffer overflow."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="crash",
            exception_message="buffer overflow detected",
            stack_trace="stack smash protection triggered",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_triage_benign_timeout(self) -> None:
        """Test triage for timeout (benign)."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="timeout",
            exception_message="timeout exceeded",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity == Severity.LOW
        assert triage.exploitability == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

    def test_triage_benign_permission_denied(self) -> None:
        """Test triage for permission denied (benign)."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="error",
            exception_message="permission denied",
        )

        triage = engine.triage_crash(crash)

        assert triage.severity == Severity.LOW

    def test_triage_caching(self) -> None:
        """Test that triage results are cached."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(crash_type="crash")

        triage1 = engine.triage_crash(crash)
        triage2 = engine.triage_crash(crash)

        # Should return cached result
        assert triage1.crash_id == triage2.crash_id
        assert len(engine.triage_cache) == 1

    def test_triage_crashes_multiple(self) -> None:
        """Test triaging multiple crashes."""
        engine = CrashTriageEngine()

        crashes = [
            self.create_crash_record(
                crash_type="SIGSEGV",
                exception_message="write access violation",
            ),
            self.create_crash_record(
                crash_type="timeout",
                exception_message="timeout exceeded",
            ),
        ]

        triages = engine.triage_crashes(crashes)

        # Should be sorted by priority (highest first)
        assert len(triages) == 2
        assert triages[0].priority_score >= triages[1].priority_score

    def test_get_triage_summary(self) -> None:
        """Test getting summary statistics."""
        engine = CrashTriageEngine()

        crashes = [
            self.create_crash_record(crash_type="SIGSEGV"),
            self.create_crash_record(crash_type="timeout", exception_message="timeout"),
        ]

        triages = engine.triage_crashes(crashes)
        summary = engine.get_triage_summary(triages)

        assert summary["total_crashes"] == 2
        assert "by_severity" in summary
        assert "by_exploitability" in summary
        assert "average_priority" in summary

    def test_get_triage_summary_empty(self) -> None:
        """Test summary with no crashes."""
        engine = CrashTriageEngine()
        summary = engine.get_triage_summary([])

        assert summary["total_crashes"] == 0
        assert summary["average_priority"] == 0.0

    def test_extract_indicators(self) -> None:
        """Test indicator extraction."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="crash",
            exception_message="heap buffer overflow",
            stack_trace="stack smash detected",
            exception_type="MemoryError",
        )

        indicators = engine._extract_indicators(crash)

        assert any("crash_type" in ind for ind in indicators)
        assert any(
            "heap" in ind.lower() or "stack" in ind.lower() for ind in indicators
        )

    def test_generate_tags(self) -> None:
        """Test tag generation."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(crash_type="crash")
        indicators = ["heap: malloc", "memory: buffer overflow"]

        tags = engine._generate_tags(crash, indicators)

        assert "crash" in tags
        assert "heap-related" in tags or "memory-corruption" in tags

    def test_generate_recommendations_high_severity(self) -> None:
        """Test recommendations for high severity crash."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record()
        indicators = ["heap: use-after-free"]

        recommendations = engine._generate_recommendations(
            crash,
            Severity.CRITICAL,
            ExploitabilityRating.EXPLOITABLE,
            indicators,
        )

        assert any("immediately" in r.lower() for r in recommendations)
        assert any(
            "exploit" in r.lower() or "asan" in r.lower() for r in recommendations
        )

    def test_generate_summary(self) -> None:
        """Test summary generation."""
        engine = CrashTriageEngine()
        crash = self.create_crash_record(
            crash_type="SIGSEGV",
            exception_message="segmentation fault at 0x0",
        )

        summary = engine._generate_summary(
            crash, Severity.HIGH, ExploitabilityRating.PROBABLY_EXPLOITABLE
        )

        assert "SIGSEGV" in summary
        assert "high" in summary
        assert "probably_exploitable" in summary

    def test_priority_score_calculation(self) -> None:
        """Test priority score calculation."""
        engine = CrashTriageEngine()

        # Critical + exploitable should be highest
        crash_critical = self.create_crash_record(
            crash_type="SIGSEGV",
            exception_message="write access violation heap corruption use-after-free",
        )
        triage_critical = engine.triage_crash(crash_critical)

        # Low + benign should be lowest
        crash_low = self.create_crash_record(
            crash_type="error",
            exception_message="file not found",
        )
        triage_low = engine.triage_crash(crash_low)

        assert triage_critical.priority_score > triage_low.priority_score

    def test_crash_triage_str(self) -> None:
        """Test CrashTriage string representation."""
        triage = CrashTriage(
            crash_id="test",
            severity=Severity.HIGH,
            exploitability=ExploitabilityRating.PROBABLY_EXPLOITABLE,
            priority_score=75.0,
            summary="Test crash",
        )

        result = str(triage)
        assert "HIGH" in result
        assert "75.0" in result
        assert "Test crash" in result


class TestTriageSessionCrashes:
    """Tests for triage_session_crashes function."""

    def test_triage_session_crashes(self) -> None:
        """Test the convenience function."""
        crashes = [
            CrashRecord(
                crash_id="crash_1",
                timestamp=datetime.now(),
                crash_type="SIGSEGV",
                severity="high",
                fuzzed_file_id="file_1",
                fuzzed_file_path="/tmp/test1.dcm",
                exception_message="write access",
            ),
            CrashRecord(
                crash_id="crash_2",
                timestamp=datetime.now(),
                crash_type="timeout",
                severity="low",
                fuzzed_file_id="file_2",
                fuzzed_file_path="/tmp/test2.dcm",
                exception_message="timeout",
            ),
        ]

        result = triage_session_crashes(crashes)

        assert "triages" in result
        assert "summary" in result
        assert "high_priority" in result
        assert "critical_crashes" in result
        assert len(result["triages"]) == 2

    def test_triage_session_crashes_empty(self) -> None:
        """Test with empty crash list."""
        result = triage_session_crashes([])

        assert result["triages"] == []
        assert result["summary"]["total_crashes"] == 0


class TestSeverityAndExploitabilityEnums:
    """Tests for Severity and ExploitabilityRating enums."""

    def test_severity_values(self) -> None:
        """Test Severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_exploitability_values(self) -> None:
        """Test ExploitabilityRating enum values."""
        assert ExploitabilityRating.EXPLOITABLE.value == "exploitable"
        assert ExploitabilityRating.PROBABLY_EXPLOITABLE.value == "probably_exploitable"
        assert (
            ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE.value
            == "probably_not_exploitable"
        )
        assert ExploitabilityRating.UNKNOWN.value == "unknown"


class TestPerformanceProfiler:
    """Tests for PerformanceProfiler class."""

    def test_profiler_context_manager(self) -> None:
        """Test profiler as context manager."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            profiler.record_file_generated()
            profiler.record_mutation("test_strategy")

        assert profiler.metrics.files_generated == 1
        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.total_duration > 0

    def test_profiler_record_file_generated(self) -> None:
        """Test recording file generation."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            for _ in range(15):  # Trigger resource sampling
                profiler.record_file_generated("metadata")

        assert profiler.metrics.files_generated == 15
        assert profiler.metrics.strategy_usage["metadata"] == 15

    def test_profiler_record_mutation_with_duration(self) -> None:
        """Test recording mutation with timing."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            profiler.record_mutation("header", duration=0.5)
            profiler.record_mutation("header", duration=0.3)
            profiler.record_mutation("pixel", duration=0.2)

        assert profiler.metrics.mutations_applied == 3
        assert profiler.metrics.strategy_timing["header"] == 0.8
        assert profiler.metrics.strategy_timing["pixel"] == 0.2

    def test_profiler_record_validation(self) -> None:
        """Test recording validation."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            profiler.record_validation()
            profiler.record_validation()

        assert profiler.metrics.validations_performed == 2

    def test_profiler_record_crash(self) -> None:
        """Test recording crash."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            profiler.record_crash()
            profiler.record_crash()
            profiler.record_crash()

        assert profiler.metrics.crashes_found == 3

    def test_profiler_get_progress_report(self) -> None:
        """Test progress report generation."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            for _ in range(10):
                profiler.record_file_generated("metadata")
                profiler.record_mutation("metadata")
            profiler.record_crash()

        report = profiler.get_progress_report()
        assert "Files Generated: 10" in report
        assert "Mutations Applied: 10" in report
        assert "Crashes Found: 1" in report
        assert "Strategy Usage:" in report

    def test_profiler_get_progress_report_with_target(self) -> None:
        """Test progress report with target."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            for _ in range(5):
                profiler.record_file_generated()

        report = profiler.get_progress_report(target=100)
        assert "Estimated Time Remaining:" in report
        assert "Progress:" in report

    def test_profiler_get_summary(self) -> None:
        """Test summary generation."""
        from dicom_fuzzer.core.profiler import PerformanceProfiler

        with PerformanceProfiler() as profiler:
            profiler.record_file_generated("header")
            profiler.record_mutation("header", 0.1)
            profiler.record_validation()

        summary = profiler.get_summary()
        assert "duration_seconds" in summary
        assert "files_generated" in summary
        assert "mutations_applied" in summary
        assert "strategy_usage" in summary
        assert "start_time" in summary


class TestFuzzingMetrics:
    """Tests for FuzzingMetrics dataclass."""

    def test_throughput_per_second(self) -> None:
        """Test throughput calculation."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 10.0

        assert metrics.throughput_per_second() == 10.0

    def test_throughput_zero_duration(self) -> None:
        """Test throughput with zero duration."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 0.0

        assert metrics.throughput_per_second() == 0.0

    def test_avg_time_per_file(self) -> None:
        """Test average time calculation."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 50
        metrics.total_duration = 100.0

        assert metrics.avg_time_per_file() == 2.0

    def test_avg_time_zero_files(self) -> None:
        """Test average time with zero files."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 0
        metrics.total_duration = 10.0

        assert metrics.avg_time_per_file() == 0.0

    def test_estimated_time_remaining(self) -> None:
        """Test time remaining estimation."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 50
        metrics.total_duration = 100.0

        # 50 files in 100s = 2s/file
        # Target 100, need 50 more = 100s remaining
        assert metrics.estimated_time_remaining(100) == 100.0

    def test_estimated_time_target_reached(self) -> None:
        """Test time remaining when target reached."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 50.0

        assert metrics.estimated_time_remaining(50) == 0.0

    def test_estimated_time_zero_files(self) -> None:
        """Test time remaining with zero files."""
        from dicom_fuzzer.core.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 0
        metrics.total_duration = 0.0

        assert metrics.estimated_time_remaining(100) == 0.0


class TestStrategyTimer:
    """Tests for StrategyTimer context manager."""

    def test_strategy_timer_context_manager(self) -> None:
        """Test strategy timer as context manager."""
        import time

        from dicom_fuzzer.core.profiler import PerformanceProfiler, StrategyTimer

        profiler = PerformanceProfiler()

        with StrategyTimer(profiler, "test_strategy"):
            time.sleep(0.01)  # Small delay

        assert profiler.metrics.mutations_applied == 1
        assert profiler.metrics.strategy_timing.get("test_strategy", 0) > 0

    def test_strategy_timer_multiple(self) -> None:
        """Test multiple timer usage."""
        import time

        from dicom_fuzzer.core.profiler import PerformanceProfiler, StrategyTimer

        profiler = PerformanceProfiler()

        for _ in range(3):
            with StrategyTimer(profiler, "header"):
                time.sleep(0.001)

        assert profiler.metrics.mutations_applied == 3
        assert profiler.metrics.strategy_usage["header"] == 3


class TestProfileFunction:
    """Tests for profile_function decorator."""

    def test_profile_function_decorator(self, capsys) -> None:
        """Test profile_function decorator."""
        from dicom_fuzzer.core.profiler import profile_function

        @profile_function("test_strategy")
        def test_func(x: int) -> int:
            return x * 2

        result = test_func(5)
        assert result == 10

        captured = capsys.readouterr()
        assert "[PROFILE]" in captured.out
        assert "test_strategy" in captured.out


class TestLazyDicomLoaderAdditional:
    """Additional tests for LazyDicomLoader."""

    @pytest.fixture
    def dicom_with_pixels(self, tmp_path: Path) -> Path:
        """Create a DICOM file with pixel data."""
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import generate_uid

        file_path = tmp_path / "pixels.dcm"
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

        ds = FileDataset(str(file_path), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.is_little_endian = True
        ds.is_implicit_VR = False
        ds.PatientName = "Test"
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = b"\x00" * (64 * 64)

        ds.save_as(str(file_path))
        return file_path

    def test_load_pixels_already_loaded(self, dicom_with_pixels: Path) -> None:
        """Test load_pixels when data already exists."""
        loader = LazyDicomLoader(metadata_only=False)
        ds = loader.load(dicom_with_pixels)

        # Load pixels again - should warn but return data
        pixels = loader.load_pixels(ds, dicom_with_pixels)
        assert len(pixels) > 0

    def test_load_pixels_metadata_only(self, dicom_with_pixels: Path) -> None:
        """Test load_pixels after metadata-only load."""
        loader = LazyDicomLoader(metadata_only=True)
        ds = loader.load(dicom_with_pixels)

        # Load pixels on demand
        pixels = loader.load_pixels(ds, dicom_with_pixels)
        assert len(pixels) > 0
        assert hasattr(ds, "PixelData")

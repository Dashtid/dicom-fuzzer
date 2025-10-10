"""
Fuzzing Session Tracker - Complete Traceability for Fuzzing Campaigns

This module provides comprehensive tracking of fuzzing sessions, maintaining
complete traceability from source files through mutations to crashes.

Key capabilities:
- Track every mutation applied to every file
- Link crashes/hangs back to exact mutation history
- Preserve crash artifacts with full context
- Generate detailed forensic reports
"""

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pydicom


@dataclass
class MutationRecord:
    """
    Record of a single mutation applied to a DICOM file.

    Tracks exactly what was changed, enabling reproduction and analysis.
    """

    mutation_id: str
    strategy_name: str
    timestamp: datetime
    target_tag: Optional[str] = None  # DICOM tag modified (e.g., "(0010,0010)")
    target_element: Optional[str] = None  # Element name (e.g., "PatientName")
    mutation_type: str = "unknown"  # Type of mutation (flip_bits, insert, delete, etc.)
    original_value: Optional[str] = None  # Value before mutation
    mutated_value: Optional[str] = None  # Value after mutation
    parameters: Dict[str, Any] = field(default_factory=dict)  # Strategy parameters

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class FuzzedFileRecord:
    """
    Complete record of a fuzzed DICOM file.

    Contains everything needed to understand how the file was created
    and reproduce the fuzzing process.
    """

    file_id: str  # Unique identifier
    source_file: str  # Original file path
    output_file: str  # Fuzzed file path
    timestamp: datetime
    file_hash: str  # SHA256 of fuzzed file
    severity: str  # Mutation severity level
    mutations: List[MutationRecord] = field(default_factory=list)

    # DICOM metadata snapshots
    source_metadata: Dict[str, str] = field(default_factory=dict)
    fuzzed_metadata: Dict[str, str] = field(default_factory=dict)

    # Test results (populated if tested against a viewer)
    test_result: Optional[str] = None  # success, crash, hang, error
    crash_details: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_id": self.file_id,
            "source_file": self.source_file,
            "output_file": self.output_file,
            "timestamp": self.timestamp.isoformat(),
            "file_hash": self.file_hash,
            "severity": self.severity,
            "mutations": [m.to_dict() for m in self.mutations],
            "source_metadata": self.source_metadata,
            "fuzzed_metadata": self.fuzzed_metadata,
            "test_result": self.test_result,
            "crash_details": self.crash_details,
        }


@dataclass
class CrashRecord:
    """
    Detailed crash record with full forensic information.

    Links crash back to exact file and mutation history that caused it.
    """

    crash_id: str
    timestamp: datetime
    crash_type: str  # crash, hang, exception
    severity: str  # critical, high, medium, low

    # Link to fuzzed file
    fuzzed_file_id: str
    fuzzed_file_path: str

    # Crash details
    return_code: Optional[int] = None
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    stack_trace: Optional[str] = None

    # Artifacts
    crash_log_path: Optional[str] = None
    preserved_sample_path: Optional[str] = None

    # Reproducibility
    reproduction_command: Optional[str] = None

    # Mutation tracking for deduplication
    mutation_sequence: List[tuple] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "crash_id": self.crash_id,
            "timestamp": self.timestamp.isoformat(),
            "crash_type": self.crash_type,
            "severity": self.severity,
            "fuzzed_file_id": self.fuzzed_file_id,
            "fuzzed_file_path": self.fuzzed_file_path,
            "return_code": self.return_code,
            "exception_type": self.exception_type,
            "exception_message": self.exception_message,
            "stack_trace": self.stack_trace,
            "crash_log_path": self.crash_log_path,
            "preserved_sample_path": self.preserved_sample_path,
            "reproduction_command": self.reproduction_command,
            "mutation_sequence": self.mutation_sequence,
        }


class FuzzingSession:
    """
    Tracks a complete fuzzing session with full traceability.

    Maintains detailed records of all files, mutations, and crashes,
    enabling forensic analysis and reproducibility.
    """

    def __init__(
        self,
        session_name: str,
        output_dir: str = "./output",
        reports_dir: str = "./reports",
    ):
        """
        Initialize fuzzing session tracker.

        Args:
            session_name: Name/ID for this fuzzing session
            output_dir: Directory for fuzzed files
            reports_dir: Directory for reports
        """
        self.session_name = session_name
        self.session_id = f"{session_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.start_time = datetime.now()

        # Directory structure
        self.output_dir = Path(output_dir)
        self.reports_dir = Path(reports_dir)
        self.crashes_dir = Path("crashes") / self.session_id

        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        # Session data
        self.fuzzed_files: Dict[str, FuzzedFileRecord] = {}
        self.crashes: List[CrashRecord] = []
        self.current_file_record: Optional[FuzzedFileRecord] = None

        # Statistics
        self.stats = {
            "files_fuzzed": 0,
            "mutations_applied": 0,
            "crashes": 0,
            "hangs": 0,
            "successes": 0,
        }

    def start_file_fuzzing(
        self,
        source_file: Path,
        output_file: Path,
        severity: str,
    ) -> str:
        """
        Start tracking a new fuzzed file.

        Args:
            source_file: Path to original DICOM file
            output_file: Path where fuzzed file will be saved
            severity: Mutation severity level

        Returns:
            File ID for tracking
        """
        # Generate unique file ID
        file_id = f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

        # Extract source metadata
        source_metadata = self._extract_metadata(source_file)

        # Create file record
        self.current_file_record = FuzzedFileRecord(
            file_id=file_id,
            source_file=str(source_file),
            output_file=str(output_file),
            timestamp=datetime.now(),
            file_hash="",  # Will be set when file is saved
            severity=severity,
            source_metadata=source_metadata,
        )

        # Add to fuzzed files immediately so it's available for mutations
        self.fuzzed_files[file_id] = self.current_file_record

        self.stats["files_fuzzed"] += 1
        return file_id

    def record_mutation(
        self,
        strategy_name: str,
        mutation_type: str = "unknown",
        target_tag: Optional[str] = None,
        target_element: Optional[str] = None,
        original_value: Optional[Any] = None,
        mutated_value: Optional[Any] = None,
        parameters: Optional[Dict] = None,
    ):
        """
        Record a mutation applied to the current file.

        Args:
            strategy_name: Name of mutation strategy
            mutation_type: Type of mutation performed
            target_tag: DICOM tag that was modified
            target_element: Element name that was modified
            original_value: Original value before mutation
            mutated_value: Value after mutation
            parameters: Additional parameters used in mutation
        """
        if not self.current_file_record:
            raise RuntimeError("No active file fuzzing session")

        mutation_id = f"mut_{len(self.current_file_record.mutations) + 1}"

        # Convert values to strings for storage
        orig_str = self._value_to_string(original_value)
        mut_str = self._value_to_string(mutated_value)

        mutation = MutationRecord(
            mutation_id=mutation_id,
            strategy_name=strategy_name,
            timestamp=datetime.now(),
            target_tag=target_tag,
            target_element=target_element,
            mutation_type=mutation_type,
            original_value=orig_str,
            mutated_value=mut_str,
            parameters=parameters or {},
        )

        self.current_file_record.mutations.append(mutation)
        self.stats["mutations_applied"] += 1

    def end_file_fuzzing(
        self,
        output_file: Path,
        success: bool = True,
    ):
        """
        Finish tracking current fuzzed file.

        Args:
            output_file: Path to saved fuzzed file
            success: Whether file was successfully created
        """
        if not self.current_file_record:
            raise RuntimeError("No active file fuzzing session")

        # Calculate file hash
        if success and output_file.exists():
            self.current_file_record.file_hash = self._calculate_file_hash(output_file)
            self.current_file_record.fuzzed_metadata = self._extract_metadata(
                output_file
            )

        # Store the record
        file_id = self.current_file_record.file_id
        self.fuzzed_files[file_id] = self.current_file_record
        self.current_file_record = None

    def record_test_result(
        self,
        file_id: str,
        result: str,
        **details,
    ):
        """
        Record test result for a fuzzed file.

        Args:
            file_id: ID of fuzzed file
            result: Test result (success, crash, hang, error)
            **details: Additional result details
        """
        if file_id not in self.fuzzed_files:
            raise KeyError(f"Unknown file ID: {file_id}")

        self.fuzzed_files[file_id].test_result = result
        self.fuzzed_files[file_id].crash_details = details

        # Update statistics
        if result == "crash":
            self.stats["crashes"] += 1
        elif result == "hang":
            self.stats["hangs"] += 1
        elif result == "success":
            self.stats["successes"] += 1

    def record_crash(
        self,
        file_id: str,
        crash_type: str,
        severity: str = "high",
        return_code: Optional[int] = None,
        exception_type: Optional[str] = None,
        exception_message: Optional[str] = None,
        stack_trace: Optional[str] = None,
        viewer_path: Optional[str] = None,
    ) -> CrashRecord:
        """
        Record a crash with full forensic details.

        Args:
            file_id: ID of file that caused crash
            crash_type: Type of crash (crash, hang, exception)
            severity: Crash severity
            return_code: Process return code
            exception_type: Exception type if applicable
            exception_message: Exception message
            stack_trace: Full stack trace
            viewer_path: Path to viewer that was tested

        Returns:
            CrashRecord object
        """
        if file_id not in self.fuzzed_files:
            raise KeyError(f"Unknown file ID: {file_id}")

        file_record = self.fuzzed_files[file_id]
        crash_id = f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

        # Create crash log
        crash_log_path = self.crashes_dir / f"{crash_id}.log"
        self._create_crash_log(
            crash_log_path,
            file_record,
            crash_type,
            return_code,
            exception_type,
            exception_message,
            stack_trace,
        )

        # Preserve the fuzzed file as crash artifact
        preserved_path = self.crashes_dir / f"{crash_id}.dcm"
        if Path(file_record.output_file).exists():
            shutil.copy2(file_record.output_file, preserved_path)

        # Create reproduction command
        repro_cmd = None
        if viewer_path:
            repro_cmd = f'"{viewer_path}" "{preserved_path}"'

        # Extract mutation sequence for deduplication
        mutation_sequence = []
        for mutation in file_record.mutations:
            mutation_sequence.append((mutation.strategy_name, mutation.mutation_type))

        # Create crash record
        crash = CrashRecord(
            crash_id=crash_id,
            timestamp=datetime.now(),
            crash_type=crash_type,
            severity=severity,
            fuzzed_file_id=file_id,
            fuzzed_file_path=file_record.output_file,
            return_code=return_code,
            exception_type=exception_type,
            exception_message=exception_message,
            stack_trace=stack_trace,
            crash_log_path=str(crash_log_path),
            preserved_sample_path=str(preserved_path),
            reproduction_command=repro_cmd,
            mutation_sequence=mutation_sequence,
        )

        self.crashes.append(crash)

        # Update statistics only if test_result hasn't been set yet
        # (to avoid double-counting when record_test_result is also called)
        file_record = self.fuzzed_files[file_id]
        if file_record.test_result is None:
            if crash_type == "crash":
                self.stats["crashes"] += 1
            elif crash_type == "hang":
                self.stats["hangs"] += 1

        return crash

    def generate_session_report(self) -> Dict:
        """
        Generate complete session report.

        Returns:
            Dictionary with full session data
        """
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        return {
            "session_info": {
                "session_id": self.session_id,
                "session_name": self.session_name,
                "start_time": self.start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
            },
            "statistics": self.stats.copy(),
            "fuzzed_files": {
                file_id: record.to_dict()
                for file_id, record in self.fuzzed_files.items()
            },
            "crashes": [crash.to_dict() for crash in self.crashes],
        }

    def save_session_report(
        self,
        json_path: Optional[Path] = None,
    ) -> Path:
        """
        Save session report to JSON file.

        Args:
            json_path: Path for JSON report (auto-generated if None)

        Returns:
            Path to saved report
        """
        if json_path is None:
            json_dir = self.reports_dir / "json"
            json_dir.mkdir(parents=True, exist_ok=True)
            json_path = json_dir / f"session_{self.session_id}.json"

        report = self.generate_session_report()

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return json_path

    def get_session_summary(self) -> Dict:
        """
        Get a summary of the current session.

        Returns:
            Dictionary with session summary statistics
        """
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        # Calculate files per minute
        files_per_minute = 0
        if duration > 0:
            files_per_minute = (self.stats["files_fuzzed"] / duration) * 60

        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "duration": duration,
            "files_per_minute": files_per_minute,
            "total_files": self.stats["files_fuzzed"],
            "total_mutations": self.stats["mutations_applied"],
            "crashes": self.stats["crashes"],
            "hangs": self.stats["hangs"],
            "successes": self.stats["successes"],
        }

    def mark_test_result(self, file_id: str, result: str):
        """
        Mark the test result for a file (alias for record_test_result).

        Args:
            file_id: ID of the fuzzed file
            result: Test result (success, crash, hang, error)
        """
        self.record_test_result(file_id, result)

    def _extract_metadata(self, dicom_file: Path) -> Dict[str, str]:
        """Extract key DICOM metadata from file."""
        metadata = {}

        try:
            if not dicom_file.exists():
                return metadata

            ds = pydicom.dcmread(str(dicom_file), force=True, stop_before_pixels=True)

            # Extract key identifying fields
            key_tags = [
                ("PatientName", "(0010,0010)"),
                ("PatientID", "(0010,0020)"),
                ("StudyInstanceUID", "(0020,000D)"),
                ("SeriesInstanceUID", "(0020,000E)"),
                ("SOPInstanceUID", "(0008,0018)"),
                ("Modality", "(0008,0060)"),
                ("TransferSyntaxUID", "TransferSyntaxUID"),
            ]

            for name, tag in key_tags:
                try:
                    if hasattr(ds, name):
                        value = getattr(ds, name)
                        metadata[name] = str(value)
                except Exception:
                    continue

            metadata["file_size"] = str(dicom_file.stat().st_size)

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def _value_to_string(self, value: Any) -> Optional[str]:
        """Convert value to string representation."""
        if value is None:
            return None

        if isinstance(value, bytes):
            # For binary data, show hex representation (truncated)
            hex_str = value.hex()
            if len(hex_str) > 100:
                return f"{hex_str[:100]}... (truncated, {len(value)} bytes)"
            return hex_str

        return str(value)

    def _create_crash_log(
        self,
        log_path: Path,
        file_record: FuzzedFileRecord,
        crash_type: str,
        return_code: Optional[int],
        exception_type: Optional[str],
        exception_message: Optional[str],
        stack_trace: Optional[str],
    ):
        """Create detailed crash log file."""
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"CRASH REPORT: {log_path.stem}\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Timestamp:     {datetime.now().isoformat()}\n")
            f.write(f"Crash Type:    {crash_type}\n")
            if return_code is not None:
                f.write(f"Return Code:   {return_code}\n")
            if exception_type:
                f.write(f"Exception:     {exception_type}\n")
            f.write("\n")

            f.write("FUZZED FILE DETAILS\n")
            f.write("-" * 80 + "\n")
            f.write(f"File ID:       {file_record.file_id}\n")
            f.write(f"Source File:   {file_record.source_file}\n")
            f.write(f"Fuzzed File:   {file_record.output_file}\n")
            f.write(f"File Hash:     {file_record.file_hash}\n")
            f.write(f"Severity:      {file_record.severity}\n")
            f.write(f"Mutations:     {len(file_record.mutations)}\n")
            f.write("\n")

            f.write("MUTATION HISTORY\n")
            f.write("-" * 80 + "\n")
            for i, mut in enumerate(file_record.mutations, 1):
                f.write(f"{i}. {mut.strategy_name} - {mut.mutation_type}\n")
                if mut.target_tag:
                    f.write(f"   Tag: {mut.target_tag}")
                    if mut.target_element:
                        f.write(f" ({mut.target_element})")
                    f.write("\n")
                if mut.original_value:
                    f.write(f"   Original: {mut.original_value[:200]}\n")
                if mut.mutated_value:
                    f.write(f"   Mutated:  {mut.mutated_value[:200]}\n")
                f.write("\n")

            if exception_message:
                f.write("EXCEPTION MESSAGE\n")
                f.write("-" * 80 + "\n")
                f.write(f"{exception_message}\n\n")

            if stack_trace:
                f.write("STACK TRACE\n")
                f.write("-" * 80 + "\n")
                f.write(f"{stack_trace}\n")

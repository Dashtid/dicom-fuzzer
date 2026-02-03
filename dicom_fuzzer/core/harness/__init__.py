"""Target Harness Package.

Provides a reusable harness for testing target applications (DICOM viewers, etc.)
with mutated DICOM studies. Monitors for crashes, memory issues, and timeouts.

Example usage:
    from dicom_fuzzer.core.harness import TargetHarness, TargetConfig

    config = TargetConfig(
        executable=Path("/path/to/viewer.exe"),
        timeout_seconds=15.0,
        memory_limit_mb=2048,
    )
    harness = TargetHarness(config, crash_dir=Path("./crashes"))
    result = harness.test_study_directory(Path("./mutated_study"))
"""

from dicom_fuzzer.core.harness.harness import TargetHarness
from dicom_fuzzer.core.harness.monitoring import (
    is_psutil_available,
    kill_target_processes,
    monitor_process,
    run_observation_phase,
)
from dicom_fuzzer.core.harness.target_runner import ExecutionStatus, TargetRunner
from dicom_fuzzer.core.harness.types import (
    DEFAULT_OBSERVATION_PHASES,
    CrashArtifact,
    ObservationPhase,
    PhasedTestResult,
    PhaseResult,
    TargetConfig,
    TestResult,
    TestStatus,
    ValidationResult,
)

__all__ = [
    # Main class
    "TargetHarness",
    # Target runner
    "ExecutionStatus",
    "TargetRunner",
    # Types
    "TestStatus",
    "TargetConfig",
    "TestResult",
    "CrashArtifact",
    "ValidationResult",
    "ObservationPhase",
    "PhaseResult",
    "PhasedTestResult",
    "DEFAULT_OBSERVATION_PHASES",
    # Monitoring functions
    "is_psutil_available",
    "monitor_process",
    "run_observation_phase",
    "kill_target_processes",
]

"""Target Harness for GUI Application Testing.

Provides a reusable harness for testing target applications (DICOM viewers, etc.)
with mutated DICOM studies. Monitors for crashes, memory issues, and timeouts.

Example usage:
    from dicom_fuzzer.core.target_harness import TargetHarness, TargetConfig

    config = TargetConfig(
        executable=Path("/path/to/viewer.exe"),
        timeout_seconds=15.0,
        memory_limit_mb=2048,
    )
    harness = TargetHarness(config, crash_dir=Path("./crashes"))
    result = harness.test_study_directory(Path("./mutated_study"))

Note: This module re-exports from the `harness` subpackage for backward
compatibility. New code should import directly from the subpackage modules.
"""

# Re-export all public symbols from the harness subpackage
from dicom_fuzzer.core.harness import (
    DEFAULT_OBSERVATION_PHASES,
    CrashArtifact,
    ObservationPhase,
    PhasedTestResult,
    PhaseResult,
    TargetConfig,
    TargetHarness,
    TestResult,
    TestStatus,
    ValidationResult,
    is_psutil_available,
)


# Backward compatibility alias
def _is_psutil_available() -> bool:
    """Check if psutil is available (backward compatibility)."""
    return is_psutil_available()


__all__ = [
    # Main class
    "TargetHarness",
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
]

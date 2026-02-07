"""Target harness -- execution, monitoring, calibration.

Provides the TargetRunner for testing target applications (DICOM viewers, etc.)
with fuzzed DICOM inputs. Monitors for crashes, hangs, memory issues.

Example usage:
    from dicom_fuzzer.core.harness import TargetRunner, ExecutionStatus

    runner = TargetRunner(
        target_executable="/path/to/viewer.exe",
        timeout=15.0,
        enable_monitoring=True,
        memory_limit_mb=2048,
    )
    result = runner.execute_with_monitoring(Path("./mutated_study"))
"""

from dicom_fuzzer.core.harness.process_monitor import (
    ProcessMonitor,
    terminate_process_tree,
)
from dicom_fuzzer.core.harness.target_runner import ExecutionStatus, TargetRunner

__all__ = [
    "ExecutionStatus",
    "TargetRunner",
    "ProcessMonitor",
    "terminate_process_tree",
]

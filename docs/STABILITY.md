# DICOM Fuzzer Stability Guarantees

## Overview

DICOM-Fuzzer is built with production-grade stability features to ensure reliable, long-running fuzzing campaigns without manual intervention. This document outlines our stability guarantees, error recovery mechanisms, and best practices.

## Version

**Stability Features Added**: Version 1.1.0 (January 2025)

## Stability Features

### 1. Resource Management

#### Memory Limits
- **Default Soft Limit**: 1GB per fuzzing operation
- **Default Hard Limit**: 2GB per fuzzing operation
- **Platform Support**: Unix/Linux (full), Windows (disk only)

#### CPU Time Limits
- **Default Limit**: 30 seconds per test case
- **Prevents**: Runaway processes from consuming all CPU
- **Platform Support**: Unix/Linux only

#### Disk Space Monitoring
- **Pre-flight Check**: Validates sufficient disk space before starting
- **Minimum Required**: 1GB free space (configurable)
- **Runtime Monitoring**: Periodic checks during long campaigns

**Usage Example:**

```python
from dicom_fuzzer.core import ResourceManager, ResourceLimits

# Custom resource limits
limits = ResourceLimits(
    max_memory_mb=512,  # 512MB soft limit
    max_cpu_seconds=15,  # 15 second timeout
    min_disk_space_mb=2048  # Require 2GB free
)

manager = ResourceManager(limits)

# Use context manager for resource-limited execution
with manager.limited_execution():
    # Your fuzzing code here
    run_campaign()
```

### 2. Error Recovery

#### Automatic Retry Logic
- **Transient Errors**: Automatically retried up to 2 times by default
- **Exponential Backoff**: Brief delays between retries (100ms, 200ms)
- **Retry Tracking**: Each result includes `retry_count` for analysis

**Error Types That Trigger Retry:**
- Generic errors (Exception)
- Resource temporarily unavailable
- Network timeouts (for future network fuzzing)

**Error Types That Don't Retry:**
- Crashes (negative exit codes)
- Out of memory errors
- Successful executions

#### Circuit Breaker Pattern
- **Purpose**: Stop testing targets that consistently fail
- **Threshold**: Opens after 5 consecutive failures
- **Reset Timeout**: 60 seconds before retry attempt
- **Benefits**: Saves time, prevents resource waste

**Circuit Breaker States:**
1. **CLOSED**: Normal operation, all tests execute
2. **OPEN**: Target failing consistently, tests skipped
3. **HALF-OPEN**: After timeout, trying one test to check recovery

**Usage:**

```python
from dicom_fuzzer.core import TargetRunner

runner = TargetRunner(
    target_executable="./viewer.exe",
    max_retries=3,  # Custom retry count
    enable_circuit_breaker=True  # Default
)

# Circuit breaker automatically manages state
results = runner.run_campaign(test_files)

# Check circuit breaker status
print(f"Successes: {runner.circuit_breaker.success_count}")
print(f"Failures: {runner.circuit_breaker.failure_count}")
print(f"Circuit Open: {runner.circuit_breaker.is_open}")
```

### 3. Checkpoint and Resume

#### Campaign Checkpoints
- **Auto-save Interval**: Every 100 files processed (configurable)
- **Format**: JSON (human-readable)
- **Location**: `./checkpoints/` by default

#### Resumable Campaigns
- **Automatic Detection**: Lists interrupted campaigns on startup
- **State Preservation**: Tracks progress, statistics, file lists
- **Resume From**: Last checkpoint or specific file index

**Checkpoint Contents:**
- Campaign ID and status
- Start time and last update
- Files processed vs. total
- Success/failure/crash counts
- Current file index
- Complete test file list
- Custom metadata

**Usage:**

```python
from dicom_fuzzer.core import CampaignRecovery

recovery = CampaignRecovery(
    checkpoint_dir="./checkpoints",
    checkpoint_interval=50  # Checkpoint every 50 files
)

# Create initial checkpoint
checkpoint = recovery.create_checkpoint(
    campaign_id="campaign_2025_01_17",
    total_files=1000,
    processed_files=0,
    # ... other parameters
)

# Save checkpoint periodically
if recovery.should_checkpoint():
    recovery.save_checkpoint()

# Resume interrupted campaign
interrupted = recovery.list_interrupted_campaigns()
if interrupted:
    checkpoint = recovery.load_checkpoint(interrupted[0].campaign_id)
    # Resume from checkpoint.current_file_index
```

### 4. Graceful Shutdown

#### Signal Handling
- **Supported Signals**: SIGINT (Ctrl+C), SIGTERM
- **Behavior**: Saves checkpoint before exiting
- **Second Signal**: Forces immediate exit

**Usage:**

```python
from dicom_fuzzer.core import SignalHandler, CampaignRecovery

recovery = CampaignRecovery()
signal_handler = SignalHandler(recovery_manager=recovery)
signal_handler.install()

try:
    # Run long campaign
    for file in test_files:
        if signal_handler.check_interrupted():
            break
        # Process file
finally:
    signal_handler.uninstall()
```

### 5. Advanced Error Classification

#### Detailed Status Codes
- `SUCCESS`: Normal execution, exit code 0
- `CRASH`: Application crashed (negative exit code)
- `HANG`: Timeout expired
- `ERROR`: Non-zero exit code, generic error
- `OOM`: Out of memory detected
- `RESOURCE_EXHAUSTED`: Resource limit exceeded
- `SKIPPED`: Test not run (circuit breaker open)

#### Intelligent Error Detection
Analyzes stderr output for specific error patterns:
- Out of memory: "out of memory", "memory error", "cannot allocate"
- Resource issues: "resource", "limit", "quota", "too many"
- Crashes: Negative return codes (SIGSEGV, SIGABRT, etc.)

### 6. Pre-flight Validation

#### ConfigValidator Checks
Run before starting campaigns to catch issues early:

**File System Checks:**
- Input file exists and is readable
- Input file appears to be valid DICOM
- Output directory writable or can be created
- Sufficient disk space available

**Environment Checks:**
- Python version >= 3.11
- Required dependencies installed
- Optional dependencies (tqdm, psutil) available

**Target Application Checks:**
- Executable exists and is accessible
- File has execute permissions (Unix)

**System Resource Checks:**
- Available memory
- CPU core count
- Disk space per partition

**Usage:**

```python
from dicom_fuzzer.core import ConfigValidator
from pathlib import Path

validator = ConfigValidator(strict=False)  # Warnings don't fail

passed = validator.validate_all(
    input_file=Path("input.dcm"),
    output_dir=Path("./output"),
    target_executable=Path("./viewer.exe"),
    min_disk_space_mb=1024,
    num_files=1000
)

if not passed:
    print(validator.get_summary())
    sys.exit(1)
```

## Stability Guarantees

### What We Guarantee

1. **No Data Loss**: Checkpoints prevent progress loss on interruption
2. **Resource Safety**: Memory/CPU limits prevent system exhaustion
3. **Error Resilience**: Automatic retry and circuit breaker handling
4. **Clean Shutdown**: Graceful handling of interrupts with state saving
5. **Early Validation**: Pre-flight checks catch configuration errors

### What We Don't Guarantee

1. **Target Application Stability**: We can't fix bugs in tested applications
2. **File System Failures**: Disk failures, permissions changes during execution
3. **External Interruptions**: Power loss, hardware failures, OS crashes
4. **Perfect Resource Estimation**: Actual usage may vary from estimates

## Best Practices

### For Reliable Long-Running Campaigns

1. **Enable All Safety Features:**
   ```python
   runner = TargetRunner(
       target_executable="./app",
       max_retries=2,  # Enable retry
       enable_circuit_breaker=True,  # Enable circuit breaker
       resource_limits=ResourceLimits()  # Enable resource limits
   )
   ```

2. **Use Pre-flight Validation:**
   ```python
   validator = ConfigValidator()
   if not validator.validate_all(...):
       print(validator.get_summary())
       sys.exit(1)
   ```

3. **Enable Checkpointing:**
   ```python
   recovery = CampaignRecovery(
       checkpoint_interval=100  # Every 100 files
   )
   ```

4. **Install Signal Handlers:**
   ```python
   signal_handler = SignalHandler(recovery_manager=recovery)
   signal_handler.install()
   ```

5. **Monitor Resource Usage:**
   ```python
   manager = ResourceManager()
   usage = manager.get_current_usage(output_dir="./output")
   print(f"Memory: {usage.memory_mb:.0f}MB")
   print(f"Disk Free: {usage.disk_free_mb:.0f}MB")
   ```

### For Critical Production Campaigns

1. **Run with Conservative Limits:**
   ```python
   limits = ResourceLimits(
       max_memory_mb=512,  # Lower limit for safety
       max_cpu_seconds=10,  # Shorter timeout
       min_disk_space_mb=5120  # Require 5GB free
   )
   ```

2. **Use Strict Validation:**
   ```python
   validator = ConfigValidator(strict=True)  # Warnings = errors
   ```

3. **Set Shorter Checkpoint Intervals:**
   ```python
   recovery = CampaignRecovery(checkpoint_interval=50)
   ```

4. **Enable Verbose Logging:**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

## Performance Impact

### Resource Limit Overhead
- **Memory Monitoring**: Minimal (<1% CPU)
- **Disk Space Checks**: Negligible (cached by OS)
- **Resource Enforcement**: Only on Unix (Windows checks disk only)

### Checkpoint Overhead
- **Save Time**: ~50ms per checkpoint (JSON serialization)
- **Disk I/O**: ~1KB per checkpoint file
- **Recommendation**: Balance frequency vs. recovery granularity

### Retry Overhead
- **Delay per Retry**: 100ms default (configurable)
- **Typical Impact**: <1% for campaigns with few errors
- **High Error Rate**: May increase runtime significantly

### Circuit Breaker Impact
- **Check Overhead**: Negligible (in-memory state)
- **Benefit**: Saves significant time when target fails consistently
- **Example**: 1000 tests, 5 fail, circuit opens = 995 tests skipped

## Platform Support

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Memory Limits | ✅ Full | ❌ No | ✅ Full |
| CPU Limits | ✅ Full | ❌ No | ✅ Full |
| Disk Checks | ✅ Full | ✅ Full | ✅ Full |
| File Descriptors | ✅ Full | ❌ No | ✅ Full |
| Checkpoints | ✅ Full | ✅ Full | ✅ Full |
| Signal Handling | ✅ Full | ⚠️ SIGINT only | ✅ Full |
| Resource Monitoring | ✅ Full | ⚠️ Requires psutil | ✅ Full |

**Legend:**
- ✅ Full: Complete support
- ⚠️ Partial: Limited functionality
- ❌ No: Not supported

## Troubleshooting

### Common Issues

#### 1. Resource Limits Not Enforced (Windows)
**Symptom**: Memory/CPU limits have no effect

**Cause**: Windows doesn't support `resource` module

**Solution**: Resource limits only work on Unix-like systems. Windows users should:
- Monitor resource usage manually
- Use system-level resource management (Windows Resource Manager)
- Set shorter timeouts to prevent runaway processes

#### 2. Checkpoint Files Growing Large
**Symptom**: Checkpoint directory uses significant disk space

**Cause**: Large campaigns generate large checkpoint files

**Solutions:**
- Increase `checkpoint_interval` (fewer checkpoints)
- Clean up old checkpoints manually
- Use `.gitignore` to exclude checkpoint directory

#### 3. Circuit Breaker Opens Too Quickly
**Symptom**: Tests skipped after only a few failures

**Cause**: Default threshold (5 failures) may be too low

**Solution**: Adjust circuit breaker threshold:
```python
runner.circuit_breaker.failure_threshold = 10  # More failures allowed
```

#### 4. Pre-flight Validation Too Strict
**Symptom**: Validation fails on warnings

**Cause**: Strict mode enabled

**Solution**: Disable strict mode:
```python
validator = ConfigValidator(strict=False)
```

## Migration Guide

### From Version 1.0 to 1.1

**Breaking Changes:**
- None! All stability features are opt-in

**New Features:**
- Resource management (automatic)
- Error recovery (automatic retry)
- Circuit breaker (enabled by default)
- Checkpoints (optional)
- Pre-flight validation (optional)

**Recommended Changes:**

1. **Update target_runner.py usage** (new parameters available):
   ```python
   # Old (still works)
   runner = TargetRunner(target_executable="./app")

   # New (recommended)
   runner = TargetRunner(
       target_executable="./app",
       max_retries=2,
       enable_circuit_breaker=True
   )
   ```

2. **Add pre-flight validation**:
   ```python
   from dicom_fuzzer.core import ConfigValidator

   validator = ConfigValidator()
   validator.validate_all(input_file=..., output_dir=...)
   ```

3. **Enable checkpoints for long campaigns**:
   ```python
   from dicom_fuzzer.core import CampaignRecovery

   recovery = CampaignRecovery()
   # Use in campaign loop
   ```

## Future Improvements

**Planned for Version 1.2:**
- Automatic crash triaging and deduplication
- Distributed fuzzing across multiple machines
- Real-time monitoring dashboard
- Automatic test case minimization
- Coverage correlation and intelligent input generation

## Support

For stability issues, questions, or suggestions:

- **GitHub Issues**: [Report stability issues](https://github.com/yourusername/DICOM-Fuzzer/issues)
- **Documentation**: See `docs/TROUBLESHOOTING.md` for common problems
- **Test Suite**: Run `pytest tests/test_target_runner_stability.py -v` to verify stability features

---

**Document Version**: 1.0
**Last Updated**: January 2025
**Maintainers**: DICOM-Fuzzer Development Team

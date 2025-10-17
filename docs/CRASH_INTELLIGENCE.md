# Crash Intelligence & Stability Tracking

Comprehensive guide to DICOM-Fuzzer's crash intelligence and stability tracking features (v1.2.0).

## Table of Contents

- [Overview](#overview)
- [Crash Triaging](#crash-triaging)
- [Test Case Minimization](#test-case-minimization)
- [Stability Tracking](#stability-tracking)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)

## Overview

DICOM-Fuzzer v1.2.0 introduces production-grade crash intelligence features based on 2025 fuzzing research:

- **Automated Crash Triaging**: Intelligent crash analysis with exploitability assessment
- **Test Case Minimization**: Delta debugging for reducing crash reproducers
- **Stability Tracking**: AFL++-style metrics for detecting non-deterministic behavior

### Research Foundation

These features are based on cutting-edge research:

- **ECHO Tool**: 15.2% coverage improvement through intelligent crash deduplication
- **LLM-Assisted Analysis**: 84.4% reduction in manual crash review workload
- **AFL++ Stability**: Industry-standard stability tracking methodology
- **Delta Debugging**: Andreas Zeller's algorithm with modern improvements

## Crash Triaging

### What is Crash Triaging?

Crash triaging automatically analyzes crashes to determine:

1. **Severity**: How serious is the crash? (CRITICAL, HIGH, MEDIUM, LOW, INFO)
2. **Exploitability**: Could this be weaponized? (EXPLOITABLE, PROBABLY_EXPLOITABLE, etc.)
3. **Priority**: What order should crashes be investigated? (0-100 score)
4. **Indicators**: What specific issues were detected? (heap corruption, use-after-free, etc.)

### Quick Start

```python
from dicom_fuzzer.core import CrashTriageEngine, CrashRecord
from datetime import datetime

# Create triage engine
engine = CrashTriageEngine()

# Create crash record
crash = CrashRecord(
    crash_id="crash_001",
    timestamp=datetime.now(),
    crash_type="SIGSEGV",
    severity="high",
    fuzzed_file_id="test_001",
    fuzzed_file_path="crash_001.dcm",
    exception_type="SegmentationFault",
    exception_message="write access violation at 0x7fff",
    stack_trace="malloc() heap corruption detected\\nwrite_pixel_data() buffer overflow"
)

# Triage the crash
triage = engine.triage_crash(crash)

# Examine results
print(f"Severity: {triage.severity}")  # Severity.CRITICAL
print(f"Exploitability: {triage.exploitability}")  # ExploitabilityRating.EXPLOITABLE
print(f"Priority Score: {triage.priority_score}")  # 95.0
print(f"Indicators: {triage.indicators}")  # ['write access violation', 'heap corruption']
print(f"Recommendations: {triage.recommendations}")
```

### Severity Levels

| Level | Description | Priority Range |
|-------|-------------|----------------|
| **CRITICAL** | Likely exploitable (write access, heap corruption) | 85-100 |
| **HIGH** | Potentially exploitable (read access, stack issues) | 65-85 |
| **MEDIUM** | Stability issue (timeouts, resource exhaustion) | 40-65 |
| **LOW** | Minor issue or edge case | 20-40 |
| **INFO** | Informational only | 0-20 |

### Exploitability Ratings

| Rating | Description | Indicators |
|--------|-------------|------------|
| **EXPLOITABLE** | Definitely weaponizable | Heap corruption, write access violations, use-after-free, double-free |
| **PROBABLY_EXPLOITABLE** | Likely weaponizable | Stack smashing, return address corruption, buffer overflows |
| **PROBABLY_NOT_EXPLOITABLE** | Unlikely to be weaponized | Timeouts, resource exhaustion, assertion failures |
| **UNKNOWN** | Cannot determine | Insufficient information |

### Key Features

**Write vs Read Differentiation**:
- Write access violations: Scored 20 points higher (likely exploitable)
- Read access violations: Lower priority (less likely exploitable)

**Indicator Extraction**:
Automatically detects:
- Heap issues: `malloc`, `free`, `heap corruption`, `use-after-free`, `double-free`
- Stack issues: `stack smash`, `buffer overflow`, `canary detected`
- Memory issues: `out-of-bounds`, `write access violation`
- Control flow: `return address`, `function pointer`, `vtable`, `rip`, `eip`

**Tag Generation**:
- Crash type tags (SIGSEGV, SIGABRT, etc.)
- Issue category tags (heap-related, memory-corruption, etc.)

**Recommendation System**:
Provides actionable next steps based on severity and exploitability.

### Triaging Multiple Crashes

```python
# Triage a list of crashes
crashes = [crash1, crash2, crash3, ...]
triages = [engine.triage_crash(crash) for crash in crashes]

# Get summary statistics
summary = engine.get_triage_summary(triages)

print(f"Total crashes: {summary['total']}")
print(f"Critical: {summary['by_severity']['critical']}")
print(f"Exploitable: {summary['by_exploitability']['exploitable']}")
print(f"High priority (>75): {summary['high_priority_count']}")
```

## Test Case Minimization

### What is Test Case Minimization?

When a fuzzer finds a crashing input, it's often large and complex. Test case minimization reduces it to the **smallest input that still triggers the crash**, making debugging much easier.

### Quick Start

```python
from dicom_fuzzer.core import TestMinimizer, MinimizationStrategy
from pathlib import Path

def my_crash_predicate(test_file: Path) -> bool:
    """Return True if test_file crashes the target."""
    # Run your target application with test_file
    # Return True if it crashes, False otherwise
    result = run_target(test_file)
    return result.crashed

# Create minimizer
minimizer = TestMinimizer(
    crash_predicate=my_crash_predicate,
    strategy=MinimizationStrategy.DDMIN,  # Most effective
    max_iterations=1000,
    timeout_seconds=300
)

# Minimize crashing input
input_file = Path("large_crash.dcm")
output_dir = Path("minimized/")

result = minimizer.minimize(input_file, output_dir)

if result.success:
    print(f"Original size: {result.original_size} bytes")
    print(f"Minimized size: {result.minimized_size} bytes")
    print(f"Reduction: {result.reduction_ratio * 100:.1f}%")
    print(f"Iterations: {result.iterations}")
    print(f"Minimized file: {result.minimized_path}")
```

### Minimization Strategies

| Strategy | Description | Best For | Speed |
|----------|-------------|----------|-------|
| **DDMIN** | Delta debugging (recommended) | Most inputs, best results | Medium |
| **BINARY_SEARCH** | Cut in half repeatedly | Large files, fast reduction | Fast |
| **LINEAR** | Remove one byte at a time | Small files, thorough reduction | Slow |
| **BLOCK** | Remove fixed-size chunks | Very large files | Fast |

### How Delta Debugging (DDMIN) Works

1. Start with full crashing input
2. Divide input into chunks
3. Try removing each chunk
4. If still crashes, keep the smaller version
5. Repeat with smaller chunks until minimal

**Example**:
```
Original: AAAAXBBBB (9 bytes)
Step 1: Try AAAA, XBBBB → Both don't crash
Step 2: Try AAAAX, ABBBB, BBBBB → AAAAX crashes!
Step 3: Try AAAX, AAX, AX, X → X crashes!
Result: X (1 byte) - 88.9% reduction
```

### Advanced Usage

**Timeout Protection**:
```python
minimizer = TestMinimizer(
    crash_predicate=my_predicate,
    timeout_seconds=600  # 10 minutes max
)
```

**Iteration Limit**:
```python
minimizer = TestMinimizer(
    crash_predicate=my_predicate,
    max_iterations=50  # Stop after 50 iterations
)
```

**Strategy Comparison**:
```python
strategies = [
    MinimizationStrategy.DDMIN,
    MinimizationStrategy.BINARY_SEARCH,
    MinimizationStrategy.BLOCK,
]

for strategy in strategies:
    minimizer = TestMinimizer(crash_predicate=my_predicate, strategy=strategy)
    result = minimizer.minimize(input_file, output_dir)
    print(f"{strategy.value}: {result.minimized_size} bytes")
```

## Stability Tracking

### What is Stability Tracking?

Stability tracking monitors whether your fuzzing campaign produces **consistent results**. In an ideal fuzzer:

- Same input → Same execution path → Same coverage
- Stability percentage: 100%

**Instability indicates problems**:
- Uninitialized memory
- Race conditions
- Entropy sources (random numbers, timestamps)
- Non-deterministic behavior

### Quick Start

```python
from dicom_fuzzer.core import StabilityTracker, generate_execution_signature

# Create tracker
tracker = StabilityTracker(
    stability_window=100,  # Track last 100 executions
    retest_frequency=10    # Retest every 10 iterations
)

# During fuzzing campaign
for test_file in corpus:
    # Run test
    result = run_target(test_file)

    # Generate execution signature
    signature = generate_execution_signature(
        exit_code=result.exit_code,
        output_hash=hash(result.stdout),
        coverage=result.coverage_set
    )

    # Record execution
    is_stable = tracker.record_execution(test_file, signature)

    if not is_stable:
        print(f"[!] Unstable execution detected: {test_file.name}")

# Get metrics
metrics = tracker.get_metrics()
print(f"Stability: {metrics.stability_percentage:.1f}%")
print(f"Stable executions: {metrics.stable_executions}")
print(f"Unstable inputs: {len(metrics.unstable_inputs)}")

# Check if campaign is stable
if tracker.is_campaign_stable(threshold=95.0):
    print("[+] Campaign is stable!")
else:
    print("[-] Campaign shows instability issues")
```

### Stability Metrics

**Stability Percentage**:
```
stability_percentage = (stable_executions / total_executions) * 100
```

**Ideal**: 100% - Every retest produces the same signature

**Good**: 95-99% - Minor instability, acceptable

**Poor**: <90% - Significant instability, investigate issues

### Detecting Stability Issues

```python
from dicom_fuzzer.core import detect_stability_issues

# Analyze stability
issues = detect_stability_issues(tracker)

for issue in issues:
    print(f"[!] {issue}")

# Example output:
# [!] Low stability detected (87.3%). This may indicate uninitialized memory,
#     race conditions, or entropy sources in the target application.
# [!] 15 inputs show non-deterministic behavior. Consider investigating with
#     tools like AddressSanitizer or ThreadSanitizer.
```

### Unstable Input Report

```python
# Get detailed report of unstable inputs
report = tracker.get_unstable_inputs_report()

for entry in report:
    print(f"Input: {entry['input_hash']}")
    print(f"  Unique behaviors: {entry['unique_behaviors']}")
    print(f"  Execution count: {entry['execution_count']}")
    print(f"  Variants: {entry['variants']}")
```

### Integration with Fuzzing

**Retest Strategy**:
```python
iteration = 0
for test_file in corpus:
    # Normal execution
    result = run_target(test_file)
    signature = generate_execution_signature(result.exit_code)
    tracker.record_execution(test_file, signature)

    # Periodic retesting
    if tracker.should_retest(test_file):
        # Run again to check stability
        result2 = run_target(test_file)
        signature2 = generate_execution_signature(result2.exit_code)
        tracker.record_execution(test_file, signature2, retest=True)

    iteration += 1
```

## Usage Examples

### Complete Crash Analysis Workflow

```python
from dicom_fuzzer.core import (
    CrashTriageEngine,
    TestMinimizer,
    StabilityTracker,
    MinimizationStrategy
)

# Step 1: Triage all crashes
engine = CrashTriageEngine()
triages = [engine.triage_crash(crash) for crash in crashes]

# Step 2: Sort by priority
triages.sort(key=lambda t: t.priority_score, reverse=True)

# Step 3: Minimize high-priority crashes
for triage in triages[:10]:  # Top 10 crashes
    if triage.priority_score > 75:
        # Find original crash file
        crash_file = find_crash_file(triage.crash_id)

        # Minimize it
        minimizer = TestMinimizer(
            crash_predicate=lambda f: crashes_target(f),
            strategy=MinimizationStrategy.DDMIN
        )
        result = minimizer.minimize(crash_file, output_dir)

        print(f"[+] Minimized {triage.crash_id}")
        print(f"    Severity: {triage.severity}")
        print(f"    Original: {result.original_size} bytes")
        print(f"    Minimized: {result.minimized_size} bytes")
```

### Fuzzing with Stability Tracking

```python
# Initialize tracker
tracker = StabilityTracker()

# Fuzzing loop
for iteration in range(10000):
    # Select seed
    seed = corpus.select()

    # Mutate
    mutant = mutator.mutate(seed)

    # Execute
    result = target_runner.execute(mutant)

    # Track stability
    signature = generate_execution_signature(
        exit_code=result.exit_code,
        coverage=result.coverage
    )
    is_stable = tracker.record_execution(mutant, signature)

    # Handle instability
    if not is_stable:
        logger.warning(f"Unstable execution: {mutant.name}")

    # Periodic stability check
    if iteration % 100 == 0:
        metrics = tracker.get_metrics()
        if metrics.stability_percentage < 90:
            logger.error(f"Low stability: {metrics.stability_percentage:.1f}%")
            # Consider pausing campaign to investigate
```

## Best Practices

### Crash Triaging

1. **Triage Early**: Analyze crashes as soon as they're found
2. **Prioritize**: Focus on CRITICAL/HIGH severity first
3. **Review Indicators**: Check what specific issues were detected
4. **Follow Recommendations**: Act on the generated recommendations
5. **Track Trends**: Monitor if certain crash types increase

### Test Case Minimization

1. **Use DDMIN First**: It's the most effective strategy
2. **Set Reasonable Limits**: max_iterations=1000, timeout=300s
3. **Verify Minimized Files**: Always test that minimized files still crash
4. **Save Originals**: Keep original crash files for reference
5. **Document Results**: Record reduction ratios and iterations

### Stability Tracking

1. **Monitor Continuously**: Track stability throughout campaigns
2. **Set Thresholds**: Aim for >95% stability
3. **Investigate Drops**: If stability drops below 90%, investigate
4. **Retest Periodically**: Use retest_frequency=10 or similar
5. **Address Root Causes**: Fix instability issues in target or harness

## API Reference

### CrashTriageEngine

```python
class CrashTriageEngine:
    def triage_crash(self, crash: CrashRecord) -> CrashTriage:
        """Triage a single crash."""

    def get_triage_summary(self, triages: List[CrashTriage]) -> Dict:
        """Get summary statistics for multiple triages."""
```

### CrashTriage

```python
@dataclass
class CrashTriage:
    crash_id: str
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    exploitability: ExploitabilityRating
    priority_score: float  # 0.0-100.0
    indicators: List[str]
    recommendations: List[str]
    tags: List[str]
    summary: str
```

### TestMinimizer

```python
class TestMinimizer:
    def __init__(
        self,
        crash_predicate: Callable[[Path], bool],
        strategy: MinimizationStrategy = MinimizationStrategy.DDMIN,
        max_iterations: int = 1000,
        timeout_seconds: int = 300
    ):
        """Initialize test case minimizer."""

    def minimize(
        self,
        input_file: Path,
        output_dir: Path
    ) -> MinimizationResult:
        """Minimize a test case."""
```

### StabilityTracker

```python
class StabilityTracker:
    def __init__(
        self,
        stability_window: int = 100,
        retest_frequency: int = 10
    ):
        """Initialize stability tracker."""

    def record_execution(
        self,
        test_file: Path,
        execution_signature: str,
        retest: bool = False
    ) -> bool:
        """Record execution and check stability."""

    def get_metrics(self) -> StabilityMetrics:
        """Get current stability metrics."""

    def is_campaign_stable(self, threshold: float = 95.0) -> bool:
        """Check if campaign is stable."""

    def get_unstable_inputs_report(self) -> List[Dict]:
        """Get detailed report of unstable inputs."""
```

### Utility Functions

```python
def generate_execution_signature(
    exit_code: int,
    output_hash: Optional[str] = None,
    coverage: Optional[Set] = None
) -> str:
    """Generate signature for an execution."""

def detect_stability_issues(tracker: StabilityTracker) -> List[str]:
    """Analyze stability tracker and detect common issues."""
```

## Performance Considerations

### Crash Triaging

- **Fast**: ~0.001s per crash
- **Memory**: Minimal (caches recent triages)
- **Scalable**: Can handle thousands of crashes

### Test Case Minimization

- **Speed**: Depends on strategy and target
  - DDMIN: Medium (seconds to minutes)
  - BINARY_SEARCH: Fast (seconds)
  - LINEAR: Slow (minutes to hours)
  - BLOCK: Fast (seconds)
- **Memory**: Minimal
- **CPU**: Depends on crash predicate execution time

### Stability Tracking

- **Fast**: ~0.0001s per execution record
- **Memory**: Proportional to stability_window (default: 100 executions)
- **Scalable**: Can track millions of executions

## Troubleshooting

### Crash Triaging

**Issue**: All crashes rated as UNKNOWN exploitability

**Solution**: Ensure crash records include detailed stack traces and exception messages

**Issue**: Priority scores seem incorrect

**Solution**: Review severity and exploitability ratings - they drive priority scoring

### Test Case Minimization

**Issue**: Minimization takes too long

**Solution**: Reduce max_iterations or use BINARY_SEARCH strategy

**Issue**: Minimized file doesn't crash

**Solution**: Check crash predicate - may have false positives

**Issue**: No reduction achieved

**Solution**: Try different strategy (DDMIN usually best) or increase max_iterations

### Stability Tracking

**Issue**: Very low stability percentage

**Solution**: Investigate target application for:
- Uninitialized memory (use AddressSanitizer)
- Race conditions (use ThreadSanitizer)
- Entropy sources (timestamps, random numbers)

**Issue**: Too many unstable inputs

**Solution**: Check if fuzzing harness introduces non-determinism

## Further Reading

- [STABILITY.md](STABILITY.md) - Fuzzing stability guide
- [AFL++ Documentation](https://aflplus.plus/) - Stability concepts
- [Delta Debugging Paper](https://www.st.cs.uni-saarland.de/papers/tse2002/) - Original algorithm
- [ECHO Tool Paper](https://arxiv.org/abs/2404.16819) - Coverage improvement research

## Changelog

### v1.2.0 (2025-10-17)
- Initial release of crash intelligence features
- Crash triaging with exploitability assessment
- Test case minimization with delta debugging
- AFL++-style stability tracking

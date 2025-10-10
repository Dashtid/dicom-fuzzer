# DICOM Fuzzer Examples

This directory contains practical examples demonstrating how to use the advanced fuzzing capabilities of the DICOM Fuzzer.

## Available Examples

### 1. Coverage-Guided Fuzzing Demo
**File**: `coverage_guided_fuzzing_demo.py`

Demonstrates the most powerful fuzzing technique: coverage-guided fuzzing. This approach automatically:
- Tracks which code paths are executed during testing
- Prioritizes inputs that discover new code coverage
- Adaptively mutates inputs based on feedback
- Manages a corpus of interesting test cases
- Provides detailed statistics and crash reports

**Use when**: You want maximum bug-finding effectiveness and have computational resources for parallel execution.

**Run**:
```bash
python examples/coverage_guided_fuzzing_demo.py
```

### 2. Grammar-Based Fuzzing Demo
**File**: `grammar_fuzzing_demo.py`

Shows how to generate structurally valid DICOM files using grammar rules. This technique:
- Creates valid file structures from grammar definitions
- Focuses testing on semantic logic rather than parsing
- Generates diverse test cases systematically
- Produces complex nested structures efficiently

**Use when**: You want to test application logic with valid inputs, or when you need structurally correct but semantically varied test cases.

**Run**:
```bash
python examples/grammar_fuzzing_demo.py
```

## Quick Start

1. **Install dependencies** (if not already done):
   ```bash
   pip install -r requirements.txt
   ```

2. **Prepare test data** (optional):
   ```bash
   mkdir -p test_data/valid_dicoms
   # Copy some valid DICOM files here for seeding
   ```

3. **Run an example**:
   ```bash
   python examples/coverage_guided_fuzzing_demo.py
   ```

## Framework Modules

The DICOM Fuzzer includes several advanced framework modules:

### Core Fuzzing
- **coverage_guided_fuzzer.py**: Main coverage-guided fuzzing engine
- **grammar_fuzzer.py**: Grammar-based test generation
- **mutation_minimization.py**: Automatically minimize failing test cases

### Coverage & Analysis
- **coverage_instrumentation.py**: Code coverage tracking
- **coverage_tracker.py**: Coverage-guided feedback system
- **coverage_correlation.py**: Correlate coverage with crashes

### Corpus Management
- **corpus_manager.py**: Intelligent test case management
- **coverage_guided_mutator.py**: Adaptive mutation strategies

### Crash Analysis
- **crash_analyzer.py**: Automatic crash analysis
- **crash_deduplication.py**: Group similar crashes
- **target_runner.py**: Safely execute test targets

### Reporting
- **reporter.py**: Basic reporting
- **enhanced_reporter.py**: Advanced visualization and metrics
- **profiler.py**: Performance profiling

## Integration Patterns

### Pattern 1: Basic Coverage-Guided Fuzzing
```python
from core.coverage_guided_fuzzer import CoverageGuidedFuzzer, FuzzingConfig

config = FuzzingConfig(
    target_function=my_parser_function,
    max_iterations=10000,
    coverage_guided=True,
)

fuzzer = CoverageGuidedFuzzer(config)
stats = fuzzer.run()
```

### Pattern 2: Grammar-Based Generation
```python
from core.grammar_fuzzer import GrammarFuzzer

fuzzer = GrammarFuzzer()
dicom_file = fuzzer.generate_dicom()
```

### Pattern 3: Crash Minimization
```python
from core.mutation_minimization import MutationMinimizer

minimizer = MutationMinimizer()
minimal_input = minimizer.minimize(crash_input, target_function)
```

## Best Practices

1. **Start with seeds**: Provide valid DICOM files as seeds for better results
2. **Use parallel workers**: Set `num_workers` based on your CPU cores
3. **Monitor coverage**: Enable `verbose=True` to see coverage progress
4. **Save interesting inputs**: Enable `save_interesting=True` to build a corpus
5. **Minimize crashes**: Use mutation minimization to create minimal reproducers

## Resources

- [The Fuzzing Book](https://www.fuzzingbook.org/) - Comprehensive fuzzing guide
- [AFL Documentation](https://github.com/google/AFL) - Coverage-guided fuzzing pioneer
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html) - LLVM fuzzing library

## Troubleshooting

**Issue**: "No module named 'core'"
**Solution**: Run from the project root directory or adjust your PYTHONPATH

**Issue**: Fuzzing is slow
**Solution**: Increase `num_workers` or reduce `max_iterations` for faster results

**Issue**: No crashes found
**Solution**: Run longer, add more seed files, or adjust mutation parameters

## Contributing

To add new examples:
1. Create a new Python file in this directory
2. Add clear docstrings explaining the technique
3. Include usage instructions in this README
4. Test your example works from a clean environment

## License

These examples are part of the DICOM Fuzzer project.

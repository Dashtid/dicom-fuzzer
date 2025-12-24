# Parser Stress Test Samples

Edge case DICOM files designed to stress-test parser implementations and reveal robustness issues like crashes, hangs, memory exhaustion, or undefined behavior.

## Purpose

These samples test how parsers handle:

- Extreme values at protocol boundaries
- Malformed or inconsistent structures
- Resource exhaustion scenarios
- Undefined or ambiguous DICOM constructs

## Sample Index

| File                          | Attack Type       | Expected Behavior        |
| ----------------------------- | ----------------- | ------------------------ |
| `deep_sequence_nesting.dcm`   | Deep recursion    | Stack overflow, hang     |
| `giant_value_length.dcm`      | Memory exhaustion | OOM, crash               |
| `truncated_pixeldata.dcm`     | Incomplete data   | Crash, data corruption   |
| `undefined_length_abuse.dcm`  | Parser confusion  | Hang, incorrect parsing  |
| `invalid_transfer_syntax.dcm` | Encoding mismatch | Crash, garbled data      |
| `recursive_item_nesting.dcm`  | Infinite loop     | Hang                     |
| `zero_length_elements.dcm`    | Null handling     | Crash, assertion failure |

## Sample Descriptions

### deep_sequence_nesting.dcm

Tests parser stack depth limits by creating deeply nested Sequence (SQ) elements.

**Attack vector**: Recursive sequence items (SQ > Item > SQ > Item > ...)
**Target**: Stack-based parsers without depth limits
**Expected result**: Stack overflow or excessive memory use

### giant_value_length.dcm

Tests handling of extremely large Value Length fields (up to 2^32-1 bytes).

**Attack vector**: VL field set to 0xFFFFFFFF or other huge values
**Target**: Parsers that pre-allocate based on VL
**Expected result**: Memory exhaustion, denial of service

### truncated_pixeldata.dcm

Tests handling of incomplete or truncated pixel data.

**Attack vector**: PixelData shorter than Rows × Columns × BitsAllocated/8
**Target**: Parsers that don't validate data length
**Expected result**: Buffer over-read, crash

### undefined_length_abuse.dcm

Tests handling of Undefined Length (0xFFFFFFFF) in contexts where it shouldn't appear.

**Attack vector**: Undefined length on non-sequence elements
**Target**: Parsers with weak validation
**Expected result**: Infinite read loop, hang

### invalid_transfer_syntax.dcm

Tests handling of mismatched Transfer Syntax declarations.

**Attack vector**: Header says Explicit VR, data is Implicit VR (or vice versa)
**Target**: Parsers that trust metadata without validation
**Expected result**: Incorrect parsing, data corruption

### recursive_item_nesting.dcm

Tests handling of circular or self-referential structures.

**Attack vector**: Sequence items that reference themselves
**Target**: Parsers without cycle detection
**Expected result**: Infinite loop, hang

### zero_length_elements.dcm

Tests handling of zero-length values for required elements.

**Attack vector**: Required fields with VL=0
**Target**: Parsers that don't handle empty values
**Expected result**: Null pointer dereference, assertion failure

## Usage

```bash
# Test all stress samples against a viewer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/parser_stress/ \
    --viewer "path/to/viewer.exe" \
    --timeout 30

# Test specific sample
dcmdump samples/parser_stress/deep_sequence_nesting.dcm
```

## Expected Robustness

A robust DICOM parser should:

1. **Limit recursion depth** - Reject sequences nested beyond reasonable limits
2. **Validate lengths** - Check VL against available data before allocation
3. **Handle truncation** - Gracefully report incomplete files
4. **Validate encoding** - Detect Transfer Syntax mismatches
5. **Detect cycles** - Prevent infinite loops in structures
6. **Handle empties** - Properly handle zero-length values

## Generating New Samples

```bash
# Generate all stress test samples
python samples/parser_stress/generator.py

# Generate specific type
python samples/parser_stress/generator.py --type deep_nesting --depth 1000
```

## References

- [DICOM Part 5 - Data Structures and Encoding](https://dicom.nema.org/medical/dicom/current/output/html/part05.html)
- [DICOM Part 10 - Media Storage](https://dicom.nema.org/medical/dicom/current/output/html/part10.html)

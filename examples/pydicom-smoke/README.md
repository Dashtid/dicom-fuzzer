# pydicom smoke harness

One-shot corpus analyzer. Feeds a directory of (likely-malformed) DICOM files through `pydicom.dcmread` + iterative dataset traversal, buckets exceptions by `(type, message stem)`, and flags anything that looks like a pydicom bug worth filing upstream.

Not part of the `dicom-fuzzer` CLI. Run directly from the repo.

## Usage

```bash
python examples/pydicom-smoke/pydicom_smoke.py <corpus_dir> [--out DIR] [--timeout SEC]
```

Defaults:

- `--out` -- `artifacts/pydicom-smoke/<timestamp>/`
- `--timeout` -- per-file cap in seconds

Writes `pydicom_smoke_report.json` (full bucket data) and `pydicom_smoke_summary.md` (short triage view) to the output directory.

## What it looks for

Exceptions are bucketed into three piles:

- **interesting** -- crash classes no well-behaved parser should raise (`RecursionError`, `MemoryError`, segfault, hang). File upstream.
- **review** -- exception types pydicom isn't documented to raise on malformed input, or tracebacks that pass through non-`pydicom.errors` modules. Inspect before dismissing.
- **expected** -- documented malformation reports (`InvalidDicomError`, `BytesLengthException`, ...). Boring; count them and move on.

## When to run it

After a `--pydicom-target` campaign, or after any change that touches pydicom-facing parse paths, to sanity-check that we aren't silently regressing pydicom's graceful-degradation behavior.

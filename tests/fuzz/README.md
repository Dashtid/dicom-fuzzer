# Atheris fuzz targets

Coverage-guided libfuzzer-style targets for the project's parsing entry
points. Run on Linux only -- atheris does not build on Windows.

## Targets

| File                               | Targets                                                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| [fuzz_parser.py](fuzz_parser.py)   | `dicom_fuzzer.core.dicom.parser.DicomParser` end-to-end on raw bytes                                                      |
| [fuzz_mutator.py](fuzz_mutator.py) | `dicom_fuzzer.core.mutation.mutator.DicomMutator.apply_mutations` on `pydicom.dcmread(..., force=True)`-produced datasets |

## Run locally

```bash
uv sync --extra fuzz

# Parser harness
uv run python tests/fuzz/fuzz_parser.py \
    tests/fuzz/corpus/fuzz_parser \
    -max_total_time=60 \
    -print_final_stats=1

# Mutator harness
uv run python tests/fuzz/fuzz_mutator.py \
    tests/fuzz/corpus/fuzz_mutator \
    -max_total_time=60 \
    -print_final_stats=1
```

The first positional argument is the corpus directory. libfuzzer reads
existing entries from it on startup and writes any newly discovered
inputs back. Subsequent runs against the same directory therefore start
hot and converge faster.

## Corpus persistence in CI

[fuzz.yml](../../.github/workflows/fuzz.yml) wraps the run with
`actions/cache/restore` (looking up the latest entry by prefix
`fuzz-corpus-<target>-`) and `actions/cache/save` (writing a new entry
keyed by `${{ github.run_id }}`). Cache entries that go 7+ days
without a read are evicted by GitHub; the weekly cron is the floor.

The directory is committed with a `.gitkeep` marker so libfuzzer always
finds an existing path. Entries discovered during fuzz runs are NOT
committed -- the cache is the source of truth.

## Inspecting cached corpus locally

```bash
gh cache list --repo Dashtid/dicom-fuzzer | grep fuzz-corpus
# Pick the latest, then download via the GitHub UI's cache page.
```

GitHub's CLI does not currently expose `cache download`. For offline
analysis, trigger `gh workflow run fuzz.yml -f duration=60` and grab
the corpus from the run's logs (libfuzzer prints the final state) or
extract via the `fuzz-crashes-fuzz_parser` artifact when a run fails.

## Adding a new target

1. Add `tests/fuzz/fuzz_<name>.py` following the shape of
   [fuzz_parser.py](fuzz_parser.py): `with atheris.instrument_imports():`
   for the modules under test, then a `TestOneInput(data: bytes)` that
   catches the documented exception types and lets anything else escape
   as a finding.
2. Add the target to [fuzz.yml](../../.github/workflows/fuzz.yml)'s
   matrix list.
3. Create the corresponding `tests/fuzz/corpus/<name>/.gitkeep` so the
   directory exists in clean checkouts.

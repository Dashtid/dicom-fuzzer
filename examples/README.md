# Examples

Reference targets and ad-hoc tooling used alongside dicom-fuzzer. Not part of the installed package. Nothing here ships in `pip install dicom-fuzzer`.

## What lives here

- **`fodicom-file-harness/`** -- .NET 8 console wrapper around fo-dicom that opens a single DICOM file, walks every element, and exits with a distinct code per outcome (0 clean, 1 uncaught, 10 `DicomFileException`). Used as the file-level target for `dicom-fuzzer -t EXE`.
- **`fodicom-network-harness/`** -- .NET 8 DIMSE SCP built on [fo-dicom](https://github.com/fo-dicom/fo-dicom). Accepts every association and forces VR conversion on received datasets, so network-side parser bugs crash the process. Plain DIMSE and TLS. Used as the server side of `--network-fuzz` runs.
- **`pydicom-smoke/`** -- Post-campaign corpus analyzer. Feeds a directory of fuzzed files through `pydicom.dcmread` + iterative traversal, buckets exceptions by `(type, message)` into interesting / review / expected. Output is a JSON report plus a markdown summary, meant as a sanity check after running the pydicom-targeted fuzz paths.

Each subdirectory has its own README with build and usage notes.

## Why not in the main package

These are reference targets (something to fuzz against) and maintainer-level diagnostics. Keeping them outside `dicom_fuzzer/` keeps the installed package small and the CLI surface focused on fuzzing, not corpus QA.

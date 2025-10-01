Architecture
============

DICOM-Fuzzer follows a modular architecture with clear separation of concerns.

Core Components
---------------

* **Parser** - DICOM file reading and validation
* **Generator** - Batch file generation
* **Mutator** - DICOM structure manipulation
* **Validator** - Output verification and security checks
* **Reporter** - HTML/JSON report generation

Fuzzing Pipeline
----------------

1. Parse input DICOM file
2. Select mutation strategy
3. Apply mutations
4. Validate output
5. Generate reports

See the API documentation for implementation details.

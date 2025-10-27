"""DICOM Fuzzer CLI entry point.

Allows running the package as a module: python -m dicom_fuzzer
"""

import sys

from dicom_fuzzer.cli.main import main

if __name__ == "__main__":
    sys.exit(main())

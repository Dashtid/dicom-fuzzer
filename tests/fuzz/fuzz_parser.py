"""Atheris fuzz target for DicomParser.

Feeds random bytes through the project's DICOM parsing entry point. The
existing CWE-674 stack-overflow crash was discovered in this code path,
so coverage-guided fuzzing here is the natural high-yield target.

Run locally (Python 3.11-3.13; atheris does not yet support 3.14):

    uv sync --extra fuzz
    uv run python tests/fuzz/fuzz_parser.py -max_total_time=60

Run on CI: see .github/workflows/fuzz.yml (weekly + PR-touching paths).

The target catches the four documented exception types DicomParser is
contracted to raise; anything else escaping is a finding.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from dicom_fuzzer.core.dicom.parser import DicomParser
    from dicom_fuzzer.core.exceptions import (
        ParsingError,
        SecurityViolationError,
        ValidationError,
    )

# Cap input size so libfuzzer doesn't waste cycles on huge corpus entries
# that exceed our parser's MAX_FILE_SIZE (100 MB) anyway.
MAX_INPUT_BYTES = 10 * 1024 * 1024


def TestOneInput(data: bytes) -> None:  # noqa: N802 (atheris convention)
    if len(data) > MAX_INPUT_BYTES:
        return

    with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as f:
        f.write(data)
        temp_path = Path(f.name)

    try:
        try:
            parser = DicomParser(temp_path, security_checks=True)
            _ = parser.dataset
        except (ParsingError, SecurityViolationError, ValidationError, OSError):
            # Library refused the input cleanly via a documented exception
            # type. Not a finding.
            pass
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

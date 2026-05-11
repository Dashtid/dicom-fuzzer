"""Atheris fuzz target for DicomMutator.apply_mutations.

Feeds random bytes through pydicom's permissive (force=True) reader to
produce a Dataset, then runs the full DicomMutator pipeline against it.

The mutator catches per-strategy panics inside _apply_single_mutation,
but pre-strategy code (_get_applicable_strategies invoking each
strategy's can_mutate) and post-strategy session tracking are NOT
wrapped. This harness is what surfaces panics in those paths -- exactly
the failure mode that would break a campaign mid-batch.

Run locally (Python 3.11-3.13; atheris does not yet support 3.14):

    uv sync --extra fuzz
    uv run python tests/fuzz/fuzz_mutator.py \
        tests/fuzz/corpus/fuzz_mutator \
        -max_total_time=60

Run on CI: see .github/workflows/fuzz.yml (weekly + PR-touching paths).

The target catches the documented project-level exceptions; anything
else escaping is a candidate finding.
"""

from __future__ import annotations

import sys
from io import BytesIO

import atheris

with atheris.instrument_imports():
    import pydicom

    from dicom_fuzzer.core.exceptions import (
        ParsingError,
        ResourceExhaustedError,
        SecurityViolationError,
        ValidationError,
    )
    from dicom_fuzzer.core.mutation.mutator import DicomMutator

# Cap input size so libfuzzer doesn't waste cycles on huge inputs that
# trigger pydicom's own resource defenses anyway.
MAX_INPUT_BYTES = 1 * 1024 * 1024

# Strategy registration is heavy (36 strategies, dictionary load,
# DimensionOverflow init, etc.). Build once at module load and reuse
# the same instance per fuzzed input. Strategies are written to be
# stateless across mutate() calls; the only persistent state in the
# mutator is _strategy_cache (memoization) and current_session, both
# of which we leave alone.
_MUTATOR = DicomMutator()


def TestOneInput(data: bytes) -> None:  # noqa: N802 (atheris convention)
    if len(data) > MAX_INPUT_BYTES:
        return

    try:
        # force=True lets pydicom accept inputs without a 128-byte
        # preamble or DICM magic, widening the surface that reaches the
        # mutator. Inputs that pydicom rejects outright are out of
        # scope for this harness (fuzz_parser covers those).
        dataset = pydicom.dcmread(BytesIO(data), force=True)
    except Exception:
        return

    try:
        _MUTATOR.apply_mutations(dataset)
    except (
        ParsingError,
        ValidationError,
        SecurityViolationError,
        ResourceExhaustedError,
        OSError,
    ):
        # Documented refusal path. Not a finding.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

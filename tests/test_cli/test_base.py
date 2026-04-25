"""Tests for dicom_fuzzer.cli.base.SubcommandBase.

Exercises the top-level exception handling in SubcommandBase.main -- the
existing coverage only hit the happy path (execute returns normally), so
the stderr-print + verbose-traceback branch was unreachable to the
merged report.
"""

from __future__ import annotations

import argparse

import pytest

from dicom_fuzzer.cli.base import SubcommandBase


class _DummyCommand(SubcommandBase):
    """Subclass used to drive SubcommandBase.main from tests.

    The two class attributes let each test decide what execute() does
    without having to define a fresh subclass per case.
    """

    _to_raise: Exception | None = None
    _return_value: int | None = 0

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="dummy")
        parser.add_argument("-v", "--verbose", action="store_true")
        return parser

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        if cls._to_raise is not None:
            raise cls._to_raise
        return cls._return_value if cls._return_value is not None else 0


@pytest.fixture(autouse=True)
def _reset_dummy():
    """Reset the shared class-level test knobs between cases."""
    _DummyCommand._to_raise = None
    _DummyCommand._return_value = 0
    yield
    _DummyCommand._to_raise = None
    _DummyCommand._return_value = 0


class TestSubcommandBaseMain:
    def test_returns_zero_on_none_return(self, capsys):
        """execute() returning None is treated as exit code 0."""
        _DummyCommand._return_value = None
        assert _DummyCommand.main([]) == 0

    def test_returns_execute_exit_code(self):
        """Non-zero return from execute() propagates."""
        _DummyCommand._return_value = 7
        assert _DummyCommand.main([]) == 7

    def test_exception_returns_1_and_prints_to_stderr(self, capsys):
        """Unhandled exception -> exit 1 + '[-] {msg}' on stderr."""
        _DummyCommand._to_raise = RuntimeError("boom")

        assert _DummyCommand.main([]) == 1

        err = capsys.readouterr().err
        assert "[-] boom" in err
        # Non-verbose: no traceback frames
        assert "Traceback" not in err

    def test_exception_with_verbose_prints_traceback(self, capsys):
        """With --verbose, the full traceback is also printed to stderr."""
        _DummyCommand._to_raise = ValueError("kaboom")

        assert _DummyCommand.main(["--verbose"]) == 1

        err = capsys.readouterr().err
        assert "[-] kaboom" in err
        assert "Traceback" in err
        assert "ValueError" in err

    def test_system_exit_propagates(self):
        """SystemExit must not be swallowed by the generic handler."""
        _DummyCommand._to_raise = SystemExit(2)

        with pytest.raises(SystemExit) as exc_info:
            _DummyCommand.main([])

        assert exc_info.value.code == 2

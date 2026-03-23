"""Base class for DICOM Fuzzer CLI subcommands."""

from __future__ import annotations

import argparse
import sys
import traceback
from abc import ABC, abstractmethod


class SubcommandBase(ABC):
    """Abstract base for CLI subcommands.

    Subclasses implement ``build_parser()`` and ``execute()``.  The concrete
    ``main()`` classmethod handles argument parsing and top-level exception
    catching so each subcommand doesn't need to repeat that boilerplate.
    """

    @classmethod
    @abstractmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        pass

    @classmethod
    @abstractmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand. Returns exit code (0 = success)."""
        pass

    @classmethod
    def main(cls, argv: list[str] | None = None) -> int:
        """Parse *argv* and call ``execute()``. Returns exit code."""
        parser = cls.build_parser()
        args = parser.parse_args(argv)
        try:
            return cls.execute(args) or 0
        except SystemExit:
            raise
        except Exception as e:
            print(f"[-] {e}", file=sys.stderr)
            if getattr(args, "verbose", False):
                traceback.print_exc(file=sys.stderr)
            return 1

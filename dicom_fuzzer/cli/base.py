"""Base class for CLI subcommands.

Provides common patterns for argument parsing, error handling, and dispatch.
"""

from __future__ import annotations

import argparse
import traceback
from abc import ABC, abstractmethod
from collections.abc import Callable


class SubcommandBase(ABC):
    """Abstract base class for CLI subcommands.

    Provides common patterns for argument parsing, error handling, and dispatch.

    Example:
        class MyCommand(SubcommandBase):
            @property
            def name(self) -> str:
                return "my-cmd"

            @property
            def description(self) -> str:
                return "My custom command"

            def configure_parser(self, parser: argparse.ArgumentParser) -> None:
                parser.add_argument("--input", required=True)

            def run(self, args: argparse.Namespace) -> int:
                print(f"Processing: {args.input}")
                return 0

    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Command name (e.g., 'samples', 'tls')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description for help text."""
        ...

    @property
    def epilog(self) -> str:
        """Optional epilog with examples. Override to add examples."""
        return ""

    @abstractmethod
    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        """Add arguments to the parser.

        Args:
            parser: The argument parser to configure.

        """
        ...

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        """Execute the command.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Exit code: 0 for success, 1 for failure.

        """
        ...

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser with standard formatting.

        Returns:
            Configured ArgumentParser instance.

        """
        parser = argparse.ArgumentParser(
            prog=f"dicom-fuzzer {self.name}",
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.epilog if self.epilog else None,
        )
        self.configure_parser(parser)
        return parser

    def main(self, argv: list[str] | None = None) -> int:
        """Standard entry point with error handling.

        Args:
            argv: Command-line arguments. If None, uses sys.argv[1:].

        Returns:
            Exit code: 0 for success, 1 for failure.

        """
        parser = self.create_parser()
        args = parser.parse_args(argv)
        try:
            return self.run(args)
        except ImportError as e:
            print(f"[-] Module not available: {e}")
            return 1
        except Exception as e:
            print(f"[-] Command failed: {e}")
            if getattr(args, "verbose", False):
                traceback.print_exc()
            return 1


def subcommand_main(
    create_parser_fn: Callable[[], argparse.ArgumentParser],
    run_fn: Callable[[argparse.Namespace], int],
    argv: list[str] | None = None,
) -> int:
    """Helper for function-based subcommands.

    Reduces boilerplate for existing function-based subcommands without
    requiring conversion to class-based approach.

    Args:
        create_parser_fn: Function that creates and returns an ArgumentParser.
        run_fn: Function that executes the command given parsed args.
        argv: Command-line arguments. If None, uses sys.argv[1:].

    Returns:
        Exit code: 0 for success, 1 for failure.

    Example:
        def create_parser() -> argparse.ArgumentParser:
            parser = argparse.ArgumentParser()
            parser.add_argument("--input")
            return parser

        def run(args: argparse.Namespace) -> int:
            print(args.input)
            return 0

        def main(argv: list[str] | None = None) -> int:
            return subcommand_main(create_parser, run, argv)

    """
    parser = create_parser_fn()
    args = parser.parse_args(argv)
    try:
        return run_fn(args)
    except ImportError as e:
        print(f"[-] Module not available: {e}")
        return 1
    except Exception as e:
        print(f"[-] Command failed: {e}")
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 1

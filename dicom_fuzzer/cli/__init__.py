"""DICOM Fuzzer CLI Package.

Public API:
- SubcommandBase: Base class for subcommands
- subcommand_main: Helper for function-based subcommands
- main: CLI entry point
"""

from dicom_fuzzer.cli.base import SubcommandBase, subcommand_main
from dicom_fuzzer.cli.main import main

__all__ = ["SubcommandBase", "subcommand_main", "main"]

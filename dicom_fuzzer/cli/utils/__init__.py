"""CLI utility modules.

Shared utilities for output formatting, argument parsing, and GUI support.
"""

from . import output
from .argument_parser import VERSION, create_parser

__all__ = [
    "output",
    "VERSION",
    "create_parser",
]

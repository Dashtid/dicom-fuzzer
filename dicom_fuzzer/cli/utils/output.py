"""CLI Output Utilities with Rich Integration.

Provides colored console output using rich while maintaining ASCII status
indicators for compatibility. Supports both interactive (colored) and
non-interactive (plain) output modes.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console
    from rich.progress import Progress, TaskID

# Lazy-load rich to avoid import overhead when not needed
_console = None
_use_color = None


def _get_console() -> Console:
    """Get or create the rich console instance."""
    from rich.console import Console

    global _console, _use_color
    if _console is None:
        # Detect if we should use color
        _use_color = sys.stdout.isatty()
        _console = Console(force_terminal=_use_color, no_color=not _use_color)
    return _console


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    global _use_color
    if _use_color is None:
        _get_console()
    return _use_color or False


# Status message functions using ASCII indicators with color
def success(message: str) -> None:
    """Print success message: [+] in green."""
    console = _get_console()
    console.print(f"[green]\\[+][/green] {message}")


def error(message: str) -> None:
    """Print error message: [-] in red."""
    console = _get_console()
    console.print(f"[red]\\[-][/red] {message}")


def warning(message: str) -> None:
    """Print warning message: [!] in yellow."""
    console = _get_console()
    console.print(f"[yellow]\\[!][/yellow] {message}")


def info(message: str) -> None:
    """Print info message: [i] in blue."""
    console = _get_console()
    console.print(f"[blue]\\[i][/blue] {message}")


def status(message: str) -> None:
    """Print plain status message without indicator."""
    console = _get_console()
    console.print(message)


def header(title: str, subtitle: str | None = None) -> None:
    """Print a section header with optional subtitle."""
    console = _get_console()
    console.print()
    console.print(f"[bold cyan]{title}[/bold cyan]")
    if subtitle:
        console.print(f"[dim]{subtitle}[/dim]")
    console.print()


def section(title: str) -> None:
    """Print a subsection header."""
    console = _get_console()
    console.print(f"\n[bold]{title}[/bold]")


def detail(label: str, value: str, indent: int = 2) -> None:
    """Print a labeled detail line."""
    console = _get_console()
    padding = " " * indent
    console.print(f"{padding}[dim]{label}:[/dim] {value}")


def table_row(items: list[str], widths: list[int] | None = None) -> None:
    """Print a simple table row."""
    console = _get_console()
    if widths:
        formatted = [f"{item:<{w}}" for item, w in zip(items, widths, strict=True)]
        console.print("  " + " ".join(formatted))
    else:
        console.print("  " + " ".join(items))


def divider() -> None:
    """Print a horizontal divider."""
    console = _get_console()
    console.print("[dim]" + "-" * 60 + "[/dim]")


@contextmanager
def progress_bar(
    description: str = "Processing",
    total: int | None = None,
    transient: bool = False,
) -> Iterator[tuple[Progress, TaskID]]:
    """Context manager for progress bar display.

    Args:
        description: Label for the progress bar
        total: Total number of items (None for indeterminate)
        transient: If True, remove progress bar when done

    Yields:
        Tuple of (Progress instance, task_id) for updating progress

    Example:
        with progress_bar("Fuzzing", total=100) as (progress, task):
            for i in range(100):
                do_work()
                progress.update(task, advance=1)

    """
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )

    columns = [
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("[dim]|[/dim]"),
        TimeElapsedColumn(),
        TextColumn("[dim]<[/dim]"),
        TimeRemainingColumn(),
    ]

    with Progress(*columns, transient=transient) as progress:
        task = progress.add_task(description, total=total)
        yield progress, task


@contextmanager
def spinner(message: str = "Working") -> Iterator[None]:
    """Context manager for spinner display during indeterminate operations.

    Args:
        message: Status message to display

    Example:
        with spinner("Loading DICOM files"):
            load_files()

    """
    console = _get_console()
    with console.status(f"[bold blue]{message}...[/bold blue]"):
        yield


def print_summary(
    title: str,
    stats: dict[str, str | int | float],
    success_count: int = 0,
    error_count: int = 0,
) -> None:
    """Print a formatted summary box.

    Args:
        title: Summary title
        stats: Dictionary of stat name -> value
        success_count: Number of successes (for coloring)
        error_count: Number of errors (for coloring)

    """
    from rich.panel import Panel
    from rich.table import Table

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Stat", style="dim")
    table.add_column("Value")

    for key, value in stats.items():
        # Color-code specific values
        if "success" in key.lower() or "passed" in key.lower():
            value_str = f"[green]{value}[/green]"
        elif (
            "error" in key.lower() or "failed" in key.lower() or "crash" in key.lower()
        ):
            value_str = f"[red]{value}[/red]" if value else str(value)
        elif "warning" in key.lower():
            value_str = f"[yellow]{value}[/yellow]" if value else str(value)
        else:
            value_str = str(value)

        table.add_row(key, value_str)

    # Determine panel border color (handle non-numeric types gracefully)
    try:
        has_errors = int(error_count) > 0
        has_success = int(success_count) > 0
    except (TypeError, ValueError):
        has_errors = bool(error_count)
        has_success = bool(success_count)

    if has_errors:
        border_style = "red"
    elif has_success:
        border_style = "green"
    else:
        border_style = "blue"

    panel = Panel(table, title=f"[bold]{title}[/bold]", border_style=border_style)
    console = _get_console()
    console.print(panel)


def format_crash_info(
    file_path: str,
    exit_code: int | None,
    memory_mb: float | None = None,
    error_msg: str | None = None,
) -> None:
    """Print formatted crash information."""
    console = _get_console()
    console.print(f"  [red]CRASH[/red] {file_path}")
    if exit_code is not None:
        console.print(f"    [dim]Exit code:[/dim] {exit_code}")
    if memory_mb is not None:
        console.print(f"    [dim]Memory:[/dim] {memory_mb:.1f} MB")
    if error_msg:
        console.print(f"    [dim]Error:[/dim] {error_msg}")

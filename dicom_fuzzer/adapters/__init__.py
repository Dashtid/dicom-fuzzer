"""Viewer-specific automation adapters for DICOM fuzzing.

This module provides an abstraction layer for viewer-specific automation,
allowing the fuzzer to interact with different DICOM viewers through
a common interface.

Available adapters:
    - affinity: Hermes Affinity viewer (pywinauto-based)

Usage:
    from dicom_fuzzer.adapters import get_adapter, list_adapters

    # List available adapters
    for name in list_adapters():
        print(name)

    # Get specific adapter
    adapter = get_adapter("affinity")
    adapter.connect()
    result = adapter.load_study_into_viewport(study_path)
"""

from __future__ import annotations

from .base import RenderResult, ViewerAdapter

__all__ = ["ViewerAdapter", "RenderResult", "get_adapter", "list_adapters"]

# Registry of available adapters
_ADAPTERS: dict[str, type[ViewerAdapter]] = {}


def register_adapter(name: str, adapter_class: type[ViewerAdapter]) -> None:
    """Register a viewer adapter.

    Args:
        name: Adapter name (used in CLI --adapter flag).
        adapter_class: ViewerAdapter subclass.

    """
    _ADAPTERS[name] = adapter_class


def list_adapters() -> list[str]:
    """List available adapter names.

    Returns:
        List of registered adapter names.

    """
    return list(_ADAPTERS.keys())


def get_adapter(name: str, **kwargs: object) -> ViewerAdapter:
    """Get a viewer adapter instance by name.

    Args:
        name: Adapter name.
        **kwargs: Arguments passed to adapter constructor.

    Returns:
        ViewerAdapter instance.

    Raises:
        ValueError: If adapter name is not registered.

    """
    if name not in _ADAPTERS:
        available = ", ".join(_ADAPTERS.keys()) if _ADAPTERS else "none"
        raise ValueError(f"Unknown adapter '{name}'. Available: {available}")
    return _ADAPTERS[name](**kwargs)


# Auto-register adapters on import
def _register_builtin_adapters() -> None:
    """Register built-in adapters."""
    try:
        from .affinity import AffinityAdapter

        register_adapter("affinity", AffinityAdapter)
    except ImportError:
        # pywinauto not installed, adapter not available
        pass


_register_builtin_adapters()

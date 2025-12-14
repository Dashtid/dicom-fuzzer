"""Serialization utilities for dataclasses.

Provides mixins and utilities for converting dataclasses to JSON-serializable
dictionaries with proper handling of datetime objects and nested structures.
"""

from dataclasses import fields
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class SerializableMixin:
    """Mixin for dataclasses with JSON serialization support.

    This mixin provides a standardized to_dict() method that handles:
    - Datetime conversion to ISO format strings
    - Enum conversion to values
    - Path conversion to strings
    - Nested dataclass serialization
    - List and dict handling
    - Custom computed fields via _custom_serialization() hook

    Usage:
        @dataclass
        class MyRecord(SerializableMixin):
            timestamp: datetime
            status: MyEnum
            output_path: Path
            data: dict[str, Any]

        record = MyRecord(datetime.now(), MyEnum.ACTIVE, Path("/tmp"), {"key": "value"})
        json_dict = record.to_dict()

    Custom Fields:
        Override _custom_serialization() to add computed fields:

        def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
            data["computed_field"] = self.calculate_something()
            return data
    """

    def to_dict(self) -> dict[str, Any]:
        """Convert dataclass to JSON-serializable dictionary.

        Returns:
            Dictionary with all datetime objects converted to ISO format strings,
            enums converted to values, paths converted to strings, and nested
            dataclasses recursively serialized.

        Raises:
            TypeError: If the class is not a dataclass.

        Note:
            This mixin must only be used with @dataclass decorated classes.
            Type checking enforces this at compile time.

        """
        # Runtime check: verify this is a dataclass by checking for __dataclass_fields__
        # This avoids mypy's warn_unreachable issue with is_dataclass()
        if not hasattr(self, "__dataclass_fields__"):
            raise TypeError(
                f"SerializableMixin can only be used with dataclasses. "
                f"{type(self).__name__} is not a dataclass."
            )

        # Convert dataclass to dict using fields() to build dict manually
        # This avoids asdict() type issues while maintaining same behavior
        data: dict[str, Any] = {
            f.name: getattr(self, f.name)
            for f in fields(self)  # type: ignore[arg-type]
        }
        serialized: dict[str, Any] = self._serialize_value(data)

        # Allow subclasses to add custom computed fields
        custom_method = getattr(self, "_custom_serialization", None)
        if custom_method is not None:
            serialized = custom_method(serialized)

        return serialized

    def _serialize_value(self, value: Any) -> Any:
        """Recursively serialize a value to JSON-compatible format.

        Args:
            value: Value to serialize

        Returns:
            Serialized value (primitives, datetime as ISO string, enum as value,
            Path as string, nested dataclasses as dicts, etc.)

        """
        # Handle datetime objects
        if isinstance(value, datetime):
            return value.isoformat()

        # Handle enum objects - convert to their value
        if isinstance(value, Enum):
            return value.value

        # Handle Path objects - convert to string
        if isinstance(value, Path):
            return str(value)

        # Handle nested dataclasses - convert to dict recursively
        if hasattr(value, "__dataclass_fields__"):
            nested_data: dict[str, Any] = {
                f.name: getattr(value, f.name) for f in fields(value)
            }
            return self._serialize_value(nested_data)

        # Handle dictionaries recursively
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}

        # Handle lists/tuples recursively
        if isinstance(value, (list, tuple)):
            return [self._serialize_value(item) for item in value]

        # Return primitives and other types as-is
        return value

"""Serialization utilities for dataclasses.

Provides mixins and utilities for converting dataclasses to JSON-serializable
dictionaries with proper handling of datetime objects and nested structures.
"""

from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any


class SerializableMixin:
    """Mixin for dataclasses with JSON serialization support.

    This mixin provides a standardized to_dict() method that handles:
    - Datetime conversion to ISO format strings
    - Nested dataclass serialization
    - List and dict handling

    Usage:
        @dataclass
        class MyRecord(SerializableMixin):
            timestamp: datetime
            data: dict[str, Any]

        record = MyRecord(datetime.now(), {"key": "value"})
        json_dict = record.to_dict()
    """

    def to_dict(self) -> dict[str, Any]:
        """Convert dataclass to JSON-serializable dictionary.

        Returns:
            Dictionary with all datetime objects converted to ISO format strings
            and nested dataclasses recursively serialized.

        """
        if not is_dataclass(self):
            raise TypeError(
                f"SerializableMixin can only be used with dataclasses, "
                f"got {type(self).__name__}"
            )

        data = asdict(self)  # type: ignore[unreachable]
        return self._serialize_value(data)

    def _serialize_value(self, value: Any) -> Any:
        """Recursively serialize a value to JSON-compatible format.

        Args:
            value: Value to serialize

        Returns:
            Serialized value (primitives, datetime as ISO string, etc.)

        """
        # Handle datetime objects
        if isinstance(value, datetime):
            return value.isoformat()

        # Handle dictionaries recursively
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}

        # Handle lists/tuples recursively
        if isinstance(value, (list, tuple)):
            return [self._serialize_value(item) for item in value]

        # Return primitives and other types as-is
        return value

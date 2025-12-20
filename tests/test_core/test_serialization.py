"""Comprehensive tests for dicom_fuzzer.core.serialization module.

This test suite provides complete coverage of the SerializableMixin class,
including edge cases for non-dataclass usage, enum conversion, and nested structures.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from dicom_fuzzer.core.serialization import SerializableMixin


class TestSerializableMixinBasics:
    """Test suite for basic SerializableMixin functionality."""

    def test_simple_dataclass_to_dict(self):
        """Test basic dataclass serialization."""

        @dataclass
        class SimpleRecord(SerializableMixin):
            name: str
            value: int

        record = SimpleRecord(name="test", value=42)
        result = record.to_dict()

        assert result == {"name": "test", "value": 42}

    def test_non_dataclass_raises_type_error(self):
        """Test that non-dataclass raises TypeError (lines 54-57)."""

        class NotADataclass(SerializableMixin):
            def __init__(self) -> None:
                self.name = "test"

        obj = NotADataclass()

        with pytest.raises(TypeError) as exc_info:
            obj.to_dict()

        assert "SerializableMixin can only be used with dataclasses" in str(
            exc_info.value
        )
        assert "NotADataclass" in str(exc_info.value)


class TestDatetimeSerialization:
    """Test suite for datetime serialization."""

    def test_datetime_converted_to_iso_format(self):
        """Test datetime objects are converted to ISO format strings."""

        @dataclass
        class TimestampRecord(SerializableMixin):
            created_at: datetime

        dt = datetime(2025, 1, 15, 10, 30, 45)
        record = TimestampRecord(created_at=dt)
        result = record.to_dict()

        assert result["created_at"] == "2025-01-15T10:30:45"

    def test_datetime_with_microseconds(self):
        """Test datetime with microseconds."""

        @dataclass
        class PreciseTimestamp(SerializableMixin):
            timestamp: datetime

        dt = datetime(2025, 6, 20, 14, 25, 30, 123456)
        record = PreciseTimestamp(timestamp=dt)
        result = record.to_dict()

        assert result["timestamp"] == "2025-06-20T14:25:30.123456"


class TestEnumSerialization:
    """Test suite for enum serialization."""

    def test_enum_converted_to_value(self):
        """Test enum objects are converted to their values (line 87)."""

        class Status(Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"
            PENDING = "pending"

        @dataclass
        class StatusRecord(SerializableMixin):
            status: Status

        record = StatusRecord(status=Status.ACTIVE)
        result = record.to_dict()

        assert result["status"] == "active"

    def test_enum_with_integer_value(self):
        """Test enum with integer values."""

        class Priority(Enum):
            LOW = 1
            MEDIUM = 2
            HIGH = 3

        @dataclass
        class TaskRecord(SerializableMixin):
            priority: Priority

        record = TaskRecord(priority=Priority.HIGH)
        result = record.to_dict()

        assert result["priority"] == 3

    def test_multiple_enums_in_record(self):
        """Test multiple enum fields."""

        class Color(Enum):
            RED = "red"
            GREEN = "green"
            BLUE = "blue"

        class Size(Enum):
            SMALL = "S"
            MEDIUM = "M"
            LARGE = "L"

        @dataclass
        class Product(SerializableMixin):
            color: Color
            size: Size

        record = Product(color=Color.BLUE, size=Size.MEDIUM)
        result = record.to_dict()

        assert result["color"] == "blue"
        assert result["size"] == "M"


class TestPathSerialization:
    """Test suite for Path serialization."""

    def test_path_converted_to_string(self):
        """Test Path objects are converted to strings."""

        @dataclass
        class FileRecord(SerializableMixin):
            file_path: Path

        record = FileRecord(file_path=Path("/tmp/test.txt"))
        result = record.to_dict()

        # Path string representation is OS-dependent
        # Check that the key parts are present
        assert "tmp" in result["file_path"]
        assert "test.txt" in result["file_path"]

    def test_windows_path(self):
        """Test Windows-style paths."""

        @dataclass
        class WindowsFile(SerializableMixin):
            path: Path

        record = WindowsFile(path=Path("C:/Users/test/file.txt"))
        result = record.to_dict()

        # Path normalizes separators, but string representation should work
        assert "test" in result["path"]
        assert "file.txt" in result["path"]


class TestNestedStructures:
    """Test suite for nested structure serialization."""

    def test_dict_with_datetime_values(self):
        """Test dictionary with datetime values."""

        @dataclass
        class EventLog(SerializableMixin):
            events: dict[str, datetime]

        events = {
            "start": datetime(2025, 1, 1, 9, 0, 0),
            "end": datetime(2025, 1, 1, 17, 0, 0),
        }
        record = EventLog(events=events)
        result = record.to_dict()

        assert result["events"]["start"] == "2025-01-01T09:00:00"
        assert result["events"]["end"] == "2025-01-01T17:00:00"

    def test_list_with_datetime_values(self):
        """Test list with datetime values."""

        @dataclass
        class Timeline(SerializableMixin):
            timestamps: list[datetime]

        timestamps = [
            datetime(2025, 1, 1),
            datetime(2025, 2, 1),
            datetime(2025, 3, 1),
        ]
        record = Timeline(timestamps=timestamps)
        result = record.to_dict()

        assert len(result["timestamps"]) == 3
        assert result["timestamps"][0] == "2025-01-01T00:00:00"

    def test_tuple_serialization(self):
        """Test tuple values are serialized to list."""

        @dataclass
        class Coordinates(SerializableMixin):
            point: tuple[int, int, int]

        record = Coordinates(point=(10, 20, 30))
        result = record.to_dict()

        assert result["point"] == [10, 20, 30]

    def test_nested_dict(self):
        """Test deeply nested dictionary."""

        @dataclass
        class NestedRecord(SerializableMixin):
            data: dict[str, Any]

        nested_data = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": 42,
                        "timestamp": datetime(2025, 6, 15),
                    }
                }
            }
        }
        record = NestedRecord(data=nested_data)
        result = record.to_dict()

        assert result["data"]["level1"]["level2"]["level3"]["value"] == 42
        assert (
            result["data"]["level1"]["level2"]["level3"]["timestamp"]
            == "2025-06-15T00:00:00"
        )

    def test_list_of_dicts_with_enums(self):
        """Test list of dictionaries containing enums."""

        class TaskStatus(Enum):
            TODO = "todo"
            DONE = "done"

        @dataclass
        class TaskList(SerializableMixin):
            tasks: list[dict[str, Any]]

        tasks = [
            {"name": "Task 1", "status": TaskStatus.TODO},
            {"name": "Task 2", "status": TaskStatus.DONE},
        ]
        record = TaskList(tasks=tasks)
        result = record.to_dict()

        assert result["tasks"][0]["status"] == "todo"
        assert result["tasks"][1]["status"] == "done"


class TestCustomSerialization:
    """Test suite for custom serialization hook."""

    def test_custom_serialization_hook(self):
        """Test _custom_serialization method hook."""

        @dataclass
        class CustomRecord(SerializableMixin):
            value: int

            def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
                data["computed"] = self.value * 2
                return data

        record = CustomRecord(value=21)
        result = record.to_dict()

        assert result["value"] == 21
        assert result["computed"] == 42

    def test_custom_serialization_modifies_data(self):
        """Test custom serialization can modify existing data."""

        @dataclass
        class ModifiedRecord(SerializableMixin):
            name: str

            def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
                data["name"] = data["name"].upper()
                data["length"] = len(data["name"])
                return data

        record = ModifiedRecord(name="hello")
        result = record.to_dict()

        assert result["name"] == "HELLO"
        assert result["length"] == 5


class TestPrimitiveTypes:
    """Test suite for primitive type passthrough."""

    def test_primitive_types_unchanged(self):
        """Test primitive types are passed through unchanged."""

        @dataclass
        class PrimitiveRecord(SerializableMixin):
            integer: int
            floating: float
            string: str
            boolean: bool
            none_value: None

        record = PrimitiveRecord(
            integer=42,
            floating=3.14,
            string="test",
            boolean=True,
            none_value=None,
        )
        result = record.to_dict()

        assert result["integer"] == 42
        assert result["floating"] == 3.14
        assert result["string"] == "test"
        assert result["boolean"] is True
        assert result["none_value"] is None


class TestComplexScenarios:
    """Test suite for complex real-world scenarios."""

    def test_comprehensive_record(self):
        """Test comprehensive record with all supported types."""

        class RecordType(Enum):
            INFO = "info"
            WARNING = "warning"
            ERROR = "error"

        @dataclass
        class ComprehensiveRecord(SerializableMixin):
            id: int
            name: str
            timestamp: datetime
            record_type: RecordType
            output_path: Path
            metadata: dict[str, Any]
            tags: list[str]
            active: bool

            def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
                data["summary"] = f"{data['record_type']}: {data['name']}"
                return data

        record = ComprehensiveRecord(
            id=1,
            name="Test Record",
            timestamp=datetime(2025, 1, 15, 10, 30),
            record_type=RecordType.INFO,
            output_path=Path("/output/results"),
            metadata={"key1": "value1", "nested": {"key2": datetime(2025, 6, 1)}},
            tags=["tag1", "tag2"],
            active=True,
        )
        result = record.to_dict()

        assert result["id"] == 1
        assert result["name"] == "Test Record"
        assert result["timestamp"] == "2025-01-15T10:30:00"
        assert result["record_type"] == "info"
        # Path string representation is OS-dependent
        assert "output" in result["output_path"]
        assert "results" in result["output_path"]
        assert result["metadata"]["nested"]["key2"] == "2025-06-01T00:00:00"
        assert result["tags"] == ["tag1", "tag2"]
        assert result["active"] is True
        assert result["summary"] == "info: Test Record"

    def test_empty_collections(self):
        """Test empty collections are handled correctly."""

        @dataclass
        class EmptyCollections(SerializableMixin):
            empty_list: list[str]
            empty_dict: dict[str, str]
            empty_tuple: tuple[()]

        record = EmptyCollections(
            empty_list=[],
            empty_dict={},
            empty_tuple=(),
        )
        result = record.to_dict()

        assert result["empty_list"] == []
        assert result["empty_dict"] == {}
        assert result["empty_tuple"] == []

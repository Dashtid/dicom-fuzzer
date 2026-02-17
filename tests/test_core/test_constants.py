"""Tests for shared fuzzing constants."""

from __future__ import annotations

from dicom_fuzzer.core.constants import (
    BugSeverity,
    CrashSeverity,
    Severity,
    SeverityLevel,
)


class TestSeverity:
    """Tests for unified Severity enum."""

    def test_inherits_from_str(self) -> None:
        """Test Severity inherits from str for serialization."""
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL.value == "critical"
        assert Severity.CRITICAL == "critical"

    def test_severity_values_exist(self) -> None:
        """Test all severity values are defined."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
        assert Severity.UNKNOWN.value == "unknown"

    def test_backward_compatibility_aliases(self) -> None:
        """Test backward compatibility aliases."""
        assert CrashSeverity is Severity
        assert BugSeverity is Severity
        assert SeverityLevel is Severity
        assert CrashSeverity.CRITICAL == Severity.CRITICAL
        assert BugSeverity.HIGH == Severity.HIGH
        assert SeverityLevel.MEDIUM == Severity.MEDIUM


class TestSeverityBackwardCompatibility:
    """Test backward compatibility for Severity imports."""

    def test_import_from_crash_triage(self) -> None:
        """Test Severity import from crash_triage still works."""
        from dicom_fuzzer.core.crash.crash_triage import Severity as SeverityTriage

        assert SeverityTriage is Severity
        assert SeverityTriage.INFO.value == "info"


class TestDICOMState:
    """Tests for DICOMState enum."""

    def test_basic_states_exist(self) -> None:
        """Test basic DICOM protocol states are defined."""
        from dicom_fuzzer.core.constants import DICOMState

        assert DICOMState.IDLE is not None
        assert DICOMState.ASSOCIATION_REQUESTED is not None
        assert DICOMState.ASSOCIATION_ESTABLISHED is not None
        assert DICOMState.ASSOCIATION_REJECTED is not None
        assert DICOMState.DATA_TRANSFER is not None
        assert DICOMState.RELEASE_REQUESTED is not None
        assert DICOMState.RELEASE_COMPLETED is not None
        assert DICOMState.ABORT is not None

    def test_dimse_pending_states_exist(self) -> None:
        """Test DIMSE operation pending states are defined."""
        from dicom_fuzzer.core.constants import DICOMState

        assert DICOMState.C_STORE_PENDING is not None
        assert DICOMState.C_FIND_PENDING is not None
        assert DICOMState.C_MOVE_PENDING is not None
        assert DICOMState.C_GET_PENDING is not None
        assert DICOMState.N_CREATE_PENDING is not None
        assert DICOMState.N_SET_PENDING is not None
        assert DICOMState.N_DELETE_PENDING is not None
        assert DICOMState.N_ACTION_PENDING is not None
        assert DICOMState.N_EVENT_PENDING is not None

    def test_total_state_count(self) -> None:
        """Test total number of states is 17."""
        from dicom_fuzzer.core.constants import DICOMState

        assert len(DICOMState) == 17

    def test_states_are_unique(self) -> None:
        """Test all states have unique values."""
        from dicom_fuzzer.core.constants import DICOMState

        values = [s.value for s in DICOMState]
        assert len(values) == len(set(values))


class TestStateTransitionType:
    """Tests for StateTransitionType enum."""

    def test_inherits_from_str(self) -> None:
        """Test StateTransitionType inherits from str."""
        from dicom_fuzzer.core.constants import StateTransitionType

        assert isinstance(StateTransitionType.VALID, str)
        assert StateTransitionType.VALID.value == "valid"
        assert StateTransitionType.VALID == "valid"

    def test_all_values_exist(self) -> None:
        """Test all transition types are defined."""
        from dicom_fuzzer.core.constants import StateTransitionType

        assert StateTransitionType.VALID.value == "valid"
        assert StateTransitionType.INVALID.value == "invalid"
        assert StateTransitionType.TIMEOUT.value == "timeout"
        assert StateTransitionType.ERROR.value == "error"
        assert StateTransitionType.CRASH.value == "crash"

    def test_enum_iteration(self) -> None:
        """Test all transition types can be iterated."""
        from dicom_fuzzer.core.constants import StateTransitionType

        all_types = list(StateTransitionType)
        assert len(all_types) == 5
        assert StateTransitionType.VALID in all_types
        assert StateTransitionType.CRASH in all_types

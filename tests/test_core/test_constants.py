"""Tests for shared fuzzing constants."""

from __future__ import annotations

from dicom_fuzzer.core.constants import (
    ARITH_MAX,
    INTERESTING_8,
    INTERESTING_16,
    INTERESTING_32,
    BugSeverity,
    ByteMutationType,
    CrashSeverity,
    MutationType,
    Severity,
    SeverityLevel,
)


class TestArithmeticConstants:
    """Tests for arithmetic mutation constants."""

    def test_arith_max_is_35(self) -> None:
        """Test ARITH_MAX matches AFL default of 35."""
        assert ARITH_MAX == 35
        assert ARITH_MAX > 0


class TestInteresting8:
    """Tests for 8-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_8 contains critical boundaries."""
        assert -128 in INTERESTING_8  # INT8_MIN
        assert 127 in INTERESTING_8  # INT8_MAX
        assert 0 in INTERESTING_8
        assert 1 in INTERESTING_8
        assert -1 in INTERESTING_8  # All bits set

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_8) == len(set(INTERESTING_8))


class TestInteresting16:
    """Tests for 16-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_16 contains critical boundaries."""
        assert -32768 in INTERESTING_16  # INT16_MIN
        assert 32767 in INTERESTING_16  # INT16_MAX
        assert 65535 in INTERESTING_16  # UINT16_MAX
        assert 0 in INTERESTING_16
        assert -1 in INTERESTING_16

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_16) == len(set(INTERESTING_16))


class TestInteresting32:
    """Tests for 32-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_32 contains critical boundaries."""
        assert -2147483648 in INTERESTING_32  # INT32_MIN
        assert 2147483647 in INTERESTING_32  # INT32_MAX
        assert 4294967295 in INTERESTING_32  # UINT32_MAX
        assert 0 in INTERESTING_32
        assert -1 in INTERESTING_32

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_32) == len(set(INTERESTING_32))


class TestMutationType:
    """Tests for MutationType enum."""

    def test_inherits_from_str(self) -> None:
        """Test MutationType inherits from str for serialization."""
        assert isinstance(MutationType.SPLICE, str)
        assert MutationType.SPLICE.value == "splice"
        assert MutationType.SPLICE == "splice"

    def test_afl_mutations_exist(self) -> None:
        """Test AFL-style mutations are defined."""
        assert MutationType.BIT_FLIP_1.value == "bit_flip_1"
        assert MutationType.BIT_FLIP_2.value == "bit_flip_2"
        assert MutationType.BIT_FLIP_4.value == "bit_flip_4"
        assert MutationType.BYTE_FLIP_1.value == "byte_flip_1"
        assert MutationType.BYTE_FLIP_2.value == "byte_flip_2"
        assert MutationType.BYTE_FLIP_4.value == "byte_flip_4"

    def test_arithmetic_mutations_exist(self) -> None:
        """Test arithmetic mutations are defined."""
        assert MutationType.ARITH_8.value == "arith_8"
        assert MutationType.ARITH_16.value == "arith_16"
        assert MutationType.ARITH_32.value == "arith_32"

    def test_interesting_value_mutations_exist(self) -> None:
        """Test interesting value mutations are defined."""
        assert MutationType.INTEREST_8.value == "interest_8"
        assert MutationType.INTEREST_16.value == "interest_16"
        assert MutationType.INTEREST_32.value == "interest_32"

    def test_byte_mutation_type_alias(self) -> None:
        """Test ByteMutationType is alias to MutationType."""
        assert ByteMutationType is MutationType
        assert ByteMutationType.BIT_FLIP_1 == MutationType.BIT_FLIP_1

    def test_mutation_type_count(self) -> None:
        """Test expected member count."""
        assert len(list(MutationType)) == 13


class TestMutationTypeBackwardCompatibility:
    """Test backward compatibility for MutationType imports."""

    def test_import_from_byte_mutator(self) -> None:
        """Test ByteMutationType import from byte_mutator still works."""
        from dicom_fuzzer.core.mutation.byte_mutator import (
            ByteMutationType as ByteMutationTypeMutator,
        )

        assert ByteMutationTypeMutator is MutationType
        assert ByteMutationTypeMutator.BIT_FLIP_1.value == "bit_flip_1"


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

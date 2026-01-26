"""Tests for shared fuzzing constants."""

from __future__ import annotations

from dicom_fuzzer.core.constants import (
    ARITH_MAX,
    INTERESTING_8,
    INTERESTING_8_UNSIGNED,
    INTERESTING_16,
    INTERESTING_16_UNSIGNED,
    INTERESTING_32,
    INTERESTING_32_UNSIGNED,
    MAP_SIZE,
    MAP_SIZE_POW2,
    SEVERITY_SCORES,
    BugSeverity,
    ByteMutationType,
    CrashSeverity,
    GUIResponseType,
    MutationType,
    ProtocolResponseType,
    ResponseType,
    Severity,
    SeverityLevel,
)


class TestCoverageConstants:
    """Tests for coverage tracking constants."""

    def test_map_size_is_power_of_two(self) -> None:
        """Test MAP_SIZE is 2^16 (AFL default)."""
        assert MAP_SIZE == 65536
        assert MAP_SIZE == 2**16

    def test_map_size_pow2_matches(self) -> None:
        """Test MAP_SIZE_POW2 is log2(MAP_SIZE)."""
        assert MAP_SIZE_POW2 == 16
        assert 2**MAP_SIZE_POW2 == MAP_SIZE


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

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_8_UNSIGNED)
        assert 0 in INTERESTING_8_UNSIGNED
        assert 255 in INTERESTING_8_UNSIGNED  # UINT8_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_8) == len(set(INTERESTING_8))
        assert len(INTERESTING_8_UNSIGNED) == len(set(INTERESTING_8_UNSIGNED))


class TestInteresting16:
    """Tests for 16-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_16 contains critical boundaries."""
        assert -32768 in INTERESTING_16  # INT16_MIN
        assert 32767 in INTERESTING_16  # INT16_MAX
        assert 65535 in INTERESTING_16  # UINT16_MAX
        assert 0 in INTERESTING_16
        assert -1 in INTERESTING_16

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_16_UNSIGNED)
        assert 65535 in INTERESTING_16_UNSIGNED  # UINT16_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_16) == len(set(INTERESTING_16))
        assert len(INTERESTING_16_UNSIGNED) == len(set(INTERESTING_16_UNSIGNED))


class TestInteresting32:
    """Tests for 32-bit interesting values."""

    def test_contains_boundary_values(self) -> None:
        """Test INTERESTING_32 contains critical boundaries."""
        assert -2147483648 in INTERESTING_32  # INT32_MIN
        assert 2147483647 in INTERESTING_32  # INT32_MAX
        assert 4294967295 in INTERESTING_32  # UINT32_MAX
        assert 0 in INTERESTING_32
        assert -1 in INTERESTING_32

    def test_unsigned_variant_positive_only(self) -> None:
        """Test unsigned variant has no negative values."""
        assert all(v >= 0 for v in INTERESTING_32_UNSIGNED)
        assert 4294967295 in INTERESTING_32_UNSIGNED  # UINT32_MAX

    def test_no_duplicates(self) -> None:
        """Test no duplicate values."""
        assert len(INTERESTING_32) == len(set(INTERESTING_32))
        assert len(INTERESTING_32_UNSIGNED) == len(set(INTERESTING_32_UNSIGNED))


class TestConstantsImportFromCore:
    """Test constants can be imported from dicom_fuzzer.core."""

    def test_import_from_core(self) -> None:
        """Test constants are exported from core package."""
        from dicom_fuzzer.core import (
            ARITH_MAX as ARITH_MAX_CORE,
        )
        from dicom_fuzzer.core import (
            INTERESTING_8 as INTERESTING_8_CORE,
        )
        from dicom_fuzzer.core import (
            MAP_SIZE as MAP_SIZE_CORE,
        )

        assert ARITH_MAX_CORE == ARITH_MAX
        assert INTERESTING_8_CORE == INTERESTING_8
        assert MAP_SIZE_CORE == MAP_SIZE


class TestMutationType:
    """Tests for unified MutationType enum."""

    def test_inherits_from_str(self) -> None:
        """Test MutationType inherits from str for serialization."""
        # MutationType inherits from str, so it can be used where str is expected
        assert isinstance(MutationType.HAVOC, str)
        # The .value attribute gives the string value
        assert MutationType.HAVOC.value == "havoc"
        # Direct comparison with str works due to str inheritance
        assert MutationType.HAVOC == "havoc"

    def test_afl_mutations_exist(self) -> None:
        """Test AFL-style mutations are defined."""
        # General bit/byte flips
        assert MutationType.BIT_FLIP.value == "bit_flip"
        assert MutationType.BYTE_FLIP.value == "byte_flip"
        # Specific sizes (ByteMutator)
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
        # Standardized naming
        assert MutationType.INTERESTING_8.value == "interesting_8"
        assert MutationType.INTERESTING_16.value == "interesting_16"
        assert MutationType.INTERESTING_32.value == "interesting_32"
        # Legacy naming (backward compatibility)
        assert MutationType.INTEREST_8.value == "interest_8"
        assert MutationType.INTEREST_16.value == "interest_16"
        assert MutationType.INTEREST_32.value == "interest_32"

    def test_havoc_and_splice_exist(self) -> None:
        """Test havoc and splice mutations are defined."""
        assert MutationType.HAVOC.value == "havoc"
        assert MutationType.SPLICE.value == "splice"

    def test_dicom_specific_mutations_exist(self) -> None:
        """Test DICOM-specific mutations are defined."""
        assert MutationType.TAG_MUTATION.value == "tag_mutation"
        assert MutationType.VR_MUTATION.value == "vr_mutation"
        assert MutationType.DICOM_STRUCTURE.value == "dicom_structure"
        assert MutationType.DICOM_TAG_CORRUPT.value == "dicom_tag_corrupt"

    def test_cve_mutations_exist(self) -> None:
        """Test CVE-based security mutations are defined."""
        assert MutationType.CVE_INTEGER_OVERFLOW.value == "cve_integer_overflow"
        assert MutationType.CVE_PATH_TRAVERSAL.value == "cve_path_traversal"
        assert MutationType.CVE_HEAP_OVERFLOW.value == "cve_heap_overflow"
        assert MutationType.CVE_RANDOM.value == "cve_random"

    def test_byte_mutation_type_alias(self) -> None:
        """Test ByteMutationType is alias to MutationType."""
        assert ByteMutationType is MutationType
        assert ByteMutationType.BIT_FLIP_1 == MutationType.BIT_FLIP_1

    def test_mutation_type_iteration(self) -> None:
        """Test all mutation types can be iterated."""
        all_types = list(MutationType)
        assert len(all_types) > 50  # We have many mutation types
        assert MutationType.HAVOC in all_types
        assert MutationType.CVE_RANDOM in all_types

    def test_enum_membership(self) -> None:
        """Test enum membership checking."""
        assert "havoc" in [m.value for m in MutationType]
        assert MutationType("havoc") == MutationType.HAVOC


class TestMutationTypeBackwardCompatibility:
    """Test backward compatibility for MutationType imports."""

    def test_import_from_core(self) -> None:
        """Test MutationType can be imported from core."""
        from dicom_fuzzer.core import ByteMutationType as ByteMutationTypeCore
        from dicom_fuzzer.core import MutationType as MutationTypeCore

        assert MutationTypeCore is MutationType
        assert ByteMutationTypeCore is ByteMutationType
        assert MutationTypeCore.HAVOC.value == "havoc"

    def test_import_from_persistent_fuzzer(self) -> None:
        """Test MutationType import from persistent_fuzzer still works."""
        # persistent_fuzzer now imports from constants
        from dicom_fuzzer.core.persistent_fuzzer import MOptScheduler

        # MOptScheduler uses MutationType internally
        scheduler = MOptScheduler()
        assert len(scheduler.mutation_types) > 0

    def test_import_from_byte_mutator(self) -> None:
        """Test ByteMutationType import from byte_mutator still works."""
        from dicom_fuzzer.core.byte_mutator import (
            ByteMutationType as ByteMutationTypeMutator,
        )

        assert ByteMutationTypeMutator is MutationType
        assert ByteMutationTypeMutator.BIT_FLIP_1.value == "bit_flip_1"

    def test_import_from_coverage_guided_mutator(self) -> None:
        """Test MutationType import from coverage_guided_mutator works."""
        from dicom_fuzzer.core.coverage_guided_mutator import (
            MutationType as MutationTypeCoverage,
        )

        assert MutationTypeCoverage is MutationType
        assert MutationTypeCoverage.CVE_RANDOM.value == "cve_random"


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

    def test_severity_scores_mapping(self) -> None:
        """Test SEVERITY_SCORES provides correct numeric ordering."""
        assert SEVERITY_SCORES[Severity.CRITICAL] == 5
        assert SEVERITY_SCORES[Severity.HIGH] == 4
        assert SEVERITY_SCORES[Severity.MEDIUM] == 3
        assert SEVERITY_SCORES[Severity.LOW] == 2
        assert SEVERITY_SCORES[Severity.INFO] == 1
        assert SEVERITY_SCORES[Severity.UNKNOWN] == 0
        # Test ordering
        assert SEVERITY_SCORES[Severity.CRITICAL] > SEVERITY_SCORES[Severity.HIGH]
        assert SEVERITY_SCORES[Severity.HIGH] > SEVERITY_SCORES[Severity.MEDIUM]

    def test_backward_compatibility_aliases(self) -> None:
        """Test backward compatibility aliases."""
        assert CrashSeverity is Severity
        assert BugSeverity is Severity
        assert SeverityLevel is Severity
        # Can use any alias to access values
        assert CrashSeverity.CRITICAL == Severity.CRITICAL
        assert BugSeverity.HIGH == Severity.HIGH
        assert SeverityLevel.MEDIUM == Severity.MEDIUM


class TestSeverityBackwardCompatibility:
    """Test backward compatibility for Severity imports."""

    def test_import_from_core(self) -> None:
        """Test Severity can be imported from core."""
        from dicom_fuzzer.core import CrashSeverity as CrashSeverityCore
        from dicom_fuzzer.core import Severity as SeverityCore

        assert SeverityCore is Severity
        assert CrashSeverityCore is Severity
        assert SeverityCore.CRITICAL.value == "critical"

    def test_import_from_crash_analyzer(self) -> None:
        """Test CrashSeverity import from crash_analyzer still works."""
        from dicom_fuzzer.core.crash_analyzer import (
            CrashSeverity as CrashSeverityAnalyzer,
        )

        assert CrashSeverityAnalyzer is Severity
        assert CrashSeverityAnalyzer.CRITICAL.value == "critical"

    def test_import_from_crash_triage(self) -> None:
        """Test Severity import from crash_triage still works."""
        from dicom_fuzzer.core.crash_triage import Severity as SeverityTriage

        assert SeverityTriage is Severity
        assert SeverityTriage.INFO.value == "info"

    def test_import_from_semantic_bucketer(self) -> None:
        """Test Severity and SEVERITY_SCORES import from semantic_bucketer."""
        from dicom_fuzzer.core.semantic_bucketer import (
            SEVERITY_SCORES as SeverityScoresBucketer,
        )
        from dicom_fuzzer.core.semantic_bucketer import Severity as SeverityBucketer

        assert SeverityBucketer is Severity
        assert SeverityScoresBucketer is SEVERITY_SCORES
        # Verify numeric scoring works
        assert (
            SeverityScoresBucketer[SeverityBucketer.CRITICAL]
            > SeverityScoresBucketer[SeverityBucketer.LOW]
        )


class TestGUIResponseType:
    """Tests for GUIResponseType enum."""

    def test_inherits_from_str(self) -> None:
        """Test GUIResponseType inherits from str."""
        assert isinstance(GUIResponseType.NORMAL, str)
        assert GUIResponseType.NORMAL.value == "normal"

    def test_response_type_values_exist(self) -> None:
        """Test all GUI response type values are defined."""
        assert GUIResponseType.NORMAL.value == "normal"
        assert GUIResponseType.ERROR_DIALOG.value == "error_dialog"
        assert GUIResponseType.CRASH.value == "crash"
        assert GUIResponseType.HANG.value == "hang"
        assert GUIResponseType.MEMORY_SPIKE.value == "memory_spike"

    def test_response_type_alias(self) -> None:
        """Test ResponseType is alias to GUIResponseType."""
        assert ResponseType is GUIResponseType
        assert ResponseType.CRASH == GUIResponseType.CRASH


class TestProtocolResponseType:
    """Tests for ProtocolResponseType enum."""

    def test_inherits_from_str(self) -> None:
        """Test ProtocolResponseType inherits from str."""
        assert isinstance(ProtocolResponseType.ACCEPT, str)
        assert ProtocolResponseType.ACCEPT.value == "accept"

    def test_protocol_response_values_exist(self) -> None:
        """Test all protocol response type values are defined."""
        assert ProtocolResponseType.ACCEPT.value == "accept"
        assert ProtocolResponseType.REJECT.value == "reject"
        assert ProtocolResponseType.ABORT.value == "abort"
        assert ProtocolResponseType.DATA.value == "data"
        assert ProtocolResponseType.TIMEOUT.value == "timeout"
        assert ProtocolResponseType.CRASH.value == "crash"


class TestResponseTypeBackwardCompatibility:
    """Test backward compatibility for ResponseType imports."""

    def test_import_from_gui_monitor_types(self) -> None:
        """Test ResponseType import from gui_monitor_types."""
        from dicom_fuzzer.core.gui_monitor_types import (
            ResponseType as ResponseTypeGUI,
        )

        assert ResponseTypeGUI is GUIResponseType
        assert ResponseTypeGUI.NORMAL.value == "normal"

    def test_import_from_response_aware_fuzzer(self) -> None:
        """Test ResponseType import from response_aware_fuzzer."""
        from dicom_fuzzer.core.response_aware_fuzzer import (
            ResponseType as ResponseTypeProtocol,
        )

        assert ResponseTypeProtocol is ProtocolResponseType
        assert ResponseTypeProtocol.ACCEPT.value == "accept"


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

        # C-Services
        assert DICOMState.C_STORE_PENDING is not None
        assert DICOMState.C_FIND_PENDING is not None
        assert DICOMState.C_MOVE_PENDING is not None
        assert DICOMState.C_GET_PENDING is not None
        # N-Services
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


class TestProtocolEnumsBackwardCompatibility:
    """Test backward compatibility for protocol enum imports."""

    def test_import_from_core(self) -> None:
        """Test enums can be imported from core."""
        from dicom_fuzzer.core import DICOMState as DICOMStateCore
        from dicom_fuzzer.core import StateTransitionType as StateTransitionTypeCore
        from dicom_fuzzer.core.constants import DICOMState, StateTransitionType

        assert DICOMStateCore is DICOMState
        assert StateTransitionTypeCore is StateTransitionType
        assert DICOMStateCore.IDLE is not None
        assert StateTransitionTypeCore.VALID.value == "valid"

    def test_import_from_state_aware_fuzzer(self) -> None:
        """Test enums can still be imported from state_aware_fuzzer."""
        from dicom_fuzzer.core.constants import DICOMState, StateTransitionType
        from dicom_fuzzer.core.state_aware_fuzzer import (
            DICOMState as DICOMStateAware,
        )
        from dicom_fuzzer.core.state_aware_fuzzer import (
            StateTransitionType as StateTransitionTypeAware,
        )

        assert DICOMStateAware is DICOMState
        assert StateTransitionTypeAware is StateTransitionType

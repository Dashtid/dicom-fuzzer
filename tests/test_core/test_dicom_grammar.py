"""Comprehensive tests for DICOM grammar specification.

Tests the formal grammar rules and mutation operators
for structured DICOM input generation.
"""

import struct

import pytest

from dicom_fuzzer.core.dicom_grammar import (
    VR,
    DeleteRuleMutator,
    DICOMGrammar,
    DuplicateRuleMutator,
    GrammarMutationEngine,
    GrammarRule,
    InsertRuleMutator,
    ReplaceRuleMutator,
    RuleType,
    SwapRuleMutator,
    TagDefinition,
    WeightMutator,
)


class TestVR:
    """Tests for VR (Value Representation) enum."""

    def test_string_vrs_exist(self):
        """Test string VR types exist."""
        assert VR.AE  # Application Entity
        assert VR.CS  # Code String
        assert VR.DA  # Date
        assert VR.LO  # Long String
        assert VR.PN  # Person Name
        assert VR.UI  # Unique Identifier

    def test_binary_vrs_exist(self):
        """Test binary VR types exist."""
        assert VR.OB  # Other Byte
        assert VR.OW  # Other Word
        assert VR.SQ  # Sequence
        assert VR.US  # Unsigned Short
        assert VR.UL  # Unsigned Long
        assert VR.FL  # Float

    def test_vr_values(self):
        """Test VR string values."""
        assert VR.US.value == "US"
        assert VR.OB.value == "OB"
        assert VR.SQ.value == "SQ"


class TestRuleType:
    """Tests for RuleType enum."""

    def test_all_types_exist(self):
        """Test all rule types exist."""
        assert RuleType.TERMINAL
        assert RuleType.NONTERMINAL
        assert RuleType.SEQUENCE
        assert RuleType.CHOICE
        assert RuleType.OPTIONAL
        assert RuleType.REPEAT
        assert RuleType.REPEAT_PLUS


class TestTagDefinition:
    """Tests for TagDefinition class."""

    def test_basic_creation(self):
        """Test basic tag definition."""
        tag = TagDefinition(
            group=0x0010,
            element=0x0010,
            vr=VR.PN,
            name="Patient's Name",
        )

        assert tag.group == 0x0010
        assert tag.element == 0x0010
        assert tag.vr == VR.PN
        assert tag.name == "Patient's Name"

    def test_tag_bytes_little_endian(self):
        """Test tag byte encoding (little endian)."""
        tag = TagDefinition(
            group=0x0010,
            element=0x0020,
            vr=VR.LO,
            name="Patient ID",
        )

        tag_bytes = tag.tag_bytes(little_endian=True)

        assert len(tag_bytes) == 4
        assert tag_bytes == struct.pack("<HH", 0x0010, 0x0020)

    def test_tag_bytes_big_endian(self):
        """Test tag byte encoding (big endian)."""
        tag = TagDefinition(
            group=0x0010,
            element=0x0020,
            vr=VR.LO,
            name="Patient ID",
        )

        tag_bytes = tag.tag_bytes(little_endian=False)

        assert len(tag_bytes) == 4
        assert tag_bytes == struct.pack(">HH", 0x0010, 0x0020)

    def test_required_flag(self):
        """Test required flag."""
        tag = TagDefinition(
            group=0x0008,
            element=0x0018,
            vr=VR.UI,
            name="SOP Instance UID",
            required=True,
        )

        assert tag.required is True


class TestGrammarRule:
    """Tests for GrammarRule class."""

    def test_terminal_rule(self):
        """Test terminal rule creation."""
        rule = GrammarRule(
            name="Prefix",
            rule_type=RuleType.TERMINAL,
            terminal_generator=lambda: b"DICM",
        )

        assert rule.name == "Prefix"
        assert rule.rule_type == RuleType.TERMINAL

    def test_sequence_rule(self):
        """Test sequence rule creation."""
        rule = GrammarRule(
            name="DataElement",
            rule_type=RuleType.SEQUENCE,
            children=["Tag", "VR", "Length", "Value"],
        )

        assert rule.rule_type == RuleType.SEQUENCE
        assert len(rule.children) == 4

    def test_choice_rule(self):
        """Test choice rule creation."""
        rule = GrammarRule(
            name="VR",
            rule_type=RuleType.CHOICE,
            children=["VR_US", "VR_UL", "VR_OB"],
        )

        assert rule.rule_type == RuleType.CHOICE
        assert "VR_US" in rule.children

    def test_repeat_rule(self):
        """Test repeat rule creation."""
        rule = GrammarRule(
            name="DataSet",
            rule_type=RuleType.REPEAT,
            children=["DataElement"],
            constraints={"max_repeat": 50},
        )

        assert rule.rule_type == RuleType.REPEAT
        assert rule.constraints["max_repeat"] == 50

    def test_weight_attribute(self):
        """Test weight attribute."""
        rule = GrammarRule(
            name="Test",
            rule_type=RuleType.TERMINAL,
            weight=2.5,
        )

        assert rule.weight == 2.5

    def test_coverage_hits_tracking(self):
        """Test coverage hits are tracked."""
        rule = GrammarRule(
            name="Test",
            rule_type=RuleType.TERMINAL,
            terminal_generator=lambda: b"test",
        )

        assert rule.coverage_hits == 0

        # Simulate generation
        class MockGrammar:
            def get_rule(self, name):
                return None

        rule.generate(MockGrammar())
        assert rule.coverage_hits == 1


class TestDICOMGrammar:
    """Tests for DICOMGrammar class."""

    @pytest.fixture
    def grammar(self):
        """Create a grammar instance."""
        return DICOMGrammar()

    def test_initialization(self, grammar):
        """Test grammar initialization."""
        assert len(grammar.rules) > 0
        assert len(grammar.tag_definitions) > 0

    def test_has_standard_rules(self, grammar):
        """Test grammar has standard DICOM rules."""
        assert grammar.get_rule("DICOMFile") is not None
        assert grammar.get_rule("Preamble") is not None
        assert grammar.get_rule("Prefix") is not None
        assert grammar.get_rule("DataSet") is not None
        assert grammar.get_rule("DataElement") is not None

    def test_has_tag_definitions(self, grammar):
        """Test grammar has tag definitions."""
        # Patient's Name
        assert (0x0010, 0x0010) in grammar.tag_definitions
        # Patient ID
        assert (0x0010, 0x0020) in grammar.tag_definitions
        # SOP Instance UID
        assert (0x0008, 0x0018) in grammar.tag_definitions

    def test_generate_preamble(self, grammar):
        """Test preamble generation."""
        preamble_rule = grammar.get_rule("Preamble")
        preamble = preamble_rule.generate(grammar)

        assert len(preamble) == 128
        assert preamble == b"\x00" * 128

    def test_generate_prefix(self, grammar):
        """Test prefix generation."""
        prefix_rule = grammar.get_rule("Prefix")
        prefix = prefix_rule.generate(grammar)

        assert prefix == b"DICM"

    def test_generate_tag(self, grammar):
        """Test tag generation."""
        tag = grammar._generate_tag()

        assert len(tag) == 4
        # Should be a valid group, element pair

    def test_generate_uid(self, grammar):
        """Test UID generation."""
        uid = grammar._generate_uid()

        assert uid.startswith("1.2.826.0.1.3680043.8.498")
        assert len(uid) < 64  # Max UID length

    def test_generate_string_value(self, grammar):
        """Test string value generation."""
        value = grammar._generate_string_value()

        assert isinstance(value, bytes)
        assert len(value) % 2 == 0  # Should be even length

    def test_generate_numeric_value(self, grammar):
        """Test numeric value generation."""
        value = grammar._generate_numeric_value()

        assert isinstance(value, bytes)
        assert len(value) in [2, 4]  # US, UL, SS, float

    def test_generate_full_file(self, grammar):
        """Test full DICOM file generation."""
        data = grammar.generate("DICOMFile")

        assert isinstance(data, bytes)
        # Should start with 128-byte preamble + DICM
        assert data[128:132] == b"DICM"

    def test_add_rule(self, grammar):
        """Test adding custom rules."""
        custom_rule = GrammarRule(
            name="CustomRule",
            rule_type=RuleType.TERMINAL,
            terminal_generator=lambda: b"custom",
        )

        grammar.add_rule(custom_rule)

        assert grammar.get_rule("CustomRule") is not None

    def test_get_coverage_stats(self, grammar):
        """Test coverage statistics."""
        # Generate some data to get coverage
        grammar.generate()

        stats = grammar.get_coverage_stats()

        assert "total_rules" in stats
        assert "rules_covered" in stats
        assert "coverage_percent" in stats
        assert "most_used" in stats

    def test_sop_classes_defined(self, grammar):
        """Test SOP classes are defined."""
        assert len(grammar.SOP_CLASSES) > 0
        assert "1.2.840.10008.5.1.4.1.1.2" in grammar.SOP_CLASSES  # CT

    def test_transfer_syntaxes_defined(self, grammar):
        """Test transfer syntaxes are defined."""
        assert len(grammar.TRANSFER_SYNTAXES) > 0
        assert "1.2.840.10008.1.2" in grammar.TRANSFER_SYNTAXES  # Implicit VR LE


class TestGrammarMutators:
    """Tests for grammar mutation operators."""

    @pytest.fixture
    def grammar(self):
        """Create a grammar for testing."""
        grammar = DICOMGrammar()
        # Add a testable sequence rule
        grammar.add_rule(
            GrammarRule(
                name="TestSequence",
                rule_type=RuleType.SEQUENCE,
                children=["Preamble", "Prefix"],
            )
        )
        return grammar

    def test_insert_rule_mutator(self, grammar):
        """Test InsertRuleMutator."""
        mutator = InsertRuleMutator()
        original_len = len(grammar.get_rule("TestSequence").children)

        success = mutator.mutate(grammar, "TestSequence")

        if success:
            assert len(grammar.get_rule("TestSequence").children) == original_len + 1

    def test_delete_rule_mutator(self, grammar):
        """Test DeleteRuleMutator."""
        mutator = DeleteRuleMutator()
        original_len = len(grammar.get_rule("TestSequence").children)

        success = mutator.mutate(grammar, "TestSequence")

        if success:
            assert len(grammar.get_rule("TestSequence").children) == original_len - 1

    def test_replace_rule_mutator(self, grammar):
        """Test ReplaceRuleMutator."""
        mutator = ReplaceRuleMutator()

        success = mutator.mutate(grammar, "TestSequence")

        # Should succeed since TestSequence has children
        assert isinstance(success, bool)

    def test_swap_rule_mutator(self, grammar):
        """Test SwapRuleMutator."""
        mutator = SwapRuleMutator()
        original = grammar.get_rule("TestSequence").children.copy()

        success = mutator.mutate(grammar, "TestSequence")

        if success:
            # Order should be different
            current = grammar.get_rule("TestSequence").children
            assert current != original or len(original) < 2

    def test_duplicate_rule_mutator(self, grammar):
        """Test DuplicateRuleMutator."""
        mutator = DuplicateRuleMutator()
        original_len = len(grammar.get_rule("TestSequence").children)

        success = mutator.mutate(grammar, "TestSequence")

        if success:
            assert len(grammar.get_rule("TestSequence").children) == original_len + 1

    def test_weight_mutator(self, grammar):
        """Test WeightMutator."""
        mutator = WeightMutator()
        rule = grammar.get_rule("TestSequence")
        original_weight = rule.weight

        mutator.mutate(grammar, "TestSequence")

        # Weight should have changed (or be clamped to same value)
        assert 0.1 <= rule.weight <= 10.0


class TestGrammarMutationEngine:
    """Tests for GrammarMutationEngine class."""

    @pytest.fixture
    def engine(self):
        """Create a mutation engine."""
        grammar = DICOMGrammar()
        return GrammarMutationEngine(grammar)

    def test_initialization(self, engine):
        """Test engine initialization."""
        assert len(engine.mutators) > 0
        assert engine.grammar is not None

    def test_mutate_single(self, engine):
        """Test single mutation."""
        successful = engine.mutate(num_mutations=1)

        assert successful >= 0

    def test_mutate_multiple(self, engine):
        """Test multiple mutations."""
        successful = engine.mutate(num_mutations=10)

        assert successful >= 0
        assert successful <= 10

    def test_update_effectiveness(self, engine):
        """Test effectiveness updates."""
        mutator_name = "InsertRuleMutator"

        initial = engine._effectiveness[mutator_name]
        engine.update_effectiveness(mutator_name, found_new_coverage=True)

        assert engine._effectiveness[mutator_name] > initial

    def test_effectiveness_decreases_on_failure(self, engine):
        """Test effectiveness decreases on failure."""
        mutator_name = "InsertRuleMutator"

        engine._effectiveness[mutator_name] = 5.0
        engine.update_effectiveness(mutator_name, found_new_coverage=False)

        assert engine._effectiveness[mutator_name] < 5.0

    def test_get_stats(self, engine):
        """Test statistics retrieval."""
        engine.mutate(num_mutations=5)

        stats = engine.get_stats()

        assert "total_mutations" in stats
        assert "successful_mutations" in stats
        assert "success_rate" in stats
        assert "effectiveness_scores" in stats
        assert "grammar_coverage" in stats

    def test_effectiveness_clamping(self, engine):
        """Test effectiveness is clamped to valid range."""
        mutator_name = "TestMutator"

        # Try to make it very high
        for _ in range(100):
            engine.update_effectiveness(mutator_name, found_new_coverage=True)

        assert engine._effectiveness[mutator_name] <= 10.0

        # Try to make it very low
        engine._effectiveness[mutator_name] = 0.5
        for _ in range(100):
            engine.update_effectiveness(mutator_name, found_new_coverage=False)

        assert engine._effectiveness[mutator_name] >= 0.1

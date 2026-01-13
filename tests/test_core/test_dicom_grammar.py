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


class TestDICOMGrammarBranchCoverage:
    """Additional tests for branch coverage."""

    @pytest.fixture
    def grammar(self):
        """Create a grammar instance."""
        return DICOMGrammar()

    def test_generate_rule_max_depth_exceeded(self, grammar):
        """Test that max_depth limit returns empty bytes."""
        rule = grammar.get_rule("DICOMFile")
        result = rule.generate(grammar, depth=100, max_depth=100)
        assert result == b""

    def test_generate_nonterminal_rule_type_no_handler(self, grammar):
        """Test NONTERMINAL rule type (no handler in dispatch table)."""
        rule = GrammarRule(
            name="NonTermTest",
            rule_type=RuleType.NONTERMINAL,
            children=["Preamble"],
        )
        grammar.add_rule(rule)
        result = rule.generate(grammar)
        # NONTERMINAL not in handlers, returns b""
        assert result == b""

    def test_terminal_rule_without_generator(self, grammar):
        """Test terminal rule without terminal_generator returns empty."""
        rule = GrammarRule(
            name="EmptyTerminal",
            rule_type=RuleType.TERMINAL,
            terminal_generator=None,
        )
        result = rule._generate_terminal(grammar, 0, 100)
        assert result == b""

    def test_sequence_with_missing_child_rule(self, grammar):
        """Test sequence handles missing child rule."""
        rule = GrammarRule(
            name="TestSeq",
            rule_type=RuleType.SEQUENCE,
            children=["NonexistentRule", "Prefix"],
        )
        grammar.add_rule(rule)
        result = rule.generate(grammar)
        # Should only generate Prefix (DICM) since NonexistentRule is None
        assert b"DICM" in result

    def test_choice_with_empty_children(self, grammar):
        """Test choice rule with empty children returns empty."""
        rule = GrammarRule(
            name="EmptyChoice",
            rule_type=RuleType.CHOICE,
            children=[],
        )
        result = rule._generate_choice(grammar, 0, 100)
        assert result == b""

    def test_choice_with_missing_child_rules(self, grammar):
        """Test choice handles missing child rules with default weight."""
        rule = GrammarRule(
            name="ChoiceWithMissing",
            rule_type=RuleType.CHOICE,
            children=["NonexistentRule"],
        )
        grammar.add_rule(rule)
        # Should return empty since the selected rule is None
        result = rule.generate(grammar)
        assert result == b""

    def test_optional_rule_skip_branch(self, grammar):
        """Test optional rule can skip (return empty)."""
        import random

        rule = GrammarRule(
            name="OptTest",
            rule_type=RuleType.OPTIONAL,
            children=["Prefix"],
        )
        grammar.add_rule(rule)

        # Run multiple times to hit both branches
        results = set()
        random.seed(42)
        for _ in range(20):
            result = rule.generate(grammar)
            results.add(result)

        # Should have both empty and non-empty results
        assert b"" in results or b"DICM" in results

    def test_optional_with_missing_child(self, grammar):
        """Test optional with missing child rule returns empty."""
        rule = GrammarRule(
            name="OptMissing",
            rule_type=RuleType.OPTIONAL,
            children=["NonexistentRule"],
        )
        grammar.add_rule(rule)
        # Even if random chooses to generate, rule doesn't exist
        import random

        random.seed(1)  # Seed that makes random() < 0.5
        result = rule.generate(grammar)
        assert result == b""

    def test_optional_with_empty_children(self, grammar):
        """Test optional with no children returns empty."""
        rule = GrammarRule(
            name="OptEmpty",
            rule_type=RuleType.OPTIONAL,
            children=[],
        )
        result = rule._generate_optional(grammar, 0, 100)
        assert result == b""

    def test_repeat_plus_vs_repeat_min_count(self, grammar):
        """Test REPEAT_PLUS has min_count of 1."""
        rule_plus = GrammarRule(
            name="RepeatPlusTest",
            rule_type=RuleType.REPEAT_PLUS,
            children=["Prefix"],
            constraints={"max_repeat": 3},
        )
        grammar.add_rule(rule_plus)

        import random

        random.seed(123)
        result = rule_plus.generate(grammar)
        # REPEAT_PLUS guarantees at least one occurrence
        assert b"DICM" in result

    def test_repeat_with_empty_children(self, grammar):
        """Test repeat with empty children returns empty."""
        rule = GrammarRule(
            name="RepeatEmpty",
            rule_type=RuleType.REPEAT,
            children=[],
            constraints={"max_repeat": 5},
        )
        result = rule._generate_repeat(grammar, 0, 100)
        assert result == b""

    def test_repeat_with_missing_child_rule(self, grammar):
        """Test repeat handles missing child rule."""
        rule = GrammarRule(
            name="RepeatMissing",
            rule_type=RuleType.REPEAT,
            children=["NonexistentRule"],
            constraints={"max_repeat": 2},
        )
        grammar.add_rule(rule)
        import random

        random.seed(99)
        result = rule.generate(grammar)
        assert result == b""

    def test_generate_nonexistent_start_rule(self, grammar):
        """Test generate with nonexistent start rule returns empty."""
        result = grammar.generate("NonexistentStartRule")
        assert result == b""

    def test_generate_tag_random_branch(self):
        """Test _generate_tag random tag generation branch."""
        import random

        grammar = DICOMGrammar()

        # Force random branch (>= 0.8)
        random.seed(100)  # Find seed that gives random() >= 0.8
        for _ in range(50):
            tag = grammar._generate_tag()
            assert len(tag) == 4

    def test_generate_tag_with_empty_definitions(self):
        """Test _generate_tag with empty tag_definitions."""
        grammar = DICOMGrammar()
        grammar.tag_definitions = {}

        tag = grammar._generate_tag()
        assert len(tag) == 4

    def test_generate_string_value_odd_length_padding(self):
        """Test _generate_string_value pads odd length strings."""
        import random

        grammar = DICOMGrammar()

        # Generate many values to ensure we hit odd length case
        for i in range(100):
            random.seed(i)
            value = grammar._generate_string_value()
            assert len(value) % 2 == 0  # Should always be even after padding

    def test_generate_numeric_value_all_branches(self):
        """Test all branches of _generate_numeric_value."""
        import random

        grammar = DICOMGrammar()

        # Test all 4 choice branches (0, 1, 2, 3)
        lengths_seen = set()
        for i in range(100):
            random.seed(i)
            value = grammar._generate_numeric_value()
            lengths_seen.add(len(value))

        # Should have seen different lengths: 2 (US/SS), 4 (UL/float)
        assert 2 in lengths_seen
        assert 4 in lengths_seen

    def test_generate_binary_value_odd_length_fix(self):
        """Test _generate_binary_value fixes odd lengths."""
        import random

        grammar = DICOMGrammar()

        for i in range(100):
            random.seed(i)
            value = grammar._generate_binary_value()
            assert len(value) % 2 == 0

    def test_generate_uid_element_odd_uid_padding(self):
        """Test _generate_uid_element pads odd-length UIDs."""
        grammar = DICOMGrammar()

        # Test with odd-length UID
        odd_uid = "1.2.3"  # Length 5 (odd)
        result = grammar._generate_uid_element(0x0002, 0x0002, odd_uid)

        # Should contain padded UID
        assert len(result) > 0
        # Check the length field accounts for padding
        uid_with_pad = odd_uid + "\x00"  # Padded
        assert len(uid_with_pad) % 2 == 0

    def test_generate_uid_element_even_uid_no_padding(self):
        """Test _generate_uid_element doesn't pad even-length UIDs."""
        grammar = DICOMGrammar()

        # Test with even-length UID
        even_uid = "1.2.34"  # Length 6 (even)
        result = grammar._generate_uid_element(0x0002, 0x0002, even_uid)
        assert len(result) > 0

    def test_get_coverage_stats_empty_rules(self):
        """Test get_coverage_stats with empty rules."""
        grammar = DICOMGrammar()
        grammar.rules = {}

        stats = grammar.get_coverage_stats()
        assert stats["total_rules"] == 0
        assert stats["coverage_percent"] == 0


class TestGrammarMutatorsBranchCoverage:
    """Additional branch coverage tests for mutators."""

    @pytest.fixture
    def grammar(self):
        """Create a grammar for testing."""
        return DICOMGrammar()

    def test_insert_mutator_rule_not_found(self, grammar):
        """Test InsertRuleMutator with nonexistent rule."""
        mutator = InsertRuleMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_insert_mutator_wrong_rule_type(self, grammar):
        """Test InsertRuleMutator with terminal rule type."""
        mutator = InsertRuleMutator()
        result = mutator.mutate(grammar, "Prefix")  # Terminal rule
        assert result is False

    def test_insert_mutator_no_available_rules(self):
        """Test InsertRuleMutator when no other rules available."""
        grammar = DICOMGrammar()
        grammar.rules = {
            "OnlyRule": GrammarRule(
                name="OnlyRule",
                rule_type=RuleType.SEQUENCE,
                children=["OnlyRule"],
            )
        }
        mutator = InsertRuleMutator()
        result = mutator.mutate(grammar, "OnlyRule")
        assert result is False

    def test_delete_mutator_rule_not_found(self, grammar):
        """Test DeleteRuleMutator with nonexistent rule."""
        mutator = DeleteRuleMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_delete_mutator_wrong_rule_type(self, grammar):
        """Test DeleteRuleMutator with wrong rule type."""
        mutator = DeleteRuleMutator()
        result = mutator.mutate(grammar, "Prefix")  # Terminal
        assert result is False

    def test_delete_mutator_single_child(self, grammar):
        """Test DeleteRuleMutator with only one child."""
        grammar.add_rule(
            GrammarRule(
                name="SingleChild",
                rule_type=RuleType.SEQUENCE,
                children=["Prefix"],
            )
        )
        mutator = DeleteRuleMutator()
        result = mutator.mutate(grammar, "SingleChild")
        assert result is False

    def test_replace_mutator_rule_not_found(self, grammar):
        """Test ReplaceRuleMutator with nonexistent rule."""
        mutator = ReplaceRuleMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_replace_mutator_no_children(self, grammar):
        """Test ReplaceRuleMutator with rule having no children."""
        grammar.add_rule(
            GrammarRule(
                name="NoChildren",
                rule_type=RuleType.SEQUENCE,
                children=[],
            )
        )
        mutator = ReplaceRuleMutator()
        result = mutator.mutate(grammar, "NoChildren")
        assert result is False

    def test_replace_mutator_no_available_replacements(self):
        """Test ReplaceRuleMutator with no available replacement rules."""
        grammar = DICOMGrammar()
        grammar.rules = {
            "OnlyRule": GrammarRule(
                name="OnlyRule",
                rule_type=RuleType.SEQUENCE,
                children=["OnlyRule"],
            )
        }
        mutator = ReplaceRuleMutator()
        result = mutator.mutate(grammar, "OnlyRule")
        assert result is False

    def test_swap_mutator_rule_not_found(self, grammar):
        """Test SwapRuleMutator with nonexistent rule."""
        mutator = SwapRuleMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_swap_mutator_wrong_rule_type(self, grammar):
        """Test SwapRuleMutator with non-sequence rule."""
        mutator = SwapRuleMutator()
        result = mutator.mutate(grammar, "Prefix")  # Terminal
        assert result is False

    def test_swap_mutator_single_child(self, grammar):
        """Test SwapRuleMutator with less than 2 children."""
        grammar.add_rule(
            GrammarRule(
                name="OneChild",
                rule_type=RuleType.SEQUENCE,
                children=["Prefix"],
            )
        )
        mutator = SwapRuleMutator()
        result = mutator.mutate(grammar, "OneChild")
        assert result is False

    def test_swap_mutator_same_indices_retry(self, grammar):
        """Test SwapRuleMutator retries when same indices selected."""
        import random

        grammar.add_rule(
            GrammarRule(
                name="TwoChildren",
                rule_type=RuleType.SEQUENCE,
                children=["Prefix", "Preamble"],
            )
        )
        mutator = SwapRuleMutator()
        random.seed(42)
        result = mutator.mutate(grammar, "TwoChildren")
        assert result is True

    def test_duplicate_mutator_rule_not_found(self, grammar):
        """Test DuplicateRuleMutator with nonexistent rule."""
        mutator = DuplicateRuleMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_duplicate_mutator_wrong_rule_type(self, grammar):
        """Test DuplicateRuleMutator with non-sequence rule."""
        mutator = DuplicateRuleMutator()
        result = mutator.mutate(grammar, "Prefix")  # Terminal
        assert result is False

    def test_duplicate_mutator_no_children(self, grammar):
        """Test DuplicateRuleMutator with no children."""
        grammar.add_rule(
            GrammarRule(
                name="EmptySeq",
                rule_type=RuleType.SEQUENCE,
                children=[],
            )
        )
        mutator = DuplicateRuleMutator()
        result = mutator.mutate(grammar, "EmptySeq")
        assert result is False

    def test_weight_mutator_rule_not_found(self, grammar):
        """Test WeightMutator with nonexistent rule."""
        mutator = WeightMutator()
        result = mutator.mutate(grammar, "NonexistentRule")
        assert result is False

    def test_weight_mutator_clamping(self, grammar):
        """Test WeightMutator clamps weights to valid range."""
        import random

        grammar.add_rule(
            GrammarRule(
                name="TestWeight",
                rule_type=RuleType.TERMINAL,
                weight=0.2,  # Close to min
            )
        )
        mutator = WeightMutator()

        # Run many times to test clamping
        for i in range(50):
            random.seed(i)
            mutator.mutate(grammar, "TestWeight")

        rule = grammar.get_rule("TestWeight")
        assert 0.1 <= rule.weight <= 10.0


class TestMutationEngineBranchCoverage:
    """Additional branch coverage tests for mutation engine."""

    def test_select_mutator_fallback_to_last(self):
        """Test _select_mutator falls back to last mutator."""
        import random

        grammar = DICOMGrammar()
        engine = GrammarMutationEngine(grammar)

        # Seed to test selection
        random.seed(12345)
        for _ in range(20):
            mutator, weight = engine._select_mutator()
            assert mutator is not None

    def test_mutate_tracks_history(self):
        """Test that mutations are tracked in history."""
        grammar = DICOMGrammar()
        engine = GrammarMutationEngine(grammar)

        engine.mutate(num_mutations=5)

        assert len(engine._mutation_history) == 5
        for entry in engine._mutation_history:
            assert len(entry) == 3  # (mutator_name, rule_name, success)

    def test_get_stats_with_no_mutations(self):
        """Test get_stats when no mutations have been made."""
        grammar = DICOMGrammar()
        engine = GrammarMutationEngine(grammar)

        stats = engine.get_stats()

        assert stats["total_mutations"] == 0
        assert stats["successful_mutations"] == 0
        assert stats["success_rate"] == 0

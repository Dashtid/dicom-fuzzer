"""
Tests for LLM-Assisted DICOM Fuzzing Module.

Tests LLM-guided fuzzing components including:
- LLM clients (Mock, OpenAI, Anthropic, Ollama)
- DICOM spec parsing
- Mutation generation
- Adaptive mutation selection
"""

import json
from unittest.mock import patch

import pytest

from dicom_fuzzer.core.llm_fuzzer import (
    AdaptiveMutationSelector,
    AnthropicClient,
    DICOMProtocolRule,
    DICOMSpecParser,
    GeneratedMutation,
    LLMBackend,
    LLMFuzzer,
    LLMFuzzerConfig,
    LLMMutationGenerator,
    MockLLMClient,
    MutationCategory,
    MutationFeedback,
    MutationStatistics,
    OllamaClient,
    OpenAIClient,
    create_llm_fuzzer,
)

# ============================================================================
# Test Enums
# ============================================================================


class TestLLMBackend:
    """Test LLMBackend enum."""

    def test_backend_types_defined(self):
        """Test all backend types are defined."""
        assert LLMBackend.OPENAI.value == "openai"
        assert LLMBackend.ANTHROPIC.value == "anthropic"
        assert LLMBackend.OLLAMA.value == "ollama"
        assert LLMBackend.AZURE_OPENAI.value == "azure_openai"
        assert LLMBackend.MOCK.value == "mock"


class TestMutationCategory:
    """Test MutationCategory enum."""

    def test_categories_defined(self):
        """Test all mutation categories are defined."""
        expected = [
            "BOUNDARY_VALUE",
            "FORMAT_STRING",
            "TYPE_CONFUSION",
            "LENGTH_MANIPULATION",
            "ENCODING_ERROR",
            "SEMANTIC_VIOLATION",
            "STATE_MACHINE",
            "PROTOCOL_SPECIFIC",
        ]
        for name in expected:
            assert hasattr(MutationCategory, name)


# ============================================================================
# Test Dataclasses
# ============================================================================


class TestDICOMProtocolRule:
    """Test DICOMProtocolRule dataclass."""

    def test_default_values(self):
        """Test default values."""
        rule = DICOMProtocolRule(
            rule_id="test_001",
            description="Test rule",
            element_type="tag",
            constraint={"max_length": 64},
        )

        assert rule.rule_id == "test_001"
        assert rule.mandatory is False
        assert rule.iod_module == ""
        assert rule.security_relevant is False
        assert rule.source == ""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        rule = DICOMProtocolRule(
            rule_id="VR_PN_001",
            description="Patient Name constraints",
            element_type="vr",
            constraint={"max_length": 64},
            mandatory=True,
            security_relevant=True,
            source="DICOM PS3.5",
        )

        d = rule.to_dict()

        assert d["rule_id"] == "VR_PN_001"
        assert d["description"] == "Patient Name constraints"
        assert d["mandatory"] is True
        assert d["security_relevant"] is True


class TestGeneratedMutation:
    """Test GeneratedMutation dataclass."""

    def test_default_values(self):
        """Test default values."""
        mutation = GeneratedMutation(
            mutation_id="mut_001",
            category=MutationCategory.BOUNDARY_VALUE,
            target_element="(0010,0010)",
            original_value="John Doe",
            mutated_value="A" * 1000,
            rationale="Test buffer overflow",
            expected_behavior="May crash",
        )

        assert mutation.priority == 50
        assert mutation.cve_reference == ""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        mutation = GeneratedMutation(
            mutation_id="mut_001",
            category=MutationCategory.FORMAT_STRING,
            target_element="(0010,0020)",
            original_value="12345",
            mutated_value="%s%s%s%n",
            rationale="Format string attack",
            expected_behavior="May leak memory or crash",
            priority=90,
            cve_reference="CVE-2025-1234",
        )

        d = mutation.to_dict()

        assert d["mutation_id"] == "mut_001"
        assert d["category"] == "format_string"
        assert d["priority"] == 90
        assert d["cve_reference"] == "CVE-2025-1234"


class TestLLMFuzzerConfig:
    """Test LLMFuzzerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = LLMFuzzerConfig()

        assert config.backend == LLMBackend.MOCK
        assert config.model == "gpt-4"
        assert config.api_key == ""
        assert config.temperature == 0.7
        assert config.max_tokens == 2000
        assert config.timeout == 30.0
        assert config.cache_responses is True

    def test_custom_values(self):
        """Test custom configuration."""
        config = LLMFuzzerConfig(
            backend=LLMBackend.OPENAI,
            model="gpt-4o",
            api_key="test_key",
            temperature=0.5,
        )

        assert config.backend == LLMBackend.OPENAI
        assert config.model == "gpt-4o"
        assert config.api_key == "test_key"
        assert config.temperature == 0.5


# ============================================================================
# Test LLM Clients
# ============================================================================


class TestMockLLMClient:
    """Test MockLLMClient class."""

    def test_is_available(self):
        """Test mock client is always available."""
        client = MockLLMClient()
        assert client.is_available() is True

    def test_complete_mutation_prompt(self):
        """Test mock response for mutation prompts."""
        client = MockLLMClient()
        response = client.complete("Generate mutation for (0010,0010)")

        data = json.loads(response)
        assert "mutations" in data
        assert len(data["mutations"]) > 0
        assert data["mutations"][0]["mutation_id"] == "mock_001"

    def test_complete_rule_prompt(self):
        """Test mock response for rule prompts."""
        client = MockLLMClient()
        response = client.complete("Extract rules from DICOM spec")

        data = json.loads(response)
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_complete_other_prompt(self):
        """Test mock response for other prompts."""
        client = MockLLMClient()
        response = client.complete("Hello world")

        data = json.loads(response)
        assert "response" in data


class TestOpenAIClient:
    """Test OpenAIClient class."""

    def test_initialization_without_key(self):
        """Test initialization without API key."""
        config = LLMFuzzerConfig(backend=LLMBackend.OPENAI)
        client = OpenAIClient(config)

        assert client.api_key == ""

    @patch.dict("os.environ", {"OPENAI_API_KEY": "env_test_key"})
    def test_initialization_from_env(self):
        """Test initialization from environment variable."""
        config = LLMFuzzerConfig(backend=LLMBackend.OPENAI)
        client = OpenAIClient(config)

        assert client.api_key == "env_test_key"

    def test_is_available_no_key(self):
        """Test is_available returns False without key."""
        config = LLMFuzzerConfig(backend=LLMBackend.OPENAI, api_key="")
        client = OpenAIClient(config)

        assert client.is_available() is False


class TestAnthropicClient:
    """Test AnthropicClient class."""

    def test_initialization_without_key(self):
        """Test initialization without API key."""
        config = LLMFuzzerConfig(backend=LLMBackend.ANTHROPIC)
        client = AnthropicClient(config)

        assert client.api_key == ""

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "anthropic_key"})
    def test_initialization_from_env(self):
        """Test initialization from environment variable."""
        config = LLMFuzzerConfig(backend=LLMBackend.ANTHROPIC)
        client = AnthropicClient(config)

        assert client.api_key == "anthropic_key"

    def test_is_available_no_key(self):
        """Test is_available returns False without key."""
        config = LLMFuzzerConfig(backend=LLMBackend.ANTHROPIC, api_key="")
        client = AnthropicClient(config)

        assert client.is_available() is False

    def test_is_available_with_key(self):
        """Test is_available returns True with key."""
        config = LLMFuzzerConfig(backend=LLMBackend.ANTHROPIC, api_key="test_key")
        client = AnthropicClient(config)

        assert client.is_available() is True


class TestOllamaClient:
    """Test OllamaClient class."""

    def test_initialization_default_url(self):
        """Test default base URL."""
        config = LLMFuzzerConfig(backend=LLMBackend.OLLAMA)
        client = OllamaClient(config)

        assert client.base_url == "http://localhost:11434"

    def test_initialization_custom_url(self):
        """Test custom base URL."""
        config = LLMFuzzerConfig(
            backend=LLMBackend.OLLAMA,
            api_base="http://remote:11434",
        )
        client = OllamaClient(config)

        assert client.base_url == "http://remote:11434"

    def test_is_available_server_not_running(self):
        """Test is_available returns False when server not running."""
        config = LLMFuzzerConfig(
            backend=LLMBackend.OLLAMA,
            api_base="http://localhost:99999",  # Invalid port
        )
        client = OllamaClient(config)

        assert client.is_available() is False


# ============================================================================
# Test DICOMSpecParser
# ============================================================================


class TestDICOMSpecParser:
    """Test DICOMSpecParser class."""

    def test_vr_constraints_defined(self):
        """Test VR constraints are defined."""
        assert "PN" in DICOMSpecParser.VR_CONSTRAINTS
        assert "LO" in DICOMSpecParser.VR_CONSTRAINTS
        assert "UI" in DICOMSpecParser.VR_CONSTRAINTS

    def test_vr_constraint_structure(self):
        """Test VR constraint structure."""
        pn = DICOMSpecParser.VR_CONSTRAINTS["PN"]
        assert "max_length" in pn
        assert pn["max_length"] == 64
        assert pn["components"] == 5

    def test_initialization_without_client(self):
        """Test initialization without LLM client."""
        parser = DICOMSpecParser()
        assert parser.llm_client is None
        assert parser.rules == []

    def test_get_vr_rules(self):
        """Test VR rule generation."""
        parser = DICOMSpecParser()
        rules = parser.get_vr_rules()

        assert len(rules) > 0
        # Should have rule for each VR
        assert len(rules) == len(DICOMSpecParser.VR_CONSTRAINTS)

        # Check one rule
        pn_rule = next((r for r in rules if r.rule_id == "VR_PN_001"), None)
        assert pn_rule is not None
        assert pn_rule.element_type == "vr"
        assert pn_rule.mandatory is True

    def test_extract_rules_without_client(self):
        """Test rule extraction falls back to VR rules without client."""
        parser = DICOMSpecParser()
        rules = parser.extract_rules_from_text("Some DICOM spec text")

        assert len(rules) > 0
        # Should return VR rules as fallback
        assert all(r.source == "DICOM PS3.5" for r in rules)

    def test_extract_rules_with_mock_client(self):
        """Test rule extraction with mock client."""
        client = MockLLMClient()
        parser = DICOMSpecParser(llm_client=client)

        rules = parser.extract_rules_from_text("Extract rules from this text")

        assert len(rules) > 0

    def test_save_and_load_rules(self, tmp_path):
        """Test saving and loading rules."""
        parser = DICOMSpecParser()
        parser.rules = [
            DICOMProtocolRule(
                rule_id="test_001",
                description="Test rule",
                element_type="tag",
                constraint={"max_length": 64},
                mandatory=True,
            )
        ]

        rules_file = tmp_path / "rules.json"
        parser.save_rules(rules_file)

        assert rules_file.exists()

        # Load into new parser
        parser2 = DICOMSpecParser()
        loaded_rules = parser2.load_rules(rules_file)

        assert len(loaded_rules) == 1
        assert loaded_rules[0].rule_id == "test_001"

    def test_load_rules_nonexistent_file(self, tmp_path):
        """Test loading from nonexistent file."""
        parser = DICOMSpecParser()
        rules = parser.load_rules(tmp_path / "nonexistent.json")

        assert rules == []


# ============================================================================
# Test LLMMutationGenerator
# ============================================================================


class TestLLMMutationGenerator:
    """Test LLMMutationGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create generator with mock client."""
        client = MockLLMClient()
        return LLMMutationGenerator(llm_client=client)

    def test_initialization(self, generator):
        """Test initialization."""
        assert generator.llm_client is not None
        assert generator.rules == []
        assert generator.generated_mutations == []

    def test_generate_boundary_mutations_with_max_length(self, generator):
        """Test boundary mutation generation for VR with max_length."""
        mutations = generator.generate_boundary_mutations("(0010,0010)", "PN")

        assert len(mutations) == 3  # at_max, over_max, overflow

        # Check at_max mutation
        at_max = next(m for m in mutations if "at_max" in m.mutation_id)
        assert at_max.category == MutationCategory.BOUNDARY_VALUE
        assert len(at_max.mutated_value) == 64  # PN max_length

        # Check over_max mutation
        over_max = next(m for m in mutations if "over_max" in m.mutation_id)
        assert len(over_max.mutated_value) == 65

        # Check overflow mutation
        overflow = next(m for m in mutations if "overflow" in m.mutation_id)
        assert len(overflow.mutated_value) == 6400  # max_len * 100

    def test_generate_boundary_mutations_no_max_length(self, generator):
        """Test boundary mutation for VR without max_length."""
        mutations = generator.generate_boundary_mutations("(7FE0,0010)", "OB")

        # OB doesn't have max_length, so no boundary mutations
        assert len(mutations) == 0

    def test_generate_llm_guided_mutations(self, generator):
        """Test LLM-guided mutation generation."""
        mutations = generator.generate_llm_guided_mutations("(0010,0010)")

        assert len(mutations) > 0
        # Mock returns one mutation
        assert mutations[0].mutation_id == "mock_001"

    def test_prioritize_mutations(self, generator):
        """Test mutation prioritization."""
        mutations = [
            GeneratedMutation(
                mutation_id="low",
                category=MutationCategory.BOUNDARY_VALUE,
                target_element="test",
                original_value="a",
                mutated_value="b",
                rationale="test",
                expected_behavior="test",
                priority=20,
            ),
            GeneratedMutation(
                mutation_id="high",
                category=MutationCategory.BOUNDARY_VALUE,
                target_element="test",
                original_value="a",
                mutated_value="b",
                rationale="test",
                expected_behavior="test",
                priority=90,
            ),
            GeneratedMutation(
                mutation_id="medium",
                category=MutationCategory.BOUNDARY_VALUE,
                target_element="test",
                original_value="a",
                mutated_value="b",
                rationale="test",
                expected_behavior="test",
                priority=50,
            ),
        ]

        sorted_mutations = generator.prioritize_mutations(mutations)

        assert sorted_mutations[0].mutation_id == "high"
        assert sorted_mutations[1].mutation_id == "medium"
        assert sorted_mutations[2].mutation_id == "low"


# ============================================================================
# Test LLMFuzzer
# ============================================================================


class TestLLMFuzzer:
    """Test LLMFuzzer class."""

    def test_initialization_default_config(self):
        """Test initialization with default config."""
        fuzzer = LLMFuzzer()

        assert fuzzer.config.backend == LLMBackend.MOCK
        assert isinstance(fuzzer.llm_client, MockLLMClient)

    def test_initialization_openai_backend(self):
        """Test initialization with OpenAI backend."""
        config = LLMFuzzerConfig(backend=LLMBackend.OPENAI)
        fuzzer = LLMFuzzer(config)

        assert isinstance(fuzzer.llm_client, OpenAIClient)

    def test_initialization_anthropic_backend(self):
        """Test initialization with Anthropic backend."""
        config = LLMFuzzerConfig(backend=LLMBackend.ANTHROPIC)
        fuzzer = LLMFuzzer(config)

        assert isinstance(fuzzer.llm_client, AnthropicClient)

    def test_initialization_ollama_backend(self):
        """Test initialization with Ollama backend."""
        config = LLMFuzzerConfig(backend=LLMBackend.OLLAMA)
        fuzzer = LLMFuzzer(config)

        assert isinstance(fuzzer.llm_client, OllamaClient)

    def test_initialization_with_rules_file(self, tmp_path):
        """Test initialization with rules file."""
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(
            json.dumps(
                [
                    {
                        "rule_id": "test",
                        "description": "test",
                        "element_type": "tag",
                        "constraint": {},
                    }
                ]
            )
        )

        config = LLMFuzzerConfig(rules_file=rules_file)
        fuzzer = LLMFuzzer(config)

        assert len(fuzzer.spec_parser.rules) == 1

    def test_generate_fuzzing_corpus_default_elements(self):
        """Test corpus generation with default elements."""
        fuzzer = LLMFuzzer()
        mutations = fuzzer.generate_fuzzing_corpus(count=5)

        assert len(mutations) <= 5
        assert all(isinstance(m, GeneratedMutation) for m in mutations)

    def test_generate_fuzzing_corpus_custom_elements(self):
        """Test corpus generation with custom elements."""
        fuzzer = LLMFuzzer()
        mutations = fuzzer.generate_fuzzing_corpus(
            elements=["(0010,0010)"],
            count=10,
        )

        assert len(mutations) <= 10
        # Should have mutations for Patient Name
        assert any(m.target_element == "(0010,0010)" for m in mutations)

    def test_infer_vr(self):
        """Test VR inference from element."""
        fuzzer = LLMFuzzer()

        assert fuzzer._infer_vr("(0010,0010)") == "PN"
        assert fuzzer._infer_vr("(0010,0020)") == "LO"
        assert fuzzer._infer_vr("(0008,0018)") == "UI"
        assert fuzzer._infer_vr("(9999,9999)") == ""  # Unknown

    def test_analyze_crash_mock(self):
        """Test crash analysis with mock client."""
        fuzzer = LLMFuzzer()
        crash_data = {
            "signal": "SIGSEGV",
            "address": "0x00000000",
            "stack_trace": ["func1", "func2"],
        }

        result = fuzzer.analyze_crash(crash_data)

        # Mock returns JSON with response
        assert isinstance(result, dict)

    def test_save_corpus(self, tmp_path):
        """Test saving mutation corpus."""
        fuzzer = LLMFuzzer()
        mutations = [
            GeneratedMutation(
                mutation_id="test_001",
                category=MutationCategory.BOUNDARY_VALUE,
                target_element="(0010,0010)",
                original_value="test",
                mutated_value="A" * 100,
                rationale="test",
                expected_behavior="test",
            )
        ]

        corpus_file = tmp_path / "corpus.json"
        fuzzer.save_corpus(mutations, corpus_file)

        assert corpus_file.exists()
        data = json.loads(corpus_file.read_text())
        assert len(data) == 1
        assert data[0]["mutation_id"] == "test_001"


# ============================================================================
# Test Convenience Function
# ============================================================================


class TestCreateLLMFuzzer:
    """Test create_llm_fuzzer convenience function."""

    def test_create_mock_fuzzer(self):
        """Test creating mock fuzzer."""
        fuzzer = create_llm_fuzzer(backend="mock")
        assert fuzzer.config.backend == LLMBackend.MOCK

    def test_create_openai_fuzzer(self):
        """Test creating OpenAI fuzzer."""
        fuzzer = create_llm_fuzzer(backend="openai", model="gpt-4o")
        assert fuzzer.config.backend == LLMBackend.OPENAI
        assert fuzzer.config.model == "gpt-4o"

    def test_create_anthropic_fuzzer(self):
        """Test creating Anthropic fuzzer."""
        fuzzer = create_llm_fuzzer(backend="anthropic", api_key="test_key")
        assert fuzzer.config.backend == LLMBackend.ANTHROPIC
        assert fuzzer.config.api_key == "test_key"

    def test_create_ollama_fuzzer(self):
        """Test creating Ollama fuzzer."""
        fuzzer = create_llm_fuzzer(backend="ollama", model="llama3")
        assert fuzzer.config.backend == LLMBackend.OLLAMA
        assert fuzzer.config.model == "llama3"

    def test_create_invalid_backend_fallback(self):
        """Test invalid backend falls back to mock."""
        fuzzer = create_llm_fuzzer(backend="invalid_backend")
        assert fuzzer.config.backend == LLMBackend.MOCK


# ============================================================================
# Test RL Components
# ============================================================================


class TestMutationFeedback:
    """Test MutationFeedback dataclass."""

    def test_default_values(self):
        """Test default values."""
        feedback = MutationFeedback(
            mutation_id="test",
            category=MutationCategory.BOUNDARY_VALUE,
        )

        assert feedback.caused_new_coverage is False
        assert feedback.caused_crash is False
        assert feedback.crash_severity == ""

    def test_compute_reward_crash(self):
        """Test reward computation for crash."""
        feedback = MutationFeedback(
            mutation_id="test",
            category=MutationCategory.BOUNDARY_VALUE,
            caused_crash=True,
            crash_severity="critical",
        )

        reward = feedback.compute_reward()
        assert reward >= 15.0  # Critical crash reward

    def test_compute_reward_new_coverage(self):
        """Test reward computation for new coverage."""
        feedback = MutationFeedback(
            mutation_id="test",
            category=MutationCategory.BOUNDARY_VALUE,
            caused_new_coverage=True,
        )

        reward = feedback.compute_reward()
        assert reward >= 5.0  # New coverage reward

    def test_compute_reward_fast_execution(self):
        """Test reward computation for fast execution."""
        feedback = MutationFeedback(
            mutation_id="test",
            category=MutationCategory.BOUNDARY_VALUE,
            execution_time_us=500,  # < 1ms
        )

        reward = feedback.compute_reward()
        assert reward >= 1.0  # Fast execution bonus

    def test_compute_reward_low_memory(self):
        """Test reward computation for low memory usage."""
        feedback = MutationFeedback(
            mutation_id="test",
            category=MutationCategory.BOUNDARY_VALUE,
            memory_delta=1000,  # < 1MB
        )

        reward = feedback.compute_reward()
        assert reward >= 0.5  # Low memory bonus


class TestMutationStatistics:
    """Test MutationStatistics dataclass."""

    def test_default_values(self):
        """Test default values."""
        stats = MutationStatistics(category=MutationCategory.BOUNDARY_VALUE)

        assert stats.total_selections == 0
        assert stats.total_reward == 0.0
        assert stats.successes == 0
        assert stats.failures == 0

    def test_average_reward_zero_selections(self):
        """Test average reward with zero selections."""
        stats = MutationStatistics(category=MutationCategory.BOUNDARY_VALUE)
        assert stats.average_reward == 0.0

    def test_average_reward_with_selections(self):
        """Test average reward calculation."""
        stats = MutationStatistics(
            category=MutationCategory.BOUNDARY_VALUE,
            total_selections=10,
            total_reward=50.0,
        )

        assert stats.average_reward == 5.0

    def test_success_rate_zero_attempts(self):
        """Test success rate with zero attempts."""
        stats = MutationStatistics(category=MutationCategory.BOUNDARY_VALUE)
        assert stats.success_rate == 0.0

    def test_success_rate_with_attempts(self):
        """Test success rate calculation."""
        stats = MutationStatistics(
            category=MutationCategory.BOUNDARY_VALUE,
            successes=3,
            failures=7,
        )

        assert stats.success_rate == 0.3


class TestAdaptiveMutationSelector:
    """Test AdaptiveMutationSelector class."""

    def test_initialization_default(self):
        """Test default initialization."""
        selector = AdaptiveMutationSelector()

        assert selector.exploration_factor == 1.41
        assert selector.initial_boost == 10.0

    def test_initialization_custom(self):
        """Test custom initialization."""
        selector = AdaptiveMutationSelector(
            exploration_factor=2.0,
            initial_boost=5.0,
        )

        assert selector.exploration_factor == 2.0
        assert selector.initial_boost == 5.0

    def test_select_category_returns_valid_category(self):
        """Test category selection returns valid category."""
        selector = AdaptiveMutationSelector()
        category = selector.select_category()

        assert isinstance(category, MutationCategory)

    def test_update_updates_stats(self):
        """Test update() updates statistics."""
        selector = AdaptiveMutationSelector()
        category = MutationCategory.BOUNDARY_VALUE

        feedback = MutationFeedback(
            mutation_id="test",
            category=category,
            caused_new_coverage=True,
        )

        selector.update(feedback)

        stats = selector.stats.get(category)
        assert stats is not None
        assert stats.total_selections >= 1

    def test_get_statistics_report(self):
        """Test getting selector statistics report."""
        selector = AdaptiveMutationSelector()

        # Make some selections
        for _ in range(5):
            selector.select_category()

        stats = selector.get_statistics_report()

        assert "total_rounds" in stats
        assert stats["total_rounds"] == 5
        assert "categories" in stats
        assert "probabilities" in stats

    def test_select_untried_categories_first(self):
        """Test UCB1 selects untried categories first."""
        selector = AdaptiveMutationSelector()

        # First selections should go through untried categories
        # We need to update after each selection to mark it as tried
        selected = set()
        for _ in range(len(MutationCategory)):
            cat = selector.select_category()
            selected.add(cat)
            # Mark the category as tried by updating with feedback
            feedback = MutationFeedback(
                mutation_id=f"test_{cat.value}",
                category=cat,
            )
            selector.update(feedback)

        # Should have tried each category once
        assert len(selected) == len(MutationCategory)

    def test_get_category_probabilities(self):
        """Test category probability distribution."""
        selector = AdaptiveMutationSelector()

        probs = selector.get_category_probabilities()

        # Should have probability for each category
        assert len(probs) == len(MutationCategory)
        # Probabilities should sum to 1
        assert abs(sum(probs.values()) - 1.0) < 0.01

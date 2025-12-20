"""Comprehensive tests for semantic crash bucketing.

Tests the SemanticBucketer and related classes for
intelligent crash classification and deduplication.
"""

import pytest

from dicom_fuzzer.core.semantic_bucketer import (
    BucketerConfig,
    CrashContext,
    ImpactCategory,
    RootCauseCategory,
    SemanticBucket,
    SemanticBucketer,
    Severity,
)


class TestImpactCategory:
    """Tests for ImpactCategory enum."""

    def test_all_categories_exist(self):
        """Test all impact categories exist."""
        assert ImpactCategory.DATA_LOSS
        assert ImpactCategory.PRIVACY
        assert ImpactCategory.AVAILABILITY
        assert ImpactCategory.INTEGRITY
        assert ImpactCategory.AUTHENTICATION
        assert ImpactCategory.AUTHORIZATION
        assert ImpactCategory.UNKNOWN


class TestRootCauseCategory:
    """Tests for RootCauseCategory enum."""

    def test_memory_categories_exist(self):
        """Test memory-related root causes exist."""
        assert RootCauseCategory.BUFFER_OVERFLOW
        assert RootCauseCategory.INTEGER_OVERFLOW
        assert RootCauseCategory.NULL_DEREFERENCE
        assert RootCauseCategory.USE_AFTER_FREE
        assert RootCauseCategory.DOUBLE_FREE

    def test_security_categories_exist(self):
        """Test security-related root causes exist."""
        assert RootCauseCategory.FORMAT_STRING
        assert RootCauseCategory.COMMAND_INJECTION
        assert RootCauseCategory.PATH_TRAVERSAL

    def test_logic_categories_exist(self):
        """Test logic-related root causes exist."""
        assert RootCauseCategory.ASSERTION_FAILURE
        assert RootCauseCategory.LOGIC_ERROR
        assert RootCauseCategory.PARSING_ERROR
        assert RootCauseCategory.PROTOCOL_VIOLATION


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_levels(self):
        """Test severity levels exist and have correct values."""
        assert Severity.CRITICAL.value == 5
        assert Severity.HIGH.value == 4
        assert Severity.MEDIUM.value == 3
        assert Severity.LOW.value == 2
        assert Severity.INFO.value == 1

    def test_severity_ordering(self):
        """Test severity ordering."""
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.HIGH.value > Severity.MEDIUM.value
        assert Severity.MEDIUM.value > Severity.LOW.value


class TestCrashContext:
    """Tests for CrashContext class."""

    def test_basic_creation(self):
        """Test basic context creation."""
        context = CrashContext(
            crash_type="SIGSEGV",
            error_message="Segmentation fault at 0x0",
            mutation_strategy="havoc",
        )

        assert context.crash_type == "SIGSEGV"
        assert "Segmentation" in context.error_message
        assert context.mutation_strategy == "havoc"

    def test_with_stack_trace(self):
        """Test context with stack trace."""
        context = CrashContext(
            crash_type="ValueError",
            stack_trace="File test.py, line 42\n  in parse_dicom",
        )

        assert "parse_dicom" in context.stack_trace

    def test_with_input_characteristics(self):
        """Test context with input characteristics."""
        context = CrashContext(
            input_characteristics={
                "size": 1024,
                "has_pixel_data": True,
            }
        )

        assert context.input_characteristics["size"] == 1024

    def test_with_memory_state(self):
        """Test context with memory state."""
        context = CrashContext(
            memory_state={
                "heap_size": 1000000,
                "allocations": 500,
            }
        )

        assert context.memory_state["heap_size"] == 1000000


class TestSemanticBucket:
    """Tests for SemanticBucket class."""

    def test_basic_creation(self):
        """Test basic bucket creation."""
        bucket = SemanticBucket(
            bucket_id="test_bucket",
            impact_category=ImpactCategory.AVAILABILITY,
            root_cause=RootCauseCategory.NULL_DEREFERENCE,
            severity=Severity.MEDIUM,
        )

        assert bucket.bucket_id == "test_bucket"
        assert bucket.impact_category == ImpactCategory.AVAILABILITY
        assert bucket.root_cause == RootCauseCategory.NULL_DEREFERENCE
        assert bucket.severity == Severity.MEDIUM

    def test_add_crash(self):
        """Test adding crashes to bucket."""
        bucket = SemanticBucket(bucket_id="test")

        bucket.add_crash("crash_1", "havoc")
        bucket.add_crash("crash_2", "bitflip")
        bucket.add_crash("crash_3", "havoc")

        assert len(bucket.crash_ids) == 3
        assert bucket.mutation_strategies["havoc"] == 2
        assert bucket.mutation_strategies["bitflip"] == 1

    def test_confidence_tracking(self):
        """Test confidence score tracking."""
        bucket = SemanticBucket(
            bucket_id="test",
            confidence=0.85,
        )

        assert bucket.confidence == 0.85


class TestBucketerConfig:
    """Tests for BucketerConfig class."""

    def test_default_values(self):
        """Test default configuration."""
        config = BucketerConfig()

        assert config.enable_impact_analysis is True
        assert config.enable_root_cause_detection is True
        assert config.enable_severity_inference is True
        assert config.min_confidence_threshold == 0.3
        assert config.max_buckets == 1000

    def test_custom_values(self):
        """Test custom configuration."""
        config = BucketerConfig(
            enable_impact_analysis=False,
            max_buckets=500,
        )

        assert config.enable_impact_analysis is False
        assert config.max_buckets == 500


class TestSemanticBucketer:
    """Tests for SemanticBucketer class."""

    @pytest.fixture
    def bucketer(self):
        """Create a bucketer instance."""
        return SemanticBucketer()

    def test_initialization(self, bucketer):
        """Test bucketer initialization."""
        assert len(bucketer.buckets) == 0

    def test_classify_buffer_overflow(self, bucketer):
        """Test classification of buffer overflow."""
        context = CrashContext(
            crash_type="SIGSEGV",
            error_message="heap-buffer-overflow detected",
            stack_trace="#0 in vulnerable_func",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.BUFFER_OVERFLOW
        assert bucket.severity.value >= Severity.HIGH.value
        assert confidence > 0

    def test_classify_null_dereference(self, bucketer):
        """Test classification of null dereference."""
        context = CrashContext(
            crash_type="SIGSEGV",
            error_message="SEGV on unknown address 0x000000000000",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.NULL_DEREFERENCE

    def test_classify_use_after_free(self, bucketer):
        """Test classification of use-after-free."""
        context = CrashContext(
            error_message="heap-use-after-free on address 0x1234",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.USE_AFTER_FREE
        assert bucket.severity.value >= Severity.HIGH.value

    def test_classify_assertion_failure(self, bucketer):
        """Test classification of assertion failure."""
        context = CrashContext(
            crash_type="SIGABRT",
            error_message="AssertionError: condition failed",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.ASSERTION_FAILURE

    def test_classify_parsing_error(self, bucketer):
        """Test classification of parsing error."""
        context = CrashContext(
            error_message="parse error: unexpected token at position 42",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.PARSING_ERROR

    def test_classify_resource_exhaustion(self, bucketer):
        """Test classification of resource exhaustion."""
        context = CrashContext(
            crash_type="MemoryError",
            error_message="out of memory allocating buffer",
        )

        bucket, confidence = bucketer.classify_crash("crash_1", context)

        assert bucket.root_cause == RootCauseCategory.RESOURCE_EXHAUSTION

    def test_impact_availability(self, bucketer):
        """Test availability impact detection."""
        context = CrashContext(
            crash_type="SIGSEGV",
            error_message="crash in server handler",
        )

        bucket, _ = bucketer.classify_crash("crash_1", context)

        assert bucket.impact_category == ImpactCategory.AVAILABILITY

    def test_impact_privacy(self, bucketer):
        """Test privacy impact detection."""
        context = CrashContext(
            error_message="uninitialized memory leak detected",
        )

        bucket, _ = bucketer.classify_crash("crash_1", context)

        assert bucket.impact_category == ImpactCategory.PRIVACY

    def test_similar_crashes_same_bucket(self, bucketer):
        """Test similar crashes go to same bucket."""
        context1 = CrashContext(
            crash_type="SIGSEGV",
            error_message="null pointer dereference",
        )
        context2 = CrashContext(
            crash_type="SIGSEGV",
            error_message="null pointer dereference in different func",
        )

        bucket1, _ = bucketer.classify_crash("crash_1", context1)
        bucket2, _ = bucketer.classify_crash("crash_2", context2)

        assert bucket1.bucket_id == bucket2.bucket_id

    def test_different_crashes_different_buckets(self, bucketer):
        """Test different crashes go to different buckets."""
        context1 = CrashContext(
            error_message="heap-buffer-overflow",
        )
        context2 = CrashContext(
            error_message="integer overflow detected",
        )

        bucket1, _ = bucketer.classify_crash("crash_1", context1)
        bucket2, _ = bucketer.classify_crash("crash_2", context2)

        assert bucket1.bucket_id != bucket2.bucket_id

    def test_get_bucket_for_crash(self, bucketer):
        """Test retrieving bucket for crash."""
        context = CrashContext(crash_type="SIGSEGV")
        bucketer.classify_crash("crash_1", context)

        bucket = bucketer.get_bucket_for_crash("crash_1")

        assert bucket is not None
        assert "crash_1" in bucket.crash_ids

    def test_get_bucket_for_unknown_crash(self, bucketer):
        """Test retrieving bucket for unknown crash."""
        bucket = bucketer.get_bucket_for_crash("nonexistent")
        assert bucket is None

    def test_get_buckets_by_severity(self, bucketer):
        """Test filtering buckets by severity."""
        context1 = CrashContext(error_message="heap-buffer-overflow critical")
        context2 = CrashContext(error_message="timeout warning")

        bucketer.classify_crash("crash_1", context1)
        bucketer.classify_crash("crash_2", context2)

        high_buckets = bucketer.get_buckets_by_severity(Severity.HIGH)

        # At least the buffer overflow should be high severity
        assert len(high_buckets) >= 1
        assert all(b.severity.value >= Severity.HIGH.value for b in high_buckets)

    def test_get_buckets_by_impact(self, bucketer):
        """Test filtering buckets by impact category."""
        context = CrashContext(crash_type="SIGSEGV")
        bucketer.classify_crash("crash_1", context)

        availability_buckets = bucketer.get_buckets_by_impact(
            ImpactCategory.AVAILABILITY
        )

        assert len(availability_buckets) > 0

    def test_strategy_effectiveness(self, bucketer):
        """Test mutation strategy effectiveness analysis."""
        context1 = CrashContext(
            error_message="buffer overflow",
            mutation_strategy="havoc",
        )
        context2 = CrashContext(
            error_message="buffer overflow",
            mutation_strategy="bitflip",
        )
        context3 = CrashContext(
            error_message="null pointer",
            mutation_strategy="havoc",
        )

        bucketer.classify_crash("crash_1", context1)
        bucketer.classify_crash("crash_2", context2)
        bucketer.classify_crash("crash_3", context3)

        effectiveness = bucketer.get_strategy_effectiveness()

        assert "havoc" in effectiveness
        assert len(effectiveness["havoc"]) > 0

    def test_deduplication_confidence_same_bucket(self, bucketer):
        """Test deduplication confidence for same bucket."""
        context = CrashContext(error_message="null pointer")
        bucketer.classify_crash("crash_1", context)
        bucketer.classify_crash("crash_2", context)

        confidence = bucketer.calculate_deduplication_confidence("crash_1", "crash_2")

        assert confidence > 0.5  # Same bucket = high confidence

    def test_deduplication_confidence_different_buckets(self, bucketer):
        """Test deduplication confidence for different buckets."""
        context1 = CrashContext(error_message="buffer overflow")
        context2 = CrashContext(error_message="integer overflow")

        bucketer.classify_crash("crash_1", context1)
        bucketer.classify_crash("crash_2", context2)

        confidence = bucketer.calculate_deduplication_confidence("crash_1", "crash_2")

        assert confidence < 0.5  # Different buckets = lower confidence

    def test_export_report(self, bucketer):
        """Test report export."""
        context1 = CrashContext(error_message="buffer overflow")
        context2 = CrashContext(error_message="null pointer")

        bucketer.classify_crash("crash_1", context1)
        bucketer.classify_crash("crash_2", context2)

        report = bucketer.export_report()

        assert "total_buckets" in report
        assert "total_crashes" in report
        assert "severity_distribution" in report
        assert "impact_distribution" in report
        assert "root_cause_distribution" in report
        assert "high_severity_buckets" in report

    def test_get_stats(self, bucketer):
        """Test statistics retrieval."""
        context = CrashContext(error_message="test crash")
        bucketer.classify_crash("crash_1", context)

        stats = bucketer.get_stats()

        assert "total_buckets" in stats
        assert "total_crashes" in stats
        assert "avg_bucket_size" in stats
        assert "avg_confidence" in stats

    def test_empty_stats(self, bucketer):
        """Test statistics for empty bucketer."""
        stats = bucketer.get_stats()

        assert stats["total_buckets"] == 0
        assert stats["total_crashes"] == 0

    def test_max_buckets_limit(self):
        """Test max buckets limit."""
        config = BucketerConfig(max_buckets=3)
        bucketer = SemanticBucketer(config)

        # Add crashes that would create many buckets
        for i in range(10):
            context = CrashContext(error_message=f"unique_error_{i}")
            bucketer.classify_crash(f"crash_{i}", context)

        # Should have at most 3 buckets + 1 overflow
        assert len(bucketer.buckets) <= 4

    def test_characteristics_tracking(self, bucketer):
        """Test bucket characteristics are tracked."""
        context = CrashContext(
            crash_type="SIGSEGV",
            execution_phase="parsing",
            input_characteristics={"size": 1000},
        )

        bucket, _ = bucketer.classify_crash("crash_1", context)

        # Characteristics should be tracked
        assert (
            "execution_phases" in bucket.characteristics
            or "crash_types" in bucket.characteristics
        )

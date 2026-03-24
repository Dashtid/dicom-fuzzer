"""Tests for ReportAnalytics formatters."""

from dicom_fuzzer.core.reporting.report_analytics import ReportAnalytics


class TestFormatStrategyHitRate:
    def test_with_strategies(self):
        analytics = ReportAnalytics()
        html = analytics.format_strategy_hit_rate({"metadata": 50, "pixel": 30})
        assert "<table>" in html
        assert "metadata" in html
        assert "pixel" in html
        assert "%" in html

    def test_empty_dict_returns_empty(self):
        analytics = ReportAnalytics()
        assert analytics.format_strategy_hit_rate({}) == ""

    def test_single_strategy_is_100_percent(self):
        analytics = ReportAnalytics()
        html = analytics.format_strategy_hit_rate({"metadata": 10})
        assert "100.0%" in html


class TestFormatCrashByStrategy:
    def _make_crash(self, *strategies: str) -> dict:
        return {"mutation_sequence": [(s, "some_mutation") for s in strategies]}

    def test_empty_list_returns_empty(self):
        analytics = ReportAnalytics()
        assert analytics.format_crash_by_strategy([]) == ""

    def test_no_mutation_sequence_returns_empty(self):
        analytics = ReportAnalytics()
        assert analytics.format_crash_by_strategy([{"mutation_sequence": []}]) == ""

    def test_single_strategy_is_100_percent(self):
        analytics = ReportAnalytics()
        crashes = [self._make_crash("pixel"), self._make_crash("pixel")]
        html = analytics.format_crash_by_strategy(crashes)
        assert "pixel" in html
        assert "100.0%" in html

    def test_multiple_strategies_counted_correctly(self):
        analytics = ReportAnalytics()
        crashes = [
            self._make_crash("pixel"),
            self._make_crash("pixel"),
            self._make_crash("metadata"),
        ]
        html = analytics.format_crash_by_strategy(crashes)
        # pixel: 2 crashes out of 3 = 66.7%
        assert "pixel" in html
        assert "metadata" in html
        assert "66.7%" in html
        assert "33.3%" in html

    def test_multi_strategy_file_credits_both(self):
        # A file mutated by both pixel and metadata: both get credited
        analytics = ReportAnalytics()
        crashes = [self._make_crash("pixel", "metadata")]
        html = analytics.format_crash_by_strategy(crashes)
        assert "pixel" in html
        assert "metadata" in html

    def test_output_contains_table(self):
        analytics = ReportAnalytics()
        crashes = [self._make_crash("structure")]
        html = analytics.format_crash_by_strategy(crashes)
        assert "<table>" in html
        assert "Crashes by Strategy" in html

    def test_list_entries_accepted_as_well_as_tuples(self):
        # mutation_sequence may deserialise as lists from JSON
        analytics = ReportAnalytics()
        crashes = [{"mutation_sequence": [["pixel", "dim_mismatch"]]}]
        html = analytics.format_crash_by_strategy(crashes)
        assert "pixel" in html

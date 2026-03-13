"""Tests for ReportAnalytics.format_strategy_hit_rate."""

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

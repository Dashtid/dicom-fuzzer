"""Comprehensive tests for series_reporter.py

Tests 3D series reporting functionality including mutation summaries,
HTML/JSON report generation, and strategy effectiveness analysis.
Targets 80%+ coverage.
"""

import json
from datetime import datetime

from dicom_fuzzer.core.series_reporter import (
    Series3DReport,
    Series3DReportGenerator,
    SeriesMutationSummary,
)
from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord


class TestSeriesMutationSummary:
    """Test SeriesMutationSummary dataclass and methods."""

    def test_initialization_default_values(self):
        """Test SeriesMutationSummary initialization with default values."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        assert summary.series_uid == "1.2.3.4.5"
        assert summary.modality == "CT"
        assert summary.slice_count == 10
        assert summary.total_mutations == 0
        assert summary.strategies_used == {}
        assert summary.affected_slices == []
        assert summary.severity_distribution == {}
        assert isinstance(summary.timestamp, datetime)

    def test_add_mutation_increments_count(self):
        """Test add_mutation increments total_mutations."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        record = SeriesMutationRecord(
            strategy="spatial_gradient",
            slice_index=5,
            severity="moderate",
        )

        summary.add_mutation(record)

        assert summary.total_mutations == 1

    def test_add_mutation_tracks_strategy_usage(self):
        """Test add_mutation tracks strategy usage counts."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Add mutations with different strategies
        summary.add_mutation(
            SeriesMutationRecord(
                strategy="spatial_gradient",
                slice_index=5,
                severity="moderate",
            )
        )
        summary.add_mutation(
            SeriesMutationRecord(
                strategy="spatial_gradient",
                slice_index=6,
                severity="moderate",
            )
        )
        summary.add_mutation(
            SeriesMutationRecord(
                strategy="boundary_targeting",
                slice_index=0,
                severity="aggressive",
            )
        )

        assert summary.strategies_used["spatial_gradient"] == 2
        assert summary.strategies_used["boundary_targeting"] == 1

    def test_add_mutation_tracks_affected_slices(self):
        """Test add_mutation tracks affected slice indices."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Add mutations to different slices
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=0, severity="moderate")
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=5, severity="moderate")
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=9, severity="moderate")
        )

        assert 0 in summary.affected_slices
        assert 5 in summary.affected_slices
        assert 9 in summary.affected_slices
        assert len(summary.affected_slices) == 3

    def test_add_mutation_does_not_duplicate_slices(self):
        """Test add_mutation does not duplicate affected slice indices."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Add multiple mutations to same slice
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=5, severity="moderate")
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=5, severity="moderate")
        )

        assert summary.affected_slices.count(5) == 1
        assert len(summary.affected_slices) == 1

    def test_add_mutation_tracks_severity_distribution(self):
        """Test add_mutation tracks severity distribution."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Add mutations with different severities
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=0, severity="minimal")
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=1, severity="moderate")
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=2, severity="moderate")
        )
        summary.add_mutation(
            SeriesMutationRecord(
                strategy="test",
                slice_index=3,
                severity="aggressive",
            )
        )

        assert summary.severity_distribution["minimal"] == 1
        assert summary.severity_distribution["moderate"] == 2
        assert summary.severity_distribution["aggressive"] == 1

    def test_add_mutation_handles_none_slice_index(self):
        """Test add_mutation handles None slice_index gracefully."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Mutation without slice index (series-wide mutation)
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=None, severity="moderate")
        )

        assert summary.total_mutations == 1
        assert len(summary.affected_slices) == 0

    def test_get_coverage_percentage_with_mutations(self):
        """Test get_coverage_percentage calculates correctly."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Affect 3 out of 10 slices
        for slice_idx in [0, 5, 9]:
            summary.add_mutation(
                SeriesMutationRecord(
                    strategy="test",
                    slice_index=slice_idx,
                    severity="moderate",
                )
            )

        coverage = summary.get_coverage_percentage()
        assert coverage == 30.0  # 3/10 * 100

    def test_get_coverage_percentage_zero_slices(self):
        """Test get_coverage_percentage with zero slices."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=0,
            total_mutations=0,
        )

        coverage = summary.get_coverage_percentage()
        assert coverage == 0.0

    def test_get_coverage_percentage_no_mutations(self):
        """Test get_coverage_percentage with no mutations."""
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        coverage = summary.get_coverage_percentage()
        assert coverage == 0.0


class TestSeries3DReport:
    """Test Series3DReport dataclass and methods."""

    def test_initialization_default_values(self):
        """Test Series3DReport initialization with default values."""
        report = Series3DReport(campaign_name="Test Campaign")

        assert report.campaign_name == "Test Campaign"
        assert report.series_summaries == []
        assert report.total_series_fuzzed == 0
        assert report.total_mutations_applied == 0
        assert report.total_crashes == 0
        assert report.crash_details == []
        assert isinstance(report.generated_at, datetime)

    def test_add_series_summary(self):
        """Test add_series_summary updates counts."""
        report = Series3DReport(campaign_name="Test Campaign")

        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=15,
        )

        report.add_series_summary(summary)

        assert len(report.series_summaries) == 1
        assert report.total_series_fuzzed == 1
        assert report.total_mutations_applied == 15

    def test_add_multiple_series_summaries(self):
        """Test adding multiple series summaries."""
        report = Series3DReport(campaign_name="Test Campaign")

        for i in range(3):
            summary = SeriesMutationSummary(
                series_uid=f"1.2.3.4.{i}",
                modality="CT",
                slice_count=10,
                total_mutations=10 + i,
            )
            report.add_series_summary(summary)

        assert len(report.series_summaries) == 3
        assert report.total_series_fuzzed == 3
        assert report.total_mutations_applied == 33  # 10 + 11 + 12

    def test_get_strategy_effectiveness_empty_report(self):
        """Test get_strategy_effectiveness with no series."""
        report = Series3DReport(campaign_name="Test Campaign")

        effectiveness = report.get_strategy_effectiveness()

        assert effectiveness == {}

    def test_get_strategy_effectiveness_single_strategy(self):
        """Test get_strategy_effectiveness with single strategy."""
        report = Series3DReport(campaign_name="Test Campaign")

        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Add mutations with single strategy
        for _ in range(5):
            summary.add_mutation(
                SeriesMutationRecord(
                    strategy="spatial_gradient",
                    slice_index=0,
                    severity="moderate",
                )
            )

        report.add_series_summary(summary)
        effectiveness = report.get_strategy_effectiveness()

        assert "spatial_gradient" in effectiveness
        assert effectiveness["spatial_gradient"]["usage_count"] == 5
        assert effectiveness["spatial_gradient"]["avg_mutations_per_series"] == 5.0
        assert effectiveness["spatial_gradient"]["series_coverage"] == 100.0

    def test_get_strategy_effectiveness_multiple_strategies(self):
        """Test get_strategy_effectiveness with multiple strategies."""
        report = Series3DReport(campaign_name="Test Campaign")

        # Create two series with different strategies
        summary1 = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )
        summary1.add_mutation(
            SeriesMutationRecord(
                strategy="spatial_gradient",
                slice_index=0,
                severity="moderate",
            )
        )
        summary1.add_mutation(
            SeriesMutationRecord(
                strategy="spatial_gradient",
                slice_index=1,
                severity="moderate",
            )
        )

        summary2 = SeriesMutationSummary(
            series_uid="1.2.3.4.6",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )
        summary2.add_mutation(
            SeriesMutationRecord(
                strategy="boundary_targeting",
                slice_index=0,
                severity="aggressive",
            )
        )

        report.add_series_summary(summary1)
        report.add_series_summary(summary2)

        effectiveness = report.get_strategy_effectiveness()

        assert "spatial_gradient" in effectiveness
        assert "boundary_targeting" in effectiveness
        assert effectiveness["spatial_gradient"]["usage_count"] == 2
        assert effectiveness["boundary_targeting"]["usage_count"] == 1
        assert effectiveness["spatial_gradient"]["series_coverage"] == 50.0  # 1/2
        assert effectiveness["boundary_targeting"]["series_coverage"] == 50.0  # 1/2


class TestSeries3DReportGenerator:
    """Test Series3DReportGenerator class."""

    def test_initialization_creates_output_dir(self, tmp_path):
        """Test initialization creates output directory."""
        output_dir = tmp_path / "reports"
        generator = Series3DReportGenerator(str(output_dir))

        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_generate_html_report_creates_file(self, tmp_path):
        """Test generate_html_report creates HTML file."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")
        report_path = generator.generate_html_report(report)

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "series3d_report_" in report_path.name

    def test_generate_html_report_contains_campaign_name(self, tmp_path):
        """Test HTML report contains campaign name."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="My Test Campaign")
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "My Test Campaign" in html

    def test_generate_html_report_contains_summary_stats(self, tmp_path):
        """Test HTML report contains summary statistics."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")

        # Add series data
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )
        for _ in range(5):
            summary.add_mutation(
                SeriesMutationRecord(
                    strategy="test",
                    slice_index=0,
                    severity="moderate",
                )
            )

        report.add_series_summary(summary)
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "Series Fuzzed" in html
        assert "Total Mutations" in html
        assert "Crashes Found" in html

    def test_generate_html_report_with_strategy_effectiveness(self, tmp_path):
        """Test HTML report includes strategy effectiveness table."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")

        # Add series with strategies
        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )
        summary.add_mutation(
            SeriesMutationRecord(
                strategy="spatial_gradient",
                slice_index=0,
                severity="moderate",
            )
        )

        report.add_series_summary(summary)
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "Strategy Effectiveness" in html
        assert "spatial_gradient" in html

    def test_generate_html_report_empty_report(self, tmp_path):
        """Test HTML report generation with empty report."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Empty Campaign")
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "Empty Campaign" in html
        assert "No strategy data available" in html
        assert "No series data available" in html

    def test_generate_json_report_creates_file(self, tmp_path):
        """Test generate_json_report creates JSON file."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")
        report_path = generator.generate_json_report(report)

        assert report_path.exists()
        assert report_path.suffix == ".json"
        assert "series3d_report_" in report_path.name

    def test_generate_json_report_valid_json(self, tmp_path):
        """Test JSON report contains valid JSON."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")
        report_path = generator.generate_json_report(report)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "campaign_name" in data
        assert data["campaign_name"] == "Test Campaign"
        assert "summary" in data
        assert "strategy_effectiveness" in data
        assert "series_details" in data

    def test_generate_json_report_includes_series_details(self, tmp_path):
        """Test JSON report includes series details."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")

        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )
        summary.add_mutation(
            SeriesMutationRecord(strategy="test", slice_index=5, severity="moderate")
        )

        report.add_series_summary(summary)
        report_path = generator.generate_json_report(report)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["series_details"]) == 1
        series_detail = data["series_details"][0]
        assert series_detail["series_uid"] == "1.2.3.4.5"
        assert series_detail["modality"] == "CT"
        assert series_detail["slice_count"] == 10
        assert series_detail["total_mutations"] == 1

    def test_generate_json_report_includes_coverage_percentage(self, tmp_path):
        """Test JSON report includes coverage percentage."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")

        summary = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=0,
        )

        # Affect 5 out of 10 slices (50% coverage)
        for slice_idx in range(5):
            summary.add_mutation(
                SeriesMutationRecord(
                    strategy="test",
                    slice_index=slice_idx,
                    severity="moderate",
                )
            )

        report.add_series_summary(summary)
        report_path = generator.generate_json_report(report)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["series_details"][0]["coverage_percentage"] == 50.0

    def test_html_report_contains_valid_html_structure(self, tmp_path):
        """Test HTML report has valid HTML structure."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        # Check for basic HTML structure
        assert "<!DOCTYPE html>" in html
        assert '<html lang="en">' in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html
        assert "</html>" in html

    def test_html_report_includes_css_styling(self, tmp_path):
        """Test HTML report includes CSS styling."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")
        report_path = generator.generate_html_report(report)

        with open(report_path, encoding="utf-8") as f:
            html = f.read()

        assert "<style>" in html
        assert "</style>" in html
        assert "container" in html
        assert "summary-grid" in html

    def test_json_report_avg_mutations_per_series(self, tmp_path):
        """Test JSON report calculates avg_mutations_per_series."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Test Campaign")

        # Add two series with different mutation counts
        summary1 = SeriesMutationSummary(
            series_uid="1.2.3.4.5",
            modality="CT",
            slice_count=10,
            total_mutations=10,
        )
        summary2 = SeriesMutationSummary(
            series_uid="1.2.3.4.6",
            modality="CT",
            slice_count=10,
            total_mutations=20,
        )

        report.add_series_summary(summary1)
        report.add_series_summary(summary2)

        report_path = generator.generate_json_report(report)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        # Average should be (10 + 20) / 2 = 15
        assert data["summary"]["avg_mutations_per_series"] == 15.0

    def test_json_report_handles_zero_series(self, tmp_path):
        """Test JSON report handles zero series gracefully."""
        generator = Series3DReportGenerator(str(tmp_path))

        report = Series3DReport(campaign_name="Empty Campaign")
        report_path = generator.generate_json_report(report)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        # Should handle division by zero
        assert data["summary"]["total_series_fuzzed"] == 0
        # avg_mutations_per_series should be 0 / max(0, 1) = 0
        assert data["summary"]["avg_mutations_per_series"] == 0.0


class TestIntegrationScenarios:
    """Test complete workflow scenarios."""

    def test_complete_reporting_workflow(self, tmp_path):
        """Test complete workflow from mutation to HTML/JSON reports."""
        generator = Series3DReportGenerator(str(tmp_path))

        # Create report
        report = Series3DReport(campaign_name="Integration Test Campaign")

        # Add multiple series with various mutations
        for series_idx in range(3):
            summary = SeriesMutationSummary(
                series_uid=f"1.2.3.4.{series_idx}",
                modality="CT",
                slice_count=10,
                total_mutations=0,
            )

            # Add mutations with different strategies
            strategies = ["spatial_gradient", "boundary_targeting", "orientation_flip"]
            for mutation_idx in range(5):
                summary.add_mutation(
                    SeriesMutationRecord(
                        strategy=strategies[mutation_idx % len(strategies)],
                        slice_index=mutation_idx,
                        severity="moderate",
                    )
                )

            report.add_series_summary(summary)

        # Generate both reports
        html_path = generator.generate_html_report(report)
        json_path = generator.generate_json_report(report)

        # Verify both files exist
        assert html_path.exists()
        assert json_path.exists()

        # Verify HTML content
        with open(html_path, encoding="utf-8") as f:
            html = f.read()
        assert "Integration Test Campaign" in html
        assert "spatial_gradient" in html

        # Verify JSON content
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["summary"]["total_series_fuzzed"] == 3
        assert (
            data["summary"]["total_mutations_applied"] == 15
        )  # 3 series * 5 mutations
        assert len(data["series_details"]) == 3

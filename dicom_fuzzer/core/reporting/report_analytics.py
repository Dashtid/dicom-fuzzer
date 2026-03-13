"""Report Analytics.

Generates mutation analysis sections for fuzzing reports.
"""

from typing import Any

from dicom_fuzzer.core.reporting.html_templates import escape_html


class ReportAnalytics:
    """Generates analytics sections for fuzzing reports."""

    def __init__(self, enable_triage: bool = True):
        """Initialize the report analytics.

        Args:
            enable_triage: Whether triage information is available.

        """
        self.enable_triage = enable_triage

    def format_mutation_analysis(
        self, fuzzed_files: dict[str, Any], crashes: list[dict[str, Any]] | None = None
    ) -> str:
        """Generate mutation strategy analysis.

        Args:
            fuzzed_files: Dictionary of fuzzed file records.
            crashes: Optional list of crash dictionaries.

        Returns:
            HTML string for mutation analysis.

        """
        if not fuzzed_files:
            return ""

        # Analyze mutation strategies used
        strategy_counts: dict[str, int] = {}
        mutation_type_counts: dict[str, int] = {}

        for file_record in fuzzed_files.values():
            for mutation in file_record.get("mutations", []):
                strategy = mutation.get("strategy_name", "Unknown")
                mut_type = mutation.get("mutation_type", "unknown")

                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
                mutation_type_counts[mut_type] = (
                    mutation_type_counts.get(mut_type, 0) + 1
                )

        html = """
            <h2>Mutation Analysis</h2>
            <h3>Strategy Usage</h3>
            <table>
                <tr>
                    <th>Strategy</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""

        total_mutations = sum(strategy_counts.values())

        for strategy, count in sorted(
            strategy_counts.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_mutations * 100) if total_mutations > 0 else 0
            html += f"""
                <tr>
                    <td>{strategy}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""

        html += """
            </table>

            <h3>Mutation Types</h3>
            <table>
                <tr>
                    <th>Mutation Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""

        for mut_type, count in sorted(
            mutation_type_counts.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / total_mutations * 100) if total_mutations > 0 else 0
            html += f"""
                <tr>
                    <td>{mut_type}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""

        html += """
            </table>
"""

        return html

    def format_strategy_hit_rate(self, strategies_used: dict[str, int]) -> str:
        """Return an HTML table section showing strategy hit counts and share."""
        if not strategies_used:
            return ""
        total = sum(strategies_used.values())
        rows = ""
        for name, count in sorted(strategies_used.items(), key=lambda x: -x[1]):
            pct = (count / total * 100) if total > 0 else 0
            rows += f"<tr><td>{escape_html(name)}</td><td>{count}</td><td>{pct:.1f}%</td></tr>"
        return (
            "<h2>Strategy Hit Rate</h2>"
            "<table><thead><tr><th>Strategy</th><th>Uses</th><th>Share</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )


__all__ = ["ReportAnalytics"]

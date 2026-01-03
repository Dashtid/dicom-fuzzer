"""Tests for HTML templates module."""

from __future__ import annotations

from dicom_fuzzer.core.html_templates import (
    REPORT_CSS,
    SEVERITY_COLORS,
    escape_html,
    html_document_end,
    html_document_start,
    html_report_header,
    render_alert,
    render_badge,
    render_code_block,
    render_details,
    render_info_row,
    render_progress_bar,
    render_stat_card,
    render_table_header,
    render_table_row,
)


class TestEscapeHtml:
    """Tests for HTML escaping."""

    def test_escapes_ampersand(self) -> None:
        """Test ampersand is escaped."""
        assert escape_html("foo & bar") == "foo &amp; bar"

    def test_escapes_less_than(self) -> None:
        """Test less-than is escaped."""
        assert escape_html("1 < 2") == "1 &lt; 2"

    def test_escapes_greater_than(self) -> None:
        """Test greater-than is escaped."""
        assert escape_html("2 > 1") == "2 &gt; 1"

    def test_escapes_quotes(self) -> None:
        """Test quotes are escaped."""
        assert escape_html('say "hello"') == "say &quot;hello&quot;"
        assert escape_html("it's") == "it&#39;s"

    def test_escapes_multiple(self) -> None:
        """Test multiple special chars are escaped."""
        result = escape_html("<script>alert('xss')</script>")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&#39;" in result

    def test_empty_string(self) -> None:
        """Test empty string returns empty."""
        assert escape_html("") == ""


class TestRenderBadge:
    """Tests for badge rendering."""

    def test_renders_badge(self) -> None:
        """Test basic badge rendering."""
        html = render_badge("critical", "critical")
        assert 'class="badge critical"' in html
        assert "critical" in html

    def test_escapes_text(self) -> None:
        """Test badge text is escaped."""
        html = render_badge("<script>", "high")
        assert "&lt;script&gt;" in html


class TestRenderStatCard:
    """Tests for stat card rendering."""

    def test_renders_stat_card(self) -> None:
        """Test basic stat card rendering."""
        html = render_stat_card(42, "Files Tested")
        assert 'class="stat-card"' in html
        assert "42" in html
        assert "Files Tested" in html

    def test_custom_background(self) -> None:
        """Test stat card with custom background."""
        html = render_stat_card(100, "Count", background="#ff0000")
        assert 'style="background: #ff0000;"' in html


class TestRenderAlert:
    """Tests for alert rendering."""

    def test_renders_alert(self) -> None:
        """Test basic alert rendering."""
        html = render_alert("Something went wrong", "Error", "alert")
        assert 'class="alert"' in html
        assert "Something went wrong" in html
        assert "<strong>Error</strong>" in html

    def test_warning_type(self) -> None:
        """Test warning alert type."""
        html = render_alert("Warning message", alert_type="warning")
        assert 'class="warning"' in html

    def test_success_type(self) -> None:
        """Test success alert type."""
        html = render_alert("Success!", alert_type="success")
        assert 'class="success"' in html


class TestRenderInfoRow:
    """Tests for info row rendering."""

    def test_renders_info_row(self) -> None:
        """Test basic info row rendering."""
        html = render_info_row("Status", "Active")
        assert 'class="info-label"' in html
        assert 'class="info-value"' in html
        assert "Status:" in html
        assert "Active" in html

    def test_file_path_styling(self) -> None:
        """Test file path styling."""
        html = render_info_row("Path", "/tmp/test.dcm", is_file_path=True)
        assert 'class="file-path"' in html


class TestRenderCodeBlock:
    """Tests for code block rendering."""

    def test_renders_code_block(self) -> None:
        """Test basic code block rendering."""
        html = render_code_block("print('hello')")
        assert 'class="code-block"' in html
        assert "print" in html

    def test_escapes_html(self) -> None:
        """Test code block escapes HTML."""
        html = render_code_block("<script>alert(1)</script>")
        assert "&lt;script&gt;" in html


class TestRenderDetails:
    """Tests for details element rendering."""

    def test_renders_details(self) -> None:
        """Test basic details rendering."""
        html = render_details("Click to expand", "<p>Content</p>")
        assert "<details>" in html
        assert "<summary>" in html
        assert "Click to expand" in html
        assert "<p>Content</p>" in html

    def test_open_by_default(self) -> None:
        """Test details open by default."""
        html = render_details("Summary", "Content", open_by_default=True)
        assert "<details open>" in html


class TestRenderTable:
    """Tests for table rendering."""

    def test_renders_table_header(self) -> None:
        """Test table header rendering."""
        html = render_table_header(["Name", "Value", "Status"])
        assert "<tr>" in html
        assert "<th>Name</th>" in html
        assert "<th>Value</th>" in html
        assert "<th>Status</th>" in html

    def test_renders_table_row(self) -> None:
        """Test table row rendering."""
        html = render_table_row(["foo", 123, "ok"])
        assert "<tr>" in html
        assert "<td>foo</td>" in html
        assert "<td>123</td>" in html
        assert "<td>ok</td>" in html

    def test_no_escape_option(self) -> None:
        """Test table row without escaping."""
        html = render_table_row(['<span class="badge">OK</span>'], escape=False)
        assert '<span class="badge">OK</span>' in html


class TestRenderProgressBar:
    """Tests for progress bar rendering."""

    def test_renders_progress_bar(self) -> None:
        """Test basic progress bar rendering."""
        html = render_progress_bar(50, 100, "Progress")
        assert "Progress" in html
        assert "50.0%" in html

    def test_custom_color(self) -> None:
        """Test progress bar with custom color."""
        html = render_progress_bar(25, 100, "Done", color="#ff0000")
        assert "#ff0000" in html

    def test_show_count(self) -> None:
        """Test progress bar with count display."""
        html = render_progress_bar(25, 100, "Items", show_count=25)
        assert "25" in html


class TestDocumentStructure:
    """Tests for document structure templates."""

    def test_html_document_start(self) -> None:
        """Test document start includes required elements."""
        html = html_document_start("Test Report")
        assert "<!DOCTYPE html>" in html
        assert '<html lang="en">' in html
        assert "<head>" in html
        assert "<style>" in html
        assert "Test Report" in html
        assert 'class="container"' in html

    def test_html_document_end(self) -> None:
        """Test document end closes tags."""
        html = html_document_end()
        assert "</div>" in html
        assert "</body>" in html
        assert "</html>" in html

    def test_html_report_header(self) -> None:
        """Test report header rendering."""
        html = html_report_header("My Report", "Fuzzing Results", "ID: 12345")
        assert 'class="header"' in html
        assert "My Report" in html
        assert "Fuzzing Results" in html
        assert "ID: 12345" in html


class TestConstants:
    """Tests for template constants."""

    def test_report_css_not_empty(self) -> None:
        """Test REPORT_CSS contains styles."""
        assert len(REPORT_CSS) > 100
        assert "body" in REPORT_CSS
        assert ".container" in REPORT_CSS
        assert ".stat-card" in REPORT_CSS

    def test_severity_colors_complete(self) -> None:
        """Test severity colors has all levels."""
        assert "critical" in SEVERITY_COLORS
        assert "high" in SEVERITY_COLORS
        assert "medium" in SEVERITY_COLORS
        assert "low" in SEVERITY_COLORS
        assert "info" in SEVERITY_COLORS

    def test_severity_colors_are_hex(self) -> None:
        """Test severity colors are valid hex codes."""
        for color in SEVERITY_COLORS.values():
            assert color.startswith("#")
            assert len(color) == 7

"""Tests for HTML templates module."""

from __future__ import annotations

from dicom_fuzzer.core.reporting.html_templates import (
    REPORT_CSS,
    escape_html,
    html_document_end,
    html_document_start,
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


class TestConstants:
    """Tests for template constants."""

    def test_report_css_not_empty(self) -> None:
        """Test REPORT_CSS contains styles."""
        assert len(REPORT_CSS) > 100
        assert "body" in REPORT_CSS
        assert ".container" in REPORT_CSS
        assert ".stat-card" in REPORT_CSS

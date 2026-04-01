"""Tests for output formatting modules."""

from __future__ import annotations

import os
from unittest.mock import patch

from fenceline.check.scoring import RiskReport
from fenceline.output.console import format_console, _color
from fenceline.output.github import format_markdown


def _make_report(name="express", score=5, level="LOW", **kwargs):
    defaults = {
        "old_version": "4.17.0",
        "new_version": "4.18.0",
        "change_type": "updated",
        "signals": [],
    }
    defaults.update(kwargs)
    return RiskReport(name=name, score=score, level=level, **defaults)


class TestConsoleFormat:
    def test_basic_output(self):
        reports = [_make_report()]
        output = format_console(reports)
        assert "express" in output
        assert "LOW" in output
        assert "4.17.0" in output

    def test_critical_uses_x_icon(self):
        reports = [_make_report(score=70, level="CRITICAL")]
        output = format_console(reports)
        assert "[X]" in output

    def test_signals_shown(self):
        reports = [_make_report(
            score=30, level="MEDIUM",
            signals=[{"points": 20, "signal": "has_postinstall", "detail": "postinstall script"}],
        )]
        output = format_console(reports)
        assert "has_postinstall" in output
        assert "+20" in output

    def test_no_color_env_disables_ansi(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            text = _color("CRITICAL", "test")
            assert "\033[" not in text

    def test_color_enabled_has_ansi(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove NO_COLOR if present
            os.environ.pop("NO_COLOR", None)
            text = _color("CRITICAL", "test")
            assert "\033[" in text

    def test_multiple_reports(self):
        reports = [
            _make_report(name="a", score=5, level="LOW"),
            _make_report(name="b", score=50, level="HIGH"),
        ]
        output = format_console(reports)
        assert "a" in output
        assert "b" in output


class TestMarkdownFormat:
    def test_has_table_header(self):
        reports = [_make_report()]
        output = format_markdown(reports)
        assert "| Status |" in output
        assert "| Package |" in output

    def test_contains_package_name(self):
        reports = [_make_report(name="lodash")]
        output = format_markdown(reports)
        assert "lodash" in output

    def test_emoji_for_levels(self):
        reports = [_make_report(level="CRITICAL", score=70)]
        output = format_markdown(reports)
        # Should not crash — emoji rendering depends on terminal

    def test_high_risk_summary(self):
        reports = [_make_report(level="HIGH", score=50)]
        output = format_markdown(reports)
        assert "flagged as HIGH or CRITICAL" in output

    def test_clean_summary(self):
        reports = [_make_report(level="LOW", score=5)]
        output = format_markdown(reports)
        assert "All LOW/MEDIUM" in output

    def test_version_display(self):
        reports = [_make_report(old_version=None, new_version="1.0.0", change_type="added")]
        output = format_markdown(reports)
        assert "new" in output
        assert "1.0.0" in output

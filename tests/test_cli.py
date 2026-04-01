"""Tests for CLI entry point and argument parsing."""

from __future__ import annotations

import pytest

from fenceline.cli import main, build_parser


class TestArgumentParsing:
    def test_no_command_returns_zero(self, capsys):
        assert main([]) == 0
        out = capsys.readouterr().out
        assert "wrap" in out  # hero command visible in help

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0

    def test_install_no_args_shows_usage(self, capsys):
        assert main(["install"]) == 1
        err = capsys.readouterr().err
        assert "Usage" in err

    def test_wrap_no_flags_shows_usage(self, capsys):
        assert main(["wrap"]) == 1

    def test_install_format_flag_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--format", "json", "npm", "install", "x"])
        assert args.output_format == "json"

    def test_install_format_defaults_to_text(self):
        parser = build_parser()
        args = parser.parse_args(["install", "npm", "install", "x"])
        assert args.output_format == "text"

    def test_check_format_flag_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["check", "--format", "json"])
        assert args.format == "json"

    def test_wrap_enable_flag_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["wrap", "--enable"])
        assert args.enable is True

    def test_wrap_is_first_subcommand(self, capsys):
        """wrap should appear first in help output."""
        main([])
        out = capsys.readouterr().out
        wrap_pos = out.find("wrap")
        install_pos = out.find("install")
        assert wrap_pos < install_pos

    def test_check_fail_on_flag_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["check", "--fail-on", "critical"])
        assert args.fail_on == "critical"

    def test_check_fail_on_defaults_to_high(self):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert args.fail_on == "high"

    def test_check_fail_on_rejects_invalid(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["check", "--fail-on", "extreme"])

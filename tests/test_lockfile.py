"""Tests for lockfile parsing and diffing."""

from pathlib import Path

from fenceline.check.lockfile import parse_lockfile, diff_lockfiles

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_base_lockfile():
    packages = parse_lockfile(FIXTURES / "package-lock-base.json")
    assert "express" in packages
    assert "lodash" in packages
    assert "debug" in packages
    assert packages["express"]["version"] == "4.18.2"
    assert packages["lodash"]["version"] == "4.17.21"
    assert packages["debug"]["version"] == "4.3.4"


def test_parse_changed_lockfile():
    packages = parse_lockfile(FIXTURES / "package-lock-changed.json")
    assert packages["lodash"]["version"] == "4.17.22"
    assert "fake-utils" in packages
    assert packages["fake-utils"]["hasInstallScript"] is True


def test_diff_detects_update():
    base = parse_lockfile(FIXTURES / "package-lock-base.json")
    head = parse_lockfile(FIXTURES / "package-lock-changed.json")
    changes = diff_lockfiles(base, head)

    names = {c.name: c for c in changes}
    assert "lodash" in names
    assert names["lodash"].change_type == "updated"
    assert names["lodash"].old_version == "4.17.21"
    assert names["lodash"].new_version == "4.17.22"


def test_diff_detects_added():
    base = parse_lockfile(FIXTURES / "package-lock-base.json")
    head = parse_lockfile(FIXTURES / "package-lock-changed.json")
    changes = diff_lockfiles(base, head)

    names = {c.name: c for c in changes}
    assert "fake-utils" in names
    assert names["fake-utils"].change_type == "added"
    assert names["fake-utils"].new_version == "0.1.0"
    assert names["fake-utils"].has_install_script is True


def test_diff_ignores_unchanged():
    base = parse_lockfile(FIXTURES / "package-lock-base.json")
    head = parse_lockfile(FIXTURES / "package-lock-changed.json")
    changes = diff_lockfiles(base, head)

    names = {c.name for c in changes}
    assert "debug" not in names
    assert "express" not in names


def test_diff_detects_removed():
    base = parse_lockfile(FIXTURES / "package-lock-changed.json")
    head = parse_lockfile(FIXTURES / "package-lock-base.json")
    changes = diff_lockfiles(base, head)

    names = {c.name: c for c in changes}
    assert "fake-utils" in names
    assert names["fake-utils"].change_type == "removed"


def test_diff_empty_base():
    head = parse_lockfile(FIXTURES / "package-lock-base.json")
    changes = diff_lockfiles({}, head)
    assert len(changes) == 3
    assert all(c.change_type == "added" for c in changes)


def test_diff_empty_head():
    base = parse_lockfile(FIXTURES / "package-lock-base.json")
    changes = diff_lockfiles(base, {})
    assert len(changes) == 3
    assert all(c.change_type == "removed" for c in changes)

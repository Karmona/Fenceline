"""Tests for lockfile parsing and diffing."""

import json
from pathlib import Path

from fenceline.check.lockfile import (
    parse_lockfile,
    parse_pipfile_lock,
    parse_requirements_txt,
    parse_requirements_txt_as_map,
    detect_lockfile,
    diff_lockfiles,
    _strip_node_modules,
)

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


# --- Pipfile.lock parsing ---


class TestParsePipfileLock:
    def test_basic_pipfile(self, tmp_path):
        lockfile = tmp_path / "Pipfile.lock"
        lockfile.write_text(json.dumps({
            "default": {
                "requests": {"version": "==2.31.0"},
                "flask": {"version": "==3.0.0"},
            },
            "develop": {
                "pytest": {"version": "==8.0.0"},
            },
        }))
        packages = parse_pipfile_lock(lockfile)
        assert "requests" in packages
        assert packages["requests"]["version"] == "2.31.0"  # == stripped
        assert "flask" in packages
        assert "pytest" in packages

    def test_strips_version_prefix(self, tmp_path):
        lockfile = tmp_path / "Pipfile.lock"
        lockfile.write_text(json.dumps({
            "default": {"six": {"version": "==1.16.0"}},
        }))
        packages = parse_pipfile_lock(lockfile)
        assert packages["six"]["version"] == "1.16.0"

    def test_empty_pipfile(self, tmp_path):
        lockfile = tmp_path / "Pipfile.lock"
        lockfile.write_text(json.dumps({"default": {}, "develop": {}}))
        packages = parse_pipfile_lock(lockfile)
        assert packages == {}

    def test_has_install_script_always_false(self, tmp_path):
        lockfile = tmp_path / "Pipfile.lock"
        lockfile.write_text(json.dumps({
            "default": {"pkg": {"version": "==1.0"}},
        }))
        packages = parse_pipfile_lock(lockfile)
        assert packages["pkg"]["hasInstallScript"] is False


# --- requirements.txt parsing ---


class TestParseRequirementsTxt:
    def test_basic_requirements(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.0\n")
        packages = parse_requirements_txt(req)
        assert len(packages) == 2
        assert packages[0]["name"] == "requests"
        assert packages[0]["version"] == "2.31.0"

    def test_skips_comments_and_blanks(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n\nrequests==2.31.0\n-r other.txt\n")
        packages = parse_requirements_txt(req)
        assert len(packages) == 1

    def test_handles_extras_and_markers(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0; python_version>='3.7'\n")
        packages = parse_requirements_txt(req)
        assert len(packages) == 1
        assert packages[0]["version"] == "2.31.0"

    def test_as_map(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("Flask==3.0.0\nclick==8.1.7\n")
        packages = parse_requirements_txt_as_map(req)
        assert "flask" in packages  # lowercased
        assert packages["flask"]["version"] == "3.0.0"


# --- detect_lockfile ---


class TestDetectLockfile:
    def test_finds_package_lock(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        result = detect_lockfile(tmp_path)
        assert result is not None
        assert result[0] == "npm"

    def test_finds_pipfile_lock(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text("{}")
        result = detect_lockfile(tmp_path)
        assert result is not None
        assert result[0] == "pipfile"

    def test_finds_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = detect_lockfile(tmp_path)
        assert result is not None
        assert result[0] == "requirements"

    def test_prefers_npm_over_pip(self, tmp_path):
        """package-lock.json takes priority over Pipfile.lock."""
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "Pipfile.lock").write_text("{}")
        result = detect_lockfile(tmp_path)
        assert result[0] == "npm"

    def test_returns_none_when_empty(self, tmp_path):
        assert detect_lockfile(tmp_path) is None


# --- _strip_node_modules ---


class TestStripNodeModules:
    def test_simple_package(self):
        assert _strip_node_modules("node_modules/express") == "express"

    def test_scoped_package(self):
        assert _strip_node_modules("node_modules/@types/node") == "@types/node"

    def test_nested_package(self):
        result = _strip_node_modules("node_modules/express/node_modules/debug")
        assert result == "debug"

    def test_empty_string(self):
        assert _strip_node_modules("") == ""

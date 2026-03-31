"""Tests for pip/PyPI lockfile parsing and diffing."""

from pathlib import Path

from fenceline.check.lockfile import (
    parse_pipfile_lock,
    parse_requirements_txt,
    parse_requirements_txt_as_map,
    detect_lockfile,
    diff_lockfiles,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# parse_pipfile_lock
# ---------------------------------------------------------------------------


def test_parse_pipfile_lock_default_packages():
    packages = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    assert "requests" in packages
    assert "flask" in packages
    assert "pyyaml" in packages
    assert packages["requests"]["version"] == "2.31.0"
    assert packages["flask"]["version"] == "3.0.0"
    assert packages["pyyaml"]["version"] == "6.0.1"


def test_parse_pipfile_lock_develop_packages():
    packages = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    assert "pytest" in packages
    assert packages["pytest"]["version"] == "7.4.0"


def test_parse_pipfile_lock_strips_version_prefix():
    packages = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    # Versions in Pipfile.lock are prefixed with "==" — parser should strip.
    for pkg in packages.values():
        assert not pkg["version"].startswith("==")


def test_parse_pipfile_lock_pip_fields():
    packages = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    # Pip packages don't have resolved URLs or install scripts.
    for pkg in packages.values():
        assert pkg["resolved"] is None
        assert pkg["hasInstallScript"] is False


# ---------------------------------------------------------------------------
# parse_requirements_txt
# ---------------------------------------------------------------------------


def test_parse_requirements_txt():
    packages = parse_requirements_txt(FIXTURES / "requirements.txt")
    assert len(packages) == 3
    names = {p["name"] for p in packages}
    assert names == {"requests", "flask", "pyyaml"}


def test_parse_requirements_txt_versions():
    packages = parse_requirements_txt(FIXTURES / "requirements.txt")
    by_name = {p["name"]: p for p in packages}
    assert by_name["requests"]["version"] == "2.31.0"
    assert by_name["flask"]["version"] == "3.0.0"
    assert by_name["pyyaml"]["version"] == "6.0.1"


def test_parse_requirements_txt_as_map():
    packages = parse_requirements_txt_as_map(FIXTURES / "requirements.txt")
    assert "requests" in packages
    assert packages["requests"]["version"] == "2.31.0"
    assert packages["requests"]["resolved"] is None
    assert packages["requests"]["hasInstallScript"] is False


# ---------------------------------------------------------------------------
# detect_lockfile
# ---------------------------------------------------------------------------


def test_detect_lockfile_npm(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}")
    result = detect_lockfile(tmp_path)
    assert result is not None
    assert result[0] == "npm"
    assert result[1].name == "package-lock.json"


def test_detect_lockfile_pipfile(tmp_path):
    (tmp_path / "Pipfile.lock").write_text("{}")
    result = detect_lockfile(tmp_path)
    assert result is not None
    assert result[0] == "pipfile"
    assert result[1].name == "Pipfile.lock"


def test_detect_lockfile_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0")
    result = detect_lockfile(tmp_path)
    assert result is not None
    assert result[0] == "requirements"
    assert result[1].name == "requirements.txt"


def test_detect_lockfile_priority(tmp_path):
    """npm lockfile takes priority over Pipfile.lock."""
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "Pipfile.lock").write_text("{}")
    result = detect_lockfile(tmp_path)
    assert result is not None
    assert result[0] == "npm"


def test_detect_lockfile_none(tmp_path):
    result = detect_lockfile(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# diff_lockfiles with pip packages
# ---------------------------------------------------------------------------


def test_diff_pipfile_locks():
    base = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    head = parse_pipfile_lock(FIXTURES / "Pipfile.lock.changed")
    changes = diff_lockfiles(base, head)

    names = {c.name: c for c in changes}

    # requests was updated 2.31.0 -> 2.32.0
    assert "requests" in names
    assert names["requests"].change_type == "updated"
    assert names["requests"].old_version == "2.31.0"
    assert names["requests"].new_version == "2.32.0"

    # httpx was added
    assert "httpx" in names
    assert names["httpx"].change_type == "added"
    assert names["httpx"].new_version == "0.25.0"


def test_diff_pipfile_unchanged():
    base = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    head = parse_pipfile_lock(FIXTURES / "Pipfile.lock.changed")
    changes = diff_lockfiles(base, head)

    names = {c.name for c in changes}
    # flask and pyyaml are unchanged
    assert "flask" not in names
    assert "pyyaml" not in names


def test_diff_pipfile_no_install_script():
    base = parse_pipfile_lock(FIXTURES / "Pipfile.lock")
    head = parse_pipfile_lock(FIXTURES / "Pipfile.lock.changed")
    changes = diff_lockfiles(base, head)

    # Pip packages never have install scripts.
    for change in changes:
        assert change.has_install_script is False
        assert change.resolved_url is None

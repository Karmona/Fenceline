"""Tests for the risk scoring model."""

from datetime import timedelta

from fenceline.check.lockfile import PackageChange
from fenceline.check.scoring import compute_risk


def _make_change(**kwargs):
    defaults = {
        "name": "test-pkg",
        "old_version": None,
        "new_version": "1.0.0",
        "resolved_url": None,
        "integrity": None,
        "has_install_script": False,
        "change_type": "added",
    }
    defaults.update(kwargs)
    return PackageChange(**defaults)


def test_new_package_with_postinstall_and_low_age_scores_critical():
    """A brand-new package published yesterday with a postinstall hook
    should score CRITICAL (61+)."""
    change = _make_change(change_type="added")
    age = timedelta(days=1)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": False, "has_signatures": False, "attestation_count": 0}
    capabilities = ["has_postinstall"]

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    # very_new_version=30 + has_postinstall=20 + no_provenance=10 + new_package=5 = 65
    assert report.score == 65
    assert report.level == "CRITICAL"
    signal_names = {s["signal"] for s in report.signals}
    assert "very_new_version" in signal_names
    assert "has_postinstall" in signal_names
    assert "no_provenance" in signal_names
    assert "new_package" in signal_names


def test_normal_update_scores_low():
    """An update to a well-established package with provenance should
    score LOW (0-15)."""
    change = _make_change(
        old_version="1.0.0",
        new_version="1.0.1",
        change_type="updated",
    )
    age = timedelta(days=90)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}
    capabilities = []

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    assert report.score == 0
    assert report.level == "LOW"
    assert len(report.signals) == 0


def test_maintainer_removed_adds_points():
    change = _make_change(change_type="updated", old_version="1.0.0", new_version="2.0.0")
    age = timedelta(days=60)
    maintainer = {"changed": True, "added": ["new-dev"], "removed": ["old-dev"]}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}
    capabilities = []

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    assert report.score == 25
    assert report.level == "MEDIUM"


def test_maintainer_added_only():
    change = _make_change(change_type="updated", old_version="1.0.0", new_version="2.0.0")
    age = timedelta(days=60)
    maintainer = {"changed": True, "added": ["extra-dev"], "removed": []}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}
    capabilities = []

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    assert report.score == 10
    assert report.level == "LOW"


def test_preinstall_scores_higher_than_postinstall():
    change = _make_change(change_type="updated", old_version="1.0.0", new_version="2.0.0")
    age = timedelta(days=60)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}

    report_pre = compute_risk(change, age, maintainer, provenance, ["has_preinstall"])
    report_post = compute_risk(change, age, maintainer, provenance, ["has_postinstall"])

    assert report_pre.score > report_post.score


def test_level_boundaries():
    """Verify that score boundaries map to the correct levels."""
    change = _make_change()

    no_signals = {"changed": False, "added": [], "removed": []}
    prov_yes = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}

    # 0 points -> LOW
    r = compute_risk(change, timedelta(days=365), no_signals, prov_yes, [])
    # Only new_package = 5
    assert r.level == "LOW"

    # 15 points -> LOW (boundary)
    r2 = compute_risk(
        _make_change(change_type="updated", old_version="1.0.0"),
        timedelta(days=365),
        no_signals,
        {"has_provenance": False, "has_signatures": False, "attestation_count": 0},
        [],
    )
    # no_provenance=10, no new_package since updated -> 10 = LOW
    assert r2.level == "LOW"


def test_setup_py_only_adds_points():
    """PyPI packages that are sdist-only (setup.py execution) should add 15 pts."""
    change = _make_change(change_type="updated", old_version="1.0.0", new_version="2.0.0")
    age = timedelta(days=60)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}
    capabilities = ["has_setup_py_only"]

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    assert report.score == 15
    signal_names = {s["signal"] for s in report.signals}
    assert "has_setup_py_only" in signal_names


def test_native_extension_adds_points():
    """PyPI packages with native C extensions should add 10 pts."""
    change = _make_change(change_type="updated", old_version="1.0.0", new_version="2.0.0")
    age = timedelta(days=60)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": True, "has_signatures": True, "attestation_count": 1}
    capabilities = ["has_native_extension"]

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    assert report.score == 10
    signal_names = {s["signal"] for s in report.signals}
    assert "has_native_extension" in signal_names


def test_pypi_capabilities_combined():
    """Both PyPI capabilities together should accumulate."""
    change = _make_change(change_type="added")
    age = timedelta(days=60)
    maintainer = {"changed": False, "added": [], "removed": []}
    provenance = {"has_provenance": False, "has_signatures": False, "attestation_count": 0}
    capabilities = ["has_setup_py_only", "has_native_extension"]

    report = compute_risk(change, age, maintainer, provenance, capabilities)

    # has_setup_py_only=15 + has_native_extension=10 + no_provenance=10 + new_package=5 = 40
    assert report.score == 40
    assert report.level == "HIGH"

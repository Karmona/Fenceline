"""Tests for fenceline audit-actions command."""

from __future__ import annotations

import os
import tempfile
import textwrap

import pytest

from fenceline.actions.audit import _classify, _scan_workflow, run


# ---------------------------------------------------------------------------
# Unit tests for _classify
# ---------------------------------------------------------------------------

class TestClassify:
    def test_sha_pinned_passes(self):
        f = _classify("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29")
        assert f.level == "PASS"

    def test_tag_pinned_warns(self):
        f = _classify("actions/checkout@v4")
        assert f.level == "WARNING"
        assert "tag" in f.reason.lower()

    def test_semver_tag_warns(self):
        f = _classify("actions/setup-python@v5.1.0")
        assert f.level == "WARNING"

    def test_main_is_critical(self):
        f = _classify("some-org/dangerous-action@main")
        assert f.level == "CRITICAL"

    def test_master_is_critical(self):
        f = _classify("another-org/risky-action@master")
        assert f.level == "CRITICAL"

    def test_docker_action_skipped(self):
        f = _classify("docker://ghcr.io/some/image:latest")
        assert f.level == "SKIP"

    def test_local_action_skipped(self):
        f = _classify("./local-action")
        assert f.level == "SKIP"

    def test_relative_parent_action_skipped(self):
        f = _classify("../other-action")
        assert f.level == "SKIP"


# ---------------------------------------------------------------------------
# Integration test: scan the fixture workflow
# ---------------------------------------------------------------------------

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "test-workflow.yml"
)


class TestScanWorkflow:
    def test_fixture_returns_expected_findings(self):
        findings = _scan_workflow(FIXTURE_PATH)
        levels = [f.level for f in findings]

        assert levels.count("PASS") == 2       # two SHA-pinned
        assert levels.count("WARNING") == 2     # two tag-pinned
        assert levels.count("CRITICAL") == 2    # @main + @master
        assert levels.count("SKIP") == 2        # docker + local

    def test_total_findings(self):
        findings = _scan_workflow(FIXTURE_PATH)
        assert len(findings) == 8


# ---------------------------------------------------------------------------
# Integration test: multiple workflows scanned via run()
# ---------------------------------------------------------------------------

class TestRunMultipleWorkflows:
    def test_scans_multiple_files(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)

        # Workflow 1 — all safe
        (wf_dir / "safe.yml").write_text(textwrap.dedent("""\
            name: Safe
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        """))

        # Workflow 2 — has a critical
        (wf_dir / "dangerous.yml").write_text(textwrap.dedent("""\
            name: Dangerous
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: evil-org/bad-action@main
        """))

        import argparse
        args = argparse.Namespace(path=str(tmp_path), verbose=False, no_color=True)
        exit_code = run(args)
        assert exit_code == 1  # critical found

    def test_all_safe_returns_zero(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)

        (wf_dir / "safe.yml").write_text(textwrap.dedent("""\
            name: Safe
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        """))

        import argparse
        args = argparse.Namespace(path=str(tmp_path), verbose=False, no_color=True)
        exit_code = run(args)
        assert exit_code == 0

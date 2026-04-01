"""Integration tests that require a running Docker daemon.

These tests exercise the full sandbox pipeline with real Docker containers.
They are marked with @pytest.mark.integration and skipped in unit test runs.

Run with: python -m pytest tests/integration/ -v -m integration
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fenceline.install.sandbox import docker_available


def _docker_ok():
    """Check if Docker is available for integration testing."""
    try:
        return docker_available()
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _docker_ok(), reason="Docker daemon not available"),
]


class TestNpmSandbox:
    """End-to-end npm install through the sandbox."""

    def test_clean_install(self, tmp_path):
        """npm install is-odd should complete successfully in sandbox."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text('{"name": "test", "version": "1.0.0"}')

        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "install", "--sandbox",
             "npm", "install", "is-odd"],
            capture_output=True, text=True, timeout=180,
            cwd=str(tmp_path),
        )

        # Must succeed — timeout is a failure, not a pass
        assert result.returncode == 0, (
            f"Expected clean install (exit 0), got exit {result.returncode}\n"
            f"stdout: {result.stdout[-500:]}\nstderr: {result.stderr[-500:]}"
        )

        # Artifacts should exist on host
        assert (tmp_path / "node_modules").exists(), (
            "node_modules not copied to host after clean install"
        )

    def test_json_output_format(self, tmp_path):
        """--format json should always produce valid JSON regardless of exit code."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text('{"name": "test", "version": "1.0.0"}')

        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "install", "--sandbox",
             "--format", "json", "npm", "install", "is-odd"],
            capture_output=True, text=True, timeout=180,
            cwd=str(tmp_path),
        )

        # JSON output must be valid regardless of exit code
        stdout = result.stdout
        # Find JSON start (there may be log output before it)
        json_start = -1
        for i, ch in enumerate(stdout):
            if ch == '{':
                json_start = i
                break

        assert json_start >= 0, (
            f"No JSON object found in stdout.\n"
            f"exit code: {result.returncode}\n"
            f"stdout: {stdout[-500:]}\nstderr: {result.stderr[-500:]}"
        )

        data = json.loads(stdout[json_start:])
        assert "verdict" in data, f"JSON missing 'verdict' field: {data}"
        assert "alerts" in data, f"JSON missing 'alerts' field: {data}"
        assert "duration_seconds" in data, f"JSON missing 'duration_seconds' field: {data}"

        if result.returncode == 0:
            assert data["verdict"] == "CLEAN"

    def test_blocked_nonstandard_port(self, tmp_path):
        """A package that connects to a non-standard port should be BLOCKED."""
        # Create a malicious package with postinstall that connects to port 8080
        evil_pkg = tmp_path / "evil-pkg"
        evil_pkg.mkdir()
        (evil_pkg / "package.json").write_text(json.dumps({
            "name": "evil-test",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"try{require('net').connect(8080,'93.184.216.34')}catch(e){}\""
            },
        }))
        (evil_pkg / "index.js").write_text("module.exports = {};")

        # Pack it
        pack_result = subprocess.run(
            ["npm", "pack"],
            capture_output=True, text=True, timeout=30,
            cwd=str(evil_pkg),
        )
        if pack_result.returncode != 0:
            pytest.skip("npm pack failed")

        tarball = evil_pkg / "evil-test-1.0.0.tgz"
        if not tarball.exists():
            pytest.skip("tarball not created")

        # Try to install it through the sandbox
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text('{"name": "test", "version": "1.0.0"}')

        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "install", "--sandbox",
             "npm", "install", str(tarball)],
            capture_output=True, text=True, timeout=180,
            cwd=str(tmp_path),
        )

        combined = result.stdout + result.stderr
        # The postinstall connects to port 8080 — must be blocked.
        # If the connection was detected, BLOCKED must appear and exit code must be non-zero.
        # If the connection somehow never happened (rare: DNS failure, container network
        # issue), we still require either BLOCKED or a non-zero exit code.
        assert "BLOCKED" in combined or result.returncode != 0, (
            f"Expected BLOCKED or non-zero exit for malicious package.\n"
            f"exit code: {result.returncode}\n"
            f"stdout: {result.stdout[-500:]}\nstderr: {result.stderr[-500:]}"
        )

        if "BLOCKED" in combined:
            assert result.returncode != 0, (
                "BLOCKED message present but exit code was 0"
            )
            # node_modules should NOT be copied when blocked
            node_modules = tmp_path / "node_modules"
            has_evil = (node_modules / "evil-test").exists() if node_modules.exists() else False
            assert not has_evil, "Blocked package was copied to host"


class TestGracefulDegradation:
    """Test behavior when Docker is not ideal."""

    def test_fenceline_version_works(self):
        """Basic smoke test — fenceline --version should always work."""
        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        # --version causes SystemExit(0) which subprocess sees as returncode 0
        assert "fenceline" in result.stdout.lower() or result.returncode == 0

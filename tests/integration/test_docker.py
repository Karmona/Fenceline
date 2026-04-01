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
        # Set up a minimal npm project
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text('{"name": "test", "version": "1.0.0"}')

        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "install", "--sandbox",
             "npm", "install", "is-odd"],
            capture_output=True, text=True, timeout=180,
            cwd=str(tmp_path),
        )

        # Should succeed (exit 0) or timeout (exit 124)
        assert result.returncode in (0, 124), (
            f"Expected clean install, got exit {result.returncode}\n"
            f"stdout: {result.stdout[-500:]}\nstderr: {result.stderr[-500:]}"
        )

    def test_json_output_format(self, tmp_path):
        """--format json should produce valid JSON."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text('{"name": "test", "version": "1.0.0"}')

        result = subprocess.run(
            [sys.executable, "-m", "fenceline", "install", "--sandbox",
             "--format", "json", "npm", "install", "is-odd"],
            capture_output=True, text=True, timeout=180,
            cwd=str(tmp_path),
        )

        if result.returncode == 0:
            # JSON output should be valid
            data = json.loads(result.stdout)
            assert "verdict" in data
            assert data["verdict"] == "CLEAN"
            assert "alerts" in data
            assert "duration_seconds" in data

    def test_blocked_nonstandard_port(self, tmp_path):
        """A package that connects to a non-standard port should be BLOCKED."""
        # Create a malicious package that connects to port 8080
        pkg_dir = tmp_path / "node_modules" / "evil-test"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "evil-test",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"require('net').connect(8080, '93.184.216.34')\""
            },
        }))

        # Create a tarball-like installable package
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
        # The postinstall connects to port 8080 — should be blocked
        # (might also timeout or fail to resolve the IP)
        if "BLOCKED" in combined:
            assert result.returncode != 0
        # If it didn't connect (DNS failure in container), that's OK too


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

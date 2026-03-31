"""Tests for the shell wrapper module."""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from fenceline.install.sandbox import _extract_package_name


class TestExtractPackageName:
    def test_npm_install_express(self):
        assert _extract_package_name(["npm", "install", "express"]) == "express"

    def test_npm_i_shorthand(self):
        assert _extract_package_name(["npm", "i", "lodash"]) == "lodash"

    def test_npm_install_with_flags(self):
        assert _extract_package_name(["npm", "install", "--save", "react"]) == "react"

    def test_npm_install_with_version(self):
        assert _extract_package_name(["npm", "install", "express@4.18"]) == "express"

    def test_pip_install(self):
        assert _extract_package_name(["pip", "install", "requests"]) == "requests"

    def test_pip_with_version_specifier(self):
        assert _extract_package_name(["pip", "install", "requests==2.31.0"]) == "requests"

    def test_scoped_npm_package(self):
        assert _extract_package_name(["npm", "install", "@types/node"]) == "@types/node"

    def test_scoped_npm_with_version(self):
        assert _extract_package_name(["npm", "install", "@types/node@18.0.0"]) == "@types/node"

    def test_yarn_add(self):
        assert _extract_package_name(["yarn", "add", "react"]) == "react"

    def test_no_package(self):
        assert _extract_package_name(["npm", "install"]) is None

    def test_empty_cmd(self):
        assert _extract_package_name([]) is None


class TestWrapperScript:
    """Test the wrapper script content generation."""

    def test_fail_closed_no_docker(self):
        """Wrapper script should BLOCK when Docker is not available, not fall through."""
        from fenceline.wrap import _WRAPPER_SCRIPT
        assert "BLOCKED" in _WRAPPER_SCRIPT
        assert "exit 1" in _WRAPPER_SCRIPT

    def test_npm_ci_matched(self):
        """npm ci should be caught as an install command."""
        from fenceline.wrap import _WRAPPER_SCRIPT
        assert "ci)" in _WRAPPER_SCRIPT

    def test_non_install_passes_through(self):
        """Non-install commands should pass through to the real tool."""
        from fenceline.wrap import _WRAPPER_SCRIPT
        assert "REAL_CMD" in _WRAPPER_SCRIPT


class TestWrapperFilesystem:
    """Test wrapper enable/disable filesystem operations."""

    @patch("fenceline.wrap._WRAPPER_DIR")
    @patch("fenceline.wrap._find_real_tool")
    @patch("fenceline.wrap._find_fenceline", return_value="/usr/local/bin/fenceline")
    def test_enable_creates_executable_wrappers(self, _mock_fl, mock_find, mock_dir, tmp_path):
        wrapper_dir = tmp_path / "bin"
        mock_dir.__truediv__ = lambda self, name: wrapper_dir / name
        mock_dir.mkdir = lambda parents=True, exist_ok=True: wrapper_dir.mkdir(
            parents=parents, exist_ok=exist_ok
        )
        mock_dir.exists.return_value = True
        mock_dir.__str__ = lambda self: str(wrapper_dir)

        mock_find.side_effect = lambda name: f"/usr/local/bin/{name}" if name == "npm" else None

        from fenceline.wrap import _enable_wrappers
        result = _enable_wrappers()
        assert result == 0

        npm_wrapper = wrapper_dir / "npm"
        assert npm_wrapper.exists()
        assert npm_wrapper.stat().st_mode & 0o755 == 0o755
        content = npm_wrapper.read_text()
        assert "/usr/local/bin/npm" in content
        assert "/usr/local/bin/fenceline" in content

    @patch("fenceline.wrap._WRAPPER_DIR")
    @patch("fenceline.wrap._find_real_tool", return_value=None)
    @patch("fenceline.wrap._find_fenceline", return_value="/usr/local/bin/fenceline")
    def test_enable_skips_missing_tools(self, _mock_fl, _mock_find, mock_dir, tmp_path):
        wrapper_dir = tmp_path / "bin"
        mock_dir.mkdir = lambda parents=True, exist_ok=True: wrapper_dir.mkdir(
            parents=parents, exist_ok=exist_ok
        )

        from fenceline.wrap import _enable_wrappers
        result = _enable_wrappers()
        assert result == 1  # no tools found

    @patch("fenceline.wrap._WRAPPER_DIR")
    def test_disable_removes_wrappers(self, mock_dir, tmp_path):
        wrapper_dir = tmp_path / "bin"
        wrapper_dir.mkdir()
        npm_wrapper = wrapper_dir / "npm"
        npm_wrapper.write_text("#!/bin/bash\n")

        mock_dir.exists.return_value = True
        mock_dir.__truediv__ = lambda self, name: wrapper_dir / name

        from fenceline.wrap import _disable_wrappers
        result = _disable_wrappers()
        assert result == 0
        assert not npm_wrapper.exists()

    @patch("fenceline.wrap._WRAPPER_DIR")
    def test_disable_noop_when_no_dir(self, mock_dir):
        mock_dir.exists.return_value = False

        from fenceline.wrap import _disable_wrappers
        result = _disable_wrappers()
        assert result == 0


_has_bash = shutil.which("bash") is not None


@pytest.mark.skipif(not _has_bash, reason="bash not available")
@pytest.mark.skipif(sys.platform == "win32", reason="bash wrappers are Unix-only")
class TestWrapperRouting:
    """Test actual wrapper script command routing via bash execution."""

    def _make_wrapper(self, tmp_path):
        """Create a wrapper script with stub commands for testing."""
        from fenceline.wrap import _WRAPPER_SCRIPT

        # Create stub "real" command that echoes what it receives
        real_cmd = tmp_path / "real_npm"
        real_cmd.write_text('#!/bin/bash\necho "REAL_CALLED $@"\n')
        real_cmd.chmod(0o755)

        # Create stub fenceline command
        fenceline_cmd = tmp_path / "fenceline"
        fenceline_cmd.write_text('#!/bin/bash\necho "FENCELINE_CALLED $@"\n')
        fenceline_cmd.chmod(0o755)

        # Write wrapper script with stubs
        wrapper = tmp_path / "npm"
        script = _WRAPPER_SCRIPT.format(
            real_path=str(real_cmd),
            fenceline_path=str(fenceline_cmd),
        )
        wrapper.write_text(script)
        wrapper.chmod(0o755)
        return wrapper

    def test_install_routes_to_fenceline(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        # Add a fake docker to PATH so the wrapper thinks Docker is available
        fake_docker = tmp_path / "docker"
        fake_docker.write_text("#!/bin/bash\nexit 0\n")
        fake_docker.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"

        result = subprocess.run(
            ["bash", str(wrapper), "install", "express"],
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert "FENCELINE_CALLED" in result.stdout

    def test_non_install_passes_through(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        result = subprocess.run(
            ["bash", str(wrapper), "test"],
            capture_output=True, text=True, timeout=10,
        )
        assert "REAL_CALLED" in result.stdout

    def test_no_docker_blocks_install(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        # PATH includes tmp_path (for stubs) but NOT docker's directory.
        # We still need bash-internal commands to work, so keep /usr/bin.
        # The key: no 'docker' binary on this restricted PATH.
        bash_dir = os.path.dirname(shutil.which("bash"))
        env = {
            "PATH": f"{tmp_path}:{bash_dir}",
            "HOME": os.environ.get("HOME", "/tmp"),
        }

        result = subprocess.run(
            ["bash", str(wrapper), "install", "express"],
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert result.returncode == 1
        assert "BLOCKED" in result.stderr

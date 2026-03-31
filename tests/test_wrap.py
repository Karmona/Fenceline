"""Tests for the shell wrapper module."""

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
        # The script should contain fail-closed logic
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

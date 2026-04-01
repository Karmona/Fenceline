"""Tests for git hook installation."""

from __future__ import annotations

import os
import stat
from unittest.mock import patch, MagicMock

from fenceline.init.hooks import run, _replace_section, MARKER


class TestHookInstall:
    @patch("fenceline.init.hooks.subprocess.run")
    def test_creates_hooks_in_git_repo(self, mock_run, tmp_path):
        """Hooks should be created in the .git/hooks directory."""
        git_dir = tmp_path / ".git"
        hooks_dir = git_dir / "hooks"
        git_dir.mkdir()

        mock_run.return_value = MagicMock(
            returncode=0, stdout=str(git_dir) + "\n"
        )

        args = MagicMock(force=False)
        result = run(args)
        assert result == 0
        assert (hooks_dir / "pre-commit").exists()
        assert (hooks_dir / "post-merge").exists()

        # Hooks should be executable
        pre_commit_mode = os.stat(hooks_dir / "pre-commit").st_mode
        assert pre_commit_mode & stat.S_IEXEC

    @patch("fenceline.init.hooks.subprocess.run")
    def test_not_git_repo_returns_error(self, mock_run):
        """Should return 1 if not in a git repository."""
        from subprocess import CalledProcessError
        mock_run.side_effect = CalledProcessError(128, "git")
        args = MagicMock(force=False)
        assert run(args) == 1

    @patch("fenceline.init.hooks.subprocess.run")
    def test_force_appends_to_existing(self, mock_run, tmp_path):
        """--force should append to an existing hook without marker."""
        git_dir = tmp_path / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)

        # Pre-existing hook without fenceline marker
        existing_hook = hooks_dir / "pre-commit"
        existing_hook.write_text("#!/bin/bash\necho 'existing hook'\n")
        existing_hook.chmod(0o755)

        mock_run.return_value = MagicMock(
            returncode=0, stdout=str(git_dir) + "\n"
        )

        args = MagicMock(force=True)
        result = run(args)
        assert result == 0

        content = existing_hook.read_text()
        assert "existing hook" in content
        assert MARKER in content

    @patch("fenceline.init.hooks.subprocess.run")
    def test_updates_existing_fenceline_section(self, mock_run, tmp_path):
        """If hook already has fenceline marker, replace that section."""
        git_dir = tmp_path / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)

        # Pre-existing hook with old fenceline section
        old_content = (
            "#!/bin/bash\nset -e\n\n"
            f"{MARKER}\nold fenceline content\n{MARKER}-end\n"
        )
        existing_hook = hooks_dir / "pre-commit"
        existing_hook.write_text(old_content)
        existing_hook.chmod(0o755)

        mock_run.return_value = MagicMock(
            returncode=0, stdout=str(git_dir) + "\n"
        )

        args = MagicMock(force=False)
        result = run(args)
        assert result == 0

        content = existing_hook.read_text()
        assert "old fenceline content" not in content
        assert MARKER in content
        assert "fenceline check" in content


class TestReplaceSection:
    def test_replaces_marked_section(self):
        existing = f"before\n{MARKER}\nold\n{MARKER}-end\nafter\n"
        new = f"{MARKER}\nnew content\n{MARKER}-end\n"
        result = _replace_section(existing, new)
        assert "old" not in result
        assert "new content" in result
        assert "before" in result
        assert "after" in result

    def test_no_markers_returns_unchanged(self):
        existing = "just some text"
        result = _replace_section(existing, "new")
        assert result == existing

"""Tests for filesystem diffing."""

from unittest.mock import patch, MagicMock

from fenceline.install.fsdiff import (
    FileEntry,
    FsAlert,
    parse_find_output,
    diff_snapshots,
    check_suspicious_files,
    snapshot_container,
    _is_executable,
)


class TestParseFindOutput:
    def test_parses_basic_output(self):
        output = "/app/node_modules/express/index.js\t644\t1234\n"
        files = parse_find_output(output)
        assert len(files) == 1
        assert files["/app/node_modules/express/index.js"].permissions == "644"
        assert files["/app/node_modules/express/index.js"].size == 1234

    def test_parses_multiple_files(self):
        output = (
            "/app/node_modules/a/index.js\t644\t100\n"
            "/app/node_modules/b/index.js\t755\t200\n"
        )
        files = parse_find_output(output)
        assert len(files) == 2

    def test_empty_output(self):
        assert parse_find_output("") == {}

    def test_skips_malformed_lines(self):
        output = "bad line\n/app/good.js\t644\t100\n"
        files = parse_find_output(output)
        assert len(files) == 1
        assert "/app/good.js" in files


class TestDiffSnapshots:
    def test_detects_added_files(self):
        before = {"/app/a.js": FileEntry("/app/a.js", "644", 100)}
        after = {
            "/app/a.js": FileEntry("/app/a.js", "644", 100),
            "/app/b.js": FileEntry("/app/b.js", "644", 200),
        }
        added, removed, modified = diff_snapshots(before, after)
        assert len(added) == 1
        assert added[0].path == "/app/b.js"
        assert len(removed) == 0
        assert len(modified) == 0

    def test_detects_removed_files(self):
        before = {
            "/app/a.js": FileEntry("/app/a.js", "644", 100),
            "/app/b.js": FileEntry("/app/b.js", "644", 200),
        }
        after = {"/app/a.js": FileEntry("/app/a.js", "644", 100)}
        added, removed, modified = diff_snapshots(before, after)
        assert len(removed) == 1
        assert removed[0].path == "/app/b.js"

    def test_detects_modified_size(self):
        before = {"/app/a.js": FileEntry("/app/a.js", "644", 100)}
        after = {"/app/a.js": FileEntry("/app/a.js", "644", 999)}
        added, removed, modified = diff_snapshots(before, after)
        assert len(modified) == 1
        assert modified[0].size == 999

    def test_detects_modified_permissions(self):
        before = {"/app/a.js": FileEntry("/app/a.js", "644", 100)}
        after = {"/app/a.js": FileEntry("/app/a.js", "755", 100)}
        _, _, modified = diff_snapshots(before, after)
        assert len(modified) == 1

    def test_no_changes(self):
        snap = {"/app/a.js": FileEntry("/app/a.js", "644", 100)}
        added, removed, modified = diff_snapshots(snap, snap)
        assert added == [] and removed == [] and modified == []


class TestCheckSuspiciousFiles:
    def test_executable_outside_expected_dirs(self):
        added = [FileEntry("/app/evil", "755", 5000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert "executable" in alerts[0].reason.lower()

    def test_file_in_sensitive_directory(self):
        added = [FileEntry("/etc/cron.d/backdoor", "644", 100)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert "/etc" in alerts[0].reason

    def test_file_in_expected_dir_no_alert(self):
        added = [FileEntry("/app/node_modules/express/index.js", "644", 1234)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 0

    def test_suspicious_extension_outside_expected(self):
        added = [FileEntry("/app/payload.so", "644", 5000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 1
        assert alerts[0].severity == "warning"
        assert ".so" in alerts[0].reason

    def test_permission_escalation_on_modified_file(self):
        modified = [FileEntry("/app/config.json", "755", 100)]
        alerts = check_suspicious_files([], modified, "npm")
        assert len(alerts) == 1
        assert "executable" in alerts[0].reason.lower()

    def test_pip_expected_dirs(self):
        added = [FileEntry("/usr/local/lib/python3.12/site-packages/requests/api.py", "644", 500)]
        alerts = check_suspicious_files(added, [], "pip")
        assert len(alerts) == 0

    def test_harmless_lockfile_no_alert(self):
        added = [FileEntry("/app/package-lock.json", "644", 50000)]
        alerts = check_suspicious_files(added, [], "npm")
        assert len(alerts) == 0


class TestIsExecutable:
    def test_755_is_executable(self):
        assert _is_executable("755") is True

    def test_644_is_not_executable(self):
        assert _is_executable("644") is False

    def test_700_is_executable(self):
        assert _is_executable("700") is True

    def test_invalid_returns_false(self):
        assert _is_executable("xyz") is False


class TestSnapshotContainer:
    @patch("fenceline.install.fsdiff.subprocess.run")
    def test_returns_parsed_files(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/app/file.js\t644\t100\n",
        )
        files = snapshot_container("docker", "abc123")
        assert "/app/file.js" in files

    @patch("fenceline.install.fsdiff.subprocess.run")
    def test_returns_empty_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        files = snapshot_container("docker", "abc123")
        assert files == {}

    @patch("fenceline.install.fsdiff.subprocess.run")
    def test_returns_empty_on_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)
        files = snapshot_container("docker", "abc123")
        assert files == {}


class TestPthFileDetection:
    """Detect malicious .pth files — used in TeamPCP/LiteLLM attack."""

    def test_unknown_pth_file_is_critical(self):
        """A new .pth file from a package install is a critical alert."""
        added = [FileEntry(
            path="/usr/local/lib/python3.12/site-packages/evil.pth",
            permissions="644", size=50,
        )]
        alerts = check_suspicious_files(added, [], "pip")
        pth_alerts = [a for a in alerts if ".pth" in a.reason]
        assert len(pth_alerts) == 1
        assert pth_alerts[0].severity == "critical"
        assert "TeamPCP" in pth_alerts[0].reason

    def test_known_pth_files_are_allowed(self):
        """Legitimate .pth files (easy-install, setuptools) should not alert."""
        added = [
            FileEntry(
                path="/usr/local/lib/python3.12/site-packages/easy-install.pth",
                permissions="644", size=200,
            ),
            FileEntry(
                path="/usr/local/lib/python3.12/site-packages/setuptools.pth",
                permissions="644", size=50,
            ),
            FileEntry(
                path="/usr/local/lib/python3.12/site-packages/distutils-precedence.pth",
                permissions="644", size=30,
            ),
        ]
        alerts = check_suspicious_files(added, [], "pip")
        pth_alerts = [a for a in alerts if ".pth" in a.reason]
        assert len(pth_alerts) == 0

    def test_pth_in_npm_install_is_critical(self):
        """A .pth file appearing during npm install is very suspicious."""
        added = [FileEntry(
            path="/app/node_modules/.hidden/backdoor.pth",
            permissions="644", size=100,
        )]
        alerts = check_suspicious_files(added, [], "npm")
        pth_alerts = [a for a in alerts if ".pth" in a.reason]
        assert len(pth_alerts) == 1
        assert pth_alerts[0].severity == "critical"

    def test_virtualenv_pth_is_allowed(self):
        """_virtualenv.pth is a known legitimate .pth file."""
        added = [FileEntry(
            path="/usr/local/lib/python3.12/site-packages/_virtualenv.pth",
            permissions="644", size=30,
        )]
        alerts = check_suspicious_files(added, [], "pip")
        pth_alerts = [a for a in alerts if ".pth" in a.reason]
        assert len(pth_alerts) == 0

#!/usr/bin/env python3
import json
import pathlib
import subprocess
import unittest
from unittest import mock

from obstacle_bridge import bridge_swift_tun_helper as swift_helper


class SwiftTunHelperBuildTests(unittest.TestCase):
    def test_identity_matches_only_embedded_commit_dirty_and_diff(self):
        expected = {"commit": "abc123", "dirty": False, "diff_sha": "def456"}
        self.assertTrue(swift_helper._identity_matches(dict(expected), expected))
        self.assertFalse(swift_helper._identity_matches({**expected, "commit": "old"}, expected))
        self.assertFalse(swift_helper._identity_matches({**expected, "dirty": True}, expected))
        self.assertFalse(swift_helper._identity_matches({**expected, "diff_sha": "other"}, expected))

    def test_dirty_checkout_rebuilds_even_when_embedded_identity_matches(self):
        root = pathlib.Path("/repo")
        artifact = root / "build/linux/ObstacleBridgeLinux"
        expected = {"commit": "abc123", "dirty": True, "diff_sha": "def456"}
        completed = mock.Mock()
        with mock.patch.object(swift_helper.sys, "platform", "linux"), \
             mock.patch.object(swift_helper, "_repository_root", return_value=root), \
             mock.patch.object(swift_helper, "expected_build_identity", return_value=expected), \
             mock.patch.object(swift_helper, "_artifact_path", return_value=artifact), \
             mock.patch.object(swift_helper, "_embedded_build_identity", return_value=dict(expected)), \
             mock.patch.object(swift_helper.subprocess, "run", return_value=completed) as run:
            self.assertEqual(swift_helper.ensure_linux_swift_tun_helper(), str(artifact))
        self.assertEqual(run.call_args.args[0], [str(root / "scripts/build_linux_app.sh")])

    def test_clean_matching_checkout_reuses_embedded_artifact(self):
        root = pathlib.Path("/repo")
        artifact = root / "build/linux/ObstacleBridgeLinux"
        expected = {"commit": "abc123", "dirty": False, "diff_sha": ""}
        with mock.patch.object(swift_helper.sys, "platform", "linux"), \
             mock.patch.object(swift_helper, "_repository_root", return_value=root), \
             mock.patch.object(swift_helper, "expected_build_identity", return_value=expected), \
             mock.patch.object(swift_helper, "_artifact_path", return_value=artifact), \
             mock.patch.object(swift_helper, "_embedded_build_identity", return_value=dict(expected)), \
             mock.patch.object(swift_helper.subprocess, "run") as run:
            self.assertEqual(swift_helper.ensure_linux_swift_tun_helper(), str(artifact))
        run.assert_not_called()

    def test_embedded_identity_is_read_from_binary_protocol(self):
        artifact = pathlib.Path("/opt/ObstacleBridgeLinux")
        completed = subprocess.CompletedProcess(
            args=[str(artifact), "--helper-build-info"],
            returncode=0,
            stdout=json.dumps({"commit": "abc123", "dirty": False, "diff_sha": ""}),
            stderr="",
        )
        with mock.patch.object(pathlib.Path, "is_file", return_value=True), \
             mock.patch.object(pathlib.Path, "__fspath__", return_value=str(artifact)), \
             mock.patch.object(swift_helper.os, "access", return_value=True), \
             mock.patch.object(swift_helper.subprocess, "run", return_value=completed) as run:
            self.assertEqual(swift_helper._embedded_build_identity(artifact)["commit"], "abc123")
        self.assertEqual(run.call_args.args[0], [str(artifact), "--helper-build-info"])

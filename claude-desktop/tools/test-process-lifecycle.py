"""Regression checks for exited-process handles; no proxy or app is launched."""
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import env


class LifecycleTests(unittest.TestCase):
    def test_live_process_identity(self):
        info = env.process_info(os.getpid())
        self.assertEqual(info['pid'], os.getpid())
        self.assertEqual(info['exe'], os.path.normcase(os.path.abspath(sys.executable)))
        self.assertGreater(info['created'], 0)

    def test_exited_child_with_retained_handle(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            child.wait(timeout=10)
            # Keep Popen (and its native process handle) alive during this check.
            self.assertIsNone(env.process_info(child.pid))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)

    def fake_kernel(self, waits):
        kernel = Mock()
        kernel.OpenProcess.return_value = 42
        kernel.WaitForSingleObject.side_effect = waits
        def failed_query(*args):
            ctypes.set_last_error(31)
            return 0
        kernel.QueryFullProcessImageNameW.side_effect = failed_query
        return kernel

    def test_retained_exited_handle_skips_query_and_closes(self):
        kernel = self.fake_kernel([0])
        with patch.object(env.ctypes, 'WinDLL', return_value=kernel):
            self.assertIsNone(env.process_info(123))
        kernel.QueryFullProcessImageNameW.assert_not_called()
        kernel.TerminateProcess.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(42)

    def test_exit_during_path_query(self):
        kernel = self.fake_kernel([0x102, 0])
        with patch.object(env.ctypes, 'WinDLL', return_value=kernel):
            self.assertIsNone(env.process_info(123))
        kernel.CloseHandle.assert_called_once_with(42)

    def test_live_query_error_is_not_ignored(self):
        kernel = self.fake_kernel([0x102, 0x102])
        with patch.object(env.ctypes, 'WinDLL', return_value=kernel):
            with self.assertRaises(OSError) as caught:
                env.process_info(123)
        self.assertEqual(caught.exception.winerror, 31)
        kernel.TerminateProcess.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(42)

    def test_wait_error_is_not_ignored(self):
        kernel = self.fake_kernel([0xffffffff])
        with patch.object(env.ctypes, 'WinDLL', return_value=kernel):
            ctypes.set_last_error(5)
            with self.assertRaises(OSError):
                env.process_info(123)
        kernel.QueryFullProcessImageNameW.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(42)

    def test_unknown_port_owner_still_blocks_start(self):
        with patch.object(env, 'owned_state', return_value=None), \
             patch.object(env, 'listener_pids', return_value={123}), \
             patch.object(env.RUNTIME.__class__, 'mkdir'), \
             patch.object(env.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, 'unverified process'):
                env.start()
            launch.assert_not_called()

    def test_mismatched_process_identity_cannot_be_stopped(self):
        # Requesting TERMINATE access is harmless; identity must fail before use.
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            env.process_info(os.getpid(), terminate=True, expected={})


if __name__ == '__main__':
    unittest.main(verbosity=2)

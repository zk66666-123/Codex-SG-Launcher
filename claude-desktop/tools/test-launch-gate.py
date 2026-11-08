"""Offline regression of the preflight gate. No installed app, network or scheduler is used."""
import subprocess
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import env


class LaunchGateTests(unittest.TestCase):
    def setup_mocks(self):
        stack = self.enterContext(ExitStack()) if hasattr(self, 'enterContext') else ExitStack()
        self.addCleanup(stack.close)
        def mock(name, **kwargs):
            return stack.enter_context(patch.object(env, name, **kwargs))
        self.store = mock('store_desktop_info', return_value={'path': Path('sample/Claude.exe'), 'aumid': 'package!app'})
        self.existing = mock('desktop_processes', side_effect=[[], [{'ProcessId': 112, 'UsesProxy': True}]])
        self.guard = mock('ensure_desktop_guard')
        self.start = mock('start')
        self.activate = mock('activate_store_app', return_value=112)
        self.present=stack.enter_context(patch.object(Path, 'is_file', return_value=False))
        stack.enter_context(patch.object(Path, 'glob', return_value=[]))
        stack.enter_context(patch.object(Path, 'read_text', return_value='fixture-config'))
        self.write = stack.enter_context(patch.object(Path, 'write_text'))
        self.stack=stack

    def test_missing_store_package_blocks(self):
        self.setup_mocks()
        self.store.return_value=None
        with self.assertRaisesRegex(RuntimeError, 'not installed'): env.desktop()
        self.guard.assert_not_called(); self.start.assert_not_called(); self.activate.assert_not_called()

    def test_existing_app_blocks_before_guard(self):
        self.setup_mocks(); self.existing.side_effect=[[{'ProcessId': 1}]]
        with self.assertRaises(RuntimeError): env.desktop()
        self.guard.assert_not_called(); self.start.assert_not_called(); self.activate.assert_not_called()

    def test_failed_guard_blocks_proxy_and_app(self):
        self.setup_mocks(); self.guard.side_effect=RuntimeError('guard failed')
        with self.assertRaisesRegex(RuntimeError, 'guard failed'): env.desktop()
        self.start.assert_not_called(); self.activate.assert_not_called()

    def test_occupied_port_blocks_activation(self):
        self.setup_mocks(); self.start.side_effect=RuntimeError('port occupied')
        with self.assertRaisesRegex(RuntimeError, 'port occupied'): env.desktop()
        self.activate.assert_not_called()

    def test_explicit_rollback_uses_original_proxy_only_mode(self):
        with patch.object(Path, 'is_file', return_value=True), patch.object(env.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'Protection explicitly removed. Using the original proxy-only launcher.', '')):
            env.ensure_desktop_guard('test.exe')

    def test_standalone_preferred_and_receives_proxy_environment(self):
        self.setup_mocks(); self.present.return_value=True
        proc=self.stack.enter_context(patch.object(env.subprocess,'Popen'))
        proc.return_value.pid=112
        env.desktop()
        self.store.assert_not_called(); self.activate.assert_not_called()
        actual=proc.call_args.kwargs['env']
        self.assertEqual(actual['HTTP_PROXY'],env.PROXY)
        self.assertEqual(actual['HTTPS_PROXY'],env.PROXY)
        self.assertIn('--proxy-server='+env.PROXY,proc.call_args.args[0])

    def test_verified_launch_records_success(self):
        self.setup_mocks()
        calls=[]
        self.guard.side_effect=lambda *args:calls.append('guard')
        self.start.side_effect=lambda:calls.append('proxy')
        def activate(aumid,args):
            self.assertEqual(aumid, 'package!app')
            self.assertEqual(args[0],'--proxy-server=http://127.0.0.1:7898')
            calls.append('app'); return 112
        self.activate.side_effect=activate
        env.desktop()
        self.assertEqual(calls,['guard','proxy','app']); self.write.assert_called_once()


if __name__ == '__main__': unittest.main(verbosity=2)

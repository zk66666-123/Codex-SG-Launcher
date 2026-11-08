"""Local instance lifecycle and application launchers (Windows, stdlib only)."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import uuid

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'mihomo-claude.exe'
RUNTIME = ROOT / 'runtime'
STATE = RUNTIME / 'process.json'
PORT = 7898
PROXY = f'http://127.0.0.1:{PORT}'

def process_info(pid, terminate=False, expected=None):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    # SYNCHRONIZE lets us distinguish an exited process object from a live one.
    # Windows can retain an exited PID while another process still owns a handle.
    handle = kernel.OpenProcess(0x1000 | 0x100000 | (1 if terminate else 0), False, int(pid))
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return None
        raise OSError(error, 'Unable to verify process identity')
    try:
        def has_exited():
            status = kernel.WaitForSingleObject(handle, 0)
            if status == 0:  # WAIT_OBJECT_0: process has terminated
                return True
            if status == 0x102:  # WAIT_TIMEOUT: process is still running
                return False
            if status == 0xffffffff:  # WAIT_FAILED
                raise ctypes.WinError(ctypes.get_last_error())
            raise RuntimeError(f'Unexpected process wait status: 0x{status:08X}')

        if has_exited():
            return None
        size = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(size.value)
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
            error = ctypes.get_last_error()
            if has_exited():  # Handle exit racing with the identity query.
                return None
            raise ctypes.WinError(error)
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            error = ctypes.get_last_error()
            if has_exited():
                return None
            raise ctypes.WinError(error)
        info = {'pid': int(pid), 'exe': os.path.normcase(os.path.abspath(path.value)), 'created': (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}
        if terminate:
            if info != expected or info['exe'] != os.path.normcase(str(CORE)):
                raise RuntimeError('Process identity changed; refusing to stop it.')
            if not kernel.TerminateProcess(handle, 0):
                raise ctypes.WinError(ctypes.get_last_error())
        return info
    finally:
        kernel.CloseHandle(handle)

def listener_pids():
    output = subprocess.check_output(['netstat.exe', '-ano', '-p', 'tcp'], text=True, errors='replace', creationflags=subprocess.CREATE_NO_WINDOW)
    found = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[0] == 'TCP' and fields[3] == 'LISTENING' and fields[1].rsplit(':', 1)[-1] == str(PORT):
            found.add(int(fields[4]))
    return found

def owned_state():
    if not STATE.exists():
        return None
    saved = json.loads(STATE.read_text(encoding='utf-8'))
    live = process_info(saved['pid'])
    if live == saved and live['exe'] == os.path.normcase(str(CORE)):
        return saved
    return None

def start():
    RUNTIME.mkdir(exist_ok=True)
    saved = owned_state()
    listeners = listener_pids()
    if saved and listeners == {saved['pid']}:
        print(f'[OK] This instance is already running: {PROXY} (PID {saved["pid"]})')
        return
    if listeners:
        raise RuntimeError('Port 7898 is used by an unverified process. Nothing was stopped.')
    if saved:
        raise RuntimeError('The recorded process is running without its port; inspect runtime logs or stop.cmd.')
    if not CORE.is_file() or not (ROOT / 'config.yaml').is_file():
        raise RuntimeError('Missing mihomo-claude.exe or config.yaml.')
    with (RUNTIME / 'validation.log').open('wb') as log:
        check = subprocess.run([str(CORE), '-t', '-d', str(ROOT), '-f', str(ROOT / 'config.yaml')], stdout=log, stderr=subprocess.STDOUT, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    if check.returncode:
        raise RuntimeError('Configuration validation failed. See runtime/validation.log locally.')
    with (RUNTIME / 'core.log').open('ab') as log:
        child = subprocess.Popen([str(CORE), '-d', str(ROOT), '-f', str(ROOT / 'config.yaml')], cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP, close_fds=True)
    try:
        identity = process_info(child.pid)
        if not identity:
            raise RuntimeError('Core exited during startup.')
        STATE.write_text(json.dumps(identity, indent=2) + '\n', encoding='utf-8')
        for _ in range(40):
            if child.poll() is not None:
                raise RuntimeError('Core exited during startup. See runtime/core.log locally.')
            if listener_pids() == {child.pid}:
                print(f'[OK] Started {PROXY} (PID {child.pid})')
                return
            time.sleep(0.25)
        raise RuntimeError('Startup timed out. See runtime/core.log locally.')
    except Exception:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        raise

def stop():
    saved = owned_state()
    if not saved:
        print('[OK] No verified process from this folder is running.')
        return
    process_info(saved['pid'], terminate=True, expected=saved)
    for _ in range(40):
        if not process_info(saved['pid']):
            STATE.unlink(missing_ok=True)
            print('[OK] Stopped this instance. Other proxy instances were not stopped.')
            return
        time.sleep(0.1)
    raise RuntimeError('Stop did not complete; process state retained for inspection.')

def proxy_settings():
    return {key: value for key, value in [('HTTP_PROXY', PROXY), ('HTTPS_PROXY', PROXY), ('http_proxy', PROXY), ('https_proxy', PROXY), ('NO_PROXY', 'localhost,127.0.0.1,::1'), ('no_proxy', 'localhost,127.0.0.1,::1')]}

def store_desktop_info():
    powershell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    command = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); Get-AppxPackage -Name 'Claude' | Select-Object InstallLocation,PackageFamilyName | ConvertTo-Json -Compress"
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('Could not inspect the installed Store package.')
    if not result.stdout.strip():
        return None
    packages = json.loads(result.stdout)
    if isinstance(packages, dict):
        packages = [packages]
    for item in packages:
        package = Path(item['InstallLocation'])
        manifest = package / 'AppxManifest.xml'
        if not manifest.is_file():
            continue
        for entry in ET.parse(manifest).getroot().iter():
            if entry.tag.rsplit('}', 1)[-1] == 'Application' and entry.get('Id') == 'Claude':
                app = (package / entry.attrib['Executable']).resolve()
                if not app.is_relative_to(package.resolve()):
                    raise RuntimeError('Unexpected Store application path.')
                if app.is_file():
                    return {'path': app, 'aumid': item['PackageFamilyName'] + '!' + entry.attrib['Id']}
    return None

def activate_store_app(aumid, arguments):
    # Use the supported Windows application activation API; do not modify WindowsApps permissions.
    class GUID(ctypes.Structure):
        _fields_ = [('data1', wintypes.DWORD), ('data2', wintypes.WORD), ('data3', wintypes.WORD), ('data4', ctypes.c_ubyte * 8)]
    ole = ctypes.OleDLL('ole32')
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    ole.CoCreateInstance.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
    ole.CoCreateInstance.restype = ctypes.c_long
    initialized = ole.CoInitializeEx(None, 2)
    if initialized < 0:
        raise OSError(f'COM initialization failed: 0x{initialized & 0xffffffff:08X}')
    manager = ctypes.c_void_p()
    try:
        clsid = GUID.from_buffer_copy(uuid.UUID('45BA127D-10A8-46EA-8AB7-56EA9078943C').bytes_le)
        iid = GUID.from_buffer_copy(uuid.UUID('2E941141-7F97-4756-BA1D-9DECDE894A3D').bytes_le)
        hr = ole.CoCreateInstance(ctypes.byref(clsid), None, 4, ctypes.byref(iid), ctypes.byref(manager))
        if hr < 0:
            raise OSError(f'Application activation unavailable: 0x{hr & 0xffffffff:08X}')
        table = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        activate = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))(table[3])
        pid = wintypes.DWORD()
        hr = activate(manager, aumid, subprocess.list2cmdline(arguments), 0, ctypes.byref(pid))
        if hr < 0:
            raise OSError(f'Store app activation failed: 0x{hr & 0xffffffff:08X}')
        return pid.value
    finally:
        if manager:
            table = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(table[2])(manager)
        ole.CoUninitialize()

def desktop_processes(app):
    # Match the installed desktop executable, not unrelated Claude Code binaries.
    powershell = Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    command = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; @(Get-CimInstance Win32_Process -Filter \"Name='claude.exe'\" | Select-Object ProcessId,ExecutablePath,@{N='UsesProxy';E={$_.CommandLine -match '--proxy-server=http://127[.]0[.]0[.]1:7898(?:\\s|$|\")'}}) | ConvertTo-Json -Compress"
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('无法检查 Claude 桌面进程，未继续启动。')
    processes = json.loads(result.stdout) if result.stdout.strip() else []
    if isinstance(processes, dict):
        processes = [processes]
    if any(not item.get('ExecutablePath') for item in processes):
        raise RuntimeError('无法核对某个 Claude 进程的路径，请退出该进程后重试。')
    expected = os.path.normcase(os.path.abspath(app))
    return [item for item in processes if os.path.normcase(os.path.abspath(item['ExecutablePath'])) == expected]


def ensure_desktop_guard(app):
    """Require a fresh privileged inventory/rule check before application activation."""
    script = Path(os.environ['PROGRAMFILES']) / 'Claude7898Guard' / 'ManageClaudeGuard.ps1'
    if not script.is_file():
        raise RuntimeError('Claude 防直连维护程序缺失，未启动桌面版。请先修复保护安装。')
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    # A launcher started from PowerShell 7 must not feed its module search path
    # into Windows PowerShell 5.1. This changes only the helper's environment.
    child_env = {key: value for key, value in os.environ.items()
                 if key.upper() != 'PSMODULEPATH'}
    child_env['PSModulePath'] = str(powershell.parent / 'Modules')
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    command = (
        '[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); '
        f'& {quote(script)} -Mode Prepare -Target {quote(app)}; exit $LASTEXITCODE'
    )
    result = subprocess.run(
        [str(powershell), '-NoProfile', '-NonInteractive', '-Command', command],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=115,
        env=child_env,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise RuntimeError('Claude 防直连检查未通过，未启动桌面版。\n' + result.stdout + result.stderr)
    print(result.stdout.strip())


def desktop():
    base = Path(os.environ['LOCALAPPDATA'])
    choices = [base / 'AnthropicClaude/claude.exe', base / 'Programs/Claude/Claude.exe', base / 'Claude/claude.exe', Path(os.environ['PROGRAMFILES']) / 'Claude/Claude.exe']
    choices += sorted((base / 'AnthropicClaude').glob('app-*/claude.exe'), reverse=True)
    app = next((p for p in choices if p.is_file()), None)
    store = None
    if not app:
        store = store_desktop_info()
        app = store['path'] if store else None
    if not app:
        raise RuntimeError('Claude Desktop is not installed in a supported location.')
    if desktop_processes(app):
        raise RuntimeError('Claude 桌面版已在运行。请先保存工作，并从托盘完全退出 Claude，再双击本启动器。未关闭任何进程。')
    ensure_desktop_guard(app)
    start()
    env = os.environ.copy()
    env.update(proxy_settings())
    arguments = [f'--proxy-server={PROXY}', '--proxy-bypass-list=localhost;127.0.0.1', *sys.argv[2:]]
    if store:
        pid = activate_store_app(store['aumid'], arguments)
    else:
        pid = subprocess.Popen([str(app), *arguments], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True).pid
    verified = any(item['ProcessId'] == pid and item['UsesProxy'] for item in desktop_processes(app))
    if not verified:
        raise RuntimeError('Claude 已启动，但未确认 7898 代理参数生效；请完全退出桌面版后重试。')
    (RUNTIME / 'desktop-launch.json').write_text(json.dumps({'pid': pid, 'path': str(app), 'store_activation': bool(store), 'proxy': PROXY}, indent=2) + '\n', encoding='utf-8')
    print('[OK] Desktop launched; main process proxy argument verified: ' + PROXY)

if __name__ == '__main__':
    try:
        actions = {'start': start, 'stop': stop, 'desktop': desktop}
        if len(sys.argv) < 2 or sys.argv[1] not in actions:
            raise RuntimeError('Usage: env.py start|stop|desktop')
        actions[sys.argv[1]]()
    except Exception as exc:
        print(f'[ERROR] {exc}', file=sys.stderr)
        sys.exit(1)

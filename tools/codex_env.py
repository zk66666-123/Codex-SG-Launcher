"""Codex 新加坡出口启动器：生命周期 + 健康门禁 + 启动注入（Windows, stdlib only）。

用法: codex_env.py start | stop | status | check [--no-guard]
                   | run [--no-guard] [--] <codex 参数...> | app [--no-guard] [<桌面版参数...>]
"""
import ctypes
from ctypes import wintypes
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'mihomo.exe'
CONFIG = ROOT / 'config.yaml'
RUNTIME = ROOT / 'runtime'
STATE = RUNTIME / 'process.json'
AUTOSYNC_GUARD = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'CodexSG' / 'ManageCodexGuard.ps1'
GUARD = AUTOSYNC_GUARD if AUTOSYNC_GUARD.is_file() else ROOT / 'tools' / 'ManageCodexGuard.ps1'
AUTOSYNC_TASK = 'CodexSG-GuardSync'
PORT = 7899
PROXY = f'http://127.0.0.1:{PORT}'
NO_PROXY = 'localhost,127.0.0.1,::1'
TRACE = 'https://www.cloudflare.com/cdn-cgi/trace'
POWERSHELL = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
NOWIN = subprocess.CREATE_NO_WINDOW


def log(msg, quiet=False):
    RUNTIME.mkdir(exist_ok=True)
    with (RUNTIME / 'launcher.log').open('a', encoding='utf-8') as f:
        f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + msg + '\n')
    if not quiet:
        print(msg)


# ---------- 进程身份（PID + exe 全路径 + 创建时间） ----------

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
    handle = kernel.OpenProcess(0x1000 | 0x100000 | (1 if terminate else 0), False, int(pid))
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return None
        raise OSError(error, 'Unable to verify process identity')
    try:
        if kernel.WaitForSingleObject(handle, 0) == 0:
            return None
        size = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(size.value)
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
            if kernel.WaitForSingleObject(handle, 0) == 0:
                return None
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        info = {'pid': int(pid), 'exe': os.path.normcase(os.path.abspath(path.value)),
                'created': (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}
        if terminate:
            if info != expected or info['exe'] != os.path.normcase(str(CORE)):
                raise RuntimeError('进程身份已变化，拒绝停止。')
            if not kernel.TerminateProcess(handle, 0):
                raise ctypes.WinError(ctypes.get_last_error())
        return info
    finally:
        kernel.CloseHandle(handle)


def listeners():
    """{(本地地址, PID)}：端口 7899 上所有 LISTENING（含 IPv6）。"""
    out = subprocess.check_output(['netstat.exe', '-ano'], text=True, errors='replace', creationflags=NOWIN)
    found = set()
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == 'TCP' and f[3] == 'LISTENING' and f[1].rsplit(':', 1)[-1] == str(PORT):
            found.add((f[1].rsplit(':', 1)[0], int(f[4])))
    return found


def owned_state():
    if not STATE.exists():
        return None
    saved = json.loads(STATE.read_text(encoding='utf-8'))
    live = process_info(saved['pid'])
    if live == saved and live['exe'] == os.path.normcase(str(CORE)):
        return saved
    return None


# ---------- ① 监听锁 + ② 规则锁：配置静态检查 ----------

def lint_config():
    text = re.sub(r'(^|\s)#.*', r'\1', CONFIG.read_text(encoding='utf-8'))
    for key, want in {'mixed-port': '7899', 'bind-address': '127.0.0.1', 'allow-lan': 'false', 'ipv6': 'false'}.items():
        m = re.search(rf'^{key}:\s*[\'"]?([^\s\'"]+)', text, re.M)
        if not m or m.group(1).lower() != want:
            raise RuntimeError(f'config.yaml 必须写 {key}: {want}（监听锁）')
    if re.search(r'^(port|socks-port|redir-port|tproxy-port):', text, re.M):
        raise RuntimeError('config.yaml 只允许 mixed-port 一个入站端口。')
    if re.search(r'^tun:\s*\n\s+enable:\s*true', text, re.M):
        raise RuntimeError('config.yaml 不允许开启 tun。')
    if re.search(r'\bDIRECT\b', text) or re.search(r'type:\s*(url-test|fallback|load-balance)', text):
        raise RuntimeError('config.yaml 出现 DIRECT 或 url-test/fallback/load-balance 组（规则锁）。')
    block = re.search(r'^rules:[ \t]*\n((?:[ \t]*-.*\n?|[ \t]+.*\n?|[ \t]*\n)*)', text, re.M)
    rules = [l.strip()[1:].strip() for l in (block.group(1) if block else '').splitlines() if l.strip().startswith('-')]
    if len(rules) != 1 or not rules[0].startswith('MATCH,'):
        raise RuntimeError('config.yaml 的 rules 只能有一条 MATCH,<新加坡节点>（规则锁）。')


# ---------- 生命周期 ----------

def start():
    RUNTIME.mkdir(exist_ok=True)
    saved = owned_state()
    ls = listeners()
    if saved and ls == {('127.0.0.1', saved['pid'])}:
        print(f'[OK] 本目录代理已在运行：{PROXY}（PID {saved["pid"]}）')
        return
    if ls:
        raise RuntimeError(f'Port {PORT} is used by an unverified process: {sorted(ls)}。未停止任何进程。')
    if saved:
        raise RuntimeError('记录的进程在跑但端口没监听；看 runtime\\core.log 或运行 stop.cmd。')
    if not CORE.is_file() or not CONFIG.is_file():
        raise RuntimeError('缺少 mihomo.exe 或 config.yaml（从 config.example.yaml 复制并填好节点）。')
    lint_config()
    with (RUNTIME / 'validation.log').open('wb') as f:
        check = subprocess.run([str(CORE), '-t', '-d', str(ROOT), '-f', str(CONFIG)], stdout=f,
                               stderr=subprocess.STDOUT, timeout=30, creationflags=NOWIN)
    if check.returncode:
        raise RuntimeError('配置校验失败，见 runtime\\validation.log。')
    with (RUNTIME / 'core.log').open('ab') as f:
        child = subprocess.Popen([str(CORE), '-d', str(ROOT), '-f', str(CONFIG)], cwd=ROOT, stdin=subprocess.DEVNULL,
                                 stdout=f, stderr=subprocess.STDOUT, close_fds=True,
                                 creationflags=NOWIN | subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        identity = process_info(child.pid)
        if not identity:
            raise RuntimeError('mihomo 启动即退出，见 runtime\\core.log。')
        STATE.write_text(json.dumps(identity, indent=2) + '\n', encoding='utf-8')
        for _ in range(40):
            if child.poll() is not None:
                raise RuntimeError('mihomo 启动即退出，见 runtime\\core.log。')
            ls = listeners()
            if ls == {('127.0.0.1', child.pid)}:
                log(f'[OK] 已启动 {PROXY}（PID {child.pid}）')
                return
            if ls and ls != {('127.0.0.1', child.pid)}:
                raise RuntimeError(f'监听地址不对：{sorted(ls)}，只允许 127.0.0.1。')
            time.sleep(0.25)
        raise RuntimeError('mihomo 启动超时，见 runtime\\core.log。')
    except Exception:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        STATE.unlink(missing_ok=True)
        raise


def stop():
    saved = owned_state()
    if not saved:
        print('[OK] 本目录没有正在运行且身份一致的代理。')
        return
    process_info(saved['pid'], terminate=True, expected=saved)
    for _ in range(40):
        if not process_info(saved['pid']):
            STATE.unlink(missing_ok=True)
            log('[OK] 已停止本目录代理；其它代理实例未受影响。')
            return
        time.sleep(0.1)
    raise RuntimeError('停止未完成，保留进程记录以便排查。')


# ---------- ④ 启动锁：健康门禁 ----------

def exit_trace():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': PROXY, 'https': PROXY}))
    with opener.open(TRACE, timeout=15) as r:
        body = r.read().decode('utf-8', 'replace')
    kv = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    return kv.get('ip', ''), kv.get('loc', '')


def guard_check():
    if not GUARD.is_file():
        return False, 'ManageCodexGuard.ps1 缺失'
    r = subprocess.run([str(POWERSHELL), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                        '-File', str(GUARD), '-Mode', 'Check'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60, creationflags=NOWIN)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def gate(no_guard=False):
    saved = owned_state()
    ls = listeners()
    if not saved or ls != {('127.0.0.1', saved['pid'])}:
        raise RuntimeError(f'端口 {PORT} 归属核验失败（监听：{sorted(ls) or "无"}），拒绝启动。')
    try:
        ip, loc = exit_trace()
    except Exception as exc:
        raise RuntimeError(f'出口自检请求失败（{exc}），拒绝启动。')
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise RuntimeError(f'出口自检返回的 ip 无效：{ip!r}，拒绝启动。')
    if addr.version != 4 or not addr.is_global:
        raise RuntimeError(f'出口不是公网 IPv4（ip={ip}），拒绝启动。')
    if loc != 'SG':
        raise RuntimeError(f'出口国家不是 SG（loc={loc}），拒绝启动。')
    if no_guard:
        log('[WARN] --no-guard：跳过守护层检查（已留痕）。')
    else:
        ok, detail = guard_check()
        if not ok and 'unguarded' in detail and GUARD == AUTOSYNC_GUARD:
            log('[INFO] 检测到 Codex 更新，自动同步守护层…')
            r = subprocess.run(['schtasks', '/run', '/tn', AUTOSYNC_TASK], capture_output=True,
                               text=True, errors='replace', creationflags=NOWIN)
            if r.returncode == 0:
                for _ in range(30):
                    time.sleep(3)
                    ok, detail = guard_check()
                    if ok:
                        log('[OK] 守护层已自动同步。')
                        break
            else:
                detail += '\n自动同步任务启动失败：' + (r.stdout + r.stderr).strip()
            raise RuntimeError('守护层未 active，拒绝启动。先以管理员运行 '
                               'tools\\ManageCodexGuard.ps1 -Mode Install，或显式加 --no-guard。\n' + detail)
    log(f'[OK] 自检通过：{PROXY} → ip={ip} loc=SG' + ('' if no_guard else '，守护层 active'))


def proxy_env():
    # Windows 环境变量不区分大小写，大写一套即覆盖 http_proxy/https_proxy/no_proxy。
    env = os.environ.copy()
    env.update({'HTTP_PROXY': PROXY, 'HTTPS_PROXY': PROXY, 'ALL_PROXY': PROXY, 'NO_PROXY': NO_PROXY})
    return env


def split_flags(args):
    no_guard = bool(args) and args[0] == '--no-guard'
    if no_guard:
        args = args[1:]
    if args and args[0] == '--':
        args = args[1:]
    return no_guard, args


# ---------- 命令 ----------

def codex_cli():
    js = Path(os.environ.get('APPDATA', '')) / 'npm/node_modules/@openai/codex/bin/codex.js'
    node = shutil.which('node')
    if js.is_file() and node:
        return [node, str(js)]
    exe = shutil.which('codex')
    if exe:
        return [exe]
    raise RuntimeError('找不到 codex CLI（npm i -g @openai/codex）。')


def run(args):
    no_guard, args = split_flags(args)
    cmd = codex_cli()
    start()
    gate(no_guard)
    log(f'[RUN] {" ".join(cmd)} {" ".join(args)}'.rstrip(), quiet=True)
    child = subprocess.Popen(cmd + args, env=proxy_env())
    while True:
        try:
            return child.wait()
        except KeyboardInterrupt:
            continue  # Ctrl+C 交给 codex 自己处理


def store_app():
    command = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
               "Get-AppxPackage -Name 'OpenAI.Codex' | Select-Object InstallLocation,PackageFamilyName | ConvertTo-Json -Compress")
    r = subprocess.run([str(POWERSHELL), '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=20, creationflags=NOWIN)
    if r.returncode or not r.stdout.strip():
        raise RuntimeError('没找到 Codex 桌面版（Store 包 OpenAI.Codex）。')
    pkgs = json.loads(r.stdout)
    for item in [pkgs] if isinstance(pkgs, dict) else pkgs:
        base = Path(item['InstallLocation'])
        for entry in ET.parse(base / 'AppxManifest.xml').getroot().iter():
            if entry.tag.rsplit('}', 1)[-1] == 'Application' and entry.get('Id') == 'App':
                exe = (base / entry.attrib['Executable']).resolve()
                if exe.is_file():
                    return exe, item['PackageFamilyName'] + '!App'
    raise RuntimeError('Codex 桌面版包清单里找不到主程序。')


def activate_store_app(aumid, arguments):
    class GUID(ctypes.Structure):
        _fields_ = [('d1', wintypes.DWORD), ('d2', wintypes.WORD), ('d3', wintypes.WORD), ('d4', ctypes.c_ubyte * 8)]
    ole = ctypes.OleDLL('ole32')
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    ole.CoCreateInstance.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
    ole.CoCreateInstance.restype = ctypes.c_long
    ole.CoInitializeEx(None, 2)
    manager = ctypes.c_void_p()
    try:
        clsid = GUID.from_buffer_copy(uuid.UUID('45BA127D-10A8-46EA-8AB7-56EA9078943C').bytes_le)
        iid = GUID.from_buffer_copy(uuid.UUID('2E941141-7F97-4756-BA1D-9DECDE894A3D').bytes_le)
        hr = ole.CoCreateInstance(ctypes.byref(clsid), None, 4, ctypes.byref(iid), ctypes.byref(manager))
        if hr < 0:
            raise OSError(f'ApplicationActivationManager 不可用：0x{hr & 0xffffffff:08X}')
        table = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        activate = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))(table[3])
        pid = wintypes.DWORD()
        hr = activate(manager, aumid, subprocess.list2cmdline(arguments), 0, ctypes.byref(pid))
        if hr < 0:
            raise OSError(f'桌面版激活失败：0x{hr & 0xffffffff:08X}')
        return pid.value
    finally:
        if manager:
            table = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(table[2])(manager)
        ole.CoUninitialize()


def desktop_processes(exe):
    command = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; "
               f"@(Get-CimInstance Win32_Process -Filter \"Name='{exe.name}'\" | Select-Object ProcessId,ExecutablePath,CommandLine) | ConvertTo-Json -Compress")
    r = subprocess.run([str(POWERSHELL), '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=20, creationflags=NOWIN)
    if r.returncode:
        raise RuntimeError('无法检查桌面版进程，未继续。')
    procs = json.loads(r.stdout) if r.stdout.strip() else []
    procs = [procs] if isinstance(procs, dict) else procs
    want = os.path.normcase(str(exe))
    return [p for p in procs if p.get('ExecutablePath') and os.path.normcase(p['ExecutablePath']) == want]


def app(args):
    no_guard, args = split_flags(args)
    exe, aumid = store_app()
    if desktop_processes(exe):
        raise RuntimeError('Codex 桌面版已在运行（未走本启动器的实例可能在直连）。请从托盘完全退出后再启动。未关闭任何进程。')
    start()
    gate(no_guard)
    # Store 激活不继承本进程环境，而是按 HKCU\Environment 现建一份；后台 codex.exe app-server
    # 又继承自主进程。所以只在激活这一刻把代理变量写进 HKCU，拿到 PID 后立即还原。
    import winreg
    keys = {'HTTP_PROXY': PROXY, 'HTTPS_PROXY': PROXY, 'ALL_PROXY': PROXY, 'NO_PROXY': NO_PROXY}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as env_key:
        saved = {}
        for k in keys:
            try:
                saved[k] = winreg.QueryValueEx(env_key, k)
            except FileNotFoundError:
                saved[k] = None
        try:
            for k, v in keys.items():
                winreg.SetValueEx(env_key, k, 0, winreg.REG_SZ, v)
            pid = activate_store_app(aumid, [f'--proxy-server={PROXY}', '--proxy-bypass-list=<-loopback>', *args])
        finally:
            for k, old in saved.items():
                if old is None:
                    try:
                        winreg.DeleteValue(env_key, k)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(env_key, k, 0, old[1], old[0])
    flag = f'--proxy-server={PROXY}'
    for _ in range(20):
        main = [p for p in desktop_processes(exe) if p['ProcessId'] == pid]
        if main and flag in (main[0].get('CommandLine') or ''):
            (RUNTIME / 'desktop-launch.json').write_text(json.dumps(
                {'pid': pid, 'path': str(exe), 'proxy': PROXY}, indent=2) + '\n', encoding='utf-8')
            log(f'[OK] 桌面版已启动（PID {pid}），主进程代理参数已确认：{PROXY}')
            return
        time.sleep(0.5)
    raise RuntimeError('桌面版已激活，但未确认代理参数生效；请完全退出桌面版后重试。')


def status():
    ls = listeners()
    saved = owned_state()
    print(f'端口 {PORT} 监听：{sorted(ls) or "无"}')
    print(f'本目录进程：{"PID %d（身份一致）" % saved["pid"] if saved else "无"}')
    if saved and ls == {('127.0.0.1', saved['pid'])}:
        try:
            ip, loc = exit_trace()
            print(f'出口：ip={ip} loc={loc}' + ('' if loc == 'SG' else '  ← 不是 SG！'))
        except Exception as exc:
            print(f'出口：自检失败（{exc}）')
    ok, detail = guard_check()
    print(f'守护层：{"active" if ok else "未生效"}')
    if detail:
        print('  ' + detail.replace('\n', '\n  '))


def check(args):
    no_guard, _ = split_flags(args)
    gate(no_guard)


if __name__ == '__main__':
    try:
        cmd, rest = (sys.argv[1] if len(sys.argv) > 1 else ''), sys.argv[2:]
        if cmd == 'run':
            sys.exit(run(rest))
        actions = {'start': start, 'stop': stop, 'status': status,
                   'check': lambda: check(rest), 'app': lambda: app(rest)}
        if cmd not in actions:
            raise RuntimeError('用法: codex_env.py start|stop|status|check|run|app')
        actions[cmd]()
    except Exception as exc:
        try:
            log(f'[ERROR] {exc}', quiet=True)
        except Exception:
            pass
        print(f'[ERROR] {exc}', file=sys.stderr)
        sys.exit(1)

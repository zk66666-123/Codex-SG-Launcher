# Claude 桌面版（7898）· Windows

这是现有 **Claude Desktop（7898）** 启动器的便携源码版。沿用原启动顺序：先找独立安装版，找不到再通过 Windows 商店清单定位程序；不接管已经运行的桌面进程。预检返回成功后启动本目录的 Mihomo，再启动桌面版、核对主进程代理参数。独立版同时继承代理环境变量，商店版通过 Windows 应用激活 API 启动。本工具不创建账号，也不改变系统代理。

## 构建

需要 Windows 10/11 x64、.NET Framework 4.8、Visual Studio 2022 Build Tools（C++ 桌面开发、MSVC x64 和 Windows SDK）。在本目录运行 `build.cmd`，**编译不需要管理员权限**。默认会通过 vswhere 查找工具链；也可以从 x64 Native Tools Command Prompt 运行。产物：

- `claude-desktop.exe`：双击入口。必须和 `tools/` 放在一起，不要把 EXE 单独搬到桌面；可给它创建快捷方式。
- `tools/ClaudeNetworkGuard.exe`：维护本工具专用的 Windows Filtering Platform (WFP) 规则。仅编译这两个文件不会启动服务或安装规则。

运行需要 x64 Windows PowerShell 5.1（Appx、Authenticode、任务计划程序可用）和 Python 3.9+（仅标准库）。安装 Python 后保证 `py -3` 或 `python` 可用；多版本环境可把 `CLAUDE7898_PYTHON` 设为本机 Python 3 的 python.exe 完整路径。

## 首次配置

1. 先从托盘退出已安装的 Claude Desktop。启动器识别独立安装版与 Microsoft Store 版，但配套的 **WFP 防护只核验官方 Store 包中的 EXE**。启用防护时，未被清单覆盖的独立版不会通过预检。网页、命令行版、外部解释器与虚拟机网络均不在该防护范围内。
2. 从 [Mihomo 上游发布页](https://github.com/MetaCubeX/mihomo/releases) 获取适合 Windows x64 的正式版，使用上游提供的校验信息核对后，将解压出的程序命名为 `mihomo-claude.exe` 并置于本目录。这里不分发第三方二进制。
3. 将 `config.example.yaml` 复制成 **`config.yaml`**。用自己有权使用的服务填写服务器、协议、凭据与 TLS 主机名；保留 `127.0.0.1:7898` 监听、`allow-lan: false` 以及有效的 TLS 证书校验。示例不会连通任何节点。过滤器仅限制桌面程序到本地代理；Mihomo 如何转发取决于你的配置，不要误配为 DIRECT。
4. 若已有同名防护任务或旧安装，请先核对其归属；不要覆盖来历不明的安装。首次安装由**实际使用这个启动器的同一个 Windows 管理员账号**，在提升权限的 **64 位 Windows PowerShell** 中，从仓库本目录主动执行：

   ```powershell
   .\tools\ManageClaudeGuard.ps1 -Mode Install
   ```

   这一步会核对已注册商店包及出版者签名，将管理脚本、规则助手安装到 `%ProgramFiles%\Claude7898Guard`，写入该工具的持久 WFP 规则，并登记 `Claude7898Guard-Maintenance` 登录/按需维护任务。它不更改 Claude 的更新设置。需要允许按本机正常脚本策略执行经过审阅的本地脚本；不要降低全局执行策略。若拒绝提升权限，可以构建与测试，但桌面启动器不会绕过门禁。

## 日常启动与查看

在普通用户会话中双击 `claude-desktop.exe`。如 Claude 已在运行，先保存工作并从托盘退出。启动器不接管已有 Claude 或不明端口监听者。已安装的守护程序必须完成 Prepare；找不到维护脚本、核验失败或 7898 被其他进程占用时会停止。防护处于活动状态时，会重新核验包内组件与规则；主动撤销后的例外见下文。

可从本目录用 `py -3 tools/env.py stop` 单独停止本实例的 Mihomo（只停止路径、PID、创建时间均匹配的本实例）。可用以下 PowerShell 命令查询已安装状态：

```powershell
& (Join-Path $env:ProgramFiles 'Claude7898Guard\ManageClaudeGuard.ps1') -Mode Status
```

若确实要撤销，先退出 Claude，再由原管理员账号在提升权限的 PowerShell 会话执行：

```powershell
& (Join-Path $env:ProgramFiles 'Claude7898Guard\ManageClaudeGuard.ps1') -Mode Rollback
```

撤销会删除本提供程序的规则和自己的维护任务，保留已撤销状态和维护脚本。**与原启动器一致，主动撤销后 Prepare 成功返回，后续可按仅使用代理参数的模式启动**；这个模式没有 WFP 防直连保护。请不要分享 `config.yaml`、`runtime/` 或管理员状态记录。

## 离线验证

```powershell
py -3 -B tools/test-process-lifecycle.py
py -3 -B tools/test-launch-gate.py
```

第一组检查 PID 复用/结束竞争、端口占用及拒绝误停；第二组模拟未安装、Claude 已运行、守护预检失败、主动撤销后的代理模式、端口冲突、独立版优先及其代理环境，以及商店版正常的“预检→代理→激活”顺序。它们不需要真实节点、登录或安装防护，不代表实机 WFP 拦截、实际出口或账号状态已验证。

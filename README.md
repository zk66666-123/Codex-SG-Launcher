# Codex-SG-Launcher

Windows 上的两个独立启动器。选择所用应用，并在对应目录配置代理。

| 应用 | 本机代理 | 入口 |
| --- | --- | --- |
| Codex CLI / Codex 桌面版 | `127.0.0.1:7899`，启动前检查新加坡 IPv4 出口 | 根目录的 `codex-sg.cmd` / `codex-app-sg.cmd` |
| Claude 桌面版 | `127.0.0.1:7898` | [Claude 桌面版构建与使用](claude-desktop/README.md) |

## 配置 Codex

准备 64 位 Windows、可在终端运行的 Python 3，以及要启动的 Codex CLI 或 Microsoft Store 桌面应用。将 Windows amd64 版 Mihomo 放在仓库根目录并命名为 `mihomo.exe`。原项目使用 v1.19.13。[Mihomo 发布页](https://github.com/MetaCubeX/mihomo/releases)

在仓库根目录执行以下命令，然后在 `config.yaml` 中填写自己的节点地址、密码、TLS 服务器名称和出站网卡。示例使用 Trojan 节点。两套启动器各自读取所在目录的配置文件。

```powershell
Copy-Item .\config.example.yaml .\config.yaml
notepad .\config.yaml
.\mihomo.exe -t -d . -f .\config.yaml
```

## 构建并启动 Codex

在仓库根目录的 PowerShell 中运行以下命令，使用 Windows 自带的 .NET Framework C# 编译器构建 WFP 守护程序和两个可执行入口。

```powershell
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /codepage:65001 /optimize /platform:x64 /out:tools\CodexWfpGuard.exe tools\CodexWfpGuard.cs
& $csc /nologo /codepage:65001 /target:exe /out:codex-sg.exe tools\CodexLauncher.cs
& $csc /nologo /codepage:65001 /target:winexe /define:APP /r:System.Windows.Forms.dll /out:codex-app-sg.exe tools\CodexLauncher.cs
```

首次使用时，在**管理员 Windows PowerShell** 中运行 `.\tools\ManageCodexGuard.ps1 -Mode Install`，为发现的 Codex 可执行文件安装 Windows 筛选平台（WFP）规则。日常使用普通终端运行 `.\codex-sg.cmd` 或 `.\codex-app-sg.cmd`。启动器会核对代理进程、监听端口、出口和守护状态。启动桌面版前请先完全退出已有的 Codex 桌面进程。

- 查看状态用 `.\status.cmd`，停止本目录的代理用 `.\stop.cmd`。
- 更新 Codex 后，以管理员运行 `.\tools\ManageCodexGuard.ps1 -Mode Sync` 重新发现并保护新版程序。
- 可选的 `.\tools\InstallAutoSync.ps1` 需要管理员权限，会安装一个同步规则的计划任务。完整卸载时，先用 `.\tools\InstallAutoSync.ps1 -Uninstall` 移除已安装的自动同步任务，再用 `.\tools\ManageCodexGuard.ps1 -Mode Rollback` 撤销 WFP 规则。

原项目的架构、测试步骤与早期方案记录见[设计笔记](docs/codex-design.md)。

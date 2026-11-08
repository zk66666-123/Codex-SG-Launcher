# Codex 新加坡出口启动器 —— 框架与方法（v0.1 设计稿）

> 状态：**设计稿 + 本机探测结论**，尚未提交实现代码。
> 目标：仿照 `Claude启动器与使用说明` 的做法，让 **Codex CLI 和 Codex 桌面版** 的流量
> 强制走 **IPv4 → 本地端口 → 新加坡节点**，不允许直连、不允许 IPv6、不允许换出口。
> 本方案只处理本机流量走向，不涉及任何账号批量注册。

---

## 0. 一句话架构

**一个专用内核（mihomo）只监听 `127.0.0.1:7899`，唯一出口是新加坡节点；启动器给 Codex 注入代理环境变量并做启动前自检；守护层再把这个进程的其它出站全部堵死。**

```
┌────────────────────────── Windows 本机 ──────────────────────────┐
│                                                                  │
│  codex-sg.cmd ────┐                                              │
│  codex-app-sg.cmd ┤                                              │
│                   ▼                                              │
│         tools\codex_env.py  （启动器 + 健康门禁）                 │
│                   │  ① 端口 7899 归属核验                         │
│                   │  ② 未运行则拉起 mihomo                       │
│                   │  ③ 出口自检：loc=SG，否则拒绝启动             │
│                   │  ④ 注入 HTTPS_PROXY / ALL_PROXY / NO_PROXY    │
│                   ▼                                              │
│   codex.exe / node codex.js ──── TCP 127.0.0.1:7899 ───┐          │
│        │                                               │          │
│        └── 直连 / 其它端口 / IPv6 ──── ✕ 被守护层阻断  │          │
│                                                        ▼          │
│                                                  mihomo.exe       │
│                                       唯一规则 MATCH → 新加坡      │
│                                       仅 IPv4，无 DIRECT 兜底      │
└────────────────────────────────────────────────────────┼──────────┘
                                                         ▼
                                              新加坡节点 (Trojan/TLS 443)
```

---

## 1. 「绑死」的定义：四把锁

只配一个代理端口不算绑死，必须四层同时成立，缺一层就漏。

| 锁 | 落点 | 做什么 | 失效表现 |
| --- | --- | --- | --- |
| ① 监听锁 | `config.yaml` | 只监听 `127.0.0.1:7899`，`allow-lan: false`、`bind-address: 127.0.0.1`、`ipv6: false` | 局域网/其它机器能蹭；出现 IPv6 出口 |
| ② 规则锁 | `rules:` | 唯一出口是新加坡节点，**不写 DIRECT、不写 GEOIP 分流、不用 fallback/url-test 组** | 节点挂掉时静默走直连 |
| ③ 进程锁 | 守护层 | Codex 进程除 `127.0.0.1:7899` 外一律阻断（含 IPv6、UDP） | 应用忽略代理变量时偷偷直连 |
| ④ 启动锁 | `codex_env.py` | 启动前核验端口归属 + 出口国家 = SG，任一条不过就报错退出，不启动 Codex | 带着坏配置启动，用户以为在走新加坡 |

**关键取舍**：宁可「启动失败」也不「静默直连」。第 ④ 把锁就是 fail-closed 的落点。

---

## 2. 本机已探测到的事实（2026-11-07）

| 项 | 结论 | 依据 |
| --- | --- | --- |
| Codex CLI | `0.154.0`，入口 `%APPDATA%\npm\codex.cmd` → `node codex.js` | `codex --version` |
| CLI 是否认代理变量 | **认**。设置 `HTTPS_PROXY` 后，`CONNECT chatgpt.com:443`、`CONNECT api.github.com:443` 到达本地监听 | 本地假代理监听实测，见 §7.4 |
| 桌面版 | 本体推测为 `%LOCALAPPDATA%\OpenAI\Codex\bin\14b838c1d074ff01\codex.exe`（369 MB）；同目录另有 `bin\codex.exe`（245 MB，CLI） | 目录扫描 |
| 桌面版是否认代理变量 | **未验证**（测试被中断，命中数 0 不能作为结论） | 待补测，方法见 §7.5 |
| 7898 端口 | **已被占用**：`%ProgramFiles%\Claude7898Guard` 已安装并在跑，Claude 全家族被钉在 `127.0.0.1:7898` | 目录 + `state.json`（今日更新） |
| 管理员权限 | 当前会话 **不是** 管理员，守护层安装需单独提权（UAC） | `IsInRole(Administrator) = False` |
| 编译器 | 本机 **无 `cl.exe`**，无法直接复刻 Claude 包的 WFP 守护 EXE | `Get-Command cl.exe` 为空 |

由此推出一条硬约束：**Codex 必须用 7899，不能抢 Claude 的 7898**；两者可以同时在线，各自一条新加坡出口。

---

## 3. 目录结构（计划）

```
Codex-SG-Launcher\
  codex-sg.cmd              入口：起代理 → 自检 → 在“当前目录”启动 codex CLI
  codex-app-sg.cmd          入口：起代理 → 自检 → 启动 Codex 桌面版
  start.cmd                 只起代理（给 VS Code 插件等外部入口用）
  stop.cmd                  只停本目录的代理
  status.cmd                只读状态：端口归属、出口 IP/国家、守护规则
  config.example.yaml       无凭据模板（7899 / 仅 IPv4 / MATCH 新加坡）
  mihomo.exe                内核（复用包内 v1.19.13，重命名）
  config.yaml               你自己填的真实配置（不入库、不分享）
  tools\
    codex_env.py            生命周期 + 健康门禁 + 启动注入（stdlib only）
    ManageCodexGuard.ps1    守护层：安装 / 检查 / 回滚（管理员）
    probe_proxy.py          诊断脚本：验证某程序是否真的走了代理
  runtime\                  日志与状态（首次运行自动创建）
    core.log  validation.log  launcher.log  process.json
  README.md                 本文档
```

> 仓库不含二进制（`.gitignore` 排除 `*.exe`）。克隆后：`mihomo.exe` 从 [MetaCubeX/mihomo releases](https://github.com/MetaCubeX/mihomo/releases)
> 下载 windows-amd64 v1.19.13 放到根目录；其余用系统自带编译器（在 PowerShell 里跑）：
> ```powershell
> $csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
> & $csc /nologo /codepage:65001 /optimize /platform:x64 /out:tools\CodexWfpGuard.exe tools\CodexWfpGuard.cs
> & $csc /nologo /codepage:65001 /target:exe /out:codex-sg.exe tools\CodexLauncher.cs
> & $csc /nologo /codepage:65001 /target:winexe /define:APP /r:System.Windows.Forms.dll /out:codex-app-sg.exe tools\CodexLauncher.cs
> ```

---

## 4. 配置文件要点（`config.yaml`）

模板 `config.example.yaml` 已给骨架，核心四项不可省：

```yaml
mixed-port: 7899            # 与 Claude 的 7898 隔离
bind-address: 127.0.0.1      # ① 监听锁
allow-lan: false
ipv6: false                  # ① 只要 IPv4
mode: rule
interface-name: WLAN         # 换成自己实际出站网卡
proxies:
  - name: Codex-Singapore
    type: trojan
    server: YOUR_SERVER
    port: 443
    password: YOUR_PASSWORD
    sni: YOUR_TLS_SERVER_NAME
    skip-cert-verify: false
rules:
  - MATCH,Codex-Singapore    # ② 规则锁：唯一出口，无 DIRECT、无兜底
```

三条纪律：

1. **不要**写成 `GEOIP,CN,DIRECT` + `MATCH,节点` 这类分流——分流意味着存在第二条出口。
2. **不要**用 `url-test`/`fallback` 代理组把 `DIRECT` 放进去；节点挂了就该报错，而不是换出口。
3. 改完先语法校验，再谈连通：`.\mihomo.exe -t -d . -f .\config.yaml`（返回 0 才算配置合法）。

---

## 5. 启动器怎么工作（`tools/codex_env.py`）

沿用 Claude 包里已经被验证过的那套「进程身份」思路，命令面收敛为 6 个：

| 命令 | 行为 |
| --- | --- |
| `start` | 校验 `config.yaml` → 拉起 mihomo → 写 `runtime\process.json`（PID + exe 全路径 + 创建时间）→ 等端口进入 LISTENING |
| `stop` | 只停“本目录记录且身份一致”的进程；身份不符就拒绝，绝不按端口乱杀 |
| `status` | 打印端口归属、本机出口 IP/国家、守护规则是否存在 |
| `run -- <args>` | `start` + 自检 + 注入环境变量 + 原样转发参数给 `codex`，退出码透传 |
| `app` | `start` + 自检 + 以注入环境变量的方式启动桌面版 |
| `check` | 只做自检（端口/出口/守护），不起任何进程，给 CI 或手动排障用 |

**启动前自检（第 ④ 把锁）依次确认：**

1. `127.0.0.1:7899` 的 LISTENING 进程 == 本目录记录的进程（防止被别的 mihomo 顶替）。
2. 通过该代理访问 `https://www.cloudflare.com/cdn-cgi/trace`，`loc=SG` 且 `ip` 是公网 IPv4。
   - 不是 SG → 直接失败退出，提示「出口国家不对，拒绝启动」。
3. 守护层状态为 `active`（可用 `--no-guard` 显式跳过，但会在日志里留痕）。

**环境变量注入清单**（父子进程都会继承，Codex 的子进程如 `node.exe`、MCP server 同样生效）：

```
HTTPS_PROXY=http://127.0.0.1:7899
HTTP_PROXY=http://127.0.0.1:7899
ALL_PROXY=http://127.0.0.1:7899
NO_PROXY=localhost,127.0.0.1,::1
no_proxy / https_proxy / http_proxy 同值（大小写两套都给）
```

> 已实测：CLI 收到这组变量后确实向代理发起 `CONNECT`，而不是直连（§7.4）。

---

## 6. 守护层（第 ③ 把锁）：两个选项，先小后大

> **本机实测结论（2026-11-07）：方案 A 无效，已改用方案 B。**
> Clash Verge 开着 TUN 时，防火墙阻止规则拦不住 codex.exe 直连（198.18.x.x 虚拟 IP 照样能连上），而且本机回环上的 7897 也会被当作出口绕过。
> 方案 B 已实现：`tools\CodexWfpGuard.exe`（C# 源码 `CodexWfpGuard.cs`，用系统自带的 csc 编译）+ `ManageCodexGuard.ps1 -Mode Install|Sync|Check|List|Rollback`。
> sublayer 权重设为 0xFFFF，`Check` 模式不需要管理员：先比对快照，再以被守护的身份做功能探测。实测 1.1.1.1:443 和 127.0.0.1:7897 被阻断，UDP 收不到回包，7899 放行。
> 注意：360 会把 `Documents` 下新编译的 exe 判为不可信，导致它启动的子进程读不了 AppData。用 `codex-sg.exe` 之前，先把本目录加入 360 信任区；或者直接用 `.cmd` 入口。

| 方案 | 原理 | 优点 | 代价 | 建议 |
| --- | --- | --- | --- | --- |
| **A. Windows 防火墙**（默认） | 对 `codex.exe` 建「出站阻止」规则；回环不受防火墙过滤，所以本地代理仍可连 | 系统自带、`New-NetFirewallRule` 一行安装、`Remove-` 一行回滚、无需编译 | 依赖「回环不被过滤」这一语义，必须实测确认（§7.6）；无法细到端口 | **先上 A**，5 分钟测完再决定 |
| **B. WFP 过滤器**（进阶） | 与 Claude 包同款：自建 provider/sublayer，按 ALE_APP_ID 加 4 条 BLOCK（远端≠127.0.0.1 / 端口≠7899 / 协议≠TCP / IPv6 全阻） | 精确到端口与协议，最贴近 Claude 包效果 | 需 MSVC 编译；本机无 `cl.exe`，可用 C# + `Add-Type` 复刻但同样要管理员实测 | A 不达标再上 B |

方案 A 的安装/回滚骨架（`ManageCodexGuard.ps1` 实现时照此展开）：

```powershell
# 安装（管理员）
New-NetFirewallRule -DisplayName 'CodexSG-Block-<exe名>' -Direction Outbound `
  -Program '<codex.exe 绝对路径>' -Action Block -Profile Any -Enabled True
# 回滚
Remove-NetFirewallRule -DisplayName 'CodexSG-Block-*'
```

守护层必须覆盖**多份** `codex.exe`（本机至少两份：npm 包内的 CLI 本体、桌面版版本目录里的那份），
并且**升级换目录后要重新同步**——所以 `ManageCodexGuard.ps1` 要有 `-Mode Sync`
（重新扫描 exe → 补规则 → 记录 SHA256 与路径快照），而不是装完就不管。

**自动同步（推荐，管理员跑一次）**：`powershell -ExecutionPolicy Bypass -File tools\InstallAutoSync.ps1`
把守护层复制到 `C:\Program Files\CodexSG\`（普通权限改不了，防止被替换后以管理员身份执行），
注册计划任务 `CodexSG-GuardSync`（最高权限跑 `-Mode Sync`，当前用户只能启动、不能修改）。
之后 Codex 自动更新 → 启动器检查到 `unguarded` → 自动触发该任务 → 复查通过即启动，不弹 UAC。
改了 `tools\` 里的守护文件要重跑一次安装脚本；卸载：加 `-Uninstall`，再管理员跑 `tools\ManageCodexGuard.ps1 -Mode Sync`。

**明确不覆盖**：VS Code 进程本身、`node.exe`（会波及你的其它 Node 项目）、浏览器、MCP 子进程。
这些靠 ② 规则锁 + ① 监听锁兜底，不靠进程锁。

---

## 7. 验证方法（每条都能自己跑）

### 7.1 配置语法
```powershell
.\mihomo.exe -t -d . -f .\config.yaml
```

### 7.2 代理是否活着 / 出口是不是新加坡
```powershell
curl.exe -x http://127.0.0.1:7899 https://www.cloudflare.com/cdn-cgi/trace
# 期望看到：ip=<公网IPv4>  loc=SG
```
`loc` 不是 `SG` 就说明节点选错或串了线路。

### 7.3 端口归属
```powershell
Get-NetTCPConnection -State Listen -LocalPort 7899 | Select-Object LocalAddress,OwningProcess
```
只允许是 `127.0.0.1`，**不允许** `0.0.0.0` 或 `[::]`。

### 7.4 证实「程序确实走代理」（已对 CLI 跑过）
```powershell
# 终端 1：本地假代理，只记录不转发
python tools\probe_proxy.py 20
# 终端 2：把代理指向它，跑一个会联网的命令
$env:HTTPS_PROXY='http://127.0.0.1:7899'; $env:ALL_PROXY=$env:HTTPS_PROXY
codex doctor
```
终端 1 出现 `CONNECT chatgpt.com:443` 即为认代理；全程没有 CONNECT 说明该程序忽略代理变量。

### 7.5 桌面版是否认代理（**已解决，2026-11-07**）
> 实测结论：桌面版是 Store 包（Electron 外壳 `ChatGPT.exe` + 后台 `codex.exe app-server`）。外壳认 `--proxy-server` 参数；后台只认环境变量，但 Store 激活不会继承启动器进程的环境，而是按 `HKCU\Environment` 重新生成。
> 所以 `app` 命令只在激活那一刻把代理变量写进 HKCU，拿到 PID 后立即还原。实测外壳和后台的连接全部指向 127.0.0.1:7899，没有直连。

同 7.4，把 `codex doctor` 换成启动 `bin\<hash>\codex.exe`，观察 20 秒内是否有 `CONNECT`。
- 有 → 桌面版可直接用 env 方案。
- 无 → 桌面版需另配：若为 WebView2 壳，再试 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--proxy-server=http://127.0.0.1:7899`；
  仍无效则桌面版只能靠守护层「断直连」+ 系统级方案，需重新评估（也是本文档最大的未决项）。

### 7.6 守护层方案 A 的 5 分钟验收
```powershell
# 装上规则后
curl.exe https://www.cloudflare.com/cdn-cgi/trace          # 期望：失败（直连被断）
python tools\probe_proxy.py 20                            # 再起监听
# 另开终端：codex doctor（HERMES 环境变量已注入）
```
- 假代理仍收到 `CONNECT` → 回环未被误伤，方案 A 成立。
- 假代理收不到 → 回环也被阻断，**改用方案 B**，不要凑合。

---

## 8. 日常使用

```powershell
# 命令行（在项目目录里）
codex-sg.cmd                       # 起代理 + 自检 + 进交互式 codex
codex-sg.cmd exec "修一下这个 bug"  # 参数原样透传

# 桌面版
codex-app-sg.cmd

# 只起/停代理（给 VS Code 插件用：先 start，再在插件终端里 export 代理变量）
start.cmd    stop.cmd    status.cmd
```

日志：`runtime\core.log`（内核）、`runtime\validation.log`（配置校验）、`runtime\launcher.log`（启动器与自检结论）。
分享日志前先检查有没有节点密码。

---

## 9. 故障排查

| 提示 | 含义 | 处理 |
| --- | --- | --- |
| `Port 7899 is used by an unverified process` | 端口被别的程序占着 | 先查 `Get-NetTCPConnection`，确认归属，不要直接杀 |
| `出口国家不是 SG` | 节点选错/线路串了/配置被改 | 回到 7.2，确认 `MATCH` 指向的节点就是新加坡 |
| `mihomo 启动超时` | 配置语法通过但内核起不来 | 看 `runtime\core.log`，多为端口占用或 `interface-name` 写错 |
| `配置校验失败` | `-t` 返回非 0 | 看 `runtime\validation.log`，逐行改 YAML |
| Codex 报网络错误且 7.2 正常 | 该进程没继承到代理变量 | 确认是从 `codex-sg.cmd` 启动；VS Code 内的进程要在插件终端里手动 export |
| 装完守护后 Codex 完全断网 | 回环被误伤（方案 A 风险） | 立即 `ManageCodexGuard.ps1 -Mode Rollback`，改方案 B |
| Codex 提示「Windows 设置未完成」，日志报 `helper_sandbox_lock_failed`（拒绝访问） | Codex 沙箱自己给 `.codex\.sandbox-bin` 设的权限里缺「取得所有权」，代理端口一变就要重跑设置，结果撞上这个问题 | 普通 PowerShell 跑 `icacls "$env:USERPROFILE\.codex\.sandbox-bin" /grant "${env:USERNAME}:(OI)(CI)F"` 和 `... /grant "SYSTEM:(OI)(CI)F"`，再在 Codex 里点「重新设置」。设置成功后 Codex 会自己把权限收紧回去 |

---

## 10. 回滚与卸载

```powershell
# 1) 撤守护（管理员）
.\tools\ManageCodexGuard.ps1 -Mode Rollback
# 2) 停代理
.\stop.cmd
# 3) 删目录即可，不写注册表、不装服务、不建计划任务（方案 B 若自建持久过滤器，则由 Rollback 负责删）
```
本方案**不修改** Codex 自己的 `config.toml`、不改系统代理、不动 Windows 更新设置。

---

## 11. 风险与未决项

1. **桌面版是否认 env 未确认**（§7.5）——这是实现前必须先解决的第一件事，决定要不要引入 WebView2 参数。
2. **方案 A 的回环语义未在本机实测**——没管理员权限，测不了；文档里给的验收流程就是为这个留的。
3. **Codex 自更新**：被守护层断直连后，`codex update` 只能走代理；如果更新器不认代理变量就会失败。可选做法：升级时临时 `-Mode Rollback`。
4. **代理变量会被子进程继承**：这是优点（MCP/`node.exe` 一起走），也意味着在该终端里跑别的命令同样走新加坡，属预期行为。
5. **与 Claude 7898 共存**：两套内核各自独立，互不感知；只有端口 7898/7899 之分。想共用一条出口是另一种设计（共享同一 mihomo 实例），本期不做。

---

## 12. 实施顺序（确认后按此交付）

| 阶段 | 产出 | 验收 |
| --- | --- | --- |
| P0 | 补测桌面版是否认代理（§7.5） | 有/无 CONNECT 的明确结论 |
| P1 | `codex_env.py`（start/stop/status/run/check）+ `config.example.yaml` + `mihomo.exe` + `start/stop` 脚本 | 7.1–7.4 全过；`run` 能把参数透传给 codex |
| P2 | `codex-sg.cmd` / `codex-app-sg.cmd` + 启动前 SG 自检 | 出口非 SG 时拒绝启动 |
| P3 | `ManageCodexGuard.ps1`（A 方案，含 Sync/Rollback） | 7.6 通过；回滚后直连恢复 |
| P4 | README 补「本机验证记录」+ 打包 zip | 与 Claude 包同结构，可直接解压使用 |

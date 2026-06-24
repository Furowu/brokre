# brokre — AI 安全凭据代理

<!-- README-I18N:START -->

[English](README.md) | **简体中文**

<!-- README-I18N:END -->

`brokre` 是面向 AI Agent 与个人管理的**本地凭据代理**。让 Cursor、Claude Code、Kimi Code、Trae、OpenClaw（龙虾）、Hermes Agent、ChatClaw（小龙虾）等支持 MCP 的工具安全执行 `ssh`、`mysql`、`psql` 等命令——**密码不进 AI 上下文、不进环境变量、不进 `ps`**。它包装 **`PATH` 上任意 CLI** — 不限于 SSH 或 MySQL — 在密码提示处注入已保存凭据，**不向 AI 进程、shell 历史或进程环境暴露明文**。

由 [Techinone](https://www.tio.tech)（成都同创合一科技有限公司）开发维护。

## 0.2.8 新特性

**0.2.8** 为当前正式版本：**一条 npm 命令安装**、**主流 IDE 自动注册 MCP**、**每次 MCP 启动自动升级二进制** — 并包含面向多主机 / 集群的**堡垒代理**（一台笔记本、一个 MCP 会话，操作多台内网目标）。

### npm — 安装、自动更新、自动 MCP 注册

```bash
npm install -g brokre          # 或：npx -y brokre@latest
```

| 能力 | 说明 |
|------|------|
| **自动 MCP 注册** | `postinstall` 执行 `brokre-setup-mcp` — 仅检测已安装 IDE 并合并 `npx -y brokre@latest`。补注册：`brokre mcp setup` 或 `npx brokre-setup-mcp`。跳过：`BROKRE_MCP_SKIP_SETUP=1`。 |
| **二进制自动升级** | 每次 MCP 启动对比 npm 包与 `PATH` / `~/.brokre/bin/brokre`，更旧时从 [GitHub Release](https://github.com/Furowu/brokre/releases) 下载。 |
| **无 npm 的 CLI** | install.sh 用户用 `brokre version` / `brokre upgrade`；装 IDE 后用 `brokre mcp setup` 补注册 MCP。 |
| **支持的 IDE** | Cursor、VS Code、VS Code Insiders、Claude Code、Claude Desktop、Trae、Kimi Code、Windsurf、OpenClaw — 详见 [packages/brokre-mcp/README.md](packages/brokre-mcp/README.md)。 |

推荐 MCP 配置（自动注册也会写入相同内容）：

```json
{ "command": "npx", "args": ["-y", "brokre@latest"] }
```

### 堡垒代理 — 集群管理

堡垒层让 AI Agent 在**单一跳板机**后操作**整组主机**，无需把 vault 密码复制进上下文，也无需在笔记本上散落内网明文凭据。

| 优势 | 实际效果 |
|------|----------|
| **统一控制面** | 注册堡垒 SSH 别名（`b150`），从远端 brokre 同步内网别名，用 `brokre list` / MCP `brokre_list` 驱动整个集群 |
| **智能路由** | `b150::db`、`b150::app-01`、多跳 `b1::b2::inner` — 路由分隔符 `::`；直连不可达时 AI 自动选择 `access=via_b150` |
| **密钥留在堡垒** | 路由执行在跳板机调用 `~/.brokre/bin/brokre`；笔记本只缓存元数据并做人机门控，不持有内网主机密码 |
| **人机门控 + Agent 友好** | 堡垒出站需解锁（TTY、`/bastion-auth` 或 MCP URL elicitation）；门控鉴权不受 manage UI 空闲过期影响，长时 MCP 任务可继续解锁 |
| **集群安全默认** | 毫秒级可达性探测与并发上限；默认列表隐藏不可达本地别名；环路检测与审计 `route`/`bastion` 字段 |
| **跨路由提权** | `brokre_exec_elevated` 及 `sudo`/`sudo -i` 路径支持经堡垒执行，含会话复用与 PTY 加固 |

K8s / 数据库 / 批处理集群经单一入口主机访问的典型流程：

```bash
brokre bastion enable b150
brokre bastion sync b150 --json          # 拉取内网别名目录
brokre bastion unlock
brokre list --json                       # b150::db、b150::worker-01 …
brokre ssh b150::db systemctl status   # MCP：brokre_exec 路由别名
```

MCP 等价调用：

```json
{ "binary": "ssh", "args": ["b150::db", "uname", "-a"] }
```

**门控策略（默认 / 严格）** — 详见下文 [堡垒门控策略](#堡垒门控策略默认-vs-严格)。未执行 `brokre bastion set-key` 前门控不生效；设钥后 **默认模式** 仅堡垒出站需解锁，**严格模式** 要求所有 exec/list 先解锁。

完整配置见下文 [跨网段列表继承](#跨网段列表继承堡垒代理) 与 [堡垒代理](#堡垒代理跨网段--内网入口)。

## CLI 安全防护（核心）

brokre 围绕一条原则构建：**密钥远离 AI 可达范围，且不出现在可观测的进程状态中。**

| 层级 | brokre 的做法 |
|------|-------------|
| **无 env / `ps` 泄漏** | 基于 PTY 提示注入 — 绝不通过 `-p`、`SSHPASS`、`MYSQL_PWD` 或环境变量传密 |
| **父进程不持明文**（Unix） | 已保存密码在短生命周期 `brokre --internal-injector` 子进程中解密，一次性写入 PTY 后子进程退出 |
| **AI 无法 `reveal`** | `brokre reveal` 需真实 TTY + 主口令；Web UI 不提供，**MCP 不暴露** |
| **静态保险库** | 每字段 AES-256-GCM；DEK 分别包装给 `exec`（Linux 用 OS keyring；macOS 默认 `~/.brokre/.master_kek`）与可选 Argon2id reveal 口令 |
| **MCP 边界** | MCP 暴露元数据（`brokre_list`）、执行（`brokre_exec`、`brokre_exec_elevated`）、`brokre_setup` 与只读审计（`brokre_audit_list`、`brokre_audit_verify`）— 无密码、会话 token、`reveal` |
| **管理界面** | 仅绑定 `127.0.0.1`；密码**只写**；含审计日志页；会话 token 在终端打印，不返回给 AI |
| **审计** | HMAC 链式 JSONL（`~/.brokre/audit/audit.log`）；`brokre audit list` 查询历史（仅元数据）；`brokre audit verify` 检测篡改 |
| **OS 加固** | 禁用 core dump、ptrace 检测（Linux）、可选 `mlockall` — 见 [docs/HARDENING.md](docs/HARDENING.md) |

完整威胁模型：[SECURITY.md](SECURITY.md)、[THREAT_MODEL.md](THREAT_MODEL.md)。

## 泛型 CLI（设计如此，非固定工具列表）

brokre **不是**固定的数据库/SSH 包装器集合。核心用法：

```bash
brokre <PATH-上任意-cli> [args...]
```

首次连接：原样运行，捕获你在提示处输入的密码，询问是否保存为别名。  
之后：`brokre <cli> <别名> …` 自动注入 — AI 与脚本只见别名。

**预设提示模式**覆盖常见工具（ssh、mysql、psql、redis-cli、ftp、clickhouse、git、docker、kubectl、sudo 等）。**其余任意 CLI** 使用通用 `password:` / `passphrase:` 匹配器 — 无需改代码。

```bash
brokre gsql prod-cluster -c "SELECT 1"    # PATH 上任意专有 CLI
brokre kubectl get pods                   # 若集群 CLI 提示输入密码
brokre my-internal-tool --host db.internal
```

按需定制：

- `~/.brokre/prompts.toml` — 按二进制覆盖提示正则
- `~/.brokre/manage.toml` — 管理界面自定义分区（如 GaussDB、内部工具）

内置管理 Tab（二进制已安装时）含 SSH、FTP、MySQL、PostgreSQL、Redis、ClickHouse、MinIO — 仅为便利；**PTY 包装器对任意 CLI 均有效**。

## 安装（优先 MCP — 推荐给 AI 场景）

npm 包 [`brokre`](https://www.npmjs.com/package/brokre) 通过 stdio 为 Cursor、Claude Code、Kimi Code、Trae、OpenClaw、Windsurf、VS Code 等 MCP 客户端拉起本地 `brokre mcp` 服务。

### 选择安装方式

| 方式 | 适用场景 | 安装命令 | IDE 注册 MCP | CLI 升级 |
|------|----------|----------|--------------|----------|
| **npm**（推荐） | AI 用户；一条命令搞定 | `npm install -g brokre` | 安装时**自动**（`postinstall`） | npm + 每次 MCP 启动自动拉二进制 |
| **install.sh / Homebrew** | 生产环境；日常不用 Node | `curl … \| bash` 或 `brew install brokre` | 装 IDE 后执行 `brokre mcp setup` | `brokre version` / `brokre upgrade` |
| **手动改 MCP JSON** | 仅特殊定制 | 已有 CLI 或 npm | 手改各 IDE 配置 | 取决于 CLI 安装方式 |

**推荐 MCP 配置**（自动注册也会写入相同内容）：

```json
{ "command": "npx", "args": ["-y", "brokre@latest"] }
```

无 Node 时可直接指向原生二进制：`{ "command": "brokre", "args": ["mcp"] }`。

### 路径 A — npm 一行安装（0.2.8+）

```bash
npm install -g brokre
# 或不全局安装：
npx -y brokre@latest
```

`npm install` 后自动完成三件事：

1. **MCP 启动器** — `brokre-mcp` / `npx -y brokre@latest` 拉起 `brokre mcp`。
2. **IDE 自动注册** — `postinstall` 执行 `brokre-setup-mcp`：仅检测**已安装**的 IDE（应用、CLI 或真实使用痕迹，非空目录），向各客户端全局配置合并上述 MCP 条目。幂等；保留你已有的其他 MCP。
3. **二进制自动升级** — 每次 MCP 启动时，若 `PATH` 或 `~/.brokre/bin/brokre` 版本低于 npm 包，从 [GitHub Release](https://github.com/Furowu/brokre/releases) 下载匹配版本。

**自动注册覆盖的 IDE**

| IDE | 全局配置文件 |
|-----|----------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code / Insiders | `…/Code/User/mcp.json` |
| Claude Code | `~/.claude.json` |
| Claude Desktop | `…/Claude/claude_desktop_config.json` |
| Trae | `…/Trae/User/mcp.json` |
| Kimi Code | `~/.kimi-code/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| OpenClaw | `~/.openclaw/openclaw.json`（`mcp.servers`） |

**补注册**（例如先装了 brokre、后装 Cursor）：

```bash
brokre mcp setup              # CLI 方式 — 与 postinstall 相同逻辑
npx brokre-setup-mcp          # npm 方式
brokre mcp setup --dry-run    # 仅预览
brokre mcp setup --force      # 强制覆盖已有 brokre 条目
```

跳过 `npm install` 自动注册：`BROKRE_MCP_SKIP_SETUP=1`。禁用二进制自动下载：`BROKRE_SKIP_AUTO_INSTALL=1`。固定二进制：`BROKRE_BIN=/path/to/brokre`。

需要 **Node.js 18+**（npm 路径）。

### 路径 B — 原生 CLI（install.sh / Homebrew，无 npm）

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

```bash
brew tap Furowu/brokre
brew install brokre
```

**版本与升级**（CLI 内置，无需 npm）：

```bash
brokre version                # 版本、二进制路径、安装方式
brokre version --check        # 与 GitHub 最新 release 对比
brokre version --check --json
brokre upgrade                # 下载最新 release（curl + tar）
brokre upgrade --check        # 有更新时 exit 1
brokre upgrade 0.2.10         # 安装指定版本
brokre upgrade --force        # 已是最新也强制重装
```

重复执行 `install.sh` 同样会在有新版本时升级。

**CLI 安装后注册 MCP**（需要 Node 跑 setup 脚本，或走 `npx` 回退）：

```bash
brokre mcp setup
```

### 手动按 IDE 配置（可选）

仅在跳过自动注册或需要项目级配置时使用。

**Cursor** — [一键安装](cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=eyJicm9rcmUiOnsiY29tbWFuZCI6Im5weCIsImFyZ3MiOlsiLXkiLCJicm9rcmVAbGF0ZXN0Il19fQ==)，或写入 `~/.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "brokre": { "command": "npx", "args": ["-y", "brokre@latest"] }
  }
}
```

**Claude Code** — 用户级 `~/.claude.json`，或 `claude mcp add --scope user brokre -- npx -y brokre@latest`。项目级：`.mcp.json` 并加 `"type": "stdio"`。

更多客户端与环境变量：[packages/brokre-mcp/README.md](packages/brokre-mcp/README.md)。[MCP Registry](https://registry.modelcontextprotocol.io) ID：`io.github.Furowu/brokre`。

### MCP 工具与用法

| MCP 工具 | 用途 |
|----------|------|
| `brokre_list` | 已保存别名；有堡垒时自动探测、合并路由别名（`b150::db`）、隐藏不可达项；含 `access`/`availability`/`bastion_gate` |
| `brokre_exec` | 运行**任意**已保存 CLI 别名（`binary` + `args`）；`ssh` 可用 `shell_command` 写远端脚本；`ssh` + `sudo`/`su` 时自动复用 elevated 会话 |
| `brokre_exec_elevated` | 远端提权执行（`alias` + `command` + `mode`）；默认 `session=reuse` 复用后台 shell（10 分钟空闲销毁） |
| `brokre_setup` | 在浏览器打开 manage UI，由人类添加凭据 |
| `brokre_audit_list` | 查询审计历史（仅元数据 — 参数已脱敏） |
| `brokre_audit_verify` | 验证防篡改审计链 |
| `brokre_bastion_policy` | 读取或设置堡垒门控模式（`default` / `strict`）；返回 `key_set`、`unlocked` |

#### MCP 与 CLI 对照（AI 必读）

brokre **不是** `ssh`/`mysql` 的替代品 — 必须加 `brokre` 前缀才会注入 vault 凭据。

| 场景 | MCP（Agent 在 IDE 内） | CLI（终端 / 人类调试） |
|------|------------------------|------------------------|
| 列出别名 | `brokre_list` | `brokre list --json` |
| SSH 远程命令 | `brokre_exec` `binary=ssh`, `args=["prod","uname","-a"]` | `brokre ssh prod uname -a` |
| 任意 CLI | `brokre_exec` `binary=mysql`, `args=["prod-db","-e","SHOW TABLES"]` | `brokre mysql prod-db -e "SHOW TABLES"` |
| 写远端脚本 | `shell_command="…"`（仅 ssh） | `brokre ssh prod sh -c '…'`（`-c` 后整段脚本为一个参数） |
| 提权执行 | `brokre_exec_elevated` `command="…"` | `brokre ssh prod sudo …`（MCP 有会话池；CLI 每次新 PTY） |
| 添加凭据 | `brokre_setup`（打开浏览器） | `brokre manage --open` |
| 首次保存别名 | **不可用**（需人类 TTY 输入密码） | `brokre ssh user@10.0.0.1` |

**常见错误（AI 易犯）**

| 错误 | 正确 |
|------|------|
| `ssh prod uptime` | `brokre ssh prod uptime` |
| MCP `args=["prod","uname -a"]`（一条 shell 字符串） | `args=["prod","uname","-a"]`（argv 切片） |
| MCP `args=["prod","sh -c 'echo hi'"]` | `shell_command="echo hi"` 或 `args=["prod","sh","-c","echo hi"]` |
| 直接 `mysql -h … -p` | `brokre mysql <已保存别名> …` |

远程 SSH：`alias` 之后的参数是 **argv 切片**，不是一条 shell 命令。简单命令用拆分 token；复杂脚本用 `shell_command`。

#### MCP elevated 会话（`sudo` / `su`，Unix）

默认在 `brokre mcp` 进程内复用后台 elevated shell（同 `alias` + `mode` + `user` 键），避免每次调用重复输入 sudo 密码。

**`brokre_exec_elevated`**（推荐提权场景）：

```json
{
  "alias": "prod",
  "command": "systemctl status nginx",
  "mode": "sudo_login",
  "session": "reuse"
}
```

| 字段 | 说明 |
|------|------|
| `mode` | `sudo`、`sudo_login`（或 `sudo-i`）、`su` |
| `session` | `reuse`（默认）、`new`（关闭旧会话并新建）、`close`（结束会话；`command` 传 `""`） |
| `user` | 仅 `su` 模式，默认 `root` |

启用会话池时，响应除 `exit_code` / `stdout` / `stderr` 外还有 `session_reused`、`session_idle_expires_at`（**滚动空闲窗口参考时间**，每次调用刷新，非固定过期时刻）。会话池路径下 `stderr` 通常为空。

**`brokre_exec`**：`binary=ssh` 且 `args` 含 `sudo`/`su` 时自动走同一会话池（固定 `reuse`，不支持 `session=new|close`）。例：`args=["prod","sudo","whoami"]`。

**写远端脚本/文件**（`shell_command`，仅 `binary=ssh`）：`args` 只含别名，`shell_command` 传整段 shell 脚本（brokre 内部规范化为 `sh -c`）。勿把 `sh -c '...'` 塞进 `args`，勿把 `printf`/重定向拆成多个 argv token。提权写系统路径用 `brokre_exec_elevated.command`。

```json
{
  "binary": "ssh",
  "args": ["prod"],
  "shell_command": "cat > /tmp/deploy.sh <<'EOF'\n#!/bin/sh\necho ok\nEOF"
}
```

堡垒路由同理：`args=["b150::db"]`，`shell_command` 为远端脚本内容。

| 控制项 | 默认 |
|--------|------|
| 空闲销毁 | 10 分钟 |
| 最长存活 | 30 分钟 |
| 单条命令超时 | 120 秒 |

| 环境变量 | 默认 | 含义 |
|----------|------|------|
| `BROKRE_MCP_SESSION` | `1` | `0` 禁用会话池，回退一次性子进程执行 |
| `BROKRE_MCP_SESSION_IDLE_SECS` | `600` | 空闲销毁秒数 |
| `BROKRE_MCP_SESSION_MAX_SECS` | `1800` | 最长存活秒数 |
| `BROKRE_MCP_SESSION_CMD_TIMEOUT` | `120` | 单条远程命令超时 |

仍不支持：无 `command` 的纯交互 `sudo -i` / `vim` / `top`；sudo 密码须与 vault 中 `password` 字段相同。详见 [THREAT_MODEL.md](THREAT_MODEL.md) T12。

首次连接且**保险库为空**时，brokre 会在浏览器打开 **manage**（`http://127.0.0.1:56777/?t=…`）。会话 token 留在本机 — 不返回给 AI。设置 `BROKRE_MCP_NO_AUTO_OPEN=1` 可禁用自动打开。

## 快速开始

### 添加凭据

CLI 安装后首次运行会自动打开管理界面（`brokre manage --onboard --open`）。也可随时：

```bash
brokre manage --open
```

或在任意 CLI 的首次交互连接时保存：

```bash
brokre ssh root@10.0.0.1
brokre my-tool --host internal.corp
```

### 使用（AI 安全）

```bash
brokre mysql prod-db -e "SHOW TABLES"
brokre ssh prod-bastion uname -a
brokre <你的-cli> <别名> [args...]
```

### 列出元数据（AI / 脚本安全）

```bash
brokre list --json              # 无堡垒时：本地别名；有堡垒时：智能列表（见下）
brokre list --all --json        # 含不可达别名（排查用）
brokre list --no-bastion-discovery   # 仅本地，不 SSH、不探测
```

已注册堡垒时，`brokre list` **默认**会：探测可达性（SSH 别名读服务端 banner，其它协议 TCP）、合并堡垒上的别名（如 `b150::db`）、**隐藏不可达**的本地局域网项，避免 AI 误用跨网不可达的直连别名。

### 跨网清单继承（堡垒 broker）

适用于出差、VPN、公网入口等**跨网**场景：本机直连内网主机不可达，但经堡垒（如 `b150`）可访问其上的 brokre 与内网凭据。

**前提**

1. 本机：`brokre bastion enable b150`（`b150` 为已保存的 SSH 别名）
2. 堡垒主机上已安装 brokre（标准路径 `~/.brokre/bin/brokre`，与 `npx`/安装脚本一致），并保存内网别名（如 `db`）

**智能列表**

```bash
brokre bastion unlock            # 若已设堡垒密钥
brokre list                      # 自动含 b150::db（route=b150, access=via_b150）
```

跨网时本地 `db`（`access=direct`）若不可达则**不出现在列表**；请使用 `b150::db`。

**执行**

```bash
brokre ssh b150::db uname -a
# MCP: brokre_exec binary=ssh, args=["b150::db", "uname", "-a"]
```

同一主机在本地与堡垒均可达时，列表会**同时显示** `db`（`direct`）与 `b150::db`（`via_b150`），通过 `access` 区分路径。

### 堡垒代理（跨网 / 内网入口）

将**任意**已保存且远端安装了 brokre 的 SSH 别名提升为堡垒 broker；凭据留在堡垒，本地只缓存元数据并通过 SSH 透传执行。

```bash
brokre bastion enable b150        # 提升 ssh 别名 b150 为堡垒
brokre bastion set-key              # 设定堡垒解锁密钥（TTY）
brokre bastion unlock               # 解锁出站会话（TTL，默认 30 分钟空闲）
brokre list --json                  # 智能列表：可达性 + 堡垒路由别名
brokre ssh b150::db uname -a        # 路由执行：经 b150 在远端 brokre 注入 db 凭据
brokre bastion sync b150 --json     # 仅拉取某堡垒上的别名清单
```

- 路由分隔符 **`::`**（`:` 非法，与别名 `foo/bar` 无歧义）：`db`（本地）、`b150::db`（经堡垒）、`b1::b2::inner`（多跳，深度默认 ≤2）。
- **远端 brokre**：路由执行在堡垒上以 `~/.brokre/bin/brokre` 调用（自动附带 `BROKRE_SOFT_MEMLOCK=1`、`BROKRE_ALLOW_FILE_KEYCHAIN=1`、`BROKRE_ROUTED_INNER=1`，适配 Linux 无头环境）。交互式命令（如 `sudo -i`）自动加 `-tt`。
- **护栏**：探测并发上限 + 毫秒超时 + 短缓存；环路检测；审计含 `route`/`bastion` 字段（HMAC v4）。
- **Manage UI**：`brokre manage` 主界面 **堡垒机** Tab 可注册/禁用堡垒、Web 设钥与解锁/锁定、切换严格模式、同步远端别名；非 TTY 场景仍会自动弹出 `/bastion-auth` 解锁页。审计 Tab 支持按 `bastion`/`source` 筛选并展示路由字段。

### 堡垒门控策略（默认 vs 严格）

堡垒**门控**是在敏感操作前要求人类**解锁**的机制。**未设堡垒密钥时门控不生效**（`brokre bastion set-key`）。设钥后，解锁建立本地 TTL 会话（`brokre bastion unlock`、TTY 口令、manage UI `/bastion-auth` 或 MCP 浏览器 elicitation）。

策略保存在 `~/.brokre/bastion/policy.json`（`strict_mode` 字段，默认 `false`）。

| 模式 | `gate_mode` | 何时需要解锁（须已设堡垒密钥） |
|------|-------------|-------------------------------|
| **默认** | `default` | **仅堡垒出站** — `b150::inner` 路由执行；SSH/scp/sftp 到**已注册**堡垒别名；`brokre list` / `brokre_list` 在启用堡垒发现并向堡垒 SSH 时。纯**本地**执行（如 `brokre ssh lan-db`）**不需要**解锁。 |
| **严格** | `strict` | **所有** `brokre exec` 与 `brokre list`（及 MCP `brokre_exec` / `brokre_list`）— 含本地局域网别名。适用于已配置堡垒密钥、且希望 Agent 每次操作都需人类确认的场景。 |

**示例（默认模式、已设密钥、会话未解锁）**

| 操作 | 需要解锁？ |
|------|-----------|
| `brokre ssh prod uname -a`（本地别名） | 否 |
| `brokre ssh b150::db uname -a` | 是 |
| `brokre ssh b150 uptime`（已注册堡垒） | 是 |
| `brokre list`（含堡垒发现） | 是 |
| `brokre list --no-bastion-discovery`（仅本地） | 否 |

**严格**模式下，上表所有操作均需解锁。

**切换门控模式**

```bash
brokre bastion strict status    # 查看 default | strict
brokre bastion strict on        # 严格 — 所有 exec/list 需解锁
brokre bastion strict off       # 默认 — 仅堡垒出站
```

| 入口 | 方式 |
|------|------|
| CLI | `brokre bastion strict on\|off\|status` |
| Manage UI | **堡垒机** Tab — 严格模式开关 |
| MCP | `brokre_bastion_policy` — 读取当前策略，或传 `{"strict_mode": true}` / `false` |

MCP 读取返回 `strict_mode`、`gate_mode`、`key_set`、`unlocked`。list/exec 响应含 `bastion_gate`（`required`、`unlocked_during_call`、`idle_expires_at`）。

**解锁会话 TTL**（默认）：空闲 **30 分钟**（`BROKRE_BASTION_IDLE_SECS`）、最长 **8 小时**（`BROKRE_BASTION_MAX_SECS`）。已解锁期间每次门控调用会**续期**空闲窗口（CLI、MCP、manage UI 共享 `~/.brokre/run/bastion_session.json`）。堡垒门控鉴权与 manage UI 会话空闲过期**独立**。MCP 解锁时禁用自动打开浏览器：`BROKRE_BASTION_NO_AUTO_OPEN=1`。

### Reveal / 删除（仅人类，需真实 TTY）

```bash
brokre reveal mysql prod-db --field password
brokre rm ssh prod-bastion
```

### 审计日志（仅元数据）

```bash
brokre audit list --profile ssh --action exec --json
brokre audit verify --json
```

事件保存在 `~/.brokre/audit/audit.log`（HMAC 链式）。命令参数统一脱敏为 `<REDACTED>`。新事件含 `source` 字段（`cli`、`mcp`、`manage` 或路由执行时的 `bastion`）。manage UI **审计日志** 页与 MCP `brokre_audit_list` 暴露相同元数据（含 `route`/`bastion`）。

### 管理界面安全

- 仅 **127.0.0.1**；会话 token 在终端显示
- 密码：仅创建 / 轮换 — 无读取 API
- 删除 / 轮换需 reveal 口令（自动保存记录可输入 `YES`）
- 空闲 15 分钟超时

## 架构

```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI/用户 │────▶│ brokre CLI│────▶│ OS Keychain │────▶│ Vault 文件 │
└─────────┘     └──────────┘     └─────────────┘     └────────────┘
                      │
                      ▼
               ┌─────────────┐
               │ PTY + 注入  │──▶ PATH 上任意 CLI（ssh、mysql、gsql、…）
               └─────────────┘
```

- **双重加密**：每字段独立 DEK；`exec` 与 `reveal` 分别包装。
- **保险库元数据**：`profile`、`name`、`host_alias`、`saved_args` 与密文并列明文存储（[THREAT_MODEL.md](THREAT_MODEL.md) T3）。
- **SSH 私钥**：会话期内 `0600` 临时文件 + `-i`（[docs/HARDENING.md](docs/HARDENING.md)）。

## 预设管理界面分组

二进制在 `PATH` 上时的便利 Tab：

| 分组 | 二进制 |
|------|--------|
| SSH | `ssh`、`scp`、`sftp`（共享凭据） |
| FTP | `ftp`、`lftp` |
| MySQL | `mysql`、`mariadb` |
| PostgreSQL | `psql`、`postgres` |
| Redis | `redis-cli`、`redis` |
| ClickHouse | `clickhouse-client`、`clickhouse` |
| MinIO | `mc`、`minio` |

## 路线图

**当前：** 泛型 PTY 包装 + `manage.toml` 分组 + `prompts.toml` 覆盖。

**计划：** `~/.brokre/profiles/` 下完整 TOML 连接器 profile 与按工具注入策略。

## 管道 stdin 与 OpenSSH 共享

- **管道 stdin**（`tar | brokre ssh host 'tar xf -'`）：注入完成后再转发管道数据。
- **OpenSSH 族**（`ssh`、`scp`、`sftp`）：主机匹配时复用已保存凭据。须先交互保存（需 TTY）。

## 开发

```bash
cargo test    # 仅 src/ 内单元测试（本仓库无 tests/ 集成测试套件）
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release   # 二进制：target/release/brokre
```

版本号见 [`VERSION`](VERSION)（同步体现在 `Cargo.toml` 与 `packages/brokre-mcp/package.json`）。正式发布的二进制与 npm 包由 [TechinOne](https://www.tio.tech) 通过 GitHub Releases 与 CI 发布，**不属于本开源仓库内容**。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

---

[Techinone](https://www.tio.tech) · 成都同创合一科技有限公司

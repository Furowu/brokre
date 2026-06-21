# brokre — AI 安全凭据代理

<!-- README-I18N:START -->

[English](README.md) | **简体中文**

<!-- README-I18N:END -->

`brokre` 是面向 AI Agent 与个人管理的**本地凭据代理**。让 Cursor、Claude Code、Kimi Code、Trae、OpenClaw（龙虾）、Hermes Agent、ChatClaw（小龙虾）等支持 MCP 的工具安全执行 `ssh`、`mysql`、`psql` 等命令——**密码不进 AI 上下文、不进环境变量、不进 `ps`**。它包装 **`PATH` 上任意 CLI** — 不限于 SSH 或 MySQL — 在密码提示处注入已保存凭据，**不向 AI 进程、shell 历史或进程环境暴露明文**。

由 [Techinone](https://www.tio.tech)（成都同创合一科技有限公司）开发维护。

## 0.2.3 新特性 — 堡垒机助力集群管理

**0.2.3** 进一步强化 brokre 作为**多主机 / 集群场景的堡垒代理**：一台笔记本、一个 MCP 会话，即可操作多台内网目标 — 无需把 vault 密码复制进 AI 上下文，也无需在跳板机上散落明文凭据。

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
brokre ssh b150::db "systemctl status"   # MCP：brokre_exec 路由别名
```

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

npm 包 [`brokre`](https://www.npmjs.com/package/brokre) 是面向 Cursor、Claude Code、Kimi Code、Trae、OpenClaw（龙虾）、Hermes Agent、ChatClaw（小龙虾）等 **MCP 客户端**的启动器，通过 stdio 拉起本地 `brokre mcp` 服务。凡支持 stdio MCP 的 Agent / IDE，均可按同样方式接入。

### 1. 将 brokre 接入 AI 编辑器

**Cursor** — 一键安装（在 Cursor 中打开并添加 MCP 服务器）：

[在 Cursor 中安装 brokre](cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=eyJicm9rcmUiOnsiY29tbWFuZCI6Im5weCIsImFyZ3MiOlsiLXkiLCJicm9rcmVAbGF0ZXN0Il19fQ==)

或手动写入 `~/.cursor/mcp.json` 或项目 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "brokre": {
      "command": "npx",
      "args": ["-y", "brokre@latest"]
    }
  }
}
```

**Claude Code** — 项目 `.mcp.json`：

```json
{
  "mcpServers": {
    "brokre": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "brokre@latest"]
    }
  }
}
```

或命令行：

```bash
claude mcp add --scope project brokre -- npx -y brokre@latest
```

推荐 `npx -y brokre@latest`：npm 启动器与二进制均会自动保持最新。每次 MCP 启动时，若本地 `brokre`（`PATH` 或 `~/.brokre/bin/`）版本低于 npm 包版本，会自动从 GitHub Release 下载并覆盖 `~/.brokre/bin/`。

**无需 Node** — MCP 直接指向原生二进制：

```json
{ "command": "brokre", "args": ["mcp"] }
```

| MCP 工具 | 用途 |
|----------|------|
| `brokre_list` | 已保存别名；有堡垒时自动探测、合并路由别名（`b150::db`）、隐藏不可达项；含 `access`/`availability`/`bastion_gate` |
| `brokre_exec` | 运行**任意**已保存 CLI 别名（`binary` + `args`）；`ssh` + `sudo`/`su` 时自动复用 elevated 会话 |
| `brokre_exec_elevated` | 远端提权执行（`alias` + `command` + `mode`）；默认 `session=reuse` 复用后台 shell（10 分钟空闲销毁） |
| `brokre_setup` | 在浏览器打开 manage UI，由人类添加凭据 |
| `brokre_audit_list` | 查询审计历史（仅元数据 — 参数已脱敏） |
| `brokre_audit_verify` | 验证防篡改审计链 |

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

**无需单独安装 CLI**：`npx -y brokre@latest` 会在需要时从 GitHub Release 下载或升级 `~/.brokre/bin/brokre`（需 Node 18+），即使 `PATH` 上已有旧版也会自动更新。禁用自动下载：`BROKRE_SKIP_AUTO_INSTALL=1`；固定二进制：`BROKRE_BIN=/path/to/brokre`。

更多说明：[packages/brokre-mcp/README.md](packages/brokre-mcp/README.md)。

[MCP Registry](https://registry.modelcontextprotocol.io) 元数据 ID：`io.github.Furowu/brokre` — 执行 `./d npm` / `./d release` 时自动发布（或 npm 后单独 `./d registry`；设 `BROKRE_SKIP_MCP_REGISTRY=1` 可跳过）。

### 2. 安装 brokre CLI（可选 — MCP 可自动下载）

也可手动安装 CLI（系统级 `PATH`，推荐生产环境）：

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

重复执行同一命令可升级；脚本会检测已安装版本，有新版时自动重装，已是最新则跳过。

或通过 Homebrew（macOS / Linux）：

```bash
brew tap Furowu/brokre
brew install brokre
```

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

已注册堡垒时，`brokre list` **默认**会：TCP 探测可达性、合并堡垒上的别名（如 `b150::db`）、**隐藏不可达**的本地局域网项，避免 AI 误用跨网不可达的直连别名。

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
brokre bastion unlock               # 解锁出站会话（TTL，默认 10 分钟空闲）
brokre list --json                  # 智能列表：可达性 + 堡垒路由别名
brokre ssh b150::db uname -a        # 路由执行：经 b150 在远端 brokre 注入 db 凭据
brokre bastion sync b150 --json     # 仅拉取某堡垒上的别名清单
```

- 路由分隔符 **`::`**（`:` 非法，与别名 `foo/bar` 无歧义）：`db`（本地）、`b150::db`（经堡垒）、`b1::b2::inner`（多跳，深度默认 ≤2）。
- **门控**：设定堡垒密钥后，任何 SSH 出站（探测 / 透传 exec / 直连已注册堡垒别名）需先解锁。CLI 与 MCP 共用底层门控：TTY 下自动提示输入堡垒密钥；非 TTY 下自动打开本地认证页并轮询（`BROKRE_BASTION_NO_AUTO_OPEN=1` 可禁用自动打开）。MCP 额外支持 URL-mode elicitation（Cursor 等）。`/bastion-auth` 页展示调用来源（MCP 客户端、工具名或 CLI）；解锁 API 凭 URL 中的会话 token 鉴权，**不受 manage UI 空闲过期影响**；manage 进程重启时门控轮询会自动跟随 `manage.json` 重新发现实例。
- **远端 brokre**：路由执行在堡垒上以 `~/.brokre/bin/brokre` 调用（自动附带 `BROKRE_SOFT_MEMLOCK=1`、`BROKRE_ALLOW_FILE_KEYCHAIN=1`、`BROKRE_ROUTED_INNER=1`，适配 Linux 无头环境）。交互式命令（如 `sudo -i`）自动加 `-tt`。
- **护栏**：探测并发上限 + 毫秒超时 + 短缓存；环路检测；审计含 `route`/`bastion` 字段（HMAC v4）。
- **Manage UI**：`brokre manage` 主界面 **堡垒机** Tab 可注册/禁用堡垒、Web 设钥与解锁/锁定、同步远端别名；非 TTY 场景仍会自动弹出 `/bastion-auth` 解锁页。审计 Tab 支持按 `bastion`/`source` 筛选并展示路由字段。

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

# brokre — AI 安全凭据代理

<!-- README-I18N:START -->

[English](README.md) | **简体中文**

<!-- README-I18N:END -->

`brokre` 是面向 AI Agent 与个人管理的**本地凭据代理**。让 Cursor、Claude Code、Kimi Code、Trae、OpenClaw（龙虾）、Hermes Agent、ChatClaw（小龙虾）等支持 MCP 的工具安全执行 `ssh`、`mysql`、`psql` 等命令——**密码不进 AI 上下文、不进环境变量、不进 `ps`**。它包装 **`PATH` 上任意 CLI** — 不限于 SSH 或 MySQL — 在密码提示处注入已保存凭据，**不向 AI 进程、shell 历史或进程环境暴露明文**。

由 [Techinone](https://www.tio.tech)（成都同创合一科技有限公司）开发维护。

## CLI 安全防护（核心）

brokre 围绕一条原则构建：**密钥远离 AI 可达范围，且不出现在可观测的进程状态中。**

| 层级 | brokre 的做法 |
|------|-------------|
| **无 env / `ps` 泄漏** | 基于 PTY 提示注入 — 绝不通过 `-p`、`SSHPASS`、`MYSQL_PWD` 或环境变量传密 |
| **父进程不持明文**（Unix） | 已保存密码在短生命周期 `brokre --internal-injector` 子进程中解密，一次性写入 PTY 后子进程退出 |
| **AI 无法 `reveal`** | `brokre reveal` 需真实 TTY + 主口令；Web UI 不提供，**MCP 不暴露** |
| **静态保险库** | 每字段 AES-256-GCM；DEK 分别包装给 `exec`（Linux 用 OS keyring；macOS 默认 `~/.brokre/.master_kek`）与可选 Argon2id reveal 口令 |
| **MCP 边界** | MCP 仅暴露元数据（`brokre_list`）与执行（`brokre_exec`）— 无密码、会话 token、`reveal` |
| **管理界面** | 仅绑定 `127.0.0.1`；密码**只写**；会话 token 在终端打印，不返回给 AI |
| **审计** | HMAC 链式 JSONL；`brokre audit verify` 检测篡改 |
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

配置变更后重新生成安装链接：`node scripts/generate-cursor-install-link.js`

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
| `brokre_list` | 已保存别名（仅元数据 — profile、name、host） |
| `brokre_exec` | 运行**任意**已保存 CLI 别名（`binary` + `args`） |
| `brokre_setup` | 在浏览器打开 manage UI，由人类添加凭据 |

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
brokre list --json
```

### Reveal / 删除（仅人类，需真实 TTY）

```bash
brokre reveal mysql prod-db --field password
brokre rm ssh prod-bastion
```

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

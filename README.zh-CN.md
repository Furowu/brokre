# brokr — AI 安全凭据代理

<!-- README-I18N:START -->

[English](README.md) | **简体中文**

<!-- README-I18N:END -->

`brokr` 是面向 AI AGENT与个人管理的**本地凭据代理**。它包装 **`PATH` 上任意 CLI** — 不限于 SSH 或 MySQL — 在密码提示处注入已保存凭据，**不向 AI 进程、shell 历史、`ps` 或进程环境暴露明文**。

由 [Techinone](https://www.tio.tech)（成都同创合一科技有限公司）开发维护。

## CLI 安全防护（核心）

brokr 围绕一条原则构建：**密钥远离 AI 可达范围，且不出现在可观测的进程状态中。**

| 层级 | brokr 的做法 |
|------|-------------|
| **无 env / `ps` 泄漏** | 基于 PTY 提示注入 — 绝不通过 `-p`、`SSHPASS`、`MYSQL_PWD` 或环境变量传密 |
| **父进程不持明文**（Unix） | 已保存密码在短生命周期 `brokr --internal-injector` 子进程中解密，一次性写入 PTY 后子进程退出 |
| **AI 无法 `reveal`** | `brokr reveal` 需真实 TTY + 主口令；Web UI 不提供，**MCP 不暴露** |
| **静态保险库** | 每字段 AES-256-GCM；DEK 分别包装给 `exec`（Linux 用 OS keyring；macOS 默认 `~/.brokr/.master_kek`）与可选 Argon2id reveal 口令 |
| **MCP 边界** | MCP 仅暴露元数据（`brokr_list`）与执行（`brokr_exec`）— 无密码、会话 token、`reveal` |
| **管理界面** | 仅绑定 `127.0.0.1`；密码**只写**；会话 token 在终端打印，不返回给 AI |
| **审计** | HMAC 链式 JSONL；`brokr audit verify` 检测篡改 |
| **OS 加固** | 禁用 core dump、ptrace 检测（Linux）、可选 `mlockall` — 见 [docs/HARDENING.md](docs/HARDENING.md) |

完整威胁模型：[SECURITY.md](SECURITY.md)、[THREAT_MODEL.md](THREAT_MODEL.md)。

## 泛型 CLI（设计如此，非固定工具列表）

brokr **不是**固定的数据库/SSH 包装器集合。核心用法：

```bash
brokr <PATH-上任意-cli> [args...]
```

首次连接：原样运行，捕获你在提示处输入的密码，询问是否保存为别名。  
之后：`brokr <cli> <别名> …` 自动注入 — AI 与脚本只见别名。

**预设提示模式**覆盖常见工具（ssh、mysql、psql、redis-cli、ftp、clickhouse、git、docker、kubectl、sudo 等）。**其余任意 CLI** 使用通用 `password:` / `passphrase:` 匹配器 — 无需改代码。

```bash
brokr gsql prod-cluster -c "SELECT 1"    # PATH 上任意专有 CLI
brokr kubectl get pods                   # 若集群 CLI 提示输入密码
brokr my-internal-tool --host db.internal
```

按需定制：

- `~/.brokr/prompts.toml` — 按二进制覆盖提示正则
- `~/.brokr/manage.toml` — 管理界面自定义分区（如 GaussDB、内部工具）

内置管理 Tab（二进制已安装时）含 SSH、FTP、MySQL、PostgreSQL、Redis、ClickHouse、MinIO — 仅为便利；**PTY 包装器对任意 CLI 均有效**。

## 安装（优先 MCP — 推荐给 AI 场景）

npm 包 [`@techinone/brokr`](https://www.npmjs.com/package/@techinone/brokr) 是面向 Cursor、Claude Code 等 MCP 客户端的启动器，通过 stdio 拉起本地 `brokr mcp` 服务。

### 1. 将 brokr 接入 AI 编辑器

**Cursor** — `~/.cursor/mcp.json` 或项目 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "brokr": {
      "command": "npx",
      "args": ["-y", "@techinone/brokr@latest"]
    }
  }
}
```

**Claude Code** — 项目 `.mcp.json`：

```json
{
  "mcpServers": {
    "brokr": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@techinone/brokr@latest"]
    }
  }
}
```

或命令行：

```bash
claude mcp add --scope project brokr -- npx -y @techinone/brokr@latest
```

推荐 `npx -y @techinone/brokr@latest`：npm 启动器与二进制均会自动保持最新。每次 MCP 启动时，若本地 `brokr`（`PATH` 或 `~/.brokr/bin/`）版本低于 npm 包版本，会自动从 GitHub Release 下载并覆盖 `~/.brokr/bin/`。

**无需 Node** — MCP 直接指向原生二进制：

```json
{ "command": "brokr", "args": ["mcp"] }
```

| MCP 工具 | 用途 |
|----------|------|
| `brokr_list` | 已保存别名（仅元数据 — profile、name、host） |
| `brokr_exec` | 运行**任意**已保存 CLI 别名（`binary` + `args`） |
| `brokr_setup` | 在浏览器打开 manage UI，由人类添加凭据 |

首次连接且**保险库为空**时，brokr 会在浏览器打开 **manage**（`http://127.0.0.1:56777/?t=…`）。会话 token 留在本机 — 不返回给 AI。设置 `BROKR_MCP_NO_AUTO_OPEN=1` 可禁用自动打开。

**无需单独安装 CLI**：`npx -y @techinone/brokr@latest` 会在需要时从 GitHub Release 下载或升级 `~/.brokr/bin/brokr`（需 Node 18+），即使 `PATH` 上已有旧版也会自动更新。禁用自动下载：`BROKR_SKIP_AUTO_INSTALL=1`；固定二进制：`BROKR_BIN=/path/to/brokr`。

更多说明：[packages/brokr-mcp/README.md](packages/brokr-mcp/README.md)。

### 2. 安装 brokr CLI（可选 — MCP 可自动下载）

也可手动安装 CLI（系统级 `PATH`，推荐生产环境）：

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash
```

重复执行同一命令可升级；脚本会检测已安装版本，有新版时自动重装，已是最新则跳过。

或通过 Homebrew（macOS / Linux）：

```bash
brew tap Furowu/brokr
brew install brokr
```

## 快速开始

### 添加凭据

CLI 安装后首次运行会自动打开管理界面（`brokr manage --onboard --open`）。也可随时：

```bash
brokr manage --open
```

或在任意 CLI 的首次交互连接时保存：

```bash
brokr ssh root@10.0.0.1
brokr my-tool --host internal.corp
```

### 使用（AI 安全）

```bash
brokr mysql prod-db -e "SHOW TABLES"
brokr ssh prod-bastion uname -a
brokr <你的-cli> <别名> [args...]
```

### 列出元数据（AI / 脚本安全）

```bash
brokr list --json
```

### Reveal / 删除（仅人类，需真实 TTY）

```bash
brokr reveal mysql prod-db --field password
brokr rm ssh prod-bastion
```

### 管理界面安全

- 仅 **127.0.0.1**；会话 token 在终端显示
- 密码：仅创建 / 轮换 — 无读取 API
- 删除 / 轮换需 reveal 口令（自动保存记录可输入 `YES`）
- 空闲 15 分钟超时

## 架构

```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI/用户 │────▶│ brokr CLI│────▶│ OS Keychain │────▶│ Vault 文件 │
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

**计划：** `~/.brokr/profiles/` 下完整 TOML 连接器 profile 与按工具注入策略。

## 管道 stdin 与 OpenSSH 共享

- **管道 stdin**（`tar | brokr ssh host 'tar xf -'`）：注入完成后再转发管道数据。
- **OpenSSH 族**（`ssh`、`scp`、`sftp`）：主机匹配时复用已保存凭据。须先交互保存（需 TTY）。

## 开发

```bash
cargo test    # 仅 src/ 内单元测试（本仓库无 tests/ 集成测试套件）
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release   # 二进制：target/release/brokr
```

版本号见 [`VERSION`](VERSION)（同步体现在 `Cargo.toml` 与 `packages/brokr-mcp/package.json`）。正式发布的二进制与 npm 包由 [TechinOne](https://www.tio.tech) 通过 GitHub Releases 与 CI 发布，**不属于本开源仓库内容**。

## 许可证

MIT — 见 [LICENSE](LICENSE)。

---

[Techinone](https://www.tio.tech) · 成都同创合一科技有限公司

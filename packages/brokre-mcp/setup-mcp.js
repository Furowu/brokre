#!/usr/bin/env node
/**
 * Detect installed MCP-capable IDEs and register brokre globally.
 *
 * Runs on `npm i brokre` (postinstall) or manually: `npx brokre-setup-mcp`
 *
 * Opt out: BROKRE_MCP_SKIP_SETUP=1
 */
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SERVER_NAME = 'brokre';
const STDIO_ENTRY = {
  command: 'npx',
  args: ['-y', 'brokre@latest'],
};
const VSCODE_ENTRY = {
  type: 'stdio',
  ...STDIO_ENTRY,
};
const CLAUDE_CODE_ENTRY = {
  type: 'stdio',
  ...STDIO_ENTRY,
};

function homedir() {
  return os.homedir();
}

function appSupport(...segments) {
  if (process.platform === 'darwin') {
    return path.join(homedir(), 'Library', 'Application Support', ...segments);
  }
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(homedir(), 'AppData', 'Roaming');
    return path.join(base, ...segments);
  }
  return path.join(homedir(), '.config', ...segments);
}

function commandExists(name) {
  try {
    const which = process.platform === 'win32' ? 'where' : 'which';
    execFileSync(which, [name], { encoding: 'utf8', stdio: 'pipe' });
    return true;
  } catch (_) {
    return false;
  }
}

function pathExists(p) {
  try {
    return fs.existsSync(p);
  } catch (_) {
    return false;
  }
}

function macAppExists(name) {
  if (process.platform !== 'darwin') return false;
  return pathExists(`/Applications/${name}.app`);
}

function anyPathExists(paths) {
  return paths.some(pathExists);
}

function dirHasEntries(dir, { exclude = [] } = {}) {
  try {
    return fs
      .readdirSync(dir)
      .some((name) => !exclude.includes(name) && !name.startsWith('.'));
  } catch (_) {
    return false;
  }
}

function fileHasContent(filePath) {
  try {
    return fs.statSync(filePath).size > 0;
  } catch (_) {
    return false;
  }
}

function isBrokreEntry(entry) {
  if (!entry || typeof entry !== 'object') return false;
  if (entry.command === 'npx' && Array.isArray(entry.args)) {
    return entry.args.some(
      (a) => typeof a === 'string' && (a === 'brokre@latest' || a.startsWith('brokre@'))
    );
  }
  if (typeof entry.command === 'string' && entry.command.includes('brokre')) {
    return true;
  }
  return false;
}

function entriesEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function entryNeedsUpgrade(entry) {
  if (!isBrokreEntry(entry)) return true;
  return !(
    entry.command === 'npx' &&
    Array.isArray(entry.args) &&
    entry.args.includes('-y') &&
    entry.args.some((a) => typeof a === 'string' && a === 'brokre@latest')
  );
}

function findBrokreAlias(servers) {
  if (!servers || typeof servers !== 'object') return null;
  for (const [name, entry] of Object.entries(servers)) {
    if (name !== SERVER_NAME && isBrokreEntry(entry)) {
      return name;
    }
  }
  return null;
}

function readJsonFile(filePath) {
  if (!pathExists(filePath)) {
    return { exists: false, data: null };
  }
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  if (!raw) {
    return { exists: true, data: {} };
  }
  try {
    return { exists: true, data: JSON.parse(raw) };
  } catch (err) {
    return { exists: true, data: null, error: err };
  }
}

function writeJsonFile(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (pathExists(filePath)) {
    const backup = `${filePath}.brokre.bak`;
    fs.copyFileSync(filePath, backup);
  }
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
}

function mergeMcpServers(data, serversKey, entry, options = {}) {
  const next = data && typeof data === 'object' ? { ...data } : {};
  if (!next[serversKey] || typeof next[serversKey] !== 'object') {
    next[serversKey] = {};
  } else {
    next[serversKey] = { ...next[serversKey] };
  }

  const alias = findBrokreAlias(next[serversKey]);
  if (alias && !options.force) {
    return { data: next, action: 'skipped', alias };
  }

  const existing = next[serversKey][SERVER_NAME];
  if (existing && entriesEqual(existing, entry) && !options.force) {
    return { data: next, action: 'skipped' };
  }
  if (existing && !entryNeedsUpgrade(existing) && !options.force) {
    return { data: next, action: 'skipped' };
  }

  const action = existing ? 'updated' : 'added';
  next[serversKey][SERVER_NAME] = { ...entry };
  return { data: next, action };
}

function mergeOpenClaw(data, entry, options = {}) {
  const next = data && typeof data === 'object' ? { ...data } : {};
  if (!next.mcp || typeof next.mcp !== 'object') {
    next.mcp = {};
  } else {
    next.mcp = { ...next.mcp };
  }
  if (!next.mcp.servers || typeof next.mcp.servers !== 'object') {
    next.mcp.servers = {};
  } else {
    next.mcp.servers = { ...next.mcp.servers };
  }

  const alias = findBrokreAlias(next.mcp.servers);
  if (alias && !options.force) {
    return { data: next, action: 'skipped', alias };
  }

  const existing = next.mcp.servers[SERVER_NAME];
  if (existing && entriesEqual(existing, entry) && !options.force) {
    return { data: next, action: 'skipped' };
  }
  if (existing && !entryNeedsUpgrade(existing) && !options.force) {
    return { data: next, action: 'skipped' };
  }

  const action = existing ? 'updated' : 'added';
  next.mcp.servers[SERVER_NAME] = { ...entry };
  return { data: next, action };
}

function isClaudeCodeInstalled() {
  const claudeJson = path.join(homedir(), '.claude.json');
  if (commandExists('claude')) return true;
  const read = readJsonFile(claudeJson);
  if (!read.exists || !read.data || read.error) return false;
  return Boolean(
    read.data.mcpServers ||
      read.data.projects ||
      read.data.hasCompletedOnboarding !== undefined
  );
}

function isOpenClawInstalled() {
  if (commandExists('openclaw')) return true;
  const cfg =
    process.env.OPENCLAW_CONFIG_PATH || path.join(homedir(), '.openclaw', 'openclaw.json');
  const read = readJsonFile(cfg);
  if (!read.exists || !read.data || read.error) return false;
  const keys = Object.keys(read.data);
  if (keys.length === 0) return false;
  return keys.some((key) => key !== 'mcp');
}

/** Registered IDE targets for global MCP setup. */
const IDE_TARGETS = [
  {
    id: 'cursor',
    name: 'Cursor',
    isInstalled() {
      const root = path.join(homedir(), '.cursor');
      return (
        macAppExists('Cursor') ||
        anyPathExists([
          path.join(root, 'argv.json'),
          path.join(root, 'User'),
          path.join(root, 'extensions'),
          path.join(root, 'ide_state.json'),
        ])
      );
    },
    configPath() {
      return path.join(homedir(), '.cursor', 'mcp.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'vscode',
    name: 'VS Code',
    isInstalled() {
      const userDir = appSupport('Code', 'User');
      return (
        commandExists('code') ||
        anyPathExists([
          path.join(userDir, 'settings.json'),
          path.join(userDir, 'globalStorage'),
          path.join(userDir, 'keybindings.json'),
        ])
      );
    },
    configPath() {
      return path.join(appSupport('Code', 'User'), 'mcp.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'servers', VSCODE_ENTRY, options);
    },
  },
  {
    id: 'vscode-insiders',
    name: 'VS Code Insiders',
    isInstalled() {
      const userDir = appSupport('Code - Insiders', 'User');
      return (
        commandExists('code-insiders') ||
        anyPathExists([
          path.join(userDir, 'settings.json'),
          path.join(userDir, 'globalStorage'),
          path.join(userDir, 'keybindings.json'),
        ])
      );
    },
    configPath() {
      return path.join(appSupport('Code - Insiders', 'User'), 'mcp.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'servers', VSCODE_ENTRY, options);
    },
  },
  {
    id: 'claude-code',
    name: 'Claude Code',
    isInstalled: isClaudeCodeInstalled,
    configPath() {
      return path.join(homedir(), '.claude.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', CLAUDE_CODE_ENTRY, options);
    },
  },
  {
    id: 'claude-desktop',
    name: 'Claude Desktop',
    isInstalled() {
      const cfg = path.join(appSupport('Claude'), 'claude_desktop_config.json');
      return macAppExists('Claude') || (pathExists(cfg) && fileHasContent(cfg));
    },
    configPath() {
      return path.join(appSupport('Claude'), 'claude_desktop_config.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'trae',
    name: 'Trae',
    isInstalled() {
      const userDir = path.join(appSupport('Trae', 'User'));
      return (
        macAppExists('Trae') ||
        anyPathExists([
          path.join(userDir, 'settings.json'),
          path.join(userDir, 'globalStorage'),
        ]) ||
        dirHasEntries(userDir, { exclude: ['mcp.json'] })
      );
    },
    configPath() {
      return path.join(appSupport('Trae', 'User'), 'mcp.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'kimi-code',
    name: 'Kimi Code',
    isInstalled() {
      const root = process.env.KIMI_CODE_HOME || path.join(homedir(), '.kimi-code');
      return (
        commandExists('kimi') ||
        anyPathExists([
          path.join(root, 'config.toml'),
          path.join(root, 'sessions'),
          path.join(root, 'credentials'),
        ]) ||
        dirHasEntries(path.join(root, 'plugins'), {})
      );
    },
    configPath() {
      const root = process.env.KIMI_CODE_HOME || path.join(homedir(), '.kimi-code');
      return path.join(root, 'mcp.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    isInstalled() {
      const root = path.join(homedir(), '.codeium', 'windsurf');
      return (
        macAppExists('Windsurf') ||
        anyPathExists([
          path.join(root, 'user_settings.pb'),
          path.join(root, 'memories'),
          path.join(root, 'cascade'),
        ]) ||
        dirHasEntries(root, { exclude: ['mcp_config.json'] })
      );
    },
    configPath() {
      return path.join(homedir(), '.codeium', 'windsurf', 'mcp_config.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'openclaw',
    name: 'OpenClaw',
    isInstalled: isOpenClawInstalled,
    configPath() {
      return process.env.OPENCLAW_CONFIG_PATH || path.join(homedir(), '.openclaw', 'openclaw.json');
    },
    merge(data, options) {
      return mergeOpenClaw(data, STDIO_ENTRY, options);
    },
  },
];

function setupBrokreMcp(options = {}) {
  const force = Boolean(options.force);
  const dryRun = Boolean(options.dryRun);
  const targets = options.targets || IDE_TARGETS;
  const results = [];

  for (const ide of targets) {
    const installed = ide.isInstalled();
    if (!installed) {
      results.push({ id: ide.id, name: ide.name, status: 'not_installed' });
      continue;
    }

    const filePath = ide.configPath();
    const read = readJsonFile(filePath);
    if (read.error) {
      results.push({
        id: ide.id,
        name: ide.name,
        status: 'error',
        path: filePath,
        message: `invalid JSON: ${read.error.message}`,
      });
      continue;
    }

    const { data, action, alias } = ide.merge(read.data, { force });
    if (action === 'skipped') {
      results.push({
        id: ide.id,
        name: ide.name,
        status: 'skipped',
        path: filePath,
        message: alias ? `already registered as "${alias}"` : 'already configured',
      });
      continue;
    }

    if (read.exists && read.data && entriesEqual(read.data, data)) {
      results.push({
        id: ide.id,
        name: ide.name,
        status: 'skipped',
        path: filePath,
        message: 'no changes',
      });
      continue;
    }

    if (!dryRun) {
      writeJsonFile(filePath, data);
    }

    results.push({
      id: ide.id,
      name: ide.name,
      status: action,
      path: filePath,
    });
  }

  return results;
}

function printResults(results) {
  const touched = results.filter((r) => r.status !== 'not_installed');
  if (touched.length === 0) {
    process.stderr.write('brokre: no installed IDE detected; MCP config unchanged.\n');
    process.stderr.write('brokre: manual setup — npx -y brokre@latest in your IDE MCP settings.\n');
    return;
  }

  for (const r of results) {
    if (r.status === 'not_installed') continue;
    const pathHint = r.path ? ` (${r.path})` : '';
    if (r.status === 'error') {
      process.stderr.write(`brokre: ${r.name}: ${r.message}${pathHint}\n`);
      continue;
    }
    if (r.status === 'skipped') {
      process.stderr.write(`brokre: ${r.name}: ${r.message}${pathHint}\n`);
      continue;
    }
    process.stderr.write(`brokre: ${r.name}: ${r.status}${pathHint}\n`);
  }

  const changed = results.some((r) => r.status === 'added' || r.status === 'updated');
  if (changed) {
    process.stderr.write('brokre: restart your IDE(s) to load the brokre MCP server.\n');
  }
}

function shouldSkipAutoSetup() {
  if (process.env.BROKRE_MCP_SKIP_SETUP === '1') return true;
  if (process.env.CI === 'true' || process.env.CI === '1') return true;
  return false;
}

function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const force = args.includes('--force');

  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`brokre MCP setup — register brokre in detected IDEs

Usage:
  npx brokre-setup-mcp [--dry-run] [--force]

Options:
  --dry-run   Show what would change without writing files
  --force     Overwrite existing brokre MCP entries

Environment:
  BROKRE_MCP_SKIP_SETUP=1   Skip automatic setup on npm install

Only registers when the IDE is installed (app, CLI, or real usage artifacts).
Does not create config files for software that is not present.
`);
    return;
  }

  const results = setupBrokreMcp({ dryRun, force });
  printResults(results);
}

if (require.main === module) {
  const isPostinstall = process.env.npm_lifecycle_event === 'postinstall';
  if (isPostinstall && shouldSkipAutoSetup()) {
    process.exit(0);
  }
  main();
}

module.exports = {
  IDE_TARGETS,
  SERVER_NAME,
  STDIO_ENTRY,
  VSCODE_ENTRY,
  setupBrokreMcp,
  mergeMcpServers,
  mergeOpenClaw,
  isBrokreEntry,
  entryNeedsUpgrade,
  findBrokreAlias,
  entriesEqual,
  readJsonFile,
  writeJsonFile,
  isClaudeCodeInstalled,
  isOpenClawInstalled,
  dirHasEntries,
  anyPathExists,
};

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

function xdgConfig(...segments) {
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(homedir(), 'AppData', 'Roaming');
    return path.join(base, ...segments);
  }
  const base = process.env.XDG_CONFIG_HOME || path.join(homedir(), '.config');
  return path.join(base, ...segments);
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

function readTextFile(filePath) {
  if (!pathExists(filePath)) {
    return { exists: false, text: '' };
  }
  try {
    return { exists: true, text: fs.readFileSync(filePath, 'utf8') };
  } catch (err) {
    return { exists: true, text: null, error: err };
  }
}

function writeTextFile(filePath, text) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (pathExists(filePath)) {
    const backup = `${filePath}.brokre.bak`;
    fs.copyFileSync(filePath, backup);
  }
  const body = text.endsWith('\n') ? text : `${text}\n`;
  fs.writeFileSync(filePath, body, { mode: 0o600 });
}

function mergeMcpServers(data, serversKey, entry, options = {}) {
  const next = data && typeof data === 'object' ? { ...data } : {};
  if (!next[serversKey] || typeof next[serversKey] !== 'object' || Array.isArray(next[serversKey])) {
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

/** Zed uses `context_servers` instead of `mcpServers`. */
function mergeContextServers(data, entry, options = {}) {
  return mergeMcpServers(data, 'context_servers', entry, options);
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

function tomlQuote(value) {
  return JSON.stringify(String(value));
}

function formatTomlStdioTable(serverName, entry) {
  const args = (entry.args || []).map(tomlQuote).join(', ');
  return (
    `[mcp_servers.${serverName}]\n` +
    `command = ${tomlQuote(entry.command)}\n` +
    `args = [${args}]\n`
  );
}

function extractTomlTableBody(text, tableName) {
  const lines = String(text || '').split(/\r?\n/);
  const header = `[${tableName}]`;
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === header) {
      start = i + 1;
      break;
    }
  }
  if (start < 0) return null;
  const body = [];
  for (let i = start; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) break;
    body.push(lines[i]);
  }
  return body.join('\n');
}

function parseTomlStdioEntry(body) {
  if (body == null) return null;
  const commandMatch = body.match(/^\s*command\s*=\s*"((?:\\.|[^"\\])*)"\s*$/m);
  const argsMatch = body.match(/^\s*args\s*=\s*\[([\s\S]*?)\]\s*$/m);
  if (!commandMatch) return null;
  const entry = { command: JSON.parse(`"${commandMatch[1]}"`) };
  if (argsMatch) {
    const inner = argsMatch[1].trim();
    if (!inner) {
      entry.args = [];
    } else {
      try {
        entry.args = JSON.parse(`[${inner}]`);
      } catch (_) {
        entry.args = [];
      }
    }
  }
  return entry;
}

function findTomlBrokreAlias(text) {
  const re = /^\[mcp_servers\.([^\].]+)\]\s*$/gm;
  let match;
  while ((match = re.exec(text)) !== null) {
    const name = match[1];
    if (name === SERVER_NAME || name.includes('.')) continue;
    const body = extractTomlTableBody(text, `mcp_servers.${name}`);
    const entry = parseTomlStdioEntry(body);
    if (entry && isBrokreEntry(entry)) return name;
  }
  return null;
}

function stripTomlTable(text, tableName) {
  const lines = String(text || '').split(/\r?\n/);
  const out = [];
  let skipping = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const name = trimmed.slice(1, -1).trim();
      if (name === tableName || name.startsWith(`${tableName}.`)) {
        skipping = true;
        continue;
      }
      skipping = false;
    }
    if (!skipping) out.push(line);
  }
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  return out.join('\n');
}

/**
 * Upsert `[mcp_servers.brokre]` in Codex-style TOML without destroying other keys.
 */
function mergeCodexToml(text, entry = STDIO_ENTRY, options = {}) {
  const raw = text || '';
  const alias = findTomlBrokreAlias(raw);
  if (alias && !options.force) {
    return { text: raw, action: 'skipped', alias };
  }

  const existingBody = extractTomlTableBody(raw, `mcp_servers.${SERVER_NAME}`);
  const existing = parseTomlStdioEntry(existingBody);
  if (existing && entriesEqual(existing, entry) && !options.force) {
    return { text: raw, action: 'skipped' };
  }
  if (existing && !entryNeedsUpgrade(existing) && !options.force) {
    return { text: raw, action: 'skipped' };
  }

  let next = stripTomlTable(raw, `mcp_servers.${SERVER_NAME}`);
  if (next && !next.endsWith('\n')) next += '\n';
  if (next) next += '\n';
  next += formatTomlStdioTable(SERVER_NAME, entry);
  if (!next.endsWith('\n')) next += '\n';

  const action = existing ? 'updated' : 'added';
  return { text: next, action };
}

function yamlScalar(value) {
  return JSON.stringify(String(value));
}

function formatYamlStdioFields(indent, entry) {
  const pad = ' '.repeat(indent);
  const pad2 = ' '.repeat(indent + 2);
  let out = `${pad}command: ${yamlScalar(entry.command)}\n`;
  out += `${pad}args:\n`;
  for (const arg of entry.args || []) {
    out += `${pad2}- ${yamlScalar(arg)}\n`;
  }
  return out;
}

function findTopLevelKeyRange(text, key) {
  const lines = String(text || '').split(/\r?\n/);
  const keyRe = new RegExp(`^${key}:\\s*(?:#.*)?$`);
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (keyRe.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\S/.test(lines[i]) && !lines[i].startsWith('#')) {
      end = i;
      break;
    }
  }
  return { lines, start, end };
}

function findChildKeyRange(lines, parentStart, parentEnd, childKey, childIndent) {
  const childRe = new RegExp(`^${' '.repeat(childIndent)}${childKey}:\\s*(?:#.*)?$`);
  let start = -1;
  for (let i = parentStart + 1; i < parentEnd; i++) {
    if (childRe.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  let end = parentEnd;
  for (let i = start + 1; i < parentEnd; i++) {
    const line = lines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    const indent = line.match(/^ */)[0].length;
    if (indent <= childIndent) {
      end = i;
      break;
    }
  }
  return { start, end };
}

function parseYamlStdioFields(blockLines) {
  const text = blockLines.join('\n');
  const commandMatch = text.match(/^\s*command:\s*(.+?)\s*$/m);
  if (!commandMatch) return null;
  let command = commandMatch[1].trim();
  if (
    (command.startsWith('"') && command.endsWith('"')) ||
    (command.startsWith("'") && command.endsWith("'"))
  ) {
    command = command.slice(1, -1);
  }
  const args = [];
  const argsIdx = blockLines.findIndex((l) => /^\s*args:\s*(?:#.*)?$/.test(l));
  if (argsIdx >= 0) {
    for (let i = argsIdx + 1; i < blockLines.length; i++) {
      const m = blockLines[i].match(/^\s*-\s*(.+?)\s*$/);
      if (!m) break;
      let v = m[1].trim();
      if (
        (v.startsWith('"') && v.endsWith('"')) ||
        (v.startsWith("'") && v.endsWith("'"))
      ) {
        v = v.slice(1, -1);
      }
      args.push(v);
    }
  }
  return { command, args };
}

function findYamlBrokreAlias(text, mapKey) {
  const range = findTopLevelKeyRange(text, mapKey);
  if (!range) return null;
  const { lines, start, end } = range;
  for (let i = start + 1; i < end; i++) {
    const m = lines[i].match(/^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$/);
    if (!m) continue;
    const name = m[1];
    if (name === SERVER_NAME) continue;
    const child = findChildKeyRange(lines, start, end, name, 2);
    if (!child) continue;
    const entry = parseYamlStdioFields(lines.slice(child.start + 1, child.end));
    if (entry && isBrokreEntry(entry)) return name;
  }
  return null;
}

/**
 * Upsert a map-style YAML server under `mcp_servers:` (Hermes).
 * Surgical text edit — does not re-serialize the whole document.
 */
function mergeHermesYaml(text, entry = STDIO_ENTRY, options = {}) {
  const raw = text || '';
  const alias = findYamlBrokreAlias(raw, 'mcp_servers');
  if (alias && !options.force) {
    return { text: raw, action: 'skipped', alias };
  }

  const range = findTopLevelKeyRange(raw, 'mcp_servers');
  if (!range) {
    let next = raw.replace(/\s*$/, '');
    if (next) next += '\n\n';
    next +=
      'mcp_servers:\n' +
      `  ${SERVER_NAME}:\n` +
      formatYamlStdioFields(4, entry);
    return { text: next, action: 'added' };
  }

  const { lines, start, end } = range;
  const child = findChildKeyRange(lines, start, end, SERVER_NAME, 2);
  if (child) {
    const existing = parseYamlStdioFields(lines.slice(child.start + 1, child.end));
    if (existing && entriesEqual(existing, entry) && !options.force) {
      return { text: raw, action: 'skipped' };
    }
    if (existing && !entryNeedsUpgrade(existing) && !options.force) {
      return { text: raw, action: 'skipped' };
    }
    const replacement = [
      `  ${SERVER_NAME}:`,
      ...formatYamlStdioFields(4, entry).replace(/\n$/, '').split('\n'),
    ];
    const nextLines = [...lines.slice(0, child.start), ...replacement, ...lines.slice(child.end)];
    return { text: `${nextLines.join('\n')}\n`, action: 'updated' };
  }

  const insertAt = end;
  const insertion = [
    `  ${SERVER_NAME}:`,
    ...formatYamlStdioFields(4, entry).replace(/\n$/, '').split('\n'),
  ];
  const nextLines = [...lines.slice(0, insertAt), ...insertion, ...lines.slice(insertAt)];
  return { text: `${nextLines.join('\n')}\n`, action: 'added' };
}

/**
 * Upsert Continue list-style `mcpServers:` entry in config.yaml.
 */
function mergeContinueConfigYaml(text, entry = STDIO_ENTRY, options = {}) {
  const raw = text || '';
  const listItemLines = [
    '  - name: brokre',
    `    command: ${entry.command}`,
    '    args:',
    ...((entry.args || []).map((a) => `      - ${yamlScalar(a)}`)),
  ];

  const range = findTopLevelKeyRange(raw, 'mcpServers');
  if (!range) {
    let next = raw.replace(/\s*$/, '');
    if (next) next += '\n\n';
    next += `mcpServers:\n${listItemLines.join('\n')}\n`;
    return { text: next, action: 'added' };
  }

  const { lines, start, end } = range;

  // Extract existing brokre list item (if any)
  let brokreStart = -1;
  let brokreEnd = -1;
  for (let i = start + 1; i < end; i++) {
    if (/^  - name:\s*brokre\s*$/.test(lines[i])) {
      brokreStart = i;
      brokreEnd = end;
      for (let j = i + 1; j < end; j++) {
        if (/^  - name:\s*/.test(lines[j])) {
          brokreEnd = j;
          break;
        }
      }
      break;
    }
  }

  if (brokreStart >= 0 && !options.force) {
    const block = lines.slice(brokreStart, brokreEnd).join('\n');
    const cmd = /command:\s*(\S+)/.exec(block);
    const hasLatest = /brokre@latest/.test(block);
    const hasNpx = cmd && cmd[1].replace(/['"]/g, '') === 'npx';
    if (hasNpx && hasLatest && /-y/.test(block)) {
      return { text: raw, action: 'skipped' };
    }
  }

  const bodyWithoutBrokre = [];
  for (let i = start + 1; i < end; i++) {
    if (brokreStart >= 0 && i >= brokreStart && i < brokreEnd) continue;
    bodyWithoutBrokre.push(lines[i]);
  }

  const next = [
    ...lines.slice(0, start + 1),
    ...bodyWithoutBrokre,
    ...listItemLines,
    ...lines.slice(end),
  ];
  return {
    text: `${next.join('\n')}\n`,
    action: brokreStart >= 0 ? 'updated' : 'added',
  };
}

function continueDropinYaml(entry = STDIO_ENTRY) {
  return (
    'name: brokre\n' +
    'version: 0.0.1\n' +
    'schema: v1\n' +
    'mcpServers:\n' +
    '  - name: brokre\n' +
    `    command: ${entry.command}\n` +
    '    args:\n' +
    (entry.args || []).map((a) => `      - ${yamlScalar(a)}`).join('\n') +
    '\n'
  );
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

function isCodexInstalled() {
  if (commandExists('codex')) return true;
  const root = process.env.CODEX_HOME || path.join(homedir(), '.codex');
  return (
    anyPathExists([
      path.join(root, 'config.toml'),
      path.join(root, 'auth.json'),
      path.join(root, 'history.jsonl'),
      path.join(root, 'sessions'),
    ]) || dirHasEntries(root, { exclude: ['config.toml'] })
  );
}

function isGeminiCliInstalled() {
  if (commandExists('gemini')) return true;
  const root = path.join(homedir(), '.gemini');
  return (
    anyPathExists([
      path.join(root, 'settings.json'),
      path.join(root, 'tmp'),
      path.join(root, 'history'),
    ]) || dirHasEntries(root, { exclude: ['settings.json'] })
  );
}

function isHermesInstalled() {
  if (commandExists('hermes')) return true;
  const root = path.join(homedir(), '.hermes');
  const cfg = path.join(root, 'config.yaml');
  return pathExists(cfg) || dirHasEntries(root, { exclude: ['config.yaml'] });
}

function isContinueInstalled() {
  const root = path.join(homedir(), '.continue');
  return (
    anyPathExists([
      path.join(root, 'config.yaml'),
      path.join(root, 'config.json'),
      path.join(root, 'config.ts'),
      path.join(root, 'index'),
      path.join(root, 'sessions'),
      path.join(root, 'types'),
    ]) ||
    dirHasEntries(path.join(root, 'mcpServers'), {}) ||
    dirHasEntries(root, { exclude: ['mcpServers'] })
  );
}

function isZedInstalled() {
  const settings = zedSettingsPath();
  return (
    macAppExists('Zed') ||
    commandExists('zed') ||
    (pathExists(settings) && fileHasContent(settings)) ||
    dirHasEntries(path.dirname(settings), { exclude: ['settings.json'] })
  );
}

function zedSettingsPath() {
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(homedir(), 'AppData', 'Roaming');
    return path.join(base, 'Zed', 'settings.json');
  }
  return xdgConfig('zed', 'settings.json');
}

function isChatgptDesktopInstalled() {
  if (macAppExists('ChatGPT')) return true;
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA || path.join(homedir(), 'AppData', 'Local');
    return anyPathExists([
      path.join(local, 'Programs', 'ChatGPT', 'ChatGPT.exe'),
      path.join(local, 'ChatGPT'),
    ]);
  }
  if (process.platform === 'linux') {
    return (
      commandExists('chatgpt') ||
      anyPathExists([
        path.join(homedir(), '.local', 'share', 'ChatGPT'),
        '/opt/ChatGPT',
      ])
    );
  }
  return false;
}

function continueConfigPath() {
  const yamlPath = path.join(homedir(), '.continue', 'config.yaml');
  if (pathExists(yamlPath)) return yamlPath;
  return path.join(homedir(), '.continue', 'mcpServers', 'brokre.yaml');
}

/** Registered IDE targets for global MCP setup. */
const IDE_TARGETS = [
  {
    id: 'cursor',
    name: 'Cursor',
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
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
    format: 'json',
    isInstalled: isOpenClawInstalled,
    configPath() {
      return process.env.OPENCLAW_CONFIG_PATH || path.join(homedir(), '.openclaw', 'openclaw.json');
    },
    merge(data, options) {
      return mergeOpenClaw(data, STDIO_ENTRY, options);
    },
  },
  {
    id: 'codex',
    name: 'Codex CLI',
    format: 'toml',
    isInstalled: isCodexInstalled,
    configPath() {
      const root = process.env.CODEX_HOME || path.join(homedir(), '.codex');
      return path.join(root, 'config.toml');
    },
    mergeText(text, options) {
      return mergeCodexToml(text, STDIO_ENTRY, options);
    },
  },
  {
    id: 'gemini-cli',
    name: 'Gemini CLI',
    format: 'json',
    isInstalled: isGeminiCliInstalled,
    configPath() {
      return path.join(homedir(), '.gemini', 'settings.json');
    },
    merge(data, options) {
      return mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options);
    },
  },
  {
    id: 'hermes',
    name: 'Hermes Agent',
    format: 'yaml',
    isInstalled: isHermesInstalled,
    configPath() {
      return path.join(homedir(), '.hermes', 'config.yaml');
    },
    mergeText(text, options) {
      return mergeHermesYaml(text, STDIO_ENTRY, options);
    },
  },
  {
    id: 'continue',
    name: 'Continue',
    format: 'continue',
    isInstalled: isContinueInstalled,
    configPath: continueConfigPath,
    applyContinue(options) {
      const yamlConfig = path.join(homedir(), '.continue', 'config.yaml');
      if (pathExists(yamlConfig)) {
        const read = readTextFile(yamlConfig);
        if (read.error) {
          return { error: read.error, path: yamlConfig };
        }
        const { text, action, alias } = mergeContinueConfigYaml(read.text, STDIO_ENTRY, options);
        return {
          path: yamlConfig,
          exists: read.exists,
          previous: read.text,
          text,
          action,
          alias,
        };
      }
      const dropin = path.join(homedir(), '.continue', 'mcpServers', 'brokre.yaml');
      const read = readTextFile(dropin);
      const desired = continueDropinYaml(STDIO_ENTRY);
      if (read.exists && read.text === desired && !options.force) {
        return {
          path: dropin,
          exists: true,
          previous: read.text,
          text: desired,
          action: 'skipped',
        };
      }
      const action = read.exists ? 'updated' : 'added';
      return {
        path: dropin,
        exists: read.exists,
        previous: read.text,
        text: desired,
        action,
      };
    },
  },
  {
    id: 'zed',
    name: 'Zed',
    format: 'json',
    isInstalled: isZedInstalled,
    configPath: zedSettingsPath,
    merge(data, options) {
      return mergeContextServers(data, STDIO_ENTRY, options);
    },
  },
  {
    id: 'chatgpt-desktop',
    name: 'ChatGPT Desktop',
    format: 'unsupported',
    isInstalled: isChatgptDesktopInstalled,
    message:
      'ChatGPT Desktop only supports remote MCP Connectors in the UI — no local stdio config file to write',
  },
  {
    id: 'grok-bot',
    name: 'Grok Bot',
    format: 'info',
    isInstalled() {
      return true;
    },
    message:
      'Grok Bot uses connectors/plugins — ask the bot to add stdio MCP `npx -y brokre@latest`, or install when a marketplace plugin exists (no mcp.json to write)',
  },
];

function applyJsonTarget(ide, force, dryRun) {
  const filePath = ide.configPath();
  const read = readJsonFile(filePath);
  if (read.error) {
    return {
      id: ide.id,
      name: ide.name,
      status: 'error',
      path: filePath,
      message: `invalid JSON: ${read.error.message}`,
    };
  }

  const { data, action, alias } = ide.merge(read.data, { force });
  if (action === 'skipped') {
    return {
      id: ide.id,
      name: ide.name,
      status: 'skipped',
      path: filePath,
      message: alias ? `already registered as "${alias}"` : 'already configured',
    };
  }

  if (read.exists && read.data && entriesEqual(read.data, data)) {
    return {
      id: ide.id,
      name: ide.name,
      status: 'skipped',
      path: filePath,
      message: 'no changes',
    };
  }

  if (!dryRun) {
    writeJsonFile(filePath, data);
  }

  return {
    id: ide.id,
    name: ide.name,
    status: action,
    path: filePath,
  };
}

function applyTextTarget(ide, force, dryRun) {
  const filePath = ide.configPath();
  const read = readTextFile(filePath);
  if (read.error) {
    return {
      id: ide.id,
      name: ide.name,
      status: 'error',
      path: filePath,
      message: read.error.message,
    };
  }

  const { text, action, alias } = ide.mergeText(read.text, { force });
  if (action === 'skipped') {
    return {
      id: ide.id,
      name: ide.name,
      status: 'skipped',
      path: filePath,
      message: alias ? `already registered as "${alias}"` : 'already configured',
    };
  }

  if (read.exists && read.text === text) {
    return {
      id: ide.id,
      name: ide.name,
      status: 'skipped',
      path: filePath,
      message: 'no changes',
    };
  }

  if (!dryRun) {
    writeTextFile(filePath, text);
  }

  return {
    id: ide.id,
    name: ide.name,
    status: action,
    path: filePath,
  };
}

function applyContinueTarget(ide, force, dryRun) {
  const result = ide.applyContinue({ force });
  if (result.error) {
    return {
      id: ide.id,
      name: ide.name,
      status: 'error',
      path: result.path,
      message: result.error.message,
    };
  }
  if (result.action === 'skipped') {
    return {
      id: ide.id,
      name: ide.name,
      status: 'skipped',
      path: result.path,
      message: result.alias ? `already registered as "${result.alias}"` : 'already configured',
    };
  }
  if (!dryRun) {
    writeTextFile(result.path, result.text);
  }
  return {
    id: ide.id,
    name: ide.name,
    status: result.action,
    path: result.path,
  };
}

function setupBrokreMcp(options = {}) {
  const force = Boolean(options.force);
  const dryRun = Boolean(options.dryRun);
  const targets = options.targets || IDE_TARGETS;
  const results = [];

  for (const ide of targets) {
    const format = ide.format || 'json';

    if (format === 'info') {
      results.push({
        id: ide.id,
        name: ide.name,
        status: 'info',
        message: ide.message,
      });
      continue;
    }

    const installed = ide.isInstalled();
    if (!installed) {
      results.push({ id: ide.id, name: ide.name, status: 'not_installed' });
      continue;
    }

    if (format === 'unsupported') {
      results.push({
        id: ide.id,
        name: ide.name,
        status: 'unsupported',
        message: ide.message || 'unsupported',
      });
      continue;
    }

    if (format === 'continue') {
      results.push(applyContinueTarget(ide, force, dryRun));
      continue;
    }

    if (format === 'toml' || format === 'yaml') {
      results.push(applyTextTarget(ide, force, dryRun));
      continue;
    }

    results.push(applyJsonTarget(ide, force, dryRun));
  }

  return results;
}

function printResults(results) {
  const touched = results.filter(
    (r) => r.status !== 'not_installed' && r.status !== 'info'
  );
  const infos = results.filter((r) => r.status === 'info');

  if (touched.length === 0 && infos.length === 0) {
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
    if (r.status === 'unsupported') {
      process.stderr.write(`brokre: ${r.name}: skipped — ${r.message}\n`);
      continue;
    }
    if (r.status === 'info') {
      process.stderr.write(`brokre: ${r.name}: ${r.message}\n`);
      continue;
    }
    process.stderr.write(`brokre: ${r.name}: ${r.status}${pathHint}\n`);
  }

  const changed = results.some((r) => r.status === 'added' || r.status === 'updated');
  if (changed) {
    process.stderr.write('brokre: restart your IDE(s) to load the brokre MCP server.\n');
  }
}

function printGrokBotTip() {
  process.stderr.write(
    'brokre: Grok Bot tip — uses connectors/plugins; ask the bot to add stdio MCP ' +
      '`npx -y brokre@latest`, or install when a marketplace plugin exists.\n'
  );
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
  brokre mcp setup [--dry-run] [--force]

Options:
  --dry-run   Show what would change without writing files
  --force     Overwrite existing brokre MCP entries

Environment:
  BROKRE_MCP_SKIP_SETUP=1   Skip automatic setup on npm install

Only registers when the IDE is installed (app, CLI, or real usage artifacts).
Does not create config files for software that is not present.
ChatGPT Desktop has no local stdio config (remote Connectors only).
Grok Bot uses connectors/plugins — no mcp.json path to invent.
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
  if (isPostinstall) {
    printGrokBotTip();
  }
  if (isPostinstall && process.platform === 'win32') {
    process.stderr.write(
      '\nbrokre: Windows — `brokre` is only on PATH after a global install:\n' +
        '  npm install -g brokre\n' +
        'Local `npm i brokre` does not create a `brokre` command.\n' +
        'If npm warned about install-scripts, re-run:\n' +
        '  npm install -g brokre --allow-scripts=brokre\n' +
        'Do not run `npm install -g --allow-scripts=brokre` without the package name.\n'
    );
  }
}

module.exports = {
  IDE_TARGETS,
  SERVER_NAME,
  STDIO_ENTRY,
  VSCODE_ENTRY,
  setupBrokreMcp,
  mergeMcpServers,
  mergeContextServers,
  mergeOpenClaw,
  mergeCodexToml,
  mergeHermesYaml,
  mergeContinueConfigYaml,
  continueDropinYaml,
  isBrokreEntry,
  entryNeedsUpgrade,
  findBrokreAlias,
  entriesEqual,
  readJsonFile,
  writeJsonFile,
  readTextFile,
  writeTextFile,
  isClaudeCodeInstalled,
  isOpenClawInstalled,
  isCodexInstalled,
  isGeminiCliInstalled,
  isHermesInstalled,
  isContinueInstalled,
  isZedInstalled,
  isChatgptDesktopInstalled,
  dirHasEntries,
  anyPathExists,
  printGrokBotTip,
};

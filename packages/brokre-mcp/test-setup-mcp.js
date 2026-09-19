#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
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
  setupBrokreMcp,
  STDIO_ENTRY,
  VSCODE_ENTRY,
  isClaudeCodeInstalled,
  isOpenClawInstalled,
  isCodexInstalled,
  isGeminiCliInstalled,
  isHermesInstalled,
  isContinueInstalled,
  isZedInstalled,
  isChatgptDesktopInstalled,
} = require('./setup-mcp');

let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failed++;
  console.error(`  ✗ ${name}`);
  if (detail) console.error(`    ${detail}`);
}

function withTempHome(fn, { isolatePath = false } = {}) {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'brokre-setup-test-'));
  const prevHome = process.env.HOME;
  const prevPath = process.env.PATH;
  const prevCodex = process.env.CODEX_HOME;
  process.env.HOME = tmpHome;
  delete process.env.CODEX_HOME;
  if (isolatePath) {
    const emptyPath = path.join(tmpHome, 'empty-path');
    fs.mkdirSync(emptyPath, { recursive: true });
    process.env.PATH = emptyPath;
  }
  try {
    return fn(tmpHome);
  } finally {
    process.env.HOME = prevHome;
    process.env.PATH = prevPath;
    if (prevCodex === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = prevCodex;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
}

function fakeCursorTarget(tmpHome) {
  return {
    id: 'cursor',
    name: 'Cursor',
    format: 'json',
    isInstalled() {
      return fs.existsSync(path.join(tmpHome, '.cursor', 'argv.json'));
    },
    configPath: () => path.join(tmpHome, '.cursor', 'mcp.json'),
    merge: (data, options) => mergeMcpServers(data, 'mcpServers', STDIO_ENTRY, options),
  };
}

function testIsBrokreEntry() {
  console.log('\n[unit] isBrokreEntry');
  if (isBrokreEntry({ command: 'npx', args: ['-y', 'brokre@latest'] })) ok('npx brokre@latest');
  else fail('npx brokre@latest');
  if (isBrokreEntry({ command: '/path/to/brokre', args: ['mcp'] })) ok('local binary');
  else fail('local binary');
  if (!isBrokreEntry({ command: 'npx', args: ['-y', 'other'] })) ok('other package');
  else fail('other package');
}

function testEntryNeedsUpgrade() {
  console.log('\n[unit] entryNeedsUpgrade');
  if (!entryNeedsUpgrade({ command: 'npx', args: ['-y', 'brokre@latest'] })) ok('latest ok');
  else fail('latest ok');
  if (entryNeedsUpgrade({ command: '/path/brokre', args: ['mcp'] })) ok('local needs upgrade');
  else fail('local needs upgrade');
}

function testFindBrokreAlias() {
  console.log('\n[unit] findBrokreAlias');
  const alias = findBrokreAlias({
    'my-brokre': { command: 'npx', args: ['-y', 'brokre@latest'] },
    other: { command: 'node', args: ['x.js'] },
  });
  if (alias === 'my-brokre') ok('detects alias');
  else fail('detects alias', alias);
}

function testMergeNoDuplicate() {
  console.log('\n[unit] merge avoids duplicate brokre alias');
  const servers = {
    credentials: { command: 'npx', args: ['-y', 'brokre@latest'] },
    other: { command: 'node', args: ['x.js'] },
  };
  const { action, alias } = mergeMcpServers({ mcpServers: servers }, 'mcpServers', STDIO_ENTRY);
  if (action === 'skipped' && alias === 'credentials') ok('skip when alias exists');
  else fail('skip when alias exists', JSON.stringify({ action, alias }));
  if (!servers.other) fail('preserved other server');
  else ok('preserved other server');
}

function testMergeCursor() {
  console.log('\n[unit] mergeMcpServers (Cursor)');
  const { data, action } = mergeMcpServers(
    { mcpServers: { other: { command: 'node', args: ['x.js'] } } },
    'mcpServers',
    STDIO_ENTRY
  );
  if (action === 'added') ok('added brokre');
  else fail('added brokre', action);
  if (data.mcpServers.other && data.mcpServers.brokre) ok('preserved other server');
  else fail('preserved other server');

  const skip = mergeMcpServers(data, 'mcpServers', STDIO_ENTRY);
  if (skip.action === 'skipped') ok('idempotent skip');
  else fail('idempotent skip', skip.action);
}

function testMergeVscode() {
  console.log('\n[unit] mergeMcpServers (VS Code)');
  const { data, action } = mergeMcpServers({}, 'servers', VSCODE_ENTRY);
  if (action === 'added' && data.servers.brokre.type === 'stdio') ok('vscode stdio entry');
  else fail('vscode stdio entry', JSON.stringify(data));
}

function testMergeOpenClaw() {
  console.log('\n[unit] mergeOpenClaw');
  const { data, action } = mergeOpenClaw({ gateway: { port: 18789 } }, STDIO_ENTRY);
  if (action === 'added' && data.mcp.servers.brokre.command === 'npx') ok('openclaw nested');
  else fail('openclaw nested', JSON.stringify(data));
  if (data.gateway.port === 18789) ok('preserved gateway config');
  else fail('preserved gateway config');
}

function testMergeContextServers() {
  console.log('\n[unit] mergeContextServers (Zed)');
  const { data, action } = mergeContextServers(
    { theme: 'one-dark', context_servers: { other: { command: 'uvx', args: ['demo'] } } },
    STDIO_ENTRY
  );
  if (action === 'added') ok('added brokre');
  else fail('added brokre', action);
  if (data.theme === 'one-dark' && data.context_servers.other && data.context_servers.brokre) {
    ok('preserved theme + other server');
  } else fail('preserved theme + other server', JSON.stringify(data));
  const skip = mergeContextServers(data, STDIO_ENTRY);
  if (skip.action === 'skipped') ok('idempotent skip');
  else fail('idempotent skip', skip.action);
}

function testMergeCodexToml() {
  console.log('\n[unit] mergeCodexToml');
  const existing = `model = "o3"\n\n[mcp_servers.docs]\ncommand = "uvx"\nargs = ["docs"]\n`;
  const { text, action } = mergeCodexToml(existing, STDIO_ENTRY);
  if (action === 'added') ok('added brokre table');
  else fail('added brokre table', action);
  if (text.includes('model = "o3"') && text.includes('[mcp_servers.docs]')) {
    ok('preserved other toml keys');
  } else fail('preserved other toml keys', text);
  if (
    text.includes('[mcp_servers.brokre]') &&
    text.includes('command = "npx"') &&
    text.includes('"brokre@latest"')
  ) {
    ok('wrote stdio entry');
  } else fail('wrote stdio entry', text);

  const skip = mergeCodexToml(text, STDIO_ENTRY);
  if (skip.action === 'skipped') ok('idempotent skip');
  else fail('idempotent skip', skip.action);

  const aliasSkip = mergeCodexToml(
    `[mcp_servers.credentials]\ncommand = "npx"\nargs = ["-y", "brokre@latest"]\n`,
    STDIO_ENTRY
  );
  if (aliasSkip.action === 'skipped' && aliasSkip.alias === 'credentials') {
    ok('skip when toml alias exists');
  } else fail('skip when toml alias exists', JSON.stringify(aliasSkip));

  const upgraded = mergeCodexToml(
    `[mcp_servers.brokre]\ncommand = "/old/brokre"\nargs = ["mcp"]\n`,
    STDIO_ENTRY
  );
  if (upgraded.action === 'updated' && upgraded.text.includes('brokre@latest')) {
    ok('upgrades stale entry');
  } else fail('upgrades stale entry', JSON.stringify(upgraded));
}

function testMergeHermesYaml() {
  console.log('\n[unit] mergeHermesYaml');
  const existing =
    'model:\n  default: gpt-4\n\nmcp_servers:\n  filesystem:\n    command: "npx"\n    args:\n      - "-y"\n      - "@modelcontextprotocol/server-filesystem"\n';
  const { text, action } = mergeHermesYaml(existing, STDIO_ENTRY);
  if (action === 'added') ok('added brokre under mcp_servers');
  else fail('added brokre under mcp_servers', action);
  if (text.includes('model:') && text.includes('filesystem:')) ok('preserved other yaml');
  else fail('preserved other yaml', text);
  if (text.includes('brokre:') && text.includes('brokre@latest')) ok('wrote stdio fields');
  else fail('wrote stdio fields', text);

  const skip = mergeHermesYaml(text, STDIO_ENTRY);
  if (skip.action === 'skipped') ok('idempotent skip');
  else fail('idempotent skip', skip.action);

  const created = mergeHermesYaml('foo: 1\n', STDIO_ENTRY);
  if (created.action === 'added' && created.text.includes('mcp_servers:')) {
    ok('appends mcp_servers when missing');
  } else fail('appends mcp_servers when missing', created.text);
}

function testMergeContinueConfigYaml() {
  console.log('\n[unit] mergeContinueConfigYaml');
  const existing =
    'name: My Config\nversion: 1.0.0\nschema: v1\nmcpServers:\n  - name: other\n    command: uvx\n    args:\n      - demo\n';
  const { text, action } = mergeContinueConfigYaml(existing, STDIO_ENTRY);
  if (action === 'added') ok('added brokre list item');
  else fail('added brokre list item', action);
  if (text.includes('name: other') && text.includes('name: brokre')) ok('preserved other item');
  else fail('preserved other item', text);

  const skip = mergeContinueConfigYaml(text, STDIO_ENTRY);
  if (skip.action === 'skipped') ok('idempotent skip');
  else fail('idempotent skip', skip.action);

  const dropin = continueDropinYaml(STDIO_ENTRY);
  if (dropin.includes('schema: v1') && dropin.includes('brokre@latest')) ok('drop-in yaml');
  else fail('drop-in yaml', dropin);
}

function testNotInstalledSkipsWrite() {
  console.log('\n[integration] skip when IDE not installed');
  withTempHome((tmpHome) => {
    fs.mkdirSync(path.join(tmpHome, '.cursor'), { recursive: true });
    const results = setupBrokreMcp({ targets: [fakeCursorTarget(tmpHome)] });
    const row = results.find((r) => r.id === 'cursor');
    if (row && row.status === 'not_installed') ok('reports not_installed');
    else fail('reports not_installed', JSON.stringify(row));
    if (!fs.existsSync(path.join(tmpHome, '.cursor', 'mcp.json'))) ok('did not create mcp.json');
    else fail('did not create mcp.json');
  });
}

function testInstalledCreatesConfig() {
  console.log('\n[integration] write when IDE installed');
  withTempHome((tmpHome) => {
    const cursorDir = path.join(tmpHome, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(path.join(cursorDir, 'argv.json'), '{}');
    setupBrokreMcp({ targets: [fakeCursorTarget(tmpHome)] });
    const cfg = JSON.parse(fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf8'));
    if (cfg.mcpServers.brokre.args.includes('brokre@latest')) ok('wrote brokre entry');
    else fail('wrote brokre entry', JSON.stringify(cfg));
  });
}

function testDoubleRunIdempotent() {
  console.log('\n[integration] double run is idempotent');
  withTempHome((tmpHome) => {
    const cursorDir = path.join(tmpHome, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(path.join(cursorDir, 'argv.json'), '{}');
    const target = fakeCursorTarget(tmpHome);
    setupBrokreMcp({ targets: [target] });
    const afterFirst = fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf8');
    const second = setupBrokreMcp({ targets: [target] });
    const afterSecond = fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf8');
    if (second[0].status === 'skipped') ok('second run skipped');
    else fail('second run skipped', JSON.stringify(second[0]));
    if (afterFirst === afterSecond) ok('file unchanged on second run');
    else fail('file unchanged on second run');
  });
}

function testPreservesExistingConfig() {
  console.log('\n[integration] preserves unrelated config keys');
  withTempHome((tmpHome) => {
    const cursorDir = path.join(tmpHome, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(path.join(cursorDir, 'argv.json'), '{}');
    const mcpPath = path.join(cursorDir, 'mcp.json');
    fs.writeFileSync(
      mcpPath,
      JSON.stringify(
        {
          mcpServers: {
            context7: { command: 'npx', args: ['-y', '@upstash/context7-mcp'] },
          },
        },
        null,
        2
      )
    );
    setupBrokreMcp({ targets: [fakeCursorTarget(tmpHome)] });
    const cfg = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
    if (cfg.mcpServers.context7 && cfg.mcpServers.brokre) ok('kept context7');
    else fail('kept context7', JSON.stringify(cfg));
  });
}

function testClaudeCodeNotInstalledOnEmptyDir() {
  console.log('\n[integration] Claude Code not installed on empty .claude');
  withTempHome(
    (tmpHome) => {
      fs.mkdirSync(path.join(tmpHome, '.claude'), { recursive: true });
      if (!isClaudeCodeInstalled()) ok('empty .claude dir ignored');
      else fail('empty .claude dir ignored');
    },
    { isolatePath: true }
  );
}

function testClaudeCodeInstalledWithProjects() {
  console.log('\n[integration] Claude Code installed with projects key');
  withTempHome((tmpHome) => {
    fs.writeFileSync(
      path.join(tmpHome, '.claude.json'),
      JSON.stringify({ projects: { '/tmp': { history: [] } } })
    );
    if (isClaudeCodeInstalled()) ok('projects key counts as installed');
    else fail('projects key counts as installed');
  });
}

function testOpenClawNotInstalledOnMcpOnlyConfig() {
  console.log('\n[integration] OpenClaw not installed on mcp-only config');
  withTempHome(
    (tmpHome) => {
      const dir = path.join(tmpHome, '.openclaw');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'openclaw.json'),
        JSON.stringify({ mcp: { servers: { brokre: STDIO_ENTRY } } })
      );
      if (!isOpenClawInstalled()) ok('mcp-only openclaw.json ignored');
      else fail('mcp-only openclaw.json ignored');
    },
    { isolatePath: true }
  );
}

function testOpenClawInstalledWithGateway() {
  console.log('\n[integration] OpenClaw installed with gateway key');
  withTempHome((tmpHome) => {
    const dir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'openclaw.json'),
      JSON.stringify({ gateway: { port: 18789 }, mcp: { servers: {} } })
    );
    if (isOpenClawInstalled()) ok('gateway key counts as installed');
    else fail('gateway key counts as installed');
  });
}

function testDryRunNoWrite() {
  console.log('\n[integration] dry-run does not write');
  withTempHome((tmpHome) => {
    const cursorDir = path.join(tmpHome, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    fs.writeFileSync(path.join(cursorDir, 'argv.json'), '{}');
    const results = setupBrokreMcp({ dryRun: true, targets: [fakeCursorTarget(tmpHome)] });
    if (results[0].status === 'added') ok('dry-run reports added');
    else fail('dry-run reports added', JSON.stringify(results[0]));
    if (!fs.existsSync(path.join(cursorDir, 'mcp.json'))) ok('dry-run did not write');
    else fail('dry-run did not write');
  });
}

function testEntriesEqualSkip() {
  console.log('\n[unit] entriesEqual prevents noop update');
  const existing = {
    mcpServers: {
      brokre: { command: 'npx', args: ['-y', 'brokre@latest'] },
    },
  };
  const merged = mergeMcpServers(existing, 'mcpServers', STDIO_ENTRY);
  if (merged.action === 'skipped') ok('equal entry skipped');
  else fail('equal entry skipped', merged.action);
}

function testCodexIntegration() {
  console.log('\n[integration] Codex CLI toml write + backup');
  withTempHome(
    (tmpHome) => {
      const root = path.join(tmpHome, '.codex');
      fs.mkdirSync(root, { recursive: true });
      fs.writeFileSync(path.join(root, 'config.toml'), 'model = "o3"\n');
      if (!isCodexInstalled()) {
        fail('detects codex from config.toml');
        return;
      }
      ok('detects codex from config.toml');

      const target = {
        id: 'codex',
        name: 'Codex CLI',
        format: 'toml',
        isInstalled: () => true,
        configPath: () => path.join(root, 'config.toml'),
        mergeText: (text, options) => mergeCodexToml(text, STDIO_ENTRY, options),
      };
      const results = setupBrokreMcp({ targets: [target] });
      if (results[0].status === 'added') ok('wrote codex config');
      else fail('wrote codex config', JSON.stringify(results[0]));
      const cfg = fs.readFileSync(path.join(root, 'config.toml'), 'utf8');
      if (cfg.includes('model = "o3"') && cfg.includes('[mcp_servers.brokre]')) {
        ok('codex merge preserved model');
      } else fail('codex merge preserved model', cfg);
      if (fs.existsSync(path.join(root, 'config.toml.brokre.bak'))) ok('toml backup created');
      else fail('toml backup created');
    },
    { isolatePath: true }
  );
}

function testHermesIntegration() {
  console.log('\n[integration] Hermes Agent yaml write');
  withTempHome(
    (tmpHome) => {
      const root = path.join(tmpHome, '.hermes');
      fs.mkdirSync(root, { recursive: true });
      fs.writeFileSync(path.join(root, 'config.yaml'), 'model:\n  default: x\n');
      if (!isHermesInstalled()) {
        fail('detects hermes from config.yaml');
        return;
      }
      ok('detects hermes from config.yaml');
      const target = {
        id: 'hermes',
        name: 'Hermes Agent',
        format: 'yaml',
        isInstalled: () => true,
        configPath: () => path.join(root, 'config.yaml'),
        mergeText: (text, options) => mergeHermesYaml(text, STDIO_ENTRY, options),
      };
      setupBrokreMcp({ targets: [target] });
      const cfg = fs.readFileSync(path.join(root, 'config.yaml'), 'utf8');
      if (cfg.includes('model:') && cfg.includes('mcp_servers:') && cfg.includes('brokre:')) {
        ok('hermes yaml upserted');
      } else fail('hermes yaml upserted', cfg);
    },
    { isolatePath: true }
  );
}

function testContinueDropinIntegration() {
  console.log('\n[integration] Continue drop-in yaml when no config.yaml');
  withTempHome(
    (tmpHome) => {
      const root = path.join(tmpHome, '.continue');
      fs.mkdirSync(root, { recursive: true });
      fs.writeFileSync(path.join(root, 'sessions'), '');
      // sessions as file is enough for dirHasEntries? actually sessions file counts
      if (!isContinueInstalled()) {
        // dirHasEntries sees 'sessions' file
        fail('detects continue');
        return;
      }
      ok('detects continue');

      const { IDE_TARGETS } = require('./setup-mcp');
      const continueTarget = IDE_TARGETS.find((t) => t.id === 'continue');
      const results = setupBrokreMcp({ targets: [continueTarget] });
      const row = results[0];
      if (row.status === 'added' && row.path.endsWith(path.join('mcpServers', 'brokre.yaml'))) {
        ok('wrote continue drop-in');
      } else fail('wrote continue drop-in', JSON.stringify(row));
      const body = fs.readFileSync(row.path, 'utf8');
      if (body.includes('schema: v1') && body.includes('brokre@latest')) ok('drop-in contents');
      else fail('drop-in contents', body);
    },
    { isolatePath: true }
  );
}

function testZedIntegration() {
  console.log('\n[integration] Zed context_servers merge');
  withTempHome(
    (tmpHome) => {
      const settingsDir = path.join(tmpHome, '.config', 'zed');
      fs.mkdirSync(settingsDir, { recursive: true });
      const settingsPath = path.join(settingsDir, 'settings.json');
      fs.writeFileSync(
        settingsPath,
        JSON.stringify({ theme: 'one-dark', context_servers: { other: { command: 'x' } } }, null, 2)
      );
      if (!isZedInstalled()) {
        fail('detects zed from settings');
        return;
      }
      ok('detects zed from settings');
      const { IDE_TARGETS } = require('./setup-mcp');
      const zedTarget = IDE_TARGETS.find((t) => t.id === 'zed');
      setupBrokreMcp({ targets: [zedTarget] });
      const cfg = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      if (cfg.theme === 'one-dark' && cfg.context_servers.other && cfg.context_servers.brokre) {
        ok('zed merge preserved theme');
      } else fail('zed merge preserved theme', JSON.stringify(cfg));
    },
    { isolatePath: true }
  );
}

function testChatgptUnsupported() {
  console.log('\n[integration] ChatGPT Desktop unsupported');
  withTempHome(
    (tmpHome) => {
      const { IDE_TARGETS } = require('./setup-mcp');
      const target = {
        ...IDE_TARGETS.find((t) => t.id === 'chatgpt-desktop'),
        isInstalled: () => true,
      };
      const results = setupBrokreMcp({ targets: [target] });
      if (results[0].status === 'unsupported') ok('reports unsupported');
      else fail('reports unsupported', JSON.stringify(results[0]));
    },
    { isolatePath: true }
  );
}

function testGrokBotInfo() {
  console.log('\n[integration] Grok Bot info tip');
  const { IDE_TARGETS } = require('./setup-mcp');
  const target = IDE_TARGETS.find((t) => t.id === 'grok-bot');
  const results = setupBrokreMcp({ targets: [target] });
  if (results[0].status === 'info' && /connectors/.test(results[0].message)) ok('info status');
  else fail('info status', JSON.stringify(results[0]));
}

function testGeminiDetection() {
  console.log('\n[integration] Gemini CLI detection');
  withTempHome(
    (tmpHome) => {
      if (isGeminiCliInstalled()) {
        fail('empty home should not detect gemini');
        return;
      }
      ok('empty home no gemini');
      const root = path.join(tmpHome, '.gemini');
      fs.mkdirSync(root, { recursive: true });
      fs.writeFileSync(path.join(root, 'settings.json'), '{"mcpServers":{}}');
      if (isGeminiCliInstalled()) ok('detects from settings.json');
      else fail('detects from settings.json');
    },
    { isolatePath: true }
  );
}

function main() {
  console.log('brokre-mcp setup tests');
  testIsBrokreEntry();
  testEntryNeedsUpgrade();
  testFindBrokreAlias();
  testMergeNoDuplicate();
  testMergeCursor();
  testMergeVscode();
  testMergeOpenClaw();
  testMergeContextServers();
  testMergeCodexToml();
  testMergeHermesYaml();
  testMergeContinueConfigYaml();
  testEntriesEqualSkip();
  testNotInstalledSkipsWrite();
  testInstalledCreatesConfig();
  testDoubleRunIdempotent();
  testPreservesExistingConfig();
  testClaudeCodeNotInstalledOnEmptyDir();
  testClaudeCodeInstalledWithProjects();
  testOpenClawNotInstalledOnMcpOnlyConfig();
  testOpenClawInstalledWithGateway();
  testDryRunNoWrite();
  testCodexIntegration();
  testHermesIntegration();
  testContinueDropinIntegration();
  testZedIntegration();
  testChatgptUnsupported();
  testGrokBotInfo();
  testGeminiDetection();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main();

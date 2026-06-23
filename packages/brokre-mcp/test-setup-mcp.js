#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  mergeMcpServers,
  mergeOpenClaw,
  isBrokreEntry,
  entryNeedsUpgrade,
  findBrokreAlias,
  entriesEqual,
  setupBrokreMcp,
  STDIO_ENTRY,
  VSCODE_ENTRY,
  isClaudeCodeInstalled,
  isOpenClawInstalled,
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
  process.env.HOME = tmpHome;
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
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
}

function fakeCursorTarget(tmpHome) {
  return {
    id: 'cursor',
    name: 'Cursor',
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

function main() {
  console.log('brokre-mcp setup tests');
  testIsBrokreEntry();
  testEntryNeedsUpgrade();
  testFindBrokreAlias();
  testMergeNoDuplicate();
  testMergeCursor();
  testMergeVscode();
  testMergeOpenClaw();
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
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main();

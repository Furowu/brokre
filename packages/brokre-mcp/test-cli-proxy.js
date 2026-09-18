#!/usr/bin/env node
/**
 * npm launcher must forward CLI args to the native binary.
 * Run: node packages/brokre-mcp/test-cli-proxy.js
 */
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const INDEX = path.join(__dirname, 'index.js');

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

function makeFakeCli(dir) {
  const bin = path.join(dir, 'brokre');
  fs.writeFileSync(
    bin,
    `#!/bin/sh
echo "PROXY:$*"
exit 7
`,
    { mode: 0o755 }
  );
  return bin;
}

console.log('brokre-mcp CLI proxy tests\n');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'brokre-proxy-'));
try {
  const fake = makeFakeCli(tmp);
  const res = spawnSync(process.execPath, [INDEX, 'list', '--json'], {
    encoding: 'utf8',
    timeout: 10_000,
    env: {
      ...process.env,
      BROKRE_BIN: fake,
      BROKRE_MCP_NO_AUTO_OPEN: '1',
    },
  });
  if (res.error) {
    fail('list --json reaches native CLI', res.error.message);
  } else if (!/^PROXY:list --json\s*$/m.test(res.stdout)) {
    fail(
      'list --json reaches native CLI',
      `stdout=${JSON.stringify(res.stdout)} stderr=${JSON.stringify(res.stderr)}`
    );
  } else if (res.status !== 7) {
    fail('native exit code is forwarded', `status=${res.status}`);
  } else {
    ok('list --json is forwarded to native CLI');
    ok('native exit code is forwarded');
  }

  const setup = spawnSync(
    process.execPath,
    [INDEX, 'mcp', 'setup', '--dry-run'],
    {
      encoding: 'utf8',
      timeout: 10_000,
      env: {
        ...process.env,
        BROKRE_BIN: fake,
        BROKRE_MCP_NO_AUTO_OPEN: '1',
      },
    }
  );
  if (setup.error) {
    fail('mcp setup is forwarded', setup.error.message);
  } else if (!/^PROXY:mcp setup --dry-run\s*$/m.test(setup.stdout)) {
    fail(
      'mcp setup is forwarded',
      `stdout=${JSON.stringify(setup.stdout)} stderr=${JSON.stringify(setup.stderr)}`
    );
  } else {
    ok('mcp setup is forwarded to native CLI');
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

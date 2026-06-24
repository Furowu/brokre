#!/usr/bin/env node
/**
 * Regression: npm launcher must not recurse on `brokre --version`.
 * Run: node packages/brokre-mcp/test-version-recursion.js
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

function runIndex(args, env = {}) {
  return spawnSync(process.execPath, [INDEX, ...args], {
    encoding: 'utf8',
    timeout: 10_000,
    env: { ...process.env, ...env },
  });
}

console.log('brokre-mcp version recursion tests\n');

{
  const res = runIndex(['--version'], { BROKRE_SKIP_AUTO_INSTALL: '1' });
  if (res.error) {
    fail('--version exits without hanging', res.error.message);
  } else if (res.status !== 0) {
    fail('--version exits 0', `status=${res.status} stderr=${res.stderr}`);
  } else if (!/\bbrokre\s+\d+\.\d+\.\d+/.test(res.stdout)) {
    fail('--version prints semver', res.stdout);
  } else {
    ok('--version exits quickly without recursion');
  }
}

{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'brokre-ver-'));
  const fakeBinDir = path.join(tmp, 'bin');
  fs.mkdirSync(fakeBinDir);
  const launcherLink = path.join(fakeBinDir, 'brokre');
  fs.symlinkSync(INDEX, launcherLink);
  const res = runIndex(['--version'], {
    PATH: `${fakeBinDir}:${process.env.PATH || ''}`,
    BROKRE_SKIP_AUTO_INSTALL: '1',
  });
  fs.rmSync(tmp, { recursive: true, force: true });
  if (res.error) {
    fail('--version with launcher-only PATH', res.error.message);
  } else if (res.status !== 0) {
    fail('--version with launcher-only PATH exits 0', `status=${res.status}`);
  } else {
    ok('--version does not recurse when PATH only has npm launcher');
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

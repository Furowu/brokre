#!/usr/bin/env node
/**
 * Windows npm shims must not be treated as the native CLI.
 * Run: node packages/brokre-mcp/test-launcher-shim.js
 */
'use strict';

const path = require('path');
const { isLauncherScript, pathListContainsDir } = require('./index.js');

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

function assert(name, cond, detail) {
  if (cond) ok(name);
  else fail(name, detail);
}

console.log('brokre-mcp launcher shim tests\n');

{
  const cmd = 'C:\\Users\\admin\\AppData\\Roaming\\npm\\brokre.cmd';
  assert(
    'win32 npm .cmd shim is launcher',
    isLauncherScript(cmd, 'win32') === true
  );
}

{
  const ps1 = 'C:\\Users\\admin\\AppData\\Roaming\\npm\\brokre.ps1';
  assert(
    'win32 npm .ps1 shim is launcher',
    isLauncherScript(ps1, 'win32') === true
  );
}

{
  const bashShim = 'C:\\Users\\admin\\AppData\\Roaming\\npm\\brokre';
  assert(
    'win32 extensionless npm shim is launcher',
    isLauncherScript(bashShim, 'win32') === true
  );
}

{
  const native = 'C:\\Users\\admin\\.brokre\\bin\\brokre.exe';
  assert(
    'win32 native brokre.exe is not launcher',
    isLauncherScript(native, 'win32') === false
  );
}

{
  assert(
    'this index.js is the npm launcher on current platform',
    isLauncherScript(path.join(__dirname, 'index.js')) === true
  );
}

{
  assert(
    'pathListContainsDir finds Windows dir case-insensitively',
    pathListContainsDir(
      'C:\\Windows;C:\\Users\\admin\\.brokre\\bin;',
      'C:\\Users\\admin\\.brokre\\bin\\',
      ';'
    )
  );
}

{
  assert(
    'pathListContainsDir misses absent dir',
    pathListContainsDir('C:\\Windows;C:\\npm', 'C:\\Users\\admin\\.brokre\\bin', ';') ===
      false
  );
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);

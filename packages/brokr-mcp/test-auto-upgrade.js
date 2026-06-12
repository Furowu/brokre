#!/usr/bin/env node
/**
 * Integration tests for brokr-mcp auto-upgrade logic.
 * Run: node packages/brokr-mcp/test-auto-upgrade.js
 */
'use strict';

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PKG_DIR = __dirname;
const INDEX = path.join(PKG_DIR, 'index.js');
const PKG_VERSION = require('./package.json').version;

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

function parseVersion(output) {
  const m = String(output).match(/\b(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)\b/);
  return m ? m[1] : null;
}

function makeFakeBrokr(dir, version) {
  const bin = path.join(dir, 'brokr');
  fs.writeFileSync(
    bin,
    `#!/bin/sh
if [ "$1" = "--version" ]; then echo "brokr ${version}"; exit 0; fi
exit 0
`,
    { mode: 0o755 }
  );
  return bin;
}

function runEnsureBinary(env, extraEnv = {}) {
  const res = spawnSync(process.execPath, ['-e', ENSURE_SNIPPET], {
    cwd: PKG_DIR,
    env: { ...process.env, ...env, ...extraEnv },
    encoding: 'utf8',
    timeout: 120_000,
  });
  if (res.error) throw res.error;
  return res;
}

// Inline ensureBrokrBinary from index.js (dry-run: print chosen path, no MCP spawn)
const ENSURE_SNIPPET = `
const m = require(${JSON.stringify(INDEX)});
`;

// index.js doesn't export ensureBrokrBinary — use subprocess that only runs download path
const ENSURE_RUNNER = `
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { version: PKG_VERSION } = require(${JSON.stringify(path.join(PKG_DIR, 'package.json'))});
const REPO = 'Furowu/brokr';

function findBrokrOnPath() {
  if (process.env.BROKR_BIN) return process.env.BROKR_BIN;
  try {
    const out = execFileSync('which', ['brokr'], { encoding: 'utf8' });
    const line = out.trim().split(/\\r?\\n/)[0];
    if (line) return line;
  } catch (_) {}
  return null;
}
function detectTarget() {
  const { platform, arch } = process;
  if (platform === 'darwin') return arch === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
  if (platform === 'linux') return arch === 'arm64' ? 'aarch64-unknown-linux-gnu' : 'x86_64-unknown-linux-gnu';
  throw new Error('unsupported');
}
function cachedBrokrPath() {
  return path.join(os.homedir(), '.brokr', 'bin', 'brokr');
}
function versionFilePath() {
  return path.join(os.homedir(), '.brokr', 'bin', '.version');
}
function readCachedVersion() {
  try { return fs.readFileSync(versionFilePath(), 'utf8').trim(); } catch (_) { return null; }
}
function parseVersion(output) {
  const m = String(output).match(/\\b(\\d+\\.\\d+\\.\\d+(?:[-+][\\w.-]+)?)\\b/);
  return m ? m[1] : null;
}
function getInstalledVersion(brokrPath) {
  try {
    return parseVersion(execFileSync(brokrPath, ['--version'], { encoding: 'utf8' }));
  } catch (_) { return null; }
}
function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        httpsGet(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error('HTTP ' + res.statusCode));
        return;
      }
      resolve(res);
    });
    req.on('error', reject);
  });
}
async function downloadToFile(url, dest) {
  const res = await httpsGet(url);
  await fs.promises.mkdir(path.dirname(dest), { recursive: true });
  const tmp = dest + '.download';
  await pipeline(res, fs.createWriteStream(tmp));
  await fs.promises.rename(tmp, dest);
}
function extractTarGz(tarPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  execFileSync('tar', ['-xzf', tarPath, '-C', destDir], { stdio: 'inherit' });
}
async function ensureBrokrBinary() {
  if (process.env.BROKR_BIN) return process.env.BROKR_BIN;
  if (process.env.BROKR_SKIP_AUTO_INSTALL === '1') {
    const onPath = findBrokrOnPath();
    if (onPath) return onPath;
    throw new Error('brokr not on PATH');
  }
  const brokrVersion = process.env.BROKR_VERSION || PKG_VERSION;
  const cache = cachedBrokrPath();
  const cachedVersion = readCachedVersion();
  if (fs.existsSync(cache) && cachedVersion === brokrVersion) return cache;
  const onPath = findBrokrOnPath();
  if (onPath) {
    const installed = getInstalledVersion(onPath);
    if (installed === brokrVersion) return onPath;
  }
  const target = detectTarget();
  const url = 'https://github.com/' + REPO + '/releases/download/v' + brokrVersion + '/brokr-' + target + '.tar.gz';
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'brokr-mcp-test-'));
  const tgz = path.join(tmpDir, 'brokr.tar.gz');
  try {
    await downloadToFile(url, tgz);
    extractTarGz(tgz, tmpDir);
    const extracted = path.join(tmpDir, 'brokr');
    await fs.promises.mkdir(path.dirname(cache), { recursive: true });
    await fs.promises.copyFile(extracted, cache);
    await fs.promises.chmod(cache, 0o755);
    await fs.promises.writeFile(versionFilePath(), brokrVersion + '\\n');
    return cache;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
ensureBrokrBinary()
  .then((p) => {
    const ver = getInstalledVersion(p);
    console.log(JSON.stringify({ path: p, version: ver, cached: readCachedVersion() }));
  })
  .catch((e) => {
    console.error('ERROR:' + e.message);
    process.exit(1);
  });
`;

function runEnsure(env) {
  const res = spawnSync(process.execPath, ['-e', ENSURE_RUNNER], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 120_000,
  });
  return res;
}

function testParseVersion() {
  console.log('\n[unit] parseVersion');
  if (parseVersion('brokr 0.1.3') === '0.1.3') ok('brokr 0.1.3');
  else fail('brokr 0.1.3', `got ${parseVersion('brokr 0.1.3')}`);
  if (parseVersion('brokr 0.1.4\n') === '0.1.4') ok('trailing newline');
  else fail('trailing newline');
}

function testInstallShVersionCheck() {
  console.log('\n[unit] install.sh version detection');
  const script = path.join(PKG_DIR, '../../install.sh');
  const res = spawnSync('bash', ['-n', script], { encoding: 'utf8' });
  if (res.status === 0) ok('install.sh syntax');
  else fail('install.sh syntax', res.stderr);

  const dry = spawnSync(
    'bash',
    [
      '-c',
      `source /dev/null 2>/dev/null; 
       REPO=Furowu/brokr
       parse_brokr_version() { echo "$1" | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1; }
       INSTALLED_VER=$(parse_brokr_version "brokr 0.1.3")
       TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": "v([^"]+)".*/\\1/')
       echo "installed=$INSTALLED_VER latest=$TAG"`,
    ],
    { encoding: 'utf8', timeout: 30_000 }
  );
  const out = dry.stdout.trim();
  if (out.includes('installed=0.1.3') && out.includes('latest=')) ok(`GitHub latest resolved (${out})`);
  else fail('GitHub latest resolve', out || dry.stderr);
}

async function testUpgradeFromStalePath() {
  console.log('\n[integration] PATH stale → download to ~/.brokr/bin');
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'brokr-test-home-'));
  const fakeBin = path.join(tmpHome, 'fakebin');
  fs.mkdirSync(fakeBin, { recursive: true });
  makeFakeBrokr(fakeBin, '0.1.1');

  const env = {
    HOME: tmpHome,
    PATH: `${fakeBin}:${process.env.PATH}`,
    BROKR_VERSION: PKG_VERSION,
  };

  const res = runEnsure(env);
  const stderr = res.stderr || '';
  const stdout = (res.stdout || '').trim();

  if (res.status !== 0) {
    fail('ensureBrokrBinary exit 0', `status=${res.status} stderr=${stderr} stdout=${stdout}`);
    fs.rmSync(tmpHome, { recursive: true, force: true });
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (e) {
    fail('JSON output', stdout);
    fs.rmSync(tmpHome, { recursive: true, force: true });
    return;
  }

  const cache = path.join(tmpHome, '.brokr', 'bin', 'brokr');
  if (parsed.path === cache) ok(`uses cache path ${cache}`);
  else fail('cache path', `got ${parsed.path}`);

  if (parsed.version === PKG_VERSION) ok(`binary version ${PKG_VERSION}`);
  else fail('binary version', `expected ${PKG_VERSION}, got ${parsed.version}`);

  if (parsed.cached === PKG_VERSION) ok('.version file written');
  else fail('.version file', `got ${parsed.cached}`);

  if (fs.existsSync(cache)) ok('cache binary exists');
  else fail('cache binary missing');

  fs.rmSync(tmpHome, { recursive: true, force: true });
}

function testCacheHit() {
  console.log('\n[integration] cache hit → skip download');
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'brokr-test-home-'));
  const binDir = path.join(tmpHome, '.brokr', 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const cache = path.join(binDir, 'brokr');
  // copy real brokr if available for version check
  const realBrokr = execFileSync('which', ['brokr'], { encoding: 'utf8' }).trim().split('\n')[0];
  if (!realBrokr || !fs.existsSync(realBrokr)) {
    console.log('  - skip (no real brokr on PATH)');
    fs.rmSync(tmpHome, { recursive: true, force: true });
    return;
  }
  const ver = parseVersion(execFileSync(realBrokr, ['--version'], { encoding: 'utf8' }));
  fs.copyFileSync(realBrokr, cache);
  fs.writeFileSync(path.join(binDir, '.version'), `${ver}\n`);

  const fakeBin = path.join(tmpHome, 'fakebin');
  fs.mkdirSync(fakeBin);
  makeFakeBrokr(fakeBin, '0.0.1');

  const t0 = Date.now();
  const res = runEnsure({
    HOME: tmpHome,
    PATH: `${fakeBin}:${process.env.PATH}`,
    BROKR_VERSION: ver,
  });
  const elapsed = Date.now() - t0;

  if (res.status !== 0) {
    fail('cache hit', res.stderr);
  } else {
    const parsed = JSON.parse(res.stdout.trim());
    if (parsed.path === cache) ok('returns cache');
    else fail('returns cache', parsed.path);
    if (elapsed < 3000) ok(`fast path ${elapsed}ms`);
    else fail('fast path', `took ${elapsed}ms — may have re-downloaded`);
  }
  fs.rmSync(tmpHome, { recursive: true, force: true });
}

function testRealEnvironment() {
  console.log('\n[integration] real env (your machine)');
  const pathBrokr = (() => {
    try {
      return execFileSync('which', ['brokr'], { encoding: 'utf8' }).trim().split('\n')[0];
    } catch (_) {
      return null;
    }
  })();
  if (!pathBrokr) {
    console.log('  - skip (brokr not on PATH)');
    return;
  }
  const pathVer = parseVersion(execFileSync(pathBrokr, ['--version'], { encoding: 'utf8' }));
  console.log(`  PATH brokr: ${pathBrokr} v${pathVer}, npm PKG v${PKG_VERSION}`);

  if (pathVer === PKG_VERSION) {
    console.log('  - PATH already matches PKG — skip live download test');
    return;
  }

  const realHome = process.env.HOME;
  const cacheBefore = fs.existsSync(path.join(realHome, '.brokr', 'bin', 'brokr'));
  const res = runEnsure({ HOME: realHome, BROKR_VERSION: PKG_VERSION });
  if (res.status !== 0) {
    fail('live upgrade', res.stderr || res.stdout);
    return;
  }
  const parsed = JSON.parse(res.stdout.trim());
  const cache = path.join(realHome, '.brokr', 'bin', 'brokr');
  if (parsed.path === cache) ok(`downloaded to ${cache}`);
  else fail('live upgrade path', parsed.path);
  if (parsed.version === PKG_VERSION) ok(`upgraded to v${PKG_VERSION}`);
  else fail('live version', parsed.version);
  if (!cacheBefore) ok('created new ~/.brokr/bin');
  else ok('updated existing ~/.brokr/bin');
}

async function main() {
  console.log(`brokr-mcp auto-upgrade tests (PKG_VERSION=${PKG_VERSION})`);
  testParseVersion();
  testInstallShVersionCheck();
  await testUpgradeFromStalePath();
  testCacheHit();
  testRealEnvironment();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

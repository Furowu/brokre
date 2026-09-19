#!/usr/bin/env node
/**
 * brokre — MCP launcher for brokre credential broker.
 *
 * Spawns `brokre mcp` (stdio). Uses brokre on PATH, or downloads a prebuilt
 * release from GitHub into ~/.brokre/bin/ on first run.
 */
'use strict';

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');

const { version: PKG_VERSION } = require('./package.json');
const REPO = 'Furowu/brokre';
const INSTALL_DOC =
  'https://raw.githubusercontent.com/Furowu/brokre/main/install.sh';

const LAUNCHER_REALPATH = (() => {
  try {
    return fs.realpathSync(__filename);
  } catch (_) {
    return __filename;
  }
})();

function cliBasename(binPath) {
  return String(binPath)
    .replace(/[\\/]+$/, '')
    .split(/[\\/]/)
    .pop()
    .toLowerCase();
}

/**
 * True when `binPath` is this npm MCP launcher or an npm bin shim
 * (`brokre.cmd` / `brokre.ps1`), not the native Rust CLI (`brokre.exe`).
 *
 * Windows `where brokre` returns the npm shim first. Treating that shim as
 * the native binary recurses: shim → index.js → shim → …
 */
function isLauncherScript(binPath, platform = process.platform) {
  if (!binPath) return false;
  const base = cliBasename(binPath);
  if (platform === 'win32') {
    if (base === 'brokre.exe') return false;
    if (base === 'brokre' || base === 'brokre.cmd' || base === 'brokre.ps1') {
      return true;
    }
  }
  try {
    return fs.realpathSync(binPath) === LAUNCHER_REALPATH;
  } catch (_) {
    return false;
  }
}

function printVersionAndExit() {
  const cached = cachedBrokrePath();
  if (fs.existsSync(cached) && !isLauncherScript(cached)) {
    try {
      const out = execFileSync(cached, ['--version'], {
        encoding: 'utf8',
        timeout: 5_000,
      });
      process.stdout.write(out.endsWith('\n') ? out : `${out}\n`);
      process.exit(0);
    } catch (_) {
      /* fall through to package version */
    }
  }
  process.stdout.write(`brokre ${PKG_VERSION}\n`);
  process.exit(0);
}

function handleEarlyArgv() {
  const args = process.argv.slice(2);
  if (
    args.length === 1 &&
    (args[0] === '--version' || args[0] === '-V' || args[0] === '-v')
  ) {
    printVersionAndExit();
  }
}

function redactManageTokens(chunk) {
  return chunk
    .toString()
    .split('\n')
    .map((line) =>
      line.replace(/\?t=[a-f0-9]+/gi, '?t=<redacted>').replace(
        /brokre manage: http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/gi,
        (m) => m.replace(/\?t=[a-f0-9]+/i, '?t=<redacted>')
      )
    )
    .join('\n');
}

function findBrokreOnPath() {
  if (process.env.BROKRE_BIN) {
    return process.env.BROKRE_BIN;
  }
  try {
    const which = process.platform === 'win32' ? 'where' : 'which';
    const whichArgs =
      process.platform === 'win32' ? ['brokre'] : ['-a', 'brokre'];
    const out = execFileSync(which, whichArgs, { encoding: 'utf8' });
    const lines = out
      .trim()
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    for (const line of lines) {
      if (!isLauncherScript(line)) return line;
    }
  } catch (_) {
    /* not on PATH */
  }
  return null;
}

function detectTarget() {
  const { platform, arch } = process;
  if (platform === 'darwin') {
    return arch === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
  }
  if (platform === 'linux') {
    return arch === 'arm64' ? 'aarch64-unknown-linux-gnu' : 'x86_64-unknown-linux-gnu';
  }
  if (platform === 'win32') {
    return 'x86_64-pc-windows-msvc';
  }
  throw new Error(`unsupported platform: ${platform} ${arch}`);
}

function brokreBinDir() {
  return path.join(os.homedir(), '.brokre', 'bin');
}

function cachedBrokrePath() {
  const name = process.platform === 'win32' ? 'brokre.exe' : 'brokre';
  return path.join(brokreBinDir(), name);
}

const PATH_MARKER = '# brokre CLI (brokre-mcp)';
const PATH_LINE = 'export PATH="$HOME/.brokre/bin:$PATH"';

function shellRcFiles() {
  const home = os.homedir();
  if (process.platform === 'win32') return [];
  const files = [];
  if (process.platform === 'darwin') {
    files.push(path.join(home, '.zprofile'));
    files.push(path.join(home, '.zshrc'));
  } else {
    files.push(path.join(home, '.bashrc'));
  }
  files.push(path.join(home, '.bash_profile'));
  files.push(path.join(home, '.profile'));
  return [...new Set(files)];
}

function pathListContainsDir(pathValue, dir, delimiter = path.delimiter) {
  const norm = (p) =>
    String(p || '')
      .replace(/[\\/]+$/, '')
      .toLowerCase();
  const want = norm(dir);
  if (!want) return false;
  return String(pathValue || '')
    .split(delimiter)
    .some((p) => p && norm(p) === want);
}

function prependProcessPath(dir) {
  if (pathListContainsDir(process.env.PATH, dir)) return false;
  process.env.PATH = `${dir}${path.delimiter}${process.env.PATH || ''}`;
  return true;
}

function readWindowsUserPath() {
  const out = execFileSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "[Environment]::GetEnvironmentVariable('Path','User')",
    ],
    { encoding: 'utf8', windowsHide: true, timeout: 15_000 }
  );
  return String(out).replace(/^\uFEFF/, '').trim();
}

function writeWindowsUserPath(next) {
  execFileSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "[Environment]::SetEnvironmentVariable('Path', $env:BROKRE_NEW_PATH, 'User')",
    ],
    {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 15_000,
      env: { ...process.env, BROKRE_NEW_PATH: next },
    }
  );
}

function ensureWindowsUserPath() {
  const dir = brokreBinDir();
  const alreadyOnProcessPath = pathListContainsDir(process.env.PATH, dir);
  prependProcessPath(dir);
  if (alreadyOnProcessPath) return false;
  try {
    const current = readWindowsUserPath();
    if (pathListContainsDir(current, dir, ';')) return false;
    const next = current ? `${current};${dir}` : dir;
    writeWindowsUserPath(next);
    process.stderr.write(`brokre: added ${dir} to your user PATH\n`);
    process.stderr.write(
      'brokre: open a new terminal so `brokre list` / `brokre manage` work.\n'
    );
    return true;
  } catch (err) {
    process.stderr.write(
      `brokre: could not update user PATH (${err.message}).\n` +
        `brokre: add ${dir} to PATH, or run: npx brokre list\n`
    );
    return false;
  }
}

function cliPathSetupNeeded() {
  if (process.platform === 'win32') {
    return !pathListContainsDir(process.env.PATH, brokreBinDir());
  }
  if (findBrokreOnPath()) return false;
  for (const rc of shellRcFiles()) {
    try {
      if (fs.existsSync(rc) && fs.readFileSync(rc, 'utf8').includes('.brokre/bin')) {
        return false;
      }
    } catch (_) {
      /* ignore */
    }
  }
  return true;
}

function ensureCliOnPath() {
  if (process.platform === 'win32') {
    return ensureWindowsUserPath();
  }
  if (!cliPathSetupNeeded()) return false;
  const block = `\n${PATH_MARKER}\n${PATH_LINE}\n`;
  const files = shellRcFiles();
  for (const rc of files) {
    try {
      if (fs.existsSync(rc) && fs.readFileSync(rc, 'utf8').includes('.brokre/bin')) {
        return false;
      }
    } catch (_) {
      /* ignore */
    }
  }
  for (const rc of files) {
    try {
      if (fs.existsSync(rc)) {
        const content = fs.readFileSync(rc, 'utf8');
        if (content.includes(PATH_MARKER)) continue;
        fs.appendFileSync(rc, block);
        process.stderr.write(`brokre: added ~/.brokre/bin to PATH in ${rc}\n`);
        process.stderr.write(
          `brokre: open a new terminal (or run: source ${rc}) for \`brokre manage\`.\n`
        );
        return true;
      }
    } catch (_) {
      /* try next rc */
    }
  }
  const fallback =
    process.platform === 'darwin'
      ? path.join(os.homedir(), '.zshrc')
      : path.join(os.homedir(), '.bashrc');
  try {
    fs.appendFileSync(fallback, block);
    process.stderr.write(`brokre: added ~/.brokre/bin to PATH in ${fallback}\n`);
    process.stderr.write(
      `brokre: open a new terminal (or run: source ${fallback}) for \`brokre manage\`.\n`
    );
    return true;
  } catch (_) {
    return false;
  }
}

function trySymlinkSystemWide(brokrePath) {
  if (process.platform === 'win32') return;
  const link = '/usr/local/bin/brokre';
  try {
    if (fs.existsSync(link)) {
      if (fs.realpathSync(link) === fs.realpathSync(brokrePath)) return;
      fs.unlinkSync(link);
    }
    fs.mkdirSync('/usr/local/bin', { recursive: true });
    fs.symlinkSync(brokrePath, link);
    process.stderr.write('brokre: linked /usr/local/bin/brokre\n');
  } catch (_) {
    /* no write access — shell rc PATH is the fallback */
  }
}

function cleanupLegacyBinaries() {
  const dir = brokreBinDir();
  for (const name of ['brokr', 'brokr.exe']) {
    const legacy = path.join(dir, name);
    try {
      if (fs.existsSync(legacy)) {
        fs.unlinkSync(legacy);
        process.stderr.write(`brokre: removed legacy ${legacy}\n`);
      }
    } catch (_) {
      /* ignore */
    }
  }
}

function vaultIsEmpty(brokrePath) {
  try {
    const out = execFileSync(brokrePath, ['list', '--json'], {
      encoding: 'utf8',
      timeout: 15_000,
    });
    const list = JSON.parse(out.trim());
    return !Array.isArray(list) || list.length === 0;
  } catch (_) {
    return true;
  }
}

function readExistingManageUrl() {
  try {
    const p = path.join(os.homedir(), '.brokre', 'run', 'manage.json');
    if (!fs.existsSync(p)) return null;
    const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (rec.port && rec.token) {
      return `http://127.0.0.1:${rec.port}/?t=${rec.token}`;
    }
  } catch (_) {
    /* ignore */
  }
  return null;
}

function probeManageUrl(url) {
  const portMatch = url.match(/127\.0\.0\.1:(\d+)/);
  const tokenMatch = url.match(/\?t=([a-f0-9]+)/i);
  if (!portMatch || !tokenMatch) {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: Number(portMatch[1]),
        path: '/api/config',
        method: 'GET',
        headers: { Authorization: `Bearer ${tokenMatch[1]}` },
        timeout: 800,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

function removeStaleManageRecord() {
  try {
    const p = path.join(os.homedir(), '.brokre', 'run', 'manage.json');
    if (fs.existsSync(p)) fs.unlinkSync(p);
  } catch (_) {
    /* ignore */
  }
}

function openUrlInBrowser(url) {
  try {
    if (process.platform === 'darwin') {
      execFileSync('open', [url]);
    } else if (process.platform === 'linux') {
      execFileSync('xdg-open', [url]);
    } else if (process.platform === 'win32') {
      execFileSync('cmd', ['/C', 'start', '', url]);
    }
    return true;
  } catch (err) {
    process.stderr.write(`brokre: could not open browser (${err.message})\n`);
    return false;
  }
}

function parseManageUrl(text) {
  const m = String(text).match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/i);
  return m ? m[0] : null;
}

function detachManageChild(child) {
  try {
    child.stdout?.removeAllListeners();
    child.stderr?.removeAllListeners();
    child.stdout?.destroy();
    child.stderr?.destroy();
    child.unref();
  } catch (_) {
    /* ignore */
  }
}

function openManageUrl(url) {
  process.stderr.write('brokre: opening credential manager in browser…\n');
  return openUrlInBrowser(url);
}

/** Spawn standalone `brokre manage` (no --open; browser opened once from Node). */
function spawnManageAndOpen(brokrePath) {
  return new Promise((resolve) => {
    let settled = false;
    let opened = false;
    let log = '';
    let pollTimer = null;
    let hardTimer = null;
    let child = null;

    const done = (ok) => {
      if (settled) return;
      settled = true;
      if (pollTimer) clearInterval(pollTimer);
      if (hardTimer) clearTimeout(hardTimer);
      if (child) detachManageChild(child);
      resolve(Boolean(ok));
    };

    const tryOpenFromLog = () => {
      const url = parseManageUrl(log);
      if (!url || opened) return false;
      opened = true;
      openManageUrl(url);
      return true;
    };

    const tryOpenFromRegistry = () => {
      const url = readExistingManageUrl();
      if (!url) return false;
      log += `brokre manage: ${url}\n`;
      return tryOpenFromLog();
    };

    child = spawn(brokrePath, ['manage', '--onboard'], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });

    const onData = (chunk) => {
      log += chunk.toString();
      if (tryOpenFromLog()) done(true);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', () => done(false));
    child.on('exit', (code, signal) => {
      if (signal || (code !== 0 && code !== null && !opened)) done(false);
    });

    pollTimer = setInterval(() => {
      if (tryOpenFromRegistry()) done(true);
    }, 150);

    hardTimer = setTimeout(() => {
      void (async () => {
        const url = readExistingManageUrl();
        if (url) {
          if (!opened) openManageUrl(url);
          done(opened || (await probeManageUrl(url)));
          return;
        }
        tryOpenFromRegistry();
        tryOpenFromLog();
        done(opened);
      })();
    }, 2500);
  });
}

/** Vault empty → start manage server and open http://127.0.0.1:56777/?t=… in browser. */
async function openManageIfVaultEmpty(brokrePath) {
  if (process.env.BROKRE_MCP_NO_AUTO_OPEN === '1') {
    return false;
  }
  if (!vaultIsEmpty(brokrePath)) {
    return false;
  }

  const existing = readExistingManageUrl();
  if (existing) {
    if (await probeManageUrl(existing)) {
      openManageUrl(existing);
      return true;
    }
    removeStaleManageRecord();
  }

  return spawnManageAndOpen(brokrePath);
}

function postInstallSetup(brokrePath) {
  cleanupLegacyBinaries();
  ensureCliOnPath();
  trySymlinkSystemWide(brokrePath);
}

function versionFilePath() {
  return path.join(os.homedir(), '.brokre', 'bin', '.version');
}

function readCachedVersion() {
  try {
    return fs.readFileSync(versionFilePath(), 'utf8').trim();
  } catch (_) {
    return null;
  }
}

function parseVersion(output) {
  const m = String(output).match(/\b(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)\b/);
  return m ? m[1] : null;
}

/** Compare X.Y.Z (pre-release suffix ignored for ordering). Returns -1 / 0 / 1. */
function compareSemver(a, b) {
  const parts = (v) =>
    String(v)
      .split(/[.+-]/)
      .map((x) => {
        const n = parseInt(x, 10);
        return Number.isFinite(n) ? n : 0;
      });
  const pa = parts(a);
  const pb = parts(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

function versionGte(a, b) {
  return compareSemver(a, b) >= 0;
}

async function writeCachedVersion(version) {
  await fs.promises.mkdir(path.dirname(versionFilePath()), { recursive: true });
  await fs.promises.writeFile(versionFilePath(), `${version}\n`);
}

function getInstalledVersion(brokrePath) {
  if (isLauncherScript(brokrePath)) {
    return null;
  }
  try {
    const out = execFileSync(brokrePath, ['--version'], {
      encoding: 'utf8',
      timeout: 5_000,
    });
    return parseVersion(out);
  } catch (_) {
    return null;
  }
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (
        res.statusCode >= 300 &&
        res.statusCode < 400 &&
        res.headers.location
      ) {
        res.resume();
        httpsGet(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
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
  const tmp = `${dest}.download`;
  await pipeline(res, fs.createWriteStream(tmp));
  await fs.promises.rename(tmp, dest);
}

/** Replace a cached CLI without in-place overwrite (avoids macOS SIGKILL on corrupt signature). */
async function installBinaryAtomically(src, dest) {
  await fs.promises.mkdir(path.dirname(dest), { recursive: true });
  const tmp = `${dest}.new.${process.pid}`;
  await fs.promises.copyFile(src, tmp);
  if (process.platform !== 'win32') {
    await fs.promises.chmod(tmp, 0o755);
    await fs.promises.rename(tmp, dest);
    return;
  }
  try {
    await fs.promises.rename(tmp, dest);
  } catch (err) {
    if (err.code === 'EPERM' || err.code === 'EEXIST') {
      await fs.promises.unlink(dest).catch(() => {});
      await fs.promises.rename(tmp, dest);
    } else {
      throw err;
    }
  }
  await fs.promises.chmod(dest, 0o755).catch(() => {});
}

function extractTarGz(tarPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === 'win32') {
    execFileSync('tar', ['-xzf', tarPath, '-C', destDir], { stdio: 'inherit' });
    return;
  }
  execFileSync('tar', ['-xzf', tarPath, '-C', destDir], { stdio: 'inherit' });
}

/** Keep ~/.brokre/bin/.version in sync when the resolved binary is our cache. */
async function syncVersionFileForBinary(brokrePath) {
  if (!brokrePath || isLauncherScript(brokrePath)) return;
  const cache = cachedBrokrePath();
  try {
    if (path.resolve(brokrePath) !== path.resolve(cache)) return;
  } catch (_) {
    return;
  }
  const actual = getInstalledVersion(brokrePath);
  if (!actual) return;
  if (readCachedVersion() !== actual) {
    await writeCachedVersion(actual);
  }
}

async function ensureBrokreBinary() {
  if (process.env.BROKRE_BIN) {
    const pinned = process.env.BROKRE_BIN;
    try {
      await syncVersionFileForBinary(pinned);
    } catch (_) {
      /* best-effort */
    }
    return pinned;
  }

  if (process.env.BROKRE_SKIP_AUTO_INSTALL === '1') {
    const onPath = findBrokreOnPath();
    if (onPath) return onPath;
    throw new Error('brokre not on PATH (BROKRE_SKIP_AUTO_INSTALL=1)');
  }

  const brokreVersion = process.env.BROKRE_VERSION || PKG_VERSION;
  const cache = cachedBrokrePath();
  const cachedVersion = readCachedVersion();
  const onPath = findBrokreOnPath();

  // Exact cache hit (version file matches package).
  if (fs.existsSync(cache) && cachedVersion === brokreVersion) {
    postInstallSetup(cache);
    return cache;
  }

  // Keep a cache binary that is already ≥ package version (fixes stale .version
  // and avoids downgrading a newer native install when npm lags behind).
  if (fs.existsSync(cache) && !isLauncherScript(cache)) {
    const actual = getInstalledVersion(cache) || cachedVersion;
    if (actual && versionGte(actual, brokreVersion)) {
      if (cachedVersion !== actual) {
        await writeCachedVersion(actual);
      }
      postInstallSetup(cache);
      return cache;
    }
  }

  if (onPath) {
    const installed = getInstalledVersion(onPath);
    if (installed && versionGte(installed, brokreVersion)) {
      if (installed !== brokreVersion) {
        process.stderr.write(
          `brokre: PATH has v${installed} (≥ package v${brokreVersion}); keeping it\n`
        );
      }
      try {
        if (path.resolve(onPath) === path.resolve(cache)) {
          await writeCachedVersion(installed);
        }
      } catch (_) {
        /* ignore */
      }
      postInstallSetup(onPath);
      return onPath;
    }
    if (installed) {
      process.stderr.write(
        `brokre: PATH has v${installed}, need v${brokreVersion}; downloading...\n`
      );
    }
  } else if (cachedVersion && !versionGte(cachedVersion, brokreVersion)) {
    process.stderr.write(
      `brokre: updating cached v${cachedVersion} → v${brokreVersion}...\n`
    );
  }

  const target = detectTarget();
  const url = `https://github.com/${REPO}/releases/download/v${brokreVersion}/brokre-${target}.tar.gz`;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'brokre-mcp-'));
  const tgz = path.join(tmpDir, 'brokre.tar.gz');

  try {
    if (!onPath && !cachedVersion) {
      process.stderr.write(
        `brokre: downloading v${brokreVersion} for ${target}...\n`
      );
    }
    await downloadToFile(url, tgz);
    extractTarGz(tgz, tmpDir);

    const extracted =
      process.platform === 'win32'
        ? path.join(tmpDir, 'brokre.exe')
        : path.join(tmpDir, 'brokre');
    if (!fs.existsSync(extracted)) {
      throw new Error(`brokre binary missing in release tarball (${target})`);
    }

    await installBinaryAtomically(extracted, cache);
    await writeCachedVersion(brokreVersion);
    postInstallSetup(cache);
    return cache;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function spawnNativeCli(brokre, args) {
  const child = spawn(brokre, args, {
    stdio: 'inherit',
    env: process.env,
  });
  child.on('error', (err) => {
    process.stderr.write(`brokre: ${err.message}\n`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

function spawnBrokreMcp(brokre, extraEnv = {}) {
  const child = spawn(brokre, ['mcp'], {
    stdio: ['inherit', 'inherit', 'pipe'],
    env: { ...process.env, ...extraEnv },
  });

  child.stderr.on('data', (chunk) => {
    process.stderr.write(redactManageTokens(chunk));
  });

  child.on('error', (err) => {
    if (err.code === 'ENOENT') {
      process.stderr.write(
        `brokre: not found (${brokre}). Install: curl -fsSL ${INSTALL_DOC} | bash\n`
      );
    } else {
      process.stderr.write(`brokre mcp: ${err.message}\n`);
    }
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

function windowsInstallHint() {
  if (process.platform !== 'win32') return '';
  return (
    'Windows: install with `npm install -g brokre` (the -g is required).\n' +
    'Then run `brokre list` in a new terminal. Local `npm i brokre` does not put `brokre` on PATH.\n'
  );
}

async function main() {
  handleEarlyArgv();
  const args = process.argv.slice(2);
  try {
    const brokre = await ensureBrokreBinary();
    if (isLauncherScript(brokre)) {
      throw new Error(
        'resolved brokre binary is the npm MCP launcher; install native CLI or set BROKRE_BIN'
      );
    }
    if (args.length === 0 && process.stdin.isTTY) {
      process.stderr.write(
        `brokre ${PKG_VERSION} — native CLI: ${brokre}\n` +
          'Usage: brokre list | brokre manage | brokre ssh <alias> …\n' +
          'MCP: IDEs launch this command with no TTY (stdio), not from an interactive prompt.\n'
      );
      process.exit(0);
    }
    const mcpStdio = args.length === 0 || (args.length === 1 && args[0] === 'mcp');
    if (mcpStdio) {
      const openedManage = await openManageIfVaultEmpty(brokre);
      const mcpEnv = openedManage ? { BROKRE_MCP_NO_AUTO_OPEN: '1' } : {};
      spawnBrokreMcp(brokre, mcpEnv);
      return;
    }
    spawnNativeCli(brokre, args);
  } catch (err) {
    process.stderr.write(
      `brokre: ${err.message}\n` +
        windowsInstallHint() +
        `Install manually: curl -fsSL ${INSTALL_DOC} | bash\n` +
        `Or set BROKRE_BIN to your brokre executable.\n`
    );
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  isLauncherScript,
  pathListContainsDir,
  ensureBrokreBinary,
  compareSemver,
  versionGte,
};

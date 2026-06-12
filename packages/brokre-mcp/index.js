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
    const out = execFileSync(which, ['brokre'], { encoding: 'utf8' });
    const line = out.trim().split(/\r?\n/)[0];
    if (line) return line;
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

function cliPathSetupNeeded() {
  if (process.platform === 'win32') return false;
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

function getInstalledVersion(brokrePath) {
  try {
    const out = execFileSync(brokrePath, ['--version'], { encoding: 'utf8' });
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

function extractTarGz(tarPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === 'win32') {
    execFileSync('tar', ['-xzf', tarPath, '-C', destDir], { stdio: 'inherit' });
    return;
  }
  execFileSync('tar', ['-xzf', tarPath, '-C', destDir], { stdio: 'inherit' });
}

async function ensureBrokreBinary() {
  if (process.env.BROKRE_BIN) {
    return process.env.BROKRE_BIN;
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

  if (fs.existsSync(cache) && cachedVersion === brokreVersion) {
    postInstallSetup(cache);
    return cache;
  }

  if (onPath) {
    const installed = getInstalledVersion(onPath);
    if (installed === brokreVersion) {
      postInstallSetup(onPath);
      return onPath;
    }
    if (installed) {
      process.stderr.write(
        `brokre: PATH has v${installed}, need v${brokreVersion}; downloading...\n`
      );
    }
  } else if (cachedVersion && cachedVersion !== brokreVersion) {
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

    await fs.promises.mkdir(path.dirname(cache), { recursive: true });
    await fs.promises.copyFile(extracted, cache);
    if (process.platform !== 'win32') {
      await fs.promises.chmod(cache, 0o755);
    }
    await fs.promises.writeFile(versionFilePath(), `${brokreVersion}\n`);
    postInstallSetup(cache);
    return cache;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
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

async function main() {
  try {
    const brokre = await ensureBrokreBinary();
    const openedManage = await openManageIfVaultEmpty(brokre);
    const mcpEnv = openedManage ? { BROKRE_MCP_NO_AUTO_OPEN: '1' } : {};
    spawnBrokreMcp(brokre, mcpEnv);
  } catch (err) {
    process.stderr.write(
      `brokre: ${err.message}\n` +
        `Install manually: curl -fsSL ${INSTALL_DOC} | bash\n` +
        `Or set BROKRE_BIN to your brokre executable.\n`
    );
    process.exit(1);
  }
}

main();

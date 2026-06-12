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

function cachedBrokrePath() {
  const name = process.platform === 'win32' ? 'brokre.exe' : 'brokre';
  return path.join(os.homedir(), '.brokre', 'bin', name);
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

  if (fs.existsSync(cache) && cachedVersion === brokreVersion) {
    return cache;
  }

  const onPath = findBrokreOnPath();
  if (onPath) {
    const installed = getInstalledVersion(onPath);
    if (installed === brokreVersion) {
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
    return cache;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function spawnBrokreMcp(brokre) {
  const child = spawn(brokre, ['mcp'], {
    stdio: ['inherit', 'inherit', 'pipe'],
    env: process.env,
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
    spawnBrokreMcp(brokre);
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

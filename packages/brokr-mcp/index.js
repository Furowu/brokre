#!/usr/bin/env node
/**
 * @techinone/brokr — MCP launcher for brokr credential broker.
 *
 * Spawns `brokr mcp` (stdio). Requires brokr CLI installed:
 *   curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash
 */
'use strict';

const { spawn } = require('child_process');
const { execFileSync } = require('child_process');

function findBrokr() {
  if (process.env.BROKR_BIN) {
    return process.env.BROKR_BIN;
  }
  try {
    const which = process.platform === 'win32' ? 'where' : 'which';
    const out = execFileSync(which, ['brokr'], { encoding: 'utf8' });
    const line = out.trim().split(/\r?\n/)[0];
    if (line) return line;
  } catch (_) {
    /* not on PATH */
  }
  return 'brokr';
}

function redactManageTokens(chunk) {
  return chunk
    .toString()
    .split('\n')
    .map((line) =>
      line.replace(/\?t=[a-f0-9]+/gi, '?t=<redacted>').replace(
        /brokr manage: http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/gi,
        (m) => m.replace(/\?t=[a-f0-9]+/i, '?t=<redacted>')
      )
    )
    .join('\n');
}

const brokr = findBrokr();
const child = spawn(brokr, ['mcp'], {
  stdio: ['inherit', 'inherit', 'pipe'],
  env: process.env,
});

child.stderr.on('data', (chunk) => {
  process.stderr.write(redactManageTokens(chunk));
});

child.on('error', (err) => {
  if (err.code === 'ENOENT') {
    process.stderr.write(
      'brokr: not found on PATH. Install: curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash\n'
    );
  } else {
    process.stderr.write(`brokr mcp: ${err.message}\n`);
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

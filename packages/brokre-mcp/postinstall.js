#!/usr/bin/env node
/**
 * npm postinstall for brokre:
 * 1) Best-effort download of the matching native CLI into ~/.brokre/bin
 * 2) IDE MCP registration via setup-mcp.js
 *
 * npm 11+ may skip this script unless allow-scripts includes brokre:
 *   npm install -g brokre --allow-scripts=brokre
 * First CLI/MCP run still calls ensureBrokreBinary() if this step was skipped.
 *
 * Opt out of binary download: BROKRE_SKIP_AUTO_INSTALL=1
 * Opt out of MCP setup: BROKRE_MCP_SKIP_SETUP=1
 */
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

function shouldSkipBinary() {
  if (process.env.BROKRE_SKIP_AUTO_INSTALL === '1') return true;
  if (process.env.CI === 'true' || process.env.CI === '1') return true;
  return false;
}

async function ensureBinaryBestEffort() {
  if (shouldSkipBinary()) return;
  try {
    const { ensureBrokreBinary } = require('./index.js');
    await ensureBrokreBinary();
  } catch (err) {
    process.stderr.write(
      `brokre: postinstall binary download skipped (${err.message})\n` +
        '  First `brokre` / MCP start will retry. Manual: ' +
        'https://raw.githubusercontent.com/Furowu/brokre/main/install.sh\n'
    );
  }
}

function runSetupMcp() {
  const setup = path.join(__dirname, 'setup-mcp.js');
  const res = spawnSync(process.execPath, [setup], {
    stdio: 'inherit',
    env: process.env,
  });
  if (res.error) {
    process.stderr.write(`brokre: MCP setup failed (${res.error.message})\n`);
    return;
  }
  // Never fail npm install solely because IDE merge failed.
}

async function main() {
  await ensureBinaryBestEffort();
  runSetupMcp();
}

main().catch((err) => {
  process.stderr.write(`brokre: postinstall error (${err.message})\n`);
  process.exit(0);
});

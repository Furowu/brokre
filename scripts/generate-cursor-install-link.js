#!/usr/bin/env node
/**
 * Print Cursor one-click MCP install deeplink for brokre.
 * Usage: node scripts/generate-cursor-install-link.js
 */
'use strict';

const config = {
  brokre: {
    command: 'npx',
    args: ['-y', 'brokre@latest'],
  },
};

const encoded = Buffer.from(JSON.stringify(config)).toString('base64');
const link = `cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=${encoded}`;

console.log(link);

#!/usr/bin/env node
/**
 * Copies core/scanner-core.js to every place that needs its own copy:
 *   ScannerCore.gs                      (Google Apps Script cannot import files)
 *   browser-extension/scanner-core.js   (loaded by the service worker)
 *   cli-extension/scanner-core.js       (the CLI package is installed on its own)
 *
 * `node scripts/sync-core.js`          write the copies
 * `node scripts/sync-core.js --check`  fail if any copy is out of date (used by CI and tests)
 */
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'core', 'scanner-core.js'), 'utf8');
const banner = (what) => `// GENERATED FILE - do not edit. Source: core/scanner-core.js. Run \`npm run sync-core\` after changing the source.\n// ${what}\n`;

const targets = [
  { file: 'ScannerCore.gs', content: banner('Google Apps Script copy of the shared scanning core.') + source },
  { file: 'browser-extension/scanner-core.js', content: banner('Chrome extension copy of the shared scanning core.') + source },
  { file: 'cli-extension/scanner-core.js', content: banner('CLI / MCP copy of the shared scanning core.') + source }
];

const check = process.argv.includes('--check');
let stale = 0;
for (const t of targets) {
  const full = path.join(root, t.file);
  const current = fs.existsSync(full) ? fs.readFileSync(full, 'utf8') : null;
  if (current === t.content) continue;
  if (check) {
    console.error(`OUT OF DATE: ${t.file}`);
    stale++;
  } else {
    fs.writeFileSync(full, t.content);
    console.log(`wrote ${t.file}`);
  }
}
if (check) {
  if (stale) {
    console.error('Run `npm run sync-core` and commit the result.');
    process.exit(1);
  }
  console.log('All copies of scanner-core are in sync.');
}

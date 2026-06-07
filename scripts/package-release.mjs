#!/usr/bin/env node
// Produces the distributable release ZIP: a self-contained folder that a user unzips and
// runs with zero `npm install`. Contents:
//   backend-code-review-v<version>/
//     code-review.js   — the bundled CLI (TS compiler + all deps inlined)
//     code-review.cmd  — Windows launcher (double-click / `code-review ...` in cmd/PowerShell)
//     code-review      — POSIX launcher (`./code-review ...`)
//     README.md, LICENSE, USAGE.txt
//
// Zipping is done with whatever ships on the host (PowerShell Compress-Archive on Windows,
// `zip` elsewhere). If neither is available the staged folder is left ready to zip by hand.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, writeFileSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse((await import('node:fs')).readFileSync(path.join(root, 'package.json'), 'utf-8'));
const version = pkg.version;
const bundle = path.join(root, 'release', 'code-review.js');

if (!existsSync(bundle)) {
  console.error('release/code-review.js not found — run `npm run bundle` first.');
  process.exit(1);
}

const stageRoot = path.join(root, 'release', 'staging');
const folderName = `backend-code-review-v${version}`;
const stage = path.join(stageRoot, folderName);
rmSync(stageRoot, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });

cpSync(bundle, path.join(stage, 'code-review.js'));
for (const file of ['README.md', 'LICENSE']) {
  if (existsSync(path.join(root, file))) cpSync(path.join(root, file), path.join(stage, file));
}

// Windows launcher: forwards all args to node, resolves the script next to itself (%~dp0).
writeFileSync(
  path.join(stage, 'code-review.cmd'),
  '@echo off\r\nnode "%~dp0code-review.js" %*\r\n'
);
// POSIX launcher.
const posixLauncher = path.join(stage, 'code-review');
writeFileSync(posixLauncher, '#!/bin/sh\nexec node "$(dirname "$0")/code-review.js" "$@"\n');
try { chmodSync(posixLauncher, 0o755); } catch { /* chmod is a no-op / unsupported on Windows */ }

writeFileSync(
  path.join(stage, 'USAGE.txt'),
  [
    `Backend Code Review v${version} — self-contained build (no npm install required).`,
    '',
    'Requirements: Node.js 18 or newer on PATH. Nothing else.',
    '',
    'Windows (cmd / PowerShell):',
    '  code-review.cmd --path C:\\path\\to\\service\\src --format sarif --output report.sarif',
    '  (or)  node code-review.js --path . --include-heuristics',
    '',
    'macOS / Linux:',
    '  ./code-review --path ./src --format sarif --output report.sarif',
    '  (or)  node code-review.js --path . --include-heuristics',
    '',
    'List all rules:   node code-review.js --list-rules',
    'Help:             node code-review.js --help',
    '',
  ].join('\n')
);

console.log(`✓ Staged ${folderName} at ${path.relative(root, stage)}`);

// Zip it with host-native tooling.
const zipPath = path.join(root, 'release', `${folderName}.zip`);
rmSync(zipPath, { force: true });
let zipped = false;
try {
  if (process.platform === 'win32') {
    execFileSync('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      `Compress-Archive -Path '${stage}' -DestinationPath '${zipPath}' -Force`,
    ], { stdio: 'inherit' });
  } else {
    execFileSync('zip', ['-r', '-q', zipPath, folderName], { cwd: stageRoot, stdio: 'inherit' });
  }
  zipped = existsSync(zipPath);
} catch (err) {
  console.warn(`! Could not auto-zip (${err.message}).`);
}

if (zipped) {
  console.log(`✓ Release ZIP → ${path.relative(root, zipPath)}`);
} else {
  console.log(`! Zip tool unavailable. Compress this folder manually: ${path.relative(root, stage)}`);
}

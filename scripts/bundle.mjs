#!/usr/bin/env node
// Builds the self-contained, offline release bundle.
//
// Output: release/code-review.js — a single CommonJS file with the TypeScript compiler,
// yargs, fast-glob and ignore all inlined. It runs on any machine with Node >= 18 and
// NO `npm install` (no node_modules required). This is the artifact shipped in the
// release ZIP so Windows users never download a library.
//
// Two bundle-specific shims are applied:
//   1. import.meta.url → a runtime file URL of the bundle, so dependencies that call
//      `createRequire(import.meta.url)` (e.g. yargs' ESM shim) work in CJS output.
//   2. __BCR_VERSION__ → the package.json version, so `--version` reports correctly even
//      though package.json itself is not present next to the bundle.
import { build } from 'esbuild';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf-8'));
const outDir = path.join(root, 'release');
mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'code-review.js');

await build({
  entryPoints: [path.join(root, 'src', 'index.ts')],
  outfile: outFile,
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'cjs',
  legalComments: 'none',
  minify: false, // keep readable for auditability; the artifact is a security tool
  logLevel: 'info',
  define: {
    __BCR_VERSION__: JSON.stringify(pkg.version),
    'import.meta.url': '__bcrImportMetaUrl',
  },
  banner: {
    js: [
      '#!/usr/bin/env node',
      // Provide a concrete import.meta.url for any bundled ESM dependency.
      "const __bcrImportMetaUrl = require('url').pathToFileURL(__filename).href;",
    ].join('\n'),
  },
});

console.log(`\n✓ Bundled ${pkg.name}@${pkg.version} → ${path.relative(root, outFile)}`);

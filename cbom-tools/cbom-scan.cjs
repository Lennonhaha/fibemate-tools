#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// cbom-scan.cjs — scan a directory tree for cryptographic assets,
// emit CycloneDX 1.6 CBOM.

'use strict';

const fs = require('fs');
const path = require('path');

const ALGO_META = JSON.parse(fs.readFileSync(path.join(__dirname, 'algo-metadata.json'), 'utf-8'));

const NAME_ALIASES = {
 'ML-KEM-768': 'ML-KEM',
 'ML-KEM-512': 'ML-KEM',
 'ML-KEM-1024': 'ML-KEM',
 'ML-DSA': 'ML-DSA/fml-dsa',
 'ML-DSA-44': 'ML-DSA/fml-dsa',
 'ML-DSA-65': 'ML-DSA/fml-dsa',
 'ML-DSA-87': 'ML-DSA/fml-dsa',
};

function lookupMeta(name) {
 if (ALGO_META[name]) return ALGO_META[name];
 const alias = NAME_ALIASES[name];
 if (alias && ALGO_META[alias]) return ALGO_META[alias];
 return null;
}

const DEFAULT_RULES = {
 packages: {
 '@noble/post-quantum': ['ML-KEM-768', 'ML-DSA-65', 'SLH-DSA'],
 '@noble/hashes': ['SHA3-256', 'SHA3-512', 'Keccak-256'],
 'sm-crypto': ['SM2', 'SM3', 'SM4'],
 'sm2-crypto': ['SM2'],
 jsbn: ['RSA'],
 '@fibemate/sm2-crypto': ['SM2'],
 '@fibemate/keccak': ['Keccak-256', 'SHA3-256'],
 },
 sourcePatterns: [
 { re: /require\(['"]sm-crypto['"]\)/g, algs: ['SM2', 'SM3', 'SM4'] },
 { re: /crypto\.createHash\(['"]sha3-(\d+)['"]\)/g, algs: ['SHA3-$1'] },
 { re: /crypto\.createHash\(['"]sha-?256['"]\)/g, algs: ['SHA-256'] },
 { re: /crypto\.createHash\(['"]sha-?512['"]\)/g, algs: ['SHA-512'] },
 { re: /noble.*post-?quantum/gi, algs: ['ML-KEM', 'ML-DSA'] },
 { re: /\bml[-_]?kem\b/gi, algs: ['ML-KEM'] },
 { re: /\bml[-_]?dsa\b/gi, algs: ['ML-DSA'] },
 { re: /\bslh[-_]?dsa\b/gi, algs: ['SLH-DSA'] },
 { re: /\bkeccak\b/gi, algs: ['Keccak'] },
 { re: /\bsm2\b/gi, algs: ['SM2'] },
 { re: /\bsm3\b/gi, algs: ['SM3'] },
 { re: /\bsm4\b/gi, algs: ['SM4'] },
 ],
};

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.git', '.cache']);
const SCAN_EXT = /\.(cjs|mjs|js|ts|tsx|jsx)$/;
const MAX_OCC_PER_ALGO = 50;

function loadPackageDeps(dir) {
 const pkgPath = path.join(dir, 'package.json');
 if (!fs.existsSync(pkgPath)) return {};
 try {
 const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
 return { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
 } catch {
 return {};
 }
}

function matchDeps(deps, rules) {
 const found = new Set();
 for (const name of Object.keys(deps)) {
 if (rules.packages[name]) rules.packages[name].forEach(a => found.add(a));
 }
 return found;
}

function scanSource(root, rules) {
 const found = new Map();

 function addOcc(name, file, line) {
 let arr = found.get(name);
 if (!arr) { arr = []; found.set(name, arr); }
 if (arr.length >= MAX_OCC_PER_ALGO) return;
 const loc = path.relative(root, file).replace(/\\/g, '/');
 if (arr.some(o => o.location === loc && o.line === line)) return;
 arr.push({ location: loc, line });
 }

 function walk(d) {
 let entries;
 try { entries = fs.readdirSync(d, { withFileTypes: true }); }
 catch { return; }
 for (const entry of entries) {
 if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
 const full = path.join(d, entry.name);
 if (entry.isDirectory()) walk(full);
 else if (SCAN_EXT.test(entry.name)) {
 let content;
 try { content = fs.readFileSync(full, 'utf-8'); }
 catch { continue; }
 for (const { re, algs } of rules.sourcePatterns) {
 re.lastIndex = 0;
 let m;
 while ((m = re.exec(content)) !== null) {
 const line = content.slice(0, m.index).split('\n').length;
 for (const a of algs) {
 const name = a.replace(/\$(\d+)/g, (_, i) => m[i]);
 addOcc(name, full, line);
 }
 }
 }
 }
 }
 }
 walk(root);
 return found;
}

function toCycloneDX(algorithms) {
 return {
 bomFormat: 'CycloneDX',
 specVersion: '1.6',
 version: 1,
 metadata: {
 timestamp: new Date().toISOString(),
 tools: [{ name: 'cbom-scan', version: '0.1.0', vendor: 'FIBEMATE' }],
 },
 components: [...algorithms.keys()].sort().map(name => {
 const meta = lookupMeta(name);
 const comp = {
 type: 'cryptographic-asset',
 name,
 'bom-ref': `crypto:${name}`,
 };
 if (meta) comp.cryptoProperties = meta;
 const occ = algorithms.get(name);
 if (occ && occ.length) comp.evidence = { occurrences: occ };
 return comp;
 }),
 };
}

function main() {
 const args = process.argv.slice(2);
 const dir = args.includes('--dir') ? args[args.indexOf('--dir') + 1] : process.cwd();
 const outPath = args.includes('--out') ? args[args.indexOf('--out') + 1] : null;

 const deps = loadPackageDeps(dir);
 const fromDeps = matchDeps(deps, DEFAULT_RULES);
 const fromSource = scanSource(dir, DEFAULT_RULES);

 // Merge: union of both. Source occurrences override empty array from deps.
 const merged = new Map();
 for (const name of fromDeps) merged.set(name, []);
 for (const [name, occ] of fromSource) merged.set(name, occ);

 const cbom = toCycloneDX(merged);
 const output = JSON.stringify(cbom, null, 2);
 if (outPath) {
 fs.writeFileSync(outPath, output, 'utf-8');
 console.error(`cbom-scan: wrote ${merged.size} algorithms to ${outPath}`);
 } else {
 console.log(output);
 }
 process.exit(0);
}

main();
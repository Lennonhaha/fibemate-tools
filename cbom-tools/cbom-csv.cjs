// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 刘天赫
//
// CSV-to-CBOM converter: reads a CSV of crypto scan findings
// and produces a CycloneDX 1.6 Cryptographic Bill of Materials.
//
// Usage:
//   node cbom-csv.cjs --input scan.csv [--out output.json]
//     [--map file=FILE,line=LINE,algorithm=ALGO]
//     [--name 'project-name'] [--version '1.0.0']
//
// The --map flag maps cbom-csv column names to CSV header names.
// Default: file,line,algorithm
//
// Zero runtime dependencies — uses Node built-in readline for CSV.

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

// ---- shared data (same as cbom-scan.cjs) ----

const ALGO_META = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'algo-metadata.json'), 'utf-8'),
);
const PKG = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'package.json'), 'utf-8'),
);

const NAME_ALIASES = {
  'ML-KEM-768': 'ML-KEM',
  'ML-KEM-512': 'ML-KEM',
  'ML-KEM-1024': 'ML-KEM',
  'ML-DSA': 'ML-DSA/fml-dsa',
  'ML-DSA-44': 'ML-DSA/fml-dsa',
  'ML-DSA-65': 'ML-DSA/fml-dsa',
  'ML-DSA-87': 'ML-DSA/fml-dsa',
  'Keccak-256': 'Keccak',
};

function lookupMeta(name) {
  if (ALGO_META[name]) return ALGO_META[name];
  const alias = NAME_ALIASES[name];
  if (alias && ALGO_META[alias]) return ALGO_META[alias];
  return null;
}

// ---- CLI arg parsing ----

function parseArgs(argv) {
  argv = argv || process.argv.slice(2);
  const get = (flag) => {
    const i = argv.indexOf(flag);
    return i !== -1 ? argv[i + 1] : null;
  };
  const has = (flag) => argv.includes(flag);

  const input = get('--input');
  if (!input) {
    console.error('usage: node cbom-csv.cjs --input <file.csv> [--out <file.json>]');
    console.error('  [--map col1=FILE,col2=LINE,col3=ALGO] [--name <name>] [--version <ver>]');
    console.error('  Default column mapping: file,line,algorithm');
    process.exit(2);
  }

  const colMap = { file: 'file', line: 'line', algorithm: 'algorithm' };
  const raw = get('--map');
  if (raw) {
    for (const pair of raw.split(',')) {
      const [k, v] = pair.split('=');
      if (k && v) colMap[k.trim()] = v.trim();
    }
  }

  return {
    input,
    output: get('--out'),
    projectName: get('--name'),
    projectVersion: get('--version') || '0.0.0',
    colMap,
  };
}

// ---- CSV reader ----

async function readCsv(filePath, colMap) {
  const stream = fs.createReadStream(filePath, { encoding: 'utf-8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let header = null;
  const records = [];

  for await (const line of rl) {
    if (!line.trim()) continue;
    const cells = line.split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
    if (!header) {
      header = cells;
      const required = [colMap.file, colMap.algorithm];
      for (const req of required) {
        if (!header.includes(req)) {
          console.error(`error: required column "${req}" not found in CSV header`);
          console.error(`  header: ${header.join(', ')}`);
          process.exit(2);
        }
      }
      continue;
    }
    records.push(cells);
  }

  const occurrences = new Map();
  const unknown = [];

  for (const cells of records) {
    const fileIdx = header.indexOf(colMap.file);
    const lineIdx = colMap.line ? header.indexOf(colMap.line) : -1;
    const algoIdx = header.indexOf(colMap.algorithm);

    const file = cells[fileIdx] || '';
    const rawAlgo = (cells[algoIdx] || '').trim();
    if (!rawAlgo) continue;

    const lineNum = lineIdx >= 0 ? parseInt(cells[lineIdx], 10) : null;
    if (lineIdx >= 0 && isNaN(lineNum)) {
      console.error(
        `warning: non-numeric line value "${cells[lineIdx]}" for ${rawAlgo}, skipping`,
      );
      continue;
    }

    if (!occurrences.has(rawAlgo)) occurrences.set(rawAlgo, []);

    const occ = {};
    if (file) occ.location = file;
    if (lineNum !== null) occ.line = lineNum;
    occurrences.get(rawAlgo).push(occ);
  }

  return { occurrences, unknown };
}

// ---- CBOM builder (same structure as cbom-scan.cjs) ----

function toCycloneDX(algorithms, projectName, projectVersion) {
  const metaBlock = {};
  if (projectName) {
    metaBlock.component = { name: projectName, version: projectVersion || '0.0.0' };
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'cbom-csv', version: PKG.version, vendor: 'FIBEMATE' }],
      ...metaBlock,
    },
    components: [...algorithms.keys()].sort().map((name) => {
      const meta = lookupMeta(name);
      const comp = {
        type: 'cryptographic-asset',
        name,
        'bom-ref': `crypto:${name}`,
      };
      if (meta) {
        comp.cryptoProperties = {
          assetType: meta.assetType,
          algorithmProperties: meta.algorithmProperties,
        };
        const props = [];
        if (meta.implementationPlatform)
          props.push({
            name: 'fibemate:implementationLanguages',
            value: meta.implementationPlatform,
          });
        if (meta.certificationLevel)
          props.push({ name: 'fibemate:testingStatus', value: meta.certificationLevel });
        if (meta.quantumSecurity?.level)
          props.push({ name: 'fibemate:quantumSecurity:level', value: meta.quantumSecurity.level });
        if (props.length) comp.properties = props;
      }
      const occ = algorithms.get(name);
      if (occ && occ.length) comp.evidence = { occurrences: occ };
      return comp;
    }),
  };
}

// ---- CLI entry ----

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(opts.input)) {
    console.error(`error: input file not found: ${opts.input}`);
    process.exit(2);
  }

  const { occurrences } = await readCsv(opts.input, opts.colMap);

  if (occurrences.size === 0) {
    console.error('warning: no algorithms found in CSV');
  }

  // Emit warning for unknown algorithms (classified as unknown, not silently dropped)
  const unknownAlgos = [];
  for (const name of occurrences.keys()) {
    if (!lookupMeta(name)) unknownAlgos.push(name);
  }
  if (unknownAlgos.length > 0) {
    console.error(`warning: ${unknownAlgos.length} algorithm(s) not in metadata:`);
    for (const a of unknownAlgos) console.error(`  - ${a}`);
  }

  const cbom = toCycloneDX(occurrences, opts.projectName, opts.projectVersion);
  const output = JSON.stringify(cbom, null, 2);

  if (opts.output) {
    fs.writeFileSync(opts.output, output, 'utf-8');
    console.error(`cbom-csv: wrote ${occurrences.size} algorithms to ${opts.output}`);
  } else {
    console.log(output);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { toCycloneDX, lookupMeta, readCsv, parseArgs, main };
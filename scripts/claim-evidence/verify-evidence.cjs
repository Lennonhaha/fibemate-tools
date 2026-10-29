'use strict';
// SPDX-License-Identifier: Apache-2.0
/**
 * verify-evidence — check a digest list and the timestamp token that seals it.
 *
 * Two links, and they fail separately on purpose:
 *
 *   1. manifest -> files   : every file's sha256 must equal the recorded digest
 *   2. TSR      -> manifest : the token's message imprint must equal
 *                             sha256(manifest), and the token must verify
 *                             against the CA
 *
 * Link 1 alone is worthless if whoever tampered with a file can also rewrite the
 * manifest, which is why link 2 exists. Both links report `drift`; a missing or
 * unusable input reports `unverifiable`, never `verified`.
 *
 * Exit codes: 0 verified | 1 drift | 2 usage | 3 unverifiable (missing input,
 * unparsable token, no CA, openssl absent).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const EXIT = { verified: 0, drift: 1, usage: 2, unverifiable: 3 };

function usage(msg) {
  const e = new Error(msg);
  e.code = 'USAGE';
  return e;
}

function unverifiable(msg) {
  const e = new Error(msg);
  e.code = 'UNVERIFIABLE';
  return e;
}

function parseArgs(argv) {
  const out = { json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') { out.json = true; continue; }
    if (!a.startsWith('--')) throw usage('unexpected argument: ' + a);
    const key = a.slice(2);
    const val = argv[++i];
    if (val == null) throw usage('missing value for --' + key);
    out[key] = val;
  }
  return out;
}

/** openssl on Windows needs a config; probe the usual locations before giving up. */
function opensslEnv() {
  const env = Object.assign({}, process.env);
  if (env.OPENSSL_CONF) return { env, note: 'OPENSSL_CONF from environment' };
  if (process.platform !== 'win32') return { env, note: 'posix' };
  const candidates = [
    'C:/Program Files/Common Files/SSL/openssl.cnf',
    'C:/Program Files/Git/usr/ssl/openssl.cnf',
    'C:/Program Files (x86)/Common Files/SSL/openssl.cnf',
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) { env.OPENSSL_CONF = c; return { env, note: 'OPENSSL_CONF=' + c }; }
  }
  return { env, note: 'no openssl.cnf found (openssl may still work)' };
}

function runOpenSSL(args, opts) {
  const bin = (opts && opts.opensslBin) || process.env.OPENSSL_BIN || 'openssl';
  const { env, note } = opensslEnv();
  const r = spawnSync(bin, args, { encoding: 'utf8', env, maxBuffer: 1 << 24 });
  if (r.error) {
    const e = new Error('cannot run openssl (' + bin + '): ' + r.error.message);
    e.code = 'UNVERIFIABLE';
    throw e;
  }
  // Windows shells turn stderr into an error object; the text is what matters.
  return { stdout: r.stdout || '', stderr: r.stderr || '', status: r.status, conf: note };
}

/** `openssl ts -reply -text` / `-query -text` → { imprint, serial, time, nonce, status } */
function parseTokenText(text) {
  const out = {};
  const status = text.match(/^Status:\s*(.+)$/m);
  if (status) out.status = status[1].trim();
  const serial = text.match(/^Serial number:\s*(0x[0-9a-fA-F]+)/m);
  if (serial) out.serial = serial[1].toLowerCase();
  const time = text.match(/^Time stamp:\s*(.+)$/m);
  if (time) out.time = time[1].trim();
  const nonce = text.match(/^Nonce:\s*(0x[0-9a-fA-F]+)/m);
  if (nonce) out.nonce = nonce[1].toLowerCase();
  const alg = text.match(/^Hash Algorithm:\s*(\S+)/m);
  if (alg) out.hashAlgorithm = alg[1].trim();
  const start = text.indexOf('Message data:');
  if (start >= 0) {
    const hex = [];
    for (const line of text.slice(start + 'Message data:'.length).split('\n')) {
      if (!/^\s*[0-9a-fA-F]{4}\s*-/.test(line)) {
        if (hex.length) break;      // first non-dump line ends the block
        continue;
      }
      const body = line.replace(/^\s*[0-9a-fA-F]{4}\s*-\s*/, '').split(/\s{2,}/)[0];
      hex.push(body.replace(/[^0-9a-fA-F]/g, ''));
    }
    if (hex.length) out.imprint = hex.join('').toLowerCase();
  }
  return out;
}

function readManifest(file) {
  const text = fs.readFileSync(file, 'utf8');
  const entries = [];
  const bad = [];
  text.split('\n').forEach((line, i) => {
    if (!line.trim() || line.trim().startsWith('#')) return;
    const m = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/);
    if (!m) { bad.push({ line: i + 1, text: line.slice(0, 120) }); return; }
    entries.push({ digest: m[1].toLowerCase(), file: m[2] });
  });
  return { entries, bad, bytes: fs.readFileSync(file), sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') };
}

function sha256File(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function verify(opts) {
  const result = {
    verdict: 'verified',
    checks: {},
    files: [],
    manifest: null,
    token: null,
    notes: [],
  };
  const fail = (verdict) => {
    const rank = { verified: 0, drift: 1, unverifiable: 2 };
    if (rank[verdict] > rank[result.verdict]) result.verdict = verdict;
  };

  if (!opts.manifest || !opts.root || !opts.tsr) {
    throw usage('required: --manifest <SHA256SUMS> --root <dir> --tsr <file> [--tsq <file>] [--ca <pem>]');
  }
  const manifestPath = path.resolve(opts.manifest);
  const root = path.resolve(opts.root);
  // Missing inputs mean the evidence cannot be checked, not that the caller typed it wrong.
  if (!fs.existsSync(manifestPath)) throw unverifiable('manifest not found: ' + manifestPath);
  if (!fs.existsSync(root)) throw unverifiable('root not found: ' + root);

  // Link 1: manifest -> files
  const man = readManifest(manifestPath);
  result.manifest = { path: manifestPath, entries: man.entries.length, malformed: man.bad, sha256: man.sha256 };
  if (!man.entries.length) fail('unverifiable');
  if (man.bad.length) { fail('unverifiable'); result.notes.push('manifest has malformed lines: ' + man.bad.length); }
  for (const e of man.entries) {
    const p = path.join(root, e.file);
    const row = { file: e.file, expected: e.digest };
    if (!fs.existsSync(p)) { row.status = 'missing'; fail('drift'); }
    else {
      row.actual = sha256File(p);
      row.status = row.actual === e.digest ? 'match' : 'mismatch';
      if (row.status === 'mismatch') fail('drift');
    }
    result.files.push(row);
  }
  const mismatched = result.files.filter((f) => f.status !== 'match').length;
  result.checks.filesMatchManifest = mismatched === 0 ? 'pass' : 'fail (' + mismatched + '/' + result.files.length + ')';

  // Link 2: TSR -> manifest
  const tsrPath = path.resolve(opts.tsr);
  if (!fs.existsSync(tsrPath)) throw unverifiable('tsr not found: ' + tsrPath);
  const reply = runOpenSSL(['ts', '-reply', '-in', tsrPath, '-text'], opts);
  const token = parseTokenText(reply.stdout + '\n' + reply.stderr);
  result.token = {
    serial: token.serial || null,
    time: token.time || null,
    nonce: token.nonce || null,
    hashAlgorithm: token.hashAlgorithm || null,
    status: token.status || null,
    imprint: token.imprint || null,
    opensslConf: reply.conf,
  };
  if (!token.imprint) { fail('unverifiable'); result.checks.tokenParsed = 'fail'; }
  else {
    result.checks.tokenParsed = 'pass';
    const ok = token.imprint === man.sha256;
    result.checks.imprintMatchesManifest = ok ? 'pass' : 'fail';
    result.token.manifestSha256 = man.sha256;
    if (!ok) fail('drift');
    if (token.status && !/^Granted/i.test(token.status)) { fail('unverifiable'); result.notes.push('token status is not Granted: ' + token.status); }
  }

  // Signature verification: require the literal OK line, do not trust exit codes
  // (PowerShell reports rc=1 for stderr output that openssl considers success).
  if (opts.ca) {
    const ca = path.resolve(opts.ca);
    if (!fs.existsSync(ca)) throw unverifiable('ca not found: ' + ca);
    const v = runOpenSSL(['ts', '-verify', '-in', tsrPath, '-data', manifestPath, '-CAfile', ca], opts);
    const blob = v.stdout + '\n' + v.stderr;
    const ok = /Verification:\s*OK/i.test(blob);
    result.checks.signatureVerified = ok ? 'pass' : 'fail';
    if (!ok) {
      fail('drift');
      result.notes.push('openssl ts -verify did not report OK: ' + blob.split('\n').filter((l) => l.trim()).slice(-3).join(' | '));
    }
  } else {
    result.checks.signatureVerified = 'skipped (no --ca)';
    fail('unverifiable');
    result.notes.push('no CA supplied: the token was parsed but not verified');
  }

  // Optional: the request nonce must appear in the token, or the token answers
  // some other request that happens to carry the same imprint.
  if (opts.tsq) {
    const tsqPath = path.resolve(opts.tsq);
    if (!fs.existsSync(tsqPath)) throw unverifiable('tsq not found: ' + tsqPath);
    const q = parseTokenText(runOpenSSL(['ts', '-query', '-in', tsqPath, '-text'], opts).stdout);
    if (q.nonce && token.nonce) {
      const ok = q.nonce === token.nonce;
      result.checks.nonceMatchesRequest = ok ? 'pass' : 'fail';
      if (!ok) fail('drift');
    } else {
      result.checks.nonceMatchesRequest = 'unparsed';
      fail('unverifiable');
    }
    if (q.imprint && token.imprint) {
      const ok = q.imprint === token.imprint;
      result.checks.requestImprintMatchesToken = ok ? 'pass' : 'fail';
      if (!ok) fail('drift');
    }
    result.request = { nonce: q.nonce || null, imprint: q.imprint || null };
  }

  return result;
}

function render(result) {
  const lines = [];
  lines.push('verdict: ' + result.verdict);
  for (const [k, v] of Object.entries(result.checks)) lines.push('  ' + k + ': ' + v);
  if (result.token) {
    lines.push('  token: serial=' + result.token.serial + ' time=' + JSON.stringify(result.token.time));
  }
  const bad = result.files.filter((f) => f.status !== 'match');
  if (bad.length) {
    lines.push('  files that failed:');
    for (const f of bad.slice(0, 10)) lines.push('    ' + f.status + ' ' + f.file + ' expected ' + f.expected.slice(0, 16) + '… actual ' + (f.actual || '-').slice(0, 16) + '…');
    if (bad.length > 10) lines.push('    … ' + (bad.length - 10) + ' more');
  }
  for (const n of result.notes) lines.push('  note: ' + n);
  return lines.join('\n');
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
    const result = verify(opts);
    if (opts.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    else process.stdout.write(render(result) + '\n');
    if (opts.out) fs.writeFileSync(path.resolve(opts.out), JSON.stringify(result, null, 2) + '\n', 'utf8');
    return EXIT[result.verdict];
  } catch (e) {
    const code = e.code === 'USAGE' ? EXIT.usage : EXIT.unverifiable;
    process.stderr.write('verify-evidence: ' + e.message + '\n');
    if (code === EXIT.usage) process.stderr.write('usage: verify-evidence --manifest <SHA256SUMS> --root <dir> --tsr <file> [--tsq <file>] [--ca <pem>] [--json] [--out <file>]\n');
    return code;
  }
}

if (require.main === module) process.exit(main(process.argv.slice(2)));

module.exports = { verify, parseTokenText, readManifest, opensslEnv, EXIT };

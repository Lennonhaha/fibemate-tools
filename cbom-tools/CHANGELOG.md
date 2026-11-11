# Changelog

Entries start at 0.2.7; earlier releases predate this file. Versions follow
[Semantic Versioning](https://semver.org/), and this tool is pre-1.0, so the
minor number moves for behaviour changes.

## 0.2.7 — 2026-11-11

### Breaking change: an invalid `--dir` is now an error

`cbom-scan --dir <path>` used to print an empty BOM and exit `0` when the path
did not exist or was not a directory. A pipeline reads an empty BOM as "this
tree contains no cryptography", so a typo in a path produced a clean, green
result — the exact false negative this tool exists to prevent.

It now exits `2` and writes `--dir not found` (or `not a directory`) to stderr.
Callers that relied on the old behaviour must either fix the path or treat `2`
as "the scan did not happen", not as "nothing found".

```diff
-  # exit 0, components: []
-  npx cbom-tools scan --dir ./typo-path --out cbom.json
+  # exit 2, stderr: --dir not found: ./typo-path
+  npx cbom-tools scan --dir ./typo-path --out cbom.json
```

### Added

- Names assembled out of literals are resolved before matching: adjacent
  concatenation (`'sha' + '256'`), array joins (`['ml','-kem'].join('')`),
  template interpolation (`` `ml-kem-${'768'}` ``), `Buffer.from(..., 'base64')`,
  `atob(...)`, and `\xNN` / `\uNNNN` escapes. Previously all of these were
  invisible, and an invisible algorithm still produces a clean-looking BOM.
- Receiver-agnostic patterns, so `createHash('sha-256')` and
  `createCipheriv('aes-256-gcm', ...)` are caught without hard-coding the API
  object name.
- Test suite: 83 → 122 tests. Ten evasion fixtures (one per hiding technique),
  one explicit negative control for names computed at runtime (asserted **not**
  detected — a static scan cannot see them, and the test says so), CLI
  dispatcher coverage for `cli.cjs`, and fault-tolerance cases.
- Coverage gate in CI: `npm run test:coverage` fails below 90% lines,
  90% functions, 80% branches. Measured: **96.5% lines, 97.4% functions,
  86.6% branches**.

### Changed

- Files larger than 8 MB are skipped with a warning instead of being read into
  memory.
- Unreadable files, unreadable directories and an unparsable `package.json`
  now warn on stderr and let the scan continue; previously the first two could
  abort the walk and the third threw.
- The literal resolver is a hand-written single-pass scanner rather than a set
  of regexes over raw source, so adversarial input cannot trigger backtracking.

### Fixed

- `cbom-diff --format markdown` printed `undefined` for a property absent on
  one side; it now prints `<absent>`.

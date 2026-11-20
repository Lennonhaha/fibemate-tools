# falcon-gate

Two questions, one exit code.

```bash
node falcon/falcon-gate.cjs --cbom-dir cbom-tools
node falcon/falcon-gate.cjs --cbom-dir . --docs docs --artifacts artifacts
```

| stage | tool | question | goes red when |
| --- | --- | --- | --- |
| `assets` | `cbom-tools scan` | does this tree actually contain cryptographic assets? | nothing was found, or fewer than `--min-assets` |
| `claims` | `verifact verify` | do the numbers a document claims match the artefacts? | any drift, or a claim the policy rejects |

Exit codes: `0` both passed, `1` a stage failed, `2` usage error.

## Why a chain, and not a new analyser

`falcon-gate` makes no judgement of its own. `cbom-tools` decides what is
cryptography in the tree; `verifact` decides whether prose agrees with
artefacts. The gate only decides what "both said yes" means — and it refuses to
let a stage that could not run count as a pass. A missing tool, a crashed
scanner, an unreadable BOM: all of those are `error`, and `error` is red.

The failure mode this is written against is the one that shows up in supply-chain
dashboards everywhere: a check that stops running and keeps reporting green.
Pointing it at an empty directory is therefore a supported use case, and the
answer is `1`.

`claims` has a second, quieter version of the same problem. A document with no
numeric claims produces an empty check. That passes by default — prose is
allowed to be prose — but it says `empty check, not a clean one`, and
`--require-claims` turns it into a failure for trees where numbers are expected.

## What this is not

- **Not a side-channel analysis.** Nothing here measures timing, power, or
  memory access. The name is the project's, not a claim about the Falcon
  signature scheme.
- **Not a compliance verdict.** For the 密评-oriented view of the same
  inventory, use `cbom-tools compliance --bom cbom.json --out report.md`. It
  states what it did not assess instead of scoring.
- **Not a replacement for either tool.** Anything it reports, the underlying
  tool reports with more detail; run those directly when you need to know why.

## CI

```yaml
- name: Gate must pass on this tree
  run: node falcon/falcon-gate.cjs --cbom-dir cbom-tools --min-assets 10 --require-source-evidence
- name: Gate must go red on an empty tree
  run: |
    set +e
    node falcon/falcon-gate.cjs --cbom-dir "$RUNNER_TEMP/empty"
    code=$?
    set -e
    [ "$code" -eq 1 ] || { echo "expected 1, got $code"; exit 1; }
```

Both invocations belong in CI. A gate that is only ever seen passing has not
been tested.

`--require-source-evidence` fails when every asset is manifest-only — a
dependency in `package.json` that no call site uses. Presence of a library is
not use of it.

## Tests

```bash
node --test falcon/test/falcon-gate.test.cjs
```

Ten cases, weighted towards the failures: empty tree, missing tool, drift
artefacts, zero claims, usage errors, and the process-level exit codes.

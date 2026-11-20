# falcon-gate

Two questions, one exit code.

```bash
node falcon/falcon-gate.cjs --cbom-dir cbom-tools --strict
node falcon/falcon-gate.cjs --cbom-dir . --docs docs --artifacts artifacts --strict
```

| stage | tool | question | goes red when |
| --- | --- | --- | --- |
| `assets` | `cbom-tools scan` | does this tree actually contain cryptographic assets? | nothing was found, or fewer than `--min-assets` |
| `claims` | `verifact verify` | do the numbers a document claims match the artefacts? | any drift, or a claim the policy rejects |

Exit codes: `0` nothing blocking, `1` something blocked or could not run, `2` usage error.

## Two modes, and why the default is the quiet one

| | finding (drift, short scan, timeout) | error (missing tool, crash, unreadable output) |
| --- | --- | --- |
| `--safe` (default) | warning, exit 0 | **blocking, exit 1** |
| `--strict` | blocking, exit 1 | **blocking, exit 1** |

A finding means the tools ran and told you something. An error means they did
not run — and no mode may call that green, because "the check stopped working"
is the one failure that looks exactly like success. That asymmetry is the whole
design.

Safe mode exists because a gate that blocks on day one gets removed on day two.
It prints `PASS WITH WARNINGS` and then says, in the output, that a green run
here is a report rather than evidence. If you are wiring this into a merge
requirement, use `--strict`; if you are pointing it at an unfamiliar tree to see
what it says, use the default.

`--timeout <seconds>` (default 300) bounds each stage. A scan that never returns
is a timeout, not a pass, and it is reported as such — long-running checks that
quietly disappear are how a nightly job stays red for a week without anyone
noticing.

## Why a chain, and not a new analyser

`falcon-gate` makes no judgement of its own. `cbom-tools` decides what is
cryptography in the tree; `verifact` decides whether prose agrees with
artefacts. The gate only decides what "both said yes" means — and it refuses to
let a stage that could not run count as a pass.

Pointing it at an empty directory is therefore a supported use case, and in
strict mode the answer is `1`.

`claims` has a second, quieter version of the same problem. A document with no
numeric claims produces an empty check. That is advisory rather than a pass — it
says `empty check, not a clean one` — and `--require-claims` turns it into a
failure for trees where numbers are expected. Prose is still allowed to be prose,
so this stays advisory even under `--strict`; `--require-claims` is the flag that
says "here, numbers are the point".

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
  run: node falcon/falcon-gate.cjs --cbom-dir cbom-tools --min-assets 10 --require-source-evidence --strict
- name: Gate must go red on an empty tree
  run: |
    set +e
    node falcon/falcon-gate.cjs --cbom-dir "$RUNNER_TEMP/empty" --strict
    code=$?
    set -e
    [ "$code" -eq 1 ] || { echo "expected 1, got $code"; exit 1; }
```

Both invocations belong in CI. A gate that is only ever seen passing has not
been tested. The workflow that ships with this repository runs four: pass,
empty-tree red, drift red, and safe-mode-warns-without-blocking.

`--require-source-evidence` fails when every asset is manifest-only — a
dependency in `package.json` that no call site uses. Presence of a library is
not use of it.

## Tests

```bash
node --test falcon/test/falcon-gate.test.cjs
```

Twelve cases, weighted towards the failures: empty tree, missing tool, a tool
that never returns, drift artefacts, zero claims, the mode difference, and the
process-level exit codes.

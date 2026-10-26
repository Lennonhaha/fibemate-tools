# Gate corpus

`test/fixtures` is what the unit suite uses; this directory is what the **gate**
uses. The distinction is the whole point of #111: for a window in `main`, every
real `verify` run aborted during parsing while CI stayed green, because CI only
ever scanned the fixtures.

## Contents

- `docs/status.md` — ordinary claims, each backed by `artifacts/metrics.json`.
  The baseline must stay clean (`drift: 0`).
- `docs/parser-shapes.md` — the three shapes that broke the parser in #109, kept
  as permanent regression material: a `verifact:` directive inside a fenced code
  block, the same directive inside inline code, and an unterminated fence at end
  of file. None of them is a live declaration.

## Rules

1. Every number in `docs/` must resolve to a key in `artifacts/`. If you change
   one side, change the other in the same commit.
2. `ci.yml` fails when the scanned document count is zero. "Nothing scanned" is
   not a pass.
3. The second CI step mutates `99.1%` to `97.3%` in a copy and asserts the gate
   exits 1 with `drift >= 1`. A gate that cannot be made to fail proves nothing;
   if that step ever passes without drift, the gate has rotted.

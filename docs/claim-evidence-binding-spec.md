# Claim–evidence binding spec (skeleton)

Status: **skeleton, not normative.** Written 2026-10-29 to park the idea; sections are
placeholders with the decisions that still have to be made. Do not implement against this yet.

Scope: how a written claim (a number, a count, a "PASS") binds to the artifact that produced
it, and how that binding is sealed so a later reader can tell "this was true at commit X"
from "someone edited the sentence".

Related: `verifact/` (the checker), RFC `docs/rfc-verifact-dispositions.md`, TSR practice in
`fibemate/docs/tsa/**`.

---

## 1. Claim format

What has to be decided:

- What is the unit of a claim — a key/value/unit triple plus a scope (file, commit, run id)?
  Today `extractClaims` works heuristically over Markdown, fence-aware, which is fine for
  finding claims but cannot state scope.
- Do we introduce an explicit syntax (inline annotation or a sidecar claims file) for claims
  that must be bound, and leave heuristics for prose that does not?
- How does a claim express its own **scope** so that "24/24 passed" is not compared against a
  different suite that also happens to total 24?
- What makes a claim **retractable** — a way to say "this was true, no longer is" that is not
  simply deleting the sentence (deleting is destroying evidence).

Not to be decided here: the extraction heuristics themselves (see `verifact/src/core/claims.js`).

## 2. Binding mechanism

Working assumptions from the existing evidence work, to be tightened:

- Digests are taken from committed bytes (`git cat-file blob <commit>:<path>`), never from the
  working tree, because `.gitattributes` filters can change what lands in the repository.
- A digest list plus a timestamp token (TSR) seals the list; the list plus the public commit
  seals the artifacts. The chain proves **what was published when**, not that it is correct.
- The `commit` field inside a generated artifact must name the run that produced it, not the
  commit that happens to be HEAD when someone re-seals it.

Open:

- Manifest format and ordering (stable sort by path? include tool version, node/python version,
  seed, and fixture digest?).
- Re-sealing rules: when an artifact changes, the old token is void — does the manifest get a
  new file, or a new generation number?
- Verification command that a third party can run without our repo (what is the minimum set of
  inputs: manifest, TSR, public commit, and the token's CA chain?).

## 3. Six-state verdict extension

Current verdicts, from `verifact/src/core/resolve.js`: `verified`, `drift`, `ambiguous`,
`unbound`, `ref-found`, `ref-missing`. The tool's standing rule is that incomparable things are
never judged (no false drift).

Questions for the extension:

- Is "artifact is bound and matches, but the artifact is superseded by a later run" a state of
  its own, or a property of the claim (stale) rather than a verdict?
- Where does "evidence exists but the claim's scope cannot be established" land — `ambiguous`,
  or a new `unscoped`?
- Does any new state enter the gate? Default stays `--fail-on drift`; new states should be
  reported, not gated, until they have a track record.
- Coverage reporting must keep printing both denominators (the existing rule), otherwise a new
  state silently changes what "coverage" means.

---

## Next steps (when there is time)

1. Decide §1's explicit syntax, or decide to stay heuristic-only and drop the binding ambition.
2. Write one end-to-end example on a real artifact pair (manifest → TSR → verify) and see which
   of §3's questions the example actually forces.
3. Only then turn this file into a normative spec.

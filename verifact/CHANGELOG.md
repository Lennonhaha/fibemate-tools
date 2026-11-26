# verifact changelog

## Unreleased

- Stops binding a dimensioned measurement to a unitless number unless the unitless
  side's own key names that unit. `168.2 ms` in a deploy record was resolving to
  `max_score = 100` (a CARS ceiling, not a latency) at score 0.475, just over the
  0.45 floor, and was reported as a drift. The old guard only rejected "unitless
  integer <= 50", which any score out of 100 walks past. A key that does name the unit
  (`latency.p95_ms`, `keygen.avgMs`) still compares as before.
- Stops the key context from reaching across a clause boundary. `;` and a
  non-decimal `.` end the window, so `p95 156.1 ms, max 168.2 ms; ten-run timing ...`
  no longer produces a key containing `ten` (or `pre`/`deploy` from the next
  sentence). Decimal points and URLs are not boundaries.
- Ignores a one-token artifact entry unless the claim's own primary token is one of
  them. `overlapCoefficient` divides by the shorter side, so a single-token entry
  scored a perfect overlap against any claim mentioning that word: a `tvla ... 31/36`
  claim was being diffed against `forbidden-literals.txt#tvla = 36/36`. Found while
  fixing the clause window, not a regression of it - the junk tokens had been holding
  the score under the threshold by accident.
- Effect on the fibemate corpus: drift 2 -> 0, verified 108 -> 109, ambiguous 140 -> 142.

- Adds the `pendingArtifact` config list. A claim that matches it stays `unbound` and
  keeps its score, but its `reason` becomes `pending_artifact` and its note says what is
  missing, so "no artefact exists yet" stops being indistinguishable from "nobody looked".
  The rule only ever relabels `unbound` / `ambiguous` results: a claim that resolved to
  `drift` or `verified` is untouched, and the unbound denominator does not shrink.
  `counts.pendingArtifact` carries the tally. Covered by two regression tests, one of which
  asserts that a rule pointed at a real drift changes nothing.
- Excludes record-shaped trees from the document scan: `docs/audit-log/**`, `www/**`
  (the published mirror), `p0_evidence_*/**`, `security-assessment/**`, `archives/**` and
  the `fpga-l8l9-43-tests_*.md` dump. These hold dated snapshots and copies, not claims
  about current code, so counting them as unverified claims only diluted the signal.
  Patterns are root-relative because `docs.exclude` is matched against each root's
  relative path.

## 0.2.5

Release process only; scanner behaviour and output are unchanged from `0.2.5-rc.1`.

- Releases are now produced **only** by pushing a `verifact-v<version>` tag. The
  `workflow_dispatch` path is a rehearsal: it checks out the tag you name, builds,
  tests, signs and verifies the tarball, and stops before the registry. There is no
  longer an input that can make a manual run publish.
- Fixes the provenance record for future releases. `0.2.4` was published from `main`,
  so its provenance says `refs/heads/main` while the tag points at another commit: the
  tarball content matches, but the release does not prove it came from the tag. That
  record cannot be repaired after the fact, which is why the fix is in this version and
  the historical entry stays marked as failed in the audit table.

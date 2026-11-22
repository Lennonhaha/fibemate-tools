# verifact changelog

## Unreleased

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

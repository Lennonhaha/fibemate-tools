# Release audit

Read-only checks for npm packages published from this repo: does the tarball on the
registry match its tag, its provenance, and its signed release assets?

It answers one question per published version: **can a third party verify that this
tarball came from this commit, without trusting the uploader?**

## Tools

```
verify-one.cjs   one package@version, full field set, one JSON line on stdout
enumerate.cjs    package x version matrix from tags + package.json + the registry
summarize.cjs    results/*.json -> audit.md table + counts + FAIL/WARN lists
lib/classify.cjs pure grading (verdict + level), no I/O
```

## Usage

```bash
# 1. matrix: what exists on the registry, and what has a tag
node scripts/release-audit/enumerate.cjs \
  --git-dir . --scan . \
  --packages cbom-tools,verifact,fibemate-xdiff \
  --out matrix.json

# 2. one package, latest version
node scripts/release-audit/verify-one.cjs cbom-tools 0.2.9 \
  --git-dir . --pkg-dir cbom-tools --out results/cbom-tools@0.2.9.json

# 3. historical versions: they are not supposed to be `latest`
node scripts/release-audit/verify-one.cjs cbom-tools 0.2.7 \
  --git-dir . --pkg-dir cbom-tools --ignore-latest \
  --out results/cbom-tools@0.2.7.json

# 4. table
node scripts/release-audit/summarize.cjs --dir results --out audit.md
```

`GITHUB_TOKEN` is optional; without it the GitHub API is rate-limited and Release
checks degrade to `UNKNOWN` (which is never treated as a pass).

## Reading the output

Two independent axes:

- **verdict** — `PASS` / `FAIL` / `UNKNOWN`. `UNKNOWN` means "could not check",
  which is not a pass.
- **level** — how the chain is held together:
  - `A`: provenance + cosign signature + `SHA256SUMS` + `provenance ref == tag ref`
  - `B`: evidence complete, but the ref is a branch, or the tag is lightweight, or
    the tag commit has no DCO sign-off
  - `C`: no provenance
  - `D`: tag↔commit unresolvable, or the registry and the tag are missing one side

So `B + FAIL` reads as "the bytes are signed and hashed correctly, but the artifact
was not built from the tag" — a process failure, not a file-integrity failure.

A content-equivalence note (`tag_is_ancestor_of_built` + `pkg_dir_diff_empty`) is
recorded for branch builds, but it never changes the verdict or the level. Accepting
"content is the same" as a pass would let any branch-triggered release through.

### Exit codes

| code | meaning |
|---|---|
| `0` | a verdict was reached (`PASS` or `UNKNOWN`) |
| `1` | `FAIL` — the chain does not hold |
| `2` | usage error |
| `3` | the tool could not answer (currently: the tag lookup failed), so the verdict is only provisional |

`3` exists because `1` means "the release is bad" and "git would not tell me" is not
that. A CI step that treats any non-zero exit as a release failure will misreport the
second case; check for `3` explicitly.

## Tests

```bash
node --test scripts/release-audit/test/classify.test.cjs   # offline, runs in CI
node --test scripts/release-audit/test/git-tag.test.cjs    # offline, runs in CI
AUDIT_LIVE=1 node --test scripts/release-audit/test/live.test.cjs
```

The offline tests are the real gate. `classify.test.cjs` feeds a captured
`cbom-tools@0.2.9` record and mutates it into each failure shape (branch ref, no
provenance, no tag, wrong tag commit, hash mismatch, unknown) and asserts the verdict
and level. `git-tag.test.cjs` provokes the three answers git can give - present,
absent, could-not-look - against a real repository, a temporary non-repository and a
path that does not exist, and asserts that a failed lookup never becomes
"the tag is missing". The live test only proves that the network path still works
today.

## Notes

Field-level history, the three bugs this tool had, and the batch results are in
[`NOTES.md`](./NOTES.md).

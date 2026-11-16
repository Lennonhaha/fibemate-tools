# Release discipline

Lessons that cost us a bad release, a red gate, or an hour of doubt. Every entry
names the case that produced it, so a future reader can check the claim instead
of trusting this file.

Scope: anything that ends in a tarball on a registry, a binary on a release page,
or a signature someone else is asked to verify.

## 1. The checkout must follow the tag, and only a tag push may publish

Root cause of the two releases whose provenance pointed at a branch
(`verifact@0.2.4`, `crypto-hallucination-detector@0.1.2`): `actions/checkout`
had no `ref:`, so a manual run built the branch it was started from — `main` —
while the release was named after a tag. The tarball matched the tag, but the
record of how it was built did not. Evidence and artifact were disconnected.

Two locks, both required:

```yaml
- uses: actions/checkout@<pinned sha>
  with:
    ref: ${{ github.event.inputs.tag || github.ref }}
```

```bash
if [ "${{ github.event_name }}" != "push" ] || [ "${GITHUB_REF#refs/tags/}" = "$GITHUB_REF" ]; then
  echo "refusing to publish: releases only come from a tag push" >&2
  exit 2
fi
```

A `workflow_dispatch` boolean that "defaults to safe" is not a lock. It is a
switch, and someone will flip it. Delete the input; derive rehearsal from the
event, so there is nothing to flip. `workflow_dispatch` stays for building,
testing, signing and verifying.

## 2. A gate must be killable by its own failure input

A gate that cannot go red is decoration. Two cases, same lesson:

- The release contract test asserted "dispatch exposes `dry_run`, default true",
  which encoded the *unsafe* design. When the workflow was fixed, the gate went
  red — correct behaviour, wrong invariant. The invariant had to be replaced,
  not the workflow.
- The replacement was written as a loose regex, and a mutation that swapped the
  derivation (`push -> true`) still matched it, because a `DRY="false"` remained
  somewhere in the file. **The sabotage test is what caught the weak assertion**,
  not review. Match the whole derivation, or do not claim to test it.

Corollary: every new assertion ships with the mutation that should break it. If
you cannot name an input that turns it red, it is a comment with `assert()`.

## 3. A suite full of SKIPs proves nothing

The mutation suite reported `SKIP` when a mutation no longer applied. One had
been skipping silently for months: it replaced a pinned action SHA that the
workflow no longer used. The suite still printed a green summary.

A mutation that does not apply is drift: the test no longer tests what it claims.
Treat it as failure. `12/12 detected, 0 skipped` is a result; `9/12 detected, 3
skipped` is a rumour.

## 4. Check the name on the registry before you tag

`xdiff/` publishes as `fibemate-xdiff`; `hallucination-detector/` publishes as
`crypto-hallucination-detector`. The bare names belong to other people
(`dominictarr/xdiff`, and for `entry` / `exit` / `middle` / `sample-project`,
four unrelated maintainers). A first audit pass produced a FAIL against someone
else's package because the tag prefix was used as the npm name.

Before tagging: `npm view <name> name maintainers` and confirm it is ours. The
package name comes from `package.json`, never from the directory or the tag
prefix. Local manifests whose names are already taken get `"private": true` so
they cannot be published by accident.

## 5. Not-required checks still have to be green

`CodeQL` is not in this repository's required status checks, so a CodeQL failure
shows up as `mergeStateStatus: UNSTABLE` — mergeable, and easy to wave through.
That is how two `js/incomplete-sanitization` alerts (`replace('/', '%2F')`
replacing only the first slash) nearly shipped in the release-audit tooling.

`UNSTABLE` means "the ruleset will not stop you". It does not mean "nothing is
wrong". Read the failing check before merging; a required-check list is a floor,
not a standard.

## 6. A registry 404 is not proof that a publish failed

After a successful `npm publish`, the packument and tarball URLs can keep
returning 404 from an edge cache — including a cached *negative* response, which
a plain retry never clears. Meanwhile the run log says `+ pkg@version` and the
attestation endpoint already answers:

```bash
curl -sI https://registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz                        # may 404
curl -s  https://registry.npmjs.org/<pkg>/<version>?cb=$(date +%s)                     # cache-busted
curl -s  https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>              # 200 = it landed
```

Decide with the attestation endpoint and a cache-busted fetch, not with the
first 404. The inverse also holds: a green publish step plus a 404 is not a
reason to re-publish — the second publish fails as a duplicate version and tells
you nothing.

## 7. Hash the bytes, not the decoded string

Verifying a tarball digest by accumulating the response as a string and then
`Buffer.from(body, 'binary')` produces a wrong-but-plausible hash: the utf8
decode has already destroyed the bytes. Same byte count, different digest.

Collect chunks and `Buffer.concat(chunks)`. Then compare `sha1` against
`dist.shasum` and the `sha512-` SRI against `dist.integrity`. If the two differ
from the registry's own numbers, suspect the reader before the publisher.

## Checking a release, in order

1. `npm view <name> name` — is this our package?
2. `dist-tags.latest` — did the intended version become `latest`?
3. sha1 / sha512 recomputed from the tarball — match `dist.shasum` / `dist.integrity`?
4. Provenance — `workflow_ref` is `refs/tags/<tag>`, and `gitCommit` equals the tag commit.
5. Release assets — `SHA256SUMS` covers the same tarball; `.sig` and `.pem` present.
6. Tag — annotated, and `tag_commit == provenance gitCommit`.

Steps 3–6 are what `scripts/release-audit/verify-one.cjs` automates; run it
rather than eyeballing the UI, and keep the JSON record with the release.

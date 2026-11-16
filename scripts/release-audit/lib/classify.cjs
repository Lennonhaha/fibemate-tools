'use strict';
// Pure verdict/level grading for a release-audit record.
//
// No network, no filesystem, no clock: the caller fills a record, this decides.
// Keeping it pure is what makes the gate testable offline -- a gate that can only
// be exercised against live npm/GitHub is a gate nobody can prove is able to fail.
//
// Record fields consumed (see verify-one.cjs for how they are filled):
//   registry_exists, latest_matches, sha1_match, sha512_match,
//   provenance, workflow_path, workflow_ref, tag, subject_match, prov_commit_match,
//   sha256sums, sha256_match, cosign_sig, cosign_pem,
//   tag_exists, tag_type, tag_commit_match, dco,
//   tag_is_ancestor_of_built, pkg_dir_diff_empty
//
// opts.tagExplicit says whether the caller named the tag itself. A tag that was
// derived from the package name and does not exist may simply mean the tag prefix
// differs from the package name (`hallucination-detector-v0.1.3` publishes as
// `crypto-hallucination-detector`), which is not a release defect. That case is
// UNKNOWN with no level; only an explicitly named missing tag is FAIL / D.
//
// Level grades evidence strength and process compliance; verdict grades whether the
// chain checks out. They are deliberately independent: B + FAIL means "evidence is
// complete, but the artifact was not built from the tag", which is not the same
// finding as C + FAIL ("there is no provenance at all").

const TAG_REF = (rec) => `refs/tags/${rec.tag}`;

function classify(rec, opts = {}) {
  const fail = [];
  const warn = [];
  const unknown = [];
  const notes = [];
  const need = (cond, label) => {
    if (cond === false) fail.push(label);
    else if (cond == null) unknown.push(label);
  };
  // A missing tag that nobody named may be a naming mismatch, not a missing release.
  const tagUnknown = rec.tag_exists === false && !opts.tagExplicit;

  need(rec.registry_exists, 'registry exists');
  if (!opts.ignoreLatest) need(rec.latest_matches, 'latest matches');
  need(rec.sha1_match, 'sha1 match');
  need(rec.sha512_match, 'sha512 match');
  need(rec.provenance, 'provenance');
  if (rec.provenance) {
    need(!!rec.workflow_path, 'workflow.path');
    need(rec.subject_match, 'provenance subject matches integrity');
    if (tagUnknown) {
      // Comparing against a tag we could not find would manufacture a failure.
      unknown.push(`provenance ref matches tag (tag ${rec.tag} not found)`);
      unknown.push('provenance gitCommit matches tag commit (tag not found)');
    } else {
      need(rec.workflow_ref === TAG_REF(rec), 'provenance ref matches tag');
      need(rec.prov_commit_match, 'provenance gitCommit matches tag commit');
    }
  }
  if (rec.sha256sums) need(rec.sha256_match, 'SHA256SUMS matches tarball');
  else warn.push('SHA256SUMS asset missing');
  if (!rec.cosign_sig) warn.push('cosign .sig missing');
  if (!rec.cosign_pem) warn.push('cosign .pem missing');
  if (tagUnknown) {
    unknown.push(`default tag ${rec.tag} not found; pass --tag explicitly if the tag prefix differs from the package name`);
  } else {
    need(rec.tag_exists, 'tag exists');
  }
  if (rec.tag_exists) {
    if (rec.tag_type === 'lightweight') warn.push('tag is lightweight (not annotated)');
    if (rec.tag_commit_match === false) fail.push('tag commit vs Release target');
    else if (rec.tag_commit_match == null) warn.push('tag commit vs Release target not comparable (branch name)');
    if (rec.dco === false) warn.push('no DCO sign-off on tag commit');
  }

  // Evidence only. A content-equivalent build does not make the release compliant,
  // so this never changes the verdict or the level; it stops a reader from having
  // to guess whether "built from a branch" also means "different bytes".
  if (rec.prov_commit_match === false) {
    if (rec.tag_is_ancestor_of_built && rec.pkg_dir_diff_empty) {
      notes.push('NOTE: built from a branch after the tag; package dir identical between tag and build commit (process mismatch, content equivalent)');
    } else if (rec.tag_is_ancestor_of_built === false) {
      notes.push('NOTE: tag commit is not an ancestor of the build commit - content cannot be assumed equivalent');
    }
  }

  const verdict = fail.length ? 'FAIL' : (unknown.length ? 'UNKNOWN' : 'PASS');

  const refIsTag = !!(rec.provenance && rec.workflow_ref === TAG_REF(rec));
  let level;
  if (!rec.registry_exists) level = 'D';
  else if (tagUnknown) level = null; // cannot grade a release whose tag name we never resolved
  else if (!rec.tag_exists || rec.tag_commit_match === false) level = 'D';
  else if (!rec.provenance) level = 'C';
  else if (!refIsTag || !rec.cosign_sig || !rec.sha256sums || rec.tag_type === 'lightweight' || rec.dco === false) level = 'B';
  else level = 'A';

  return {
    verdict,
    level,
    reasons: [
      ...notes,
      ...fail.map(x => `FAIL: ${x}`),
      ...warn.map(x => `WARN: ${x}`),
      ...unknown.map(x => `UNKNOWN: ${x}`),
    ],
  };
}

module.exports = { classify };

# verifact changelog

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

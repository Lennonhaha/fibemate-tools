# crypto-hallucination-detector changelog

## 0.1.3

Release process only; detection behaviour is unchanged from `0.1.3-rc.1`.

- Releases are now produced **only** by pushing a `hallucination-detector-v<version>`
  tag. `workflow_dispatch` is a rehearsal and cannot publish.
- Fixes the provenance record for future releases. `0.1.2` was published from `main`,
  so its provenance says `refs/heads/main` while the tag points at another commit.
  Content matched, evidence did not. `0.1.2` stays marked as failed in the audit table;
  a published provenance record cannot be rewritten.

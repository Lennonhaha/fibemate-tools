# Contributing

Small tool, small rules.

1. **Open an issue before a PR** for anything larger than a typo. It saves you writing code that gets declined.
2. **Run the tests**: `npm test` (185 tests). Coverage gate: `npm run test:coverage` (90% lines/functions, 80% branches).
3. **Sign off every commit**: `git commit -s`. The DCO check is a merge gate; a commit without `Signed-off-by:` fails it.
4. **No runtime dependencies.** `dependencies` stays empty. A scanner that ships a supply chain is a poor advertisement for supply-chain hygiene.
5. **No network calls, no telemetry.** If a change needs to reach the network, it does not belong in this package.
6. **New behaviour needs a test that can fail.** A test that passes when the feature is removed is decoration - pair masking, filtering and gating checks with a control run.
7. **Say what it cannot do.** Every verdict, report section or flag that has a blind spot should name it in the same place a reader meets the claim.
8. **Language**: code, comments and commit messages in English; the generated report is Chinese by design.

Questions: open an issue. Security reports: see `SECURITY.md` at the repository root.

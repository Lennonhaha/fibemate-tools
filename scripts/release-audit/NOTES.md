# Release audit — notes and corrections (2026-11-16)

## Tool corrections found while running it

1. **`enumerate.cjs` used the tag prefix as the npm package name.** Wrong for two packages
   here: `xdiff/` publishes as **`fibemate-xdiff`**, `hallucination-detector/` publishes as
   **`crypto-hallucination-detector`**. The bare name `xdiff` on npm belongs to
   `dominictarr/xdiff` ("calc diffs of complex javascript objects", maintainer
   `nopersonsmodules`), so the naive lookup produced a confident FAIL against **someone
   else's package**. The matrix is now built from each `package.json` `name`, with the tag
   prefix kept separately as `tagPrefix`.
2. **`verify-one.cjs` could not download `SHA256SUMS`.** `browser_download_url` 302s to
   `objects.githubusercontent.com`, which this host cannot always reach, so the gate
   reported UNKNOWN for releases that are fine. It now streams the same bytes through
   `GET /releases/assets/<id>` with `Accept: application/octet-stream` and an optional token.
3. **`verify-prov.cjs` had a dead ternary** (`bd.buildDefinition && bd.buildDefinition ? '' : ''`,
   both branches empty) plus two lines reading `externalParameters.source`, a field the
   GitHub SLSA v1 buildtype does not emit. Replaced by `runDetails.builder.id` and
   `resolvedDependencies[0].digest.gitCommit`. `verify-prov.cjs` itself is superseded by
   `verify-one.cjs` and kept only as scratch.

## Naming / repository facts confirmed by this audit

| directory | npm name | registry | note |
|---|---|---|---|
| `cbom-tools/` | `cbom-tools` | 13 versions, latest 0.2.9 | full chain |
| `verifact/` | `verifact` | 7 versions, latest 0.2.4 | published from `main`, see below |
| `xdiff/` | `fibemate-xdiff` | 3 versions, latest 0.1.0 | bare `xdiff` is not ours |
| `hallucination-detector/` | `crypto-hallucination-detector` | 4 versions, latest 0.1.2 | published from `main`, see below |
| `crypto-time-ledger/` | `crypto-time-ledger` | not published | `private: true`, expected |
| — | `crypto-time-machine` | not published | tags `v0.1.1`, `v0.1.2` remain, no package dir |
| — | `undecryptable-prover` | not published | tag `v0.1.0` remains, no package dir |
| `fibemate-core` (separate repo `Lennonhaha/fibemate-core`) | `fibemate-core` | 2 versions, latest 0.1.0 | tag `v0.1.0` lives in that repo |
| `fibemate` monorepo | `fml-dsa` | 2 versions, latest 0.1.0 | tag `v0.1.0-fml-dsa` |
| `fibemate` monorepo | `pqc-kem` | tag `pqc-kem-v0.1.0` exists, not audited yet | next batch |

## The two FAILs are the same shape

Both `verifact@0.2.4` and `crypto-hallucination-detector@0.1.2` were published with
`workflow_dispatch` from `refs/heads/main`, two hours and one day after their tag:

| | tag commit | built from | tag ancestor of built | package dir diff |
|---|---|---|---|---|
| `verifact@0.2.4` | `e607ee6` | `main@bdeddaa` | yes | empty |
| `crypto-hallucination-detector@0.1.2` | `5716bfa` | `main@d1ffb4c` | yes | empty |

So the tarball integrity is fine (sha1/sha512/subject all match) and the **package source is
byte-identical to the tagged commit**, but provenance points at a branch, which is exactly
what the two gates are supposed to catch: from the artifact alone you cannot prove it came
from the tag. The tool keeps the verdict **FAIL** and records `tag_is_ancestor_of_built` +
`pkg_dir_diff_empty` as evidence, so the mitigation is visible without being able to turn
the gate green.

Fix for future releases: publish from the tag (`cbom-tools` does this), never from
`workflow_dispatch` on a branch.

---

# Batch 2 (2026-11-16, after grading was split from verdict)

`--ignore-latest` is used for historical versions so they are not failed for not being
`latest`; `latest_matches` is then recorded as `null` (not applicable) with the real value
kept in `latest_actual`.

## Grading changed: level describes evidence + process, verdict stays independent

- **A**: provenance + cosign + SHA256SUMS + `provenance ref == tag ref`, all aligned
- **B**: evidence complete (sig/SUMS/tarball hash all match) but ref is a branch, or tag is
  lightweight, or the tag commit has no DCO
- **C**: no provenance
- **D**: tag↔commit unresolvable, or registry and tag missing one side

Consequence: `verifact@0.2.4`, `crypto-hallucination-detector@0.1.2`, `cbom-tools@0.2.6`
move from A+FAIL to **B+FAIL** — evidence complete, process wrong. The verdict does not move.

## Results

18 records: **PASS 6 / FAIL 12**, levels **A 3 / B 6 / C 7 / D 2**.

| group | records | reading |
|---|---|---|
| A + PASS | cbom-tools 0.2.7, 0.2.9; fibemate-xdiff 0.1.0 | full chain |
| B + PASS | cbom-tools 0.2.8（tag commit 无 DCO）; fibemate-core 0.1.0（无 sig/SUMS/DCO）; fml-dsa 0.1.0（无 SUMS） | evidence complete, cosmetic gaps |
| B + FAIL | cbom-tools 0.2.6; verifact 0.2.4; detector 0.1.2 | built from `main` after the tag, package dir identical |
| C + FAIL | cbom-tools 0.1.0, 0.2.0, 0.2.2–0.2.5; fibemate-pqc-kem 0.1.0 | published before OIDC provenance existed |
| D + FAIL | cbom-tools 0.1.1, 0.2.1 | published with **no tag and no release** at all |

**Do not try to repair C/D by re-publishing.** Provenance cannot be back-dated for an
already published version; re-publishing the same version is impossible on npm and
re-publishing under a new version would ship different bytes. C/D are historical records.

Operator facts confirmed here:

- `pqc-kem/` publishes as **`fibemate-pqc-kem`**（tag 前缀 `pqc-kem`），0.1.0 无 provenance。
- `cbom-tools@0.2.8` 的 tag `c787ddd` 无 DCO sign-off（该 commit 是教程提交）。
- `cbom-tools@0.2.5` 的 tag 是 lightweight，不是 annotated。

## Matrix status field

`enumerate.cjs` 现在给每个包一个 `status`：`PRIVATE`（如 `crypto-time-ledger`，不查 registry）、
`ORPHAN_TAG`（`crypto-time-machine` v0.1.1/v0.1.2、`undecryptable-prover` v0.1.0 —— 有 tag、
无包目录、无 registry）。ORPHAN_TAG 不进 FAIL 清单，属待清理的 tag，不是发布缺陷。

## Remaining gap before the tool is committed

入库前仍缺：一条对 `cbom-tools@0.2.9` 的测试（断言 `verdict=PASS`、`builder` 非空、
`subject_match=true`）。路径 `fibemate-tools/scripts/release-audit/`，不进 `cbom-tools` 的
`files` 白名单。

---

# Superseded scripts: field mapping

这些脚本已删/已移出，字段对应关系留在这里，否则以后没人知道为什么这么取字段。

| 旧脚本 | 由谁取代 | 字段映射 / 说明 |
|---|---|---|
| `verify-trio.cjs` | `verify-one.cjs` | `dist_shasum`→`rec.dist_shasum`；`integrity`→`rec.integrity`；现算 → `tarball_sha1` / `tarball_sha512_sri` / `tarball_sha256`；比对 → `sha1_match` / `sha512_match`。新增 `latest_matches`（旧脚本没有） |
| `verify-prov.cjs` | `verify-one.cjs` | `builder`：旧脚本打 `bd.buildDefinition`（恒 undefined，且外面套了个两分支都返回空的三元）→ 现在取 **`predicate.runDetails.builder.id`**；`source repo/digest`：旧脚本读 **`externalParameters.source`，GH 的 SLSA v1 buildtype 根本不发这个字段** → 现在读 **`resolvedDependencies[0].uri` + `.digest.gitCommit`**（`rec.prov_git_commit`）；`workflow.ref/path` 与 `runDetails.metadata.invocationId` 不变 |
| `tmp-inspect.cjs` / `tmp-audit.cjs` / `tmp-evidence.cjs` / `tmp-behavior.cjs` / `tmp-redcheck.cjs` | 0.2.9 字典补全的取证脚本 | 结论已固化进 `algorithm-hierarchy.cjs` + `test/legacy-recall.test.cjs`；`tmp-audit` 里"固定候选参数表"的做法**已废弃**（会产生 SHA3-128、Camellia-l1 之类假组合），现行做法是从规则首个捕获组读备选 |
| `probe-slsa.cjs` / `probe-prov-all.cjs` / `probe-mismatch.cjs` | `verify-one.cjs` 的字段 + 本文的等价性判据 | `probe-slsa` 的字段枚举 → `builder` / `workflow.*` / `resolvedDependencies`；`probe-mismatch` 的 `merge-base --is-ancestor` + `git diff --stat <tag> <built> -- <pkgdir>` → `rec.tag_is_ancestor_of_built` / `rec.pkg_dir_diff_empty` |

## 为什么 `builder` 必须从 `runDetails.builder.id` 取

`buildDefinition` 里没有 builder 字段。GitHub 的 SLSA v1 predicate 把构建者放在
`runDetails.builder.id`（`https://github.com/actions/runner/github-hosted`），把源码放在
`buildDefinition.resolvedDependencies[0]`。按直觉去 `buildDefinition` 下面找，会写出一行
恒为空的输出——这正是第一版 `verify-prov.cjs` 的 bug，也是本工具的第一条教训：
**验证工具自己的输出也要被看一眼**。

## 为什么等价性只做注记、不改判

`tag_is_ancestor_of_built` + `pkg_dir_diff_empty` 能证明"包目录与 tag 逐字节相同"，但
证明不了"这个 tarball 就是从 tag 构建的"——后者只有 provenance 能证明。把等价性当
通过条件，等于允许任何 branch dispatch 混过去，门禁就失效了。所以它只写进 `NOTE:`，
verdict 与 level 都不看它。

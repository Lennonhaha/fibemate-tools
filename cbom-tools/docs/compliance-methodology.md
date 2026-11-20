# Compliance methodology — how `cbom-tools compliance` decides, and what it refuses to decide

- **Status:** methodology note for `cbom-tools` 0.3.x
- **Scope:** `cbom-compliance.cjs` (classification table, the three verdict blocks, the PEM probe)
- **Related:** [ADR-0001 — source confidence](adr-0001-confidence-model.md), `README.md` § *Compliance view*

**中文摘要**

1. 这份文档不是标准、不是测评结论、不是评分表；它把 `compliance` 子命令背后的判定规则逐条写出来，好让读报告的人能审规则，而不是信工具。
2. 三条轴必须分开：**合规轴**（是否为商用密码算法）、**量子轴**（抗量子能力）、**废止轴**（是否已被淘汰）。把量子轴当合规轴用，会得出「SM4 是弱算法」——真话，但没用。
3. 三类判定的依据分别是：算法名到策略表的映射（3.1）、PEM 私钥块的高精度正则（3.2）、以及**明确承认看不到**数据流（3.3 恒为 `无法判定`）。
4. `无法判定` 不是客气的通过。凡是本工具没有采集到的东西，报告都写「没看」，不写「没问题」。

---

## 1. What this document is, and is not

When a report says `建议整改`, a reader is entitled to ask *by what rule*. This document answers that, in the same order the report uses, so the rule can be checked against the code and against the standard rather than taken on trust.

It is **not**:

- a restatement of GB/T 39786-2021 — the standard is the authority, this is one tool's reading of the part of it that concerns algorithm names;
- an assessment result — no score, no level, no pass/fail for an information system;
- a certification path — 商用密码应用安全性评估 is performed by qualified assessment bodies, not by a scanner.

## 2. Three axes that must not be collapsed

| axis | question it answers | where the answer comes from | what breaks if it is collapsed |
| --- | --- | --- | --- |
| **合规 (approval)** | is this an algorithm the regulation accepts? | the approval set: SM2 / SM3 / SM4 / SM9 / ZUC | RSA "passes" because it is not broken; AES "fails" because it is not 国密 — both wrong |
| **量子 (post-quantum)** | does it survive a quantum adversary? | `quantumSecurity` in `algo-metadata.json` | `SM3`/`SM4` reported as 弱算法, which is true on the Grover axis and useless as a compliance finding |
| **废止 (deprecation)** | has the algorithm been retired? | `certificationLevel: deprecated` in metadata, plus a small hard-coded set | MD5 hidden inside "not approved", diluting a finding that has no discussion space |

The compliance view reads **only** the first and third axes. The post-quantum axis is deliberately not read, for two reasons: it answers a different question, and its labels are coarse — `AES` is labelled `safe` while `SM3`/`SM4` are labelled `weak` under the same Grover argument, which is an inconsistency in the metadata rather than a judgement about either algorithm. Until that axis is resolved on its own terms it must not influence a compliance verdict. (Tracked separately; it does not change any verdict in this report.)

## 3. Block 3.1 — 算法强度 (algorithm strength)

### 3.1.1 Buckets

Every component in the CBOM is placed in exactly one bucket, in this order of precedence:

| # | bucket | rule | why it is a separate bucket |
| --- | --- | --- | --- |
| 1 | `approved` | name is SM2 / SM3 / SM4 / SM9 / ZUC | the only bucket that can lead to `合规` |
| 2 | `construct` | NTT, Double-Ratchet and similar non-algorithm constructs | a construction is not an algorithm; grading it is a category error |
| 3 | `deprecated` | name in the known-broken set (MD5, MD4, RC2, RC4, SHA-1, DES, 3DES, Blowfish, DSA) or metadata says `deprecated` | retired algorithms are a finding on their own axis |
| 4 | `not_approved` | post-quantum family, or metadata exists but the name is not in the approval set | "not 国密" and "broken" are different problems with different fixes |
| 5 | `unknown` | no metadata could be resolved | absence of evidence must be visible, not rounded to `approved` |

Post-quantum families are `not_approved` **by design**. A PQC algorithm is a migration target, not a compliance substitute: the common compliant architecture is 国密 for the regulated path plus PQC for the harvest-now-decrypt-later path, and reporting a PQC name as "approved" would tell a reviewer the opposite of what the standard requires.

### 3.1.2 Verdict table

The verdict is derived from the bucket counts in this fixed order — first match wins:

| condition | verdict | reason |
| --- | --- | --- |
| no components at all | `无法判定` | an empty CBOM means *not found*, not *not used* and not *compliant* |
| `deprecated > 0` | `高风险` | retired algorithms have no acceptable use in a regulated path; replacement precedes any assessment |
| `not_approved > 0` | `建议整改` | no retired algorithms, but non-国密 present: evaluate replacement per scenario |
| `unknown > 0` | `无法判定` | an unclassified algorithm is not a passed one; fill the metadata and re-run |
| otherwise (only `approved`/`construct`) | `合规` | every graded algorithm is 商用密码 — a statement about names only |

### 3.1.3 What `合规` here does not mean

`合规` in this block means **the algorithm names in the inventory are all 商用密码算法**. It says nothing about:

- **parameters** — 1024-bit vs 2048-bit RSA, 128-bit vs 256-bit SM4 mode, curve choice;
- **implementation** — constant-time behaviour, side channels, fault handling;
- **key management** — generation, distribution, storage, rotation, destruction (GB/T 39786-2021 Annex B);
- **protocol correctness** — whether the algorithm is used in a way that actually provides the claimed property.

A report that shows `合规` for 3.1 and `无法判定` for 3.3 is internally consistent: it is a name-level inventory, and it says so.

## 4. Block 3.2 — 硬编码风险 (key material in the tree)

### 4.1 What is detected

Exactly one pattern, applied to text files under the scan root:

```
-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)? PRIVATE KEY)-----
```

Certificates (`BEGIN CERTIFICATE`) are **not** matches: a public certificate in a repository is normal, and flagging it would train readers to ignore the block. Files with a NUL byte in the first 1024 bytes, files over 1 MB, and the usual dependency/build directories (`node_modules`, `dist`, `build`, `coverage`, `.git`, `.cache`) are skipped, matching the scanner's own ignore rules.

### 4.2 Verdict table

| condition | verdict | reason |
| --- | --- | --- |
| `--dir` not given | `无法判定` | the probe did not run; no claim is made either way |
| at least one PEM private-key block | `高风险` | a private key in version control is treated as disclosed; rotate it, then remove it |
| scanned, zero matches | `合规` (PEM blocks only) | the limitation is stated in the sentence, not hidden in a footnote |

### 4.3 Why high precision instead of entropy heuristics

Entropy scanning for "looks like a key" produces a steady stream of false positives — hashes, UUIDs, test fixtures, minified assets. A report read by an assessor survives one wrong finding far worse than it survives a missing one, because the missing one is covered by the explicit "not assessed" table while the wrong one discredits every other line. Key material outside PEM blocks is therefore listed as **not assessed**, not guessed at:

- hex / base64 key material assigned in code;
- `.env` files, CI variables, config maps, secret managers;
- keys derived at runtime from a passphrase;
- keys inside container images or build artefacts that never enter the repository.

These need a dedicated secret scanner with its own false-positive budget. When that exists, it belongs as a separate block with its own verdict — not folded into this one.

## 5. Block 3.3 — 加密存储边界 (storage boundary): always `无法判定`

This block has one verdict and no conditions. A CBOM records *which algorithm appears where in the tree*. It does not record:

- which data is sensitive and under which classification;
- which fields land on disk, in a cache, in a log, in a backup;
- whether ciphertext and key material are separated, and by which control;
- which links carry the data, and whether encryption terminates where it should.

Answering "is the data that should be encrypted actually encrypted" requires a data classification, a storage inventory and a link inventory — none of which this tool collects. Returning `无法判定` is the honest output; returning `合规` because "SM4 is present" would be a fabricated conclusion with a real signature on it. The report states what evidence would be required, so the gap is actionable rather than decorative.

## 6. The four verdict words

| verdict | means | does not mean |
| --- | --- | --- |
| `合规` | within this block's scope, nothing contradicting the requirement was found | the system is compliant |
| `建议整改` | a non-国密 algorithm is present; replacement is usually feasible | the system is non-compliant (a documented exception may apply) |
| `高风险` | a retired algorithm or disclosed key material is present | the system is compromised today |
| `无法判定` | the tool did not collect what the question needs | the system is fine |

**Why no score.** GB/T 39786-2021 states requirements per level (chapters 6–9) across four technical domains plus management requirements; the same finding carries different weight at level 2 and level 4. A single number would have to hide which requirement was unmet, and a number invites optimizing the number instead of the system. The report therefore lists findings and unmet evidence requirements, and leaves grading to the assessment body.

## 7. Which part of GB/T 39786-2021 is used

The tool reads the standard only for the requirement "cryptographic application shall use algorithms approved by the national cryptographic authority", and for the vocabulary of the four technical domains. The structure it relies on:

- **Chapter 5 — 通用要求**: requirements common to all levels.
- **Chapters 6–9 — 第一级 to 第四级**: level-specific requirements. Each level is organized as `x.1 物理和环境安全`, `x.2 网络和通信安全`, `x.3 设备和计算安全`, `x.4 应用和数据安全`, then `x.5 管理制度`, `x.6 人员管理`, `x.7 建设运行`, `x.8 应急处置`.
- **Annex B — 密钥生存周期管理** (informative): generation, storage, distribution, use, update, destruction.
- **4.1.2** describes the technical requirement dimensions (机密性 / 完整性 / 真实性 / 不可否认性).

What the tool covers: algorithm names appearing in source and manifests, mapped onto the approval set. What it does not cover: everything in `x.5`–`x.8` (management requirements), level differentiation, and any clause-level conformance statement. The report says "不区分等级" for that reason, and no clause number is quoted unless it has been checked against the published text.

## 8. Evidence semantics

- **Occurrence counts are evidence counts, not call sites.** Occurrences are de-duplicated by `(file, line, symbol)` and capped per algorithm (50); when the cap is hit the report prints `≥N` rather than a number that looks exact.
- **`confidence` describes how a name was found**, not how sure the tool is about parameters: `0.9` = seen in source, `0.7` = seen only in a manifest (see ADR-0001). A manifest-only component is a weaker claim about *use*, not about *identity*.
- **Reproducibility**: `SOURCE_DATE_EPOCH` fixes the timestamp so two runs on the same tree produce byte-identical output; a report whose time field drifts cannot be diffed, and a report that cannot be diffed cannot be reviewed.
- **Empty is a finding, not a pass.** "No cryptographic assets found" appears as `无法判定`, never as `合规`.

## 9. Change control for the decision table

Any change to a bucket, a precedence rule or a verdict threshold must ship with:

1. a test that fails before the change and passes after (not a test that only passes after);
2. a **negative control** proving the new rule can still go red — e.g. a mutation that flips a `无法判定` into `合规` must fail the suite;
3. no new default-pass path: an unclassified algorithm may only move toward `unknown`, never toward `approved`;
4. a CHANGELOG entry naming the rule that changed, because a report produced by two versions is not the same report.

The rules live in `cbom-compliance.cjs`: the bucket precedence in `classify()`, the verdicts in `verdicts()`, the PEM probe in `scanPrivateKeyBlocks()`, the wording in `renderMarkdown()`. Tests: `test/cbom-compliance.test.cjs`.

## 10. Known gaps (stated, not implied)

| gap | why it is not covered | where it must be covered instead |
| --- | --- | --- |
| key length / parameters | scanner is name-level; `RSA` is not `RSA-1024` | source review, or a parameter-aware analyser |
| key lifecycle | Annex B requires operational evidence | operational audit |
| RNG quality | not visible in source names | implementation review, test vectors |
| protocol correctness | needs protocol-level semantics | design review |
| cryptographic module certification | a product property, not a code property | 商用密码产品认证 records |
| side channels | needs measurement (see FIBEMATE's threat model) | TVLA / native measurement |
| non-PEM secrets | see §4.3 | dedicated secret scanner |
| management requirements (`x.5`–`x.8`) | out of scope for a source scanner | organisational audit |
| generated / minified code | may inflate or hide occurrences | scan the generator's source |

## 11. References

- **GB/T 39786-2021** 信息安全技术 信息系统密码应用基本要求 (published 2021-03-09, effective 2021-10-01).
- **CycloneDX** CBOM specification 1.6 / 1.7 — component and `cryptoProperties` model.
- **ADR-0001** — why `confidence` is decoupled from `params`.
- `README.md` § *Compliance view* — the CLI surface and the report layout.

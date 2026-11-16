# Release audit — 2026-11-16

| 包 | 版本 | 结论 | 级别 | registry | latest | sha1 | sha512 | prov | workflow | ref | subject | gitCommit | sig | sums | sha256 | tag | type | commit | dco |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cbom-tools | 0.1.0 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | a68d9c4 | ✅ |
| cbom-tools | 0.1.1 | FAIL | D | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ❌ | — | — | — |
| cbom-tools | 0.2.0 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | dd8e0db | ✅ |
| cbom-tools | 0.2.1 | FAIL | D | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ❌ | — | — | — |
| cbom-tools | 0.2.2 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | d6f7b07 | ❌ |
| cbom-tools | 0.2.3 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | 9c62558 | ❌ |
| cbom-tools | 0.2.4 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | ede5be7 | ❌ |
| cbom-tools | 0.2.5 | FAIL | C | ✅ | — | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | lightweight | caafd86 | ✅ |
| cbom-tools | 0.2.6 | FAIL | B | ✅ | — | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | annotated | e06de7f | ✅ |
| cbom-tools | 0.2.7 | PASS | A | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | annotated | 38a38a9 | ✅ |
| cbom-tools | 0.2.8 | PASS | B | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | annotated | c787ddd | ❌ |
| cbom-tools | 0.2.9 | PASS | A | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | annotated | 0cc6ee3 | ✅ |
| crypto-hallucination-detector | 0.1.2 | FAIL | B | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | annotated | 5716bfa | ✅ |
| fibemate-core | 0.1.0 | PASS | B | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | — | ✅ | annotated | 0e6dcbd | ❌ |
| fibemate-pqc-kem | 0.1.0 | FAIL | C | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | — | — | — | ❌ | ❌ | — | ✅ | annotated | 6d8fa1b | ✅ |
| fibemate-xdiff | 0.1.0 | PASS | A | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | annotated | add713a | ✅ |
| fml-dsa | 0.1.0 | PASS | B | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | — | ✅ | annotated | dff9576 | ✅ |
| verifact | 0.2.4 | FAIL | B | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | annotated | e607ee6 | ✅ |

## 汇总

- 总数: 18
- PASS: 6
- FAIL: 12
- UNKNOWN: 0
- 级别 A: 3
- 级别 B: 6
- 级别 C: 7
- 级别 D: 2

## FAIL 清单

- **cbom-tools@0.1.0** (C): FAIL: provenance
- **cbom-tools@0.1.1** (D): FAIL: provenance; FAIL: tag exists
- **cbom-tools@0.2.0** (C): FAIL: provenance
- **cbom-tools@0.2.1** (D): FAIL: provenance; FAIL: tag exists
- **cbom-tools@0.2.2** (C): FAIL: provenance
- **cbom-tools@0.2.3** (C): FAIL: provenance
- **cbom-tools@0.2.4** (C): FAIL: provenance
- **cbom-tools@0.2.5** (C): FAIL: provenance
- **cbom-tools@0.2.6** (B): FAIL: provenance ref matches tag; FAIL: provenance gitCommit matches tag commit — 证据完整、流程不符（包目录与 tag 逐字节相同，但 provenance 记的是分支）
- **crypto-hallucination-detector@0.1.2** (B): FAIL: provenance ref matches tag; FAIL: provenance gitCommit matches tag commit — 证据完整、流程不符（包目录与 tag 逐字节相同，但 provenance 记的是分支）
- **fibemate-pqc-kem@0.1.0** (C): FAIL: provenance
- **verifact@0.2.4** (B): FAIL: provenance ref matches tag; FAIL: provenance gitCommit matches tag commit — 证据完整、流程不符（包目录与 tag 逐字节相同，但 provenance 记的是分支）

## WARN 清单

- **cbom-tools@0.1.0**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name)
- **cbom-tools@0.1.1**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing
- **cbom-tools@0.2.0**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name)
- **cbom-tools@0.2.1**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing
- **cbom-tools@0.2.2**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name); WARN: no DCO sign-off on tag commit
- **cbom-tools@0.2.3**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name); WARN: no DCO sign-off on tag commit
- **cbom-tools@0.2.4**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name); WARN: no DCO sign-off on tag commit
- **cbom-tools@0.2.5**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag is lightweight (not annotated); WARN: tag commit vs Release target not comparable (branch name)
- **cbom-tools@0.2.6**: WARN: tag commit vs Release target not comparable (branch name)
- **cbom-tools@0.2.7**: WARN: tag commit vs Release target not comparable (branch name)
- **cbom-tools@0.2.8**: WARN: tag commit vs Release target not comparable (branch name); WARN: no DCO sign-off on tag commit
- **cbom-tools@0.2.9**: WARN: tag commit vs Release target not comparable (branch name)
- **crypto-hallucination-detector@0.1.2**: WARN: tag commit vs Release target not comparable (branch name)
- **fibemate-core@0.1.0**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name); WARN: no DCO sign-off on tag commit
- **fibemate-pqc-kem@0.1.0**: WARN: SHA256SUMS asset missing; WARN: cosign .sig missing; WARN: cosign .pem missing; WARN: tag commit vs Release target not comparable (branch name)
- **fibemate-xdiff@0.1.0**: WARN: tag commit vs Release target not comparable (branch name)
- **fml-dsa@0.1.0**: WARN: SHA256SUMS asset missing; WARN: tag commit vs Release target not comparable (branch name)
- **verifact@0.2.4**: WARN: tag commit vs Release target not comparable (branch name)

## 口径

- A：provenance + cosign + SHA256SUMS + **provenance ref == tag ref**，全部对齐
- B：证据链完整（签名/SUMS/tarball hash 全对），但 provenance ref 不是 tag，或 tag 非 annotated，或无 DCO
- C：无 provenance
- D：tag↔commit 无法对应，或 registry 与 tag 缺一
- 级别描述的是“证据/流程差在哪”，与 verdict 独立；B + FAIL = 证据完整但流程不符。

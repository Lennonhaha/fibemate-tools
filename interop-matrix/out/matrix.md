# ML-KEM-768 interop matrix (PASS)

Generated 2026-10-28T11:40:48.623Z | mode **D** | node v22.22.3

| end | implementation | version | source sha256 (first 16) |
|---|---|---|---|
| P | fibemate-pqc-kem | 0.1.0 | `8d98ca5f66cb09a9` |
| N | @noble/post-quantum | 0.7.1 | `e5f1a3fa994f663c` |

fibemate `e4d3d582bd6043613d00b1103aed5d78a57f00f0` | fibemate-tools `6a5fe2c6506920b372111a8375f9255f3b535339`

## Derivation (Mode D)

| seed | pk P vs N | sk P vs N |
|---|---|---|
| S1 | =P | =P |
| S2 | =P | =P |
| S3 | =P | =P |

`=P` means the bytes equal end P's output; no digests are printed here, `matrix.json` carries them.

## Cells: keygen A -> encap B -> decap A

| cell | seed | mode | baseline | ct bytes | round trip | ss =P | result |
|---|---|---|---|---|---|---|---|
| PP | S1 | D | yes | =P | PASS | =P | **PASS** |
| PN | S1 | D | no | =P | PASS | =P | **PASS** |
| NP | S1 | D | no | =P | PASS | =P | **PASS** |
| NN | S1 | D | yes | =P | PASS | =P | **PASS** |
| PP | S2 | D | yes | =P | PASS | =P | **PASS** |
| PN | S2 | D | no | =P | PASS | =P | **PASS** |
| NP | S2 | D | no | =P | PASS | =P | **PASS** |
| NN | S2 | D | yes | =P | PASS | =P | **PASS** |
| PP | S3 | D | yes | =P | PASS | =P | **PASS** |
| PN | S3 | D | no | =P | PASS | =P | **PASS** |
| NP | S3 | D | no | =P | PASS | =P | **PASS** |
| NN | S3 | D | yes | =P | PASS | =P | **PASS** |

`round trip` = decap returns the secret the sender computed (interop). `ss =P` = the secret is byte-equal to end P's. A cell can match on ciphertext bytes and still differ on the secret; that is what the `ss =P` column is for.


## Controls

| seed | flipped ct: no throw | differs | deterministic | same ss both ends | wrong key rejected |
|---|---|---|---|---|---|
| S1 | PASS | PASS | PASS | PASS | PASS |
| S2 | PASS | PASS | PASS | PASS | PASS |
| S3 | PASS | PASS | PASS | PASS | PASS |

## Verdict

**PASS** — 62/62 checks passed.

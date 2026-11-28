# ADR-0002 — Registered identifiers are read structurally, and "not a use" is silence

- **Status:** accepted, implemented in 0.3.3 (2026-11-28)
- **Scope:** `cbom-tools/registry-identifiers.cjs` (new), the scan loop and
  `mergeEvidence` in `cbom-scan.cjs`, `algorithm-hierarchy.cjs`, `algo-metadata.json`
- **Related:** CHANGELOG 0.3.3; `test/registry-identifiers.test.cjs`;
  the ShorList measured run of 2026-11-28

## 1. The two blind spots this ADR closes

### 1.1 A registered name is not a canonical name

0.3.2 recognised an algorithm when its canonical name was written out —
`AES-GCM`, `ML-KEM-768`, `SHA-256`. It did not recognise the identifiers that
standards bodies publish:

```python
CIPHER_SUITE = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"   # 0.3.2: nothing
TLS_GROUP    = "ffdhe2048"                                # 0.3.2: nothing
KexAlgorithms diffie-hellman-group16-sha512               # 0.3.2: nothing
```

Measured cost, against the ShorList catalogue (1,429 positive forms): DH 0/192,
EC 0/140, EdDSA 0/89, LMS 0/10, XMSS 0/9. Not "hard to find" — invisible.

Adding those strings to `sourcePatterns` does not scale: the miss corpus alone
contains ~1,000 distinct `TLS_*` suite names, each naming two to four
algorithms, and the IANA registry keeps growing. A word list of whole strings
also has to be re-derived for every spelling (`TLS_…`, `ECDHE-RSA-…`,
`diffie-hellman-group…`, `rsa_pss_…`).

### 1.2 A mention is not a use

The 16 false alarms in the same run were, without exception, one of four
shapes — none of them a use:

```python
logging.warning("peer offered group ffdhe6144; rejected by policy")   # log line
BLOCKED_CIPHER_SUITES = {"TLS_DH_DSS_WITH_AES_256_CBC_SHA"}           # deny-list
# Removed in v3: CIPHER_SUITE = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"  # comment
ENABLED = {"Ed448": False}                                            # off switch
```

## 2. Decision

### 2.1 Decompose, do not enumerate

`registry-identifiers.cjs` parses each name space into its constituents and
emits one component per constituent:

| identifier | components |
| --- | --- |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `ECDH`, `RSA`, `AES` |
| `TLS_KRB5_WITH_3DES_EDE_CBC_SHA` | `3DES`, `SHA-1` |
| `TLS_GROUP = "ffdhe2048"` | `DH-ffdhe2048` (size 2048) |
| `ssl_ecdh_curve secp384r1` | `EC-secp384r1`, `ECDH-secp384r1` |
| `PURPOSE_SIGN` + `secp384r1` | `EC-secp384r1`, `ECDSA` |
| `X25519MLKEM768` | `X25519`, `ML-KEM-768` |

Two rules keep the output honest:

1. **A curve does not choose a role.** `P-256` is `EC-P-256`; it becomes
   `ECDH-P-256` only in a key-agreement context (`TLS_GROUP`, `ecdh_curve`,
   `KexAlgorithms`, `AGREE_KEY`, …) and `ECDSA` only in a signing context
   (`PURPOSE_SIGN`, `KeyAlgorithm`, `ECDSA`, …). Emitting `ECDSA` for every
   curve would be a guess, and the BOM would carry it forever.
2. **A bulk cipher the vocabulary does not define is not named.** CAMELLIA,
   ARIA, SEED and NULL are skipped rather than invented as components.

Name shape is `<family>-<parameter>` in the CycloneDX style, because the
downstream vocabulary resolves a family from the leading token: `EC-P-256`,
`DH-ffdhe2048`, `EdDSA-Ed25519`. `Ed25519` alone is not a family in that
vocabulary — which is why 0.3.2 scored 0 on all 89 EdDSA forms.

Matching uses letter-only lookarounds, not `\b`. Registered identifiers glue
their parts with `_` (`SSL_GROUP_X25519_MLKEM768`,
`MBEDTLS_ECP_DP_SECP384R1`, `mbedtls_ecdsa_genkey`), and `\b` treats `_` as a
word character. This was the first bug the new tests caught.

### 2.2 Suppression is omission

CycloneDX has no "not a use" marker. A component that is emitted is a claim
that the algorithm is there; there is nowhere to attach "…but forbidden".
So the scanner must decide before emitting, in `isNotAUse`:

| shape | test |
| --- | --- |
| comment | line starts with `#`, `;`, `//`, `--`, `/*`, `<!--`, `%` — for the extensions `stripComments` does not already blank |
| log / print | a logging or output call opens before the name (`fprintf(`, `logging.warning(`, `println(`, …) |
| deny-list | the name sits under `BLOCKED_`, `REJECTED_`, `BANNED_`, `$rejected`, … |
| off switch | the name is the key of a `False` (`{"Ed448": False}`) |
| aside | `previous-key:`, `#undef`, `TODO`, `not`, `deprecated`, `rejected`, `unavailable`, … |
| excluded token | `!ECDSA` in a cipher list, `DEFAULT:-X25519MLKEM768` |
| deny statement | JSON policy object with `"Effect": "Deny"` and no `"Allow"` in the same block |

The `False` rule is keyed on the *name*: `{"Ed448": False}` denies Ed448, while
`hashlib.md5(data, usedforsecurity=False)` is a use of MD5 with an apology
attached. The first is silence; the second is a hit. The tests pin both.

### 2.3 Sizes come from the identifier

`registrySize` reads a size only where the name states one (`ffdhe2048` → 2048,
`P-384` → 384, RFC 3526 group 14 → 2048). Where the name does not (a TLS suite,
`ML-KEM`), no size is emitted. `size_ok` in the measured run went 0/53 → 119/208
as a side effect; it was not the goal.

## 3. Consequences

- **Recall up, precision up, same run.** ShorList 1,429 positive forms:
  203 → 807 recognised; wrong-family rows 4 → 0; 172 decoys: 16 false alarms
  → 0. All three moved in the same direction, which is the point of doing
  §2.1 and §2.2 together — a structural reader without suppression would have
  turned every deny-list into a finding.
- **Components the metadata table does not know** still ship, now with
  `cryptoProperties.relatedCryptoMaterialProperties.size` when the identifier
  states one, and with no `quantumSecurity` claim. `algo-metadata.json` covers
  the families it can speak about; it does not get a synthetic entry per curve.
- **The dictionary gate does not protect this module.** It iterates
  `DEFAULT_RULES.sourcePatterns`, and registry names are not rules.
  `test/registry-identifiers.test.cjs` carries the equivalent gate: every name
  the module can emit must start with a family the vocabulary has.
- **Not covered:** OID arc mapping (59 measured forms), PEM/DER and file-format
  parsers, CLI narrative (`openssl genpkey -algorithm …`), and CWE classification
  on the defect axis. Those are separate decisions with separate evidence.

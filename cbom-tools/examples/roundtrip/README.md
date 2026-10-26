# CBOM fidelity fixtures: round-trip outputs

Serialisation outputs for the corrected fixtures from PR #90 (`cc131bfd`), produced for the
BOM Fidelity round-trip stage.

## Tooling

- `cyclonedx-python-lib` **11.12.0**
- Python 3.11.10 on Windows-10-10.0.26300-SP0
- official schema files: `bom-1.6-1.6.2.json`, `bom-1.7.2.json` (+ the two defs files)
- **no converter was run**: `cyclonedx-cli` / `dotnet` are not installed in the environment used,
  so the version-conversion direction (1.6 to 1.7) is not covered here. Only same-version
  serialisation (JSON to JSON, JSON to XML) and the XML to JSON return leg are.

## Commands

```bash
python -m pip install cyclonedx-python-lib==11.12.0 jsonschema
python roundtrip_cbom.py     # JSON -> JSON, JSON -> XML, writes roundtrip-report.json
python roundtrip_diff.py     # structural diff (bom-ref keyed), XML -> JSON leg
CDX_SCHEMA_DIR=/path/to/schemas python validate_outputs.py
```

Inputs default to the parent directory, outputs to this one; `CBOM_EXAMPLES_DIR` and
`CBOM_ROUNDTRIP_OUT` override that. `CDX_SCHEMA_DIR` must point at a directory holding the
official schema files, which are not vendored here.

## Inputs and outputs

| spec | direction | input | sha256 in | output | sha256 out |
|---|---|---|---|---|---|
| 1.6.2 | JSON -> JSON | `cbom-fidelity-1.6.2.json` | `61b8a721628c794068e67e5b6b260de60ccfd2919189fb68df2e9704e8726247` | `roundtrip-1.6.2-json.json` | `5b6e0f3e41839229f8042eb3468af2eea46eef53766ea9184186ae66b4a6629b` |
| 1.6.2 | JSON -> XML | `cbom-fidelity-1.6.2.json` | `61b8a721628c794068e67e5b6b260de60ccfd2919189fb68df2e9704e8726247` | `roundtrip-1.6.2-xml.xml` | `544344d8e5455f7c2d2e9545b1a83215a1b277168bbf3622406273cf3d8f8fca` |
| 1.6.2 | XML -> JSON | `roundtrip-1.6.2-xml.xml` | `544344d8e5455f7c2d2e9545b1a83215a1b277168bbf3622406273cf3d8f8fca` | `roundtrip-1.6.2-xml-to-json.json` | `5b6e0f3e41839229f8042eb3468af2eea46eef53766ea9184186ae66b4a6629b` |
| 1.7.2 | JSON -> JSON | `cbom-fidelity-1.7.2.json` | `28016a574d812b0405b572ece2fedd65e82a06606333b63e0213f6d6aa5b2937` | `roundtrip-1.7.2-json.json` | `51cd09381d89d1c5181238d4bcb34d6b412b1a166cf47c8b6ec7792d97242732` |
| 1.7.2 | JSON -> XML | `cbom-fidelity-1.7.2.json` | `28016a574d812b0405b572ece2fedd65e82a06606333b63e0213f6d6aa5b2937` | `roundtrip-1.7.2-xml.xml` | `58a028b7465a2b400a9209b7e87f15df5bd9e364f78e675d34fcfa927ad6aefb` |
| 1.7.2 | XML -> JSON | `roundtrip-1.7.2-xml.xml` | `58a028b7465a2b400a9209b7e87f15df5bd9e364f78e675d34fcfa927ad6aefb` | `roundtrip-1.7.2-xml-to-json.json` | `51cd09381d89d1c5181238d4bcb34d6b412b1a166cf47c8b6ec7792d97242732` |

Input hashes are stable: they are the fixtures from `cc131bfd`. Output hashes are **not**
reproducible across runs, because the serialiser injects `metadata.timestamp` at serialisation
time. A rerun produces the same content with a different timestamp, and therefore different
hashes. The table above records the committed files.

## What survived

Matched by `bom-ref`, so component reordering is not counted as a value change.

| observation | 1.6.2 | 1.7.2 |
|---|---|---|
| family-only (`component.name`, no category assertion) | preserved | preserved |
| explicit `0` (MD5) | preserved as `0` | preserved as `0` |
| omitted field + `fibemate:nistQuantumSecurityLevel` property | preserved | preserved |
| `algorithmProperties.algorithmFamily` | not applicable (1.6 has no such field) | **dropped on all three components** |

### The 1.7 loss

`cyclonedx-python-lib` 11.12.0 does not model `algorithmFamily` (or `parameterSetIdentifier`):
the strings do not occur in `cyclonedx/model/crypto.py` at all. Parsing a 1.7 document and
serialising it back therefore emits a document without them, and the result is still
schema-valid, because the field is optional. That gap between validity and preservation is the
reason these outputs are published rather than described.

This is a property of the library, not of the schema and not of the input fixtures.

### Differences that are not losses

- added: `$schema`, `metadata.timestamp`, one `dependencies` entry per `bom-ref`;
- component order changes from `ML-KEM, MD5, SM2` to `MD5, ML-KEM, SM2`
  (array order carries no meaning in CycloneDX; the diff script keys by `bom-ref` for this reason);
- nothing else removed or altered, in either version.

## Schema validation of the outputs

| output | schema | result |
|---|---|---|
| `roundtrip-1.6.2-json.json` | `bom-1.6-1.6.2.json` | VALID |
| `roundtrip-1.6.2-xml-to-json.json` | `bom-1.6-1.6.2.json` | VALID |
| `roundtrip-1.7.2-json.json` | `bom-1.7.2.json` | VALID |
| `roundtrip-1.7.2-xml-to-json.json` | `bom-1.7.2.json` | VALID |

## Scope

These are the outputs of one serialiser, run once, on one machine. They are not a survey of
toolchains. The 1.7 result is a reproduction with the command that produces it, not a defect
report: whether the library should carry the field is for its maintainers to decide.

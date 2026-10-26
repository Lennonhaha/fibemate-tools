# SPDX-License-Identifier: Apache-2.0
"""Validate the round-trip outputs against the official schemas at 1.6.2 / 1.7.2.

The schema files are not vendored here. Download the release bundle you want to
check against and point CDX_SCHEMA_DIR at the directory holding:
  bom-1.6-1.6.2.json, bom-1.7.2.json, cryptography-defs.schema.json,
  spdx.schema.json, jsf-0.82.schema.json
"""

import json
import os
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from jsonschema.validators import RefResolver

HERE = Path(__file__).resolve().parent
RT = Path(os.environ.get("CBOM_ROUNDTRIP_OUT", HERE))
CDX = Path(os.environ.get("CDX_SCHEMA_DIR", "")) if os.environ.get("CDX_SCHEMA_DIR") else None
if CDX is None or not CDX.is_dir():
    sys.exit("set CDX_SCHEMA_DIR to the directory holding the official schema files")

store = {}
for f in CDX.glob("*.json"):
    doc = json.loads(f.read_text(encoding="utf-8"))
    for key in (doc.get("$id"), f.name, "http://cyclonedx.org/schema/" + f.name):
        if key:
            store[key] = doc

CASES = [
    ("bom-1.6-1.6.2.json", "roundtrip-1.6.2-json.json"),
    ("bom-1.6-1.6.2.json", "roundtrip-1.6.2-xml-to-json.json"),
    ("bom-1.7.2.json", "roundtrip-1.7.2-json.json"),
    ("bom-1.7.2.json", "roundtrip-1.7.2-xml-to-json.json"),
]

all_ok = True
for schema_file, doc_file in CASES:
    schema = json.loads((CDX / schema_file).read_text(encoding="utf-8"))
    doc = json.loads((RT / doc_file).read_text(encoding="utf-8"))
    resolver = RefResolver(base_uri="http://cyclonedx.org/schema/", referrer=schema, store=store)
    errors = sorted(Draft7Validator(schema, resolver=resolver).iter_errors(doc), key=lambda e: list(e.path))
    ok = not errors
    all_ok = all_ok and ok
    print(f"{doc_file:<36} vs {schema_file:<22} {'VALID' if ok else 'INVALID'}")
    for e in errors[:3]:
        print("   ", list(e.path), e.message[:160])

print("\nall valid:", all_ok)
sys.exit(0 if all_ok else 1)

# SPDX-License-Identifier: Apache-2.0
"""Structural diff of the round trip, plus the XML -> JSON return leg.

The first pass answers "did the three observations survive". This pass answers
"what else changed", because a serialiser that quietly adds or drops fields is
the thing BOM Fidelity exists to catch - including when the serialiser is ours.

Components are matched by bom-ref, not by array index: the library reorders
them, and index-based comparison would report reordering as value changes.

Paths default to this directory and its parent; see roundtrip_cbom.py.
"""

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

HERE = Path(__file__).resolve().parent
EXAMPLES = Path(os.environ.get("CBOM_EXAMPLES_DIR", HERE.parent))
RT = Path(os.environ.get("CBOM_ROUNDTRIP_OUT", HERE))
CASES = [("1.6.2", SchemaVersion.V1_6), ("1.7.2", SchemaVersion.V1_7)]


def flatten(node, prefix="", out=None):
    if out is None:
        out = {}
    if isinstance(node, dict):
        if not node:
            out[prefix or "/"] = "{}"
        for k, v in node.items():
            flatten(v, f"{prefix}/{k}", out)
    elif isinstance(node, list):
        if not node:
            out[prefix or "/"] = "[]"
        for i, v in enumerate(node):
            flatten(v, f"{prefix}[{i}]", out)
    else:
        out[prefix] = node
    return out


def normalise(doc):
    """Replace the components array with a bom-ref keyed map so order does not matter."""
    doc = json.loads(json.dumps(doc))
    comps = doc.pop("components", [])
    doc["components"] = {(c.get("bom-ref") or c.get("name")): c for c in comps}
    return doc


def compare(a, b, label):
    fa, fb = flatten(normalise(a)), flatten(normalise(b))
    removed = sorted(set(fa) - set(fb))
    added = sorted(set(fb) - set(fa))
    changed = sorted(k for k in set(fa) & set(fb) if fa[k] != fb[k])
    print(f"\n--- {label}")
    print(f"  paths: {len(fa)} -> {len(fb)}")
    print("  REMOVED:", removed or "none")
    print("  ADDED  :", added or "none")
    print("  CHANGED:", [(k, fa[k], fb[k]) for k in changed] or "none")
    return removed, added, changed


for tag, schema in CASES:
    src = EXAMPLES / f"cbom-fidelity-{tag}.json"
    out_json = RT / f"roundtrip-{tag}-json.json"
    out_xml = RT / f"roundtrip-{tag}-xml.xml"

    a = json.loads(src.read_text(encoding="utf-8"))
    b = json.loads(out_json.read_text(encoding="utf-8"))

    print(f"\n================ {tag} ================")
    compare(a, b, "input JSON -> output JSON")
    print("  component order in: ", [c["name"] for c in a["components"]])
    print("  component order out:", [c["name"] for c in b["components"]])

    bom = Bom.from_xml(data=ET.parse(out_xml).getroot())
    back = RT / f"roundtrip-{tag}-xml-to-json.json"
    back.write_bytes(make_outputter(bom, OutputFormat.JSON, schema).output_as_string().encode("utf-8"))
    compare(b, json.loads(back.read_text(encoding="utf-8")), f"output XML -> {back.name}")

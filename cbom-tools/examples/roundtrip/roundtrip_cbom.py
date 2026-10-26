# SPDX-License-Identifier: Apache-2.0
"""Round-trip the two CBOM fidelity fixtures through cyclonedx-python-lib.

Reserialises cbom-fidelity-1.6.2.json and cbom-fidelity-1.7.2.json to JSON and
XML and reports, for each of the three semantic observations, whether the
information survived. Nothing here decides whether the result is "correct": it
prints what the serialiser actually emitted, with hashes, so someone else can
check it against the originals.

Inputs default to the parent directory (the fixtures live next door); outputs
default to this directory. Both can be overridden:

    CBOM_EXAMPLES_DIR   directory holding cbom-fidelity-*.json
    CBOM_ROUNDTRIP_OUT  directory for the outputs
"""

import hashlib
import importlib.metadata as md
import json
import os
import platform
import sys
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

HERE = Path(__file__).resolve().parent
EXAMPLES = Path(os.environ.get("CBOM_EXAMPLES_DIR", HERE.parent))
OUT = Path(os.environ.get("CBOM_ROUNDTRIP_OUT", HERE))
OUT.mkdir(parents=True, exist_ok=True)

CASES = [
    ("1.6.2", EXAMPLES / "cbom-fidelity-1.6.2.json", SchemaVersion.V1_6),
    ("1.7.2", EXAMPLES / "cbom-fidelity-1.7.2.json", SchemaVersion.V1_7),
]

# The three observations the fixtures exist to pin down.
WANT_NAMES = ["ML-KEM", "MD5", "SM2"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def features(doc):
    """Pull out only the fields under discussion, keyed by component name."""
    out = {}
    for comp in doc.get("components", []):
        name = comp.get("name")
        if name not in WANT_NAMES:
            continue
        ap = (comp.get("cryptoProperties") or {}).get("algorithmProperties") or {}
        props = {p.get("name"): p.get("value") for p in comp.get("properties", []) or []}
        out[name] = {
            "algorithmProperties_keys": sorted(ap.keys()),
            "nistQuantumSecurityLevel": ap.get("nistQuantumSecurityLevel", "<absent>"),
            "algorithmFamily": ap.get("algorithmFamily", "<absent>"),
            "parameterSetIdentifier": ap.get("parameterSetIdentifier", "<absent>"),
            "namespaced": {k: v for k, v in props.items() if ":" in str(k)},
        }
    return out


def report(label, doc):
    f = features(doc)
    print(f"\n--- {label}")
    for name in WANT_NAMES:
        if name not in f:
            print(f"  {name:<8} MISSING FROM OUTPUT")
            continue
        d = f[name]
        print(
            f"  {name:<8} nqsl={d['nistQuantumSecurityLevel']!r:<10} "
            f"family={d['algorithmFamily']!r:<12} pset={d['parameterSetIdentifier']!r:<8} "
            f"ns={d['namespaced'] or '{}'} keys={d['algorithmProperties_keys']}"
        )
    return f


results = {
    "tool": {
        "library": "cyclonedx-python-lib",
        "library_version": md.version("cyclonedx-python-lib"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "command": "python roundtrip_cbom.py",
    },
    "cases": {},
}

for tag, src, schema in CASES:
    print(f"\n================ CycloneDX {tag} ================")
    if not src.exists():
        raise SystemExit(f"input not found: {src} (set CBOM_EXAMPLES_DIR)")
    print("input:", src)
    raw = json.loads(src.read_text(encoding="utf-8"))
    print("input sha256:", sha256(src))
    in_feat = report("input", raw)

    bom = Bom.from_json(data=raw)

    json_out = OUT / f"roundtrip-{tag}-json.json"
    json_out.write_bytes(make_outputter(bom, OutputFormat.JSON, schema).output_as_string().encode("utf-8"))
    xml_out = OUT / f"roundtrip-{tag}-xml.xml"
    xml_out.write_bytes(make_outputter(bom, OutputFormat.XML, schema).output_as_string().encode("utf-8"))

    out_json_doc = json.loads(json_out.read_text(encoding="utf-8"))
    out_feat = report(f"output JSON ({json_out.name})", out_json_doc)
    print("output sha256:", sha256(json_out))
    print("output XML sha256:", sha256(xml_out), f"({xml_out.stat().st_size} bytes)")

    diffs = []
    for name in WANT_NAMES:
        if name not in out_feat:
            diffs.append(f"{name}: dropped entirely")
            continue
        for key in ("nistQuantumSecurityLevel", "algorithmFamily", "parameterSetIdentifier", "namespaced"):
            if in_feat.get(name, {}).get(key) != out_feat[name].get(key):
                diffs.append(f"{name}.{key}: {in_feat.get(name, {}).get(key)!r} -> {out_feat[name].get(key)!r}")
    print("FIELD-LEVEL DIFF:", diffs or "none")

    results["cases"][tag] = {
        "input": src.name,
        "input_sha256": sha256(src),
        "output_json": json_out.name,
        "output_json_sha256": sha256(json_out),
        "output_xml": xml_out.name,
        "output_xml_sha256": sha256(xml_out),
        "features_in": in_feat,
        "features_out_json": out_feat,
        "field_level_diff": diffs,
    }

(OUT / "roundtrip-report.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
print("\nreport:", OUT / "roundtrip-report.json")

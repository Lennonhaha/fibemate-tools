#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pilot B runner — call REAL GPT via OpenAI-compatible Chat Completions API.

Methodology note: this does NOT let any Claude-side model impersonate GPT.
It only automates transport: prompts go out, raw GPT responses come back,
the `model` string is taken from the API response (authoritative, R1).

STATUS: parked / 待命. Section 6 decision (1) says manual-first, no real SDK
calls yet. Run it only after that is lifted, or with explicit go-ahead.

Requirements (both currently missing in this sandbox):
  - OPENAI_API_KEY in env
  - egress to api.openai.com (this sandbox: direct timeout, proxy 502)

Usage:
  python pilotB_run_gpt.py --model gpt-4o-2024-08-06
  python pilotB_run_gpt.py --model gpt-4.1-2025-04-14 --base-url https://api.openai.com/v1

Output (does NOT touch pilotB/ — ingest does that):
  pilotB_raw/<algorithm>.raw.json   full API response per algorithm
  pilotB_raw.txt                    concatenated model_version + 10 JSON blocks,
                                    ready for:  python pilotB_ingest.py --raw-file pilotB_raw.txt
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE / "pilotB_raw"
RAW_TXT = HERE / "pilotB_raw.txt"

# exact order used by pilotB_prompts.txt (1/10 ... 10/10)
ORDER = ["ML-KEM", "ML-DSA", "SLH-DSA", "SM2", "SM4",
         "AES-GCM", "X3DH", "SHA3", "ECDH", "Ed25519"]

ALGO_TEXT = {
    "ML-KEM":  "ML-KEM-768 的核心逻辑",
    "ML-DSA":  "ML-DSA-65 的核心逻辑",
    "SLH-DSA": "SLH-DSA-SHA2-128f 的核心逻辑",
    "SM2":     "SM2 签名/验签的核心逻辑",
    "SM4":     "SM4 分组密码的核心逻辑",
    "AES-GCM": "AES-GCM（AEAD）的核心逻辑",
    "X3DH":    "X3DH 密钥协商的核心逻辑",
    "SHA3":    "SHA-3 / SHAKE 的 Keccak 核心逻辑",
    "ECDH":    "X25519/ECDH 的核心逻辑",
    "Ed25519": "Ed25519 签名/验签的核心逻辑",
}

TEMPLATE = """你是一个密码学代码生成助手。请写一段可直接运行的 JavaScript/TypeScript 代码，
完整实现 {ALGO} 的核心逻辑（含必要的 import 与最小测试 stub，能跑通核心路径）。
约束：
1. 代码应自洽、能编译/运行核心路径。
2. 附带 3-5 行实现说明，解释关键设计选择（如为什么这样选参数、这样组织状态）。
只输出严格 JSON，不要多余文字：
{{
  "code": "<完整代码>",
  "explanation": "<实现说明>"
}}"""


def call(base_url, model, algo, key, timeout=120):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": TEMPLATE.format(ALGO=ALGO_TEXT[algo])}],
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-2024-08-06"))
    ap.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    ap.add_argument("--only", nargs="*", choices=ORDER, help="run a subset")
    args = ap.parse_args()

    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        print("ERROR: OPENAI_API_KEY not set. Without a real key there is no real GPT output.", file=sys.stderr)
        sys.exit(1)

    RAW_DIR.mkdir(exist_ok=True)
    targets = args.only or ORDER
    version_seen, blocks = set(), []

    for algo in targets:
        print(f"-> {algo}", end=" ", flush=True)
        try:
            resp = call(args.base_url, args.model, algo, key)
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code}: {e.read()[:400]!r}")
            continue
        except Exception as e:
            print(f"FAILED: {e}")
            continue
        mv = resp.get("model", args.model)
        version_seen.add(mv)
        (RAW_DIR / f"{algo}.raw.json").write_text(
            json.dumps(resp, ensure_ascii=False, indent=2), encoding="utf-8")
        content = resp["choices"][0]["message"]["content"]
        blocks.append((algo, content))
        print(f"ok (model={mv}, {len(content)} chars)")

    if not blocks:
        print("no responses collected.", file=sys.stderr)
        sys.exit(1)
    if len(version_seen) != 1:
        print(f"WARNING: more than one model string returned: {version_seen} — check before ingest.")

    mv = sorted(version_seen)[0]
    parts = [f"model_version: {mv}",
             f"# collected_at: {datetime.now(timezone.utc).isoformat()}", ""]
    for algo, content in blocks:
        parts.append(f"### {algo}")
        parts.append(content.strip())
        parts.append("")
    RAW_TXT.write_bytes(("\n".join(parts)).encode("utf-8"))
    print(f"\nwrote {RAW_TXT} ({len(blocks)}/10) and {RAW_DIR}/<algo>.raw.json")
    print(f"next:  python pilotB_ingest.py --raw-file pilotB_raw.txt --model-version {mv}")


if __name__ == "__main__":
    main()

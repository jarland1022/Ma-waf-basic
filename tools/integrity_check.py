#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""完整性基线初始化与校验 + 审计日志链式哈希工具。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
from typing import Dict, Iterable, List

# 纳入完整性保护的相对路径模式
DEFAULT_TARGETS = [
    "sbin/nginx",
    "conf/nginx.conf",
    "conf/modsecurity/modsecurity.conf",
    "conf/modsecurity/main.conf",
    "conf/modsecurity/custom",
]


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: pathlib.Path, rel: str) -> Iterable[pathlib.Path]:
    p = root / rel
    if p.is_file():
        yield p
    elif p.is_dir():
        for fp in sorted(p.rglob("*")):
            if fp.is_file():
                yield fp


def build_baseline(nginx_root: pathlib.Path, product_root: pathlib.Path) -> Dict:
    entries: Dict[str, str] = {}
    for rel in DEFAULT_TARGETS:
        for fp in iter_files(nginx_root, rel):
            key = str(fp)
            entries[key] = sha256_file(fp)
    # 产品脚本与工具
    for sub in ("scripts", "tools", "bin"):
        d = product_root / sub
        if d.exists():
            for fp in sorted(d.rglob("*")):
                if fp.is_file():
                    entries[str(fp)] = sha256_file(fp)
    return {
        "version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": entries,
    }


def verify_baseline(baseline_path: pathlib.Path) -> int:
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    files: Dict[str, str] = data.get("files", {})
    mismatches: List[str] = []
    missing: List[str] = []
    for path, expect in files.items():
        p = pathlib.Path(path)
        if not p.exists():
            missing.append(path)
            continue
        got = sha256_file(p)
        if got != expect:
            mismatches.append(path)
    if missing:
        print("MISSING:", *missing, sep="\n  ", file=sys.stderr)
    if mismatches:
        print("CHANGED:", *mismatches, sep="\n  ", file=sys.stderr)
    if missing or mismatches:
        return 1
    print(f"integrity OK ({len(files)} files)")
    return 0


def chain_hash_append(log_path: pathlib.Path, event: Dict, chain_path: pathlib.Path) -> str:
    """将事件写入链式哈希审计文件（只追加）。"""
    prev = "0" * 64
    if chain_path.exists() and chain_path.stat().st_size > 0:
        last = chain_path.read_text(encoding="utf-8").strip().splitlines()[-1]
        prev = json.loads(last)["hash"]
    payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    material = f"{prev}|{payload}|{ts}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    rec = {"ts": ts, "prev": prev, "hash": digest, "event": event}
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    with chain_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    # 可选同步原始事件
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(payload + "\n")
    return digest


def verify_chain(chain_path: pathlib.Path) -> int:
    prev = "0" * 64
    with chain_path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("prev") != prev:
                print(f"chain break at line {i}: prev mismatch", file=sys.stderr)
                return 1
            payload = json.dumps(rec["event"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            material = f"{rec['prev']}|{payload}|{rec['ts']}".encode("utf-8")
            expect = hashlib.sha256(material).hexdigest()
            if expect != rec["hash"]:
                print(f"chain break at line {i}: hash mismatch", file=sys.stderr)
                return 1
            prev = rec["hash"]
    print("chain OK")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--init", action="store_true")
    g.add_argument("--verify", action="store_true")
    g.add_argument("--chain-append", action="store_true")
    g.add_argument("--chain-verify", action="store_true")
    p.add_argument("--root", default="/usr/local/nginx")
    p.add_argument("--product", default="/usr/local/ma-waf")
    p.add_argument("--out", default="/usr/local/ma-waf/var/lib/integrity-baseline.json")
    p.add_argument("--baseline", default="/usr/local/ma-waf/var/lib/integrity-baseline.json")
    p.add_argument("--chain", default="/usr/local/ma-waf/var/lib/audit-chain.jsonl")
    p.add_argument("--event-json", default="")
    args = p.parse_args()

    if args.init:
        bl = build_baseline(pathlib.Path(args.root), pathlib.Path(args.product))
        out = pathlib.Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bl, indent=2), encoding="utf-8")
        os.chmod(out, 0o640)
        print(f"baseline written: {out} files={len(bl['files'])}")
        return 0
    if args.verify:
        return verify_baseline(pathlib.Path(args.baseline))
    if args.chain_append:
        event = json.loads(args.event_json or "{}")
        digest = chain_hash_append(pathlib.Path("/dev/null"), event, pathlib.Path(args.chain))
        print(digest)
        return 0
    if args.chain_verify:
        return verify_chain(pathlib.Path(args.chain))
    return 1


if __name__ == "__main__":
    sys.exit(main())

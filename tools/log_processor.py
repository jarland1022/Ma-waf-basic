#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计日志处理：分级过滤、命中统计、简易合规摘要。"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from typing import Any, Dict, Iterator


def iter_json_lines(path: pathlib.Path) -> Iterator[Dict[str, Any]]:
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def severity_of(event: Dict[str, Any]) -> str:
    # ModSecurity JSON 结构因版本略有差异，做兼容提取
    for key in ("severity", "messages", "audit_data"):
        pass
    msg = json.dumps(event, ensure_ascii=False).lower()
    if "critical" in msg:
        return "CRITICAL"
    if "warning" in msg or "error" in msg:
        return "WARNING"
    if "notice" in msg:
        return "NOTICE"
    return "INFO"


def cmd_filter(args: argparse.Namespace) -> int:
    levels = {"CRITICAL": 4, "WARNING": 3, "NOTICE": 2, "INFO": 1}
    min_level = levels[args.min_severity.upper()]
    n = 0
    for ev in iter_json_lines(pathlib.Path(args.input)):
        sev = severity_of(ev)
        if levels.get(sev, 0) >= min_level:
            print(json.dumps({"severity": sev, "event": ev}, ensure_ascii=False))
            n += 1
    print(f"# matched={n}", file=sys.stderr)
    return 0


def cmd_hit_stats(args: argparse.Namespace) -> int:
    counter: collections.Counter = collections.Counter()
    for ev in iter_json_lines(pathlib.Path(args.input)):
        blob = json.dumps(ev)
        # 提取 id:12345 形态
        import re

        for m in re.finditer(r"\bid[\"'=\s:]+(\d{5,7})", blob, re.I):
            counter[m.group(1)] += 1
    for rid, c in counter.most_common(args.top):
        print(f"{rid}\t{c}")
    return 0


def cmd_compliance_summary(args: argparse.Namespace) -> int:
    """将审计事件映射到通用合规控制域（示意，非认证结论）。"""
    mapping = {
        "access_control": ["403", "whitelist", "blacklist", "geo"],
        "logging_audit": ["audit", "request_id"],
        "crypto_tls": ["ssl", "tls"],
        "malware_attack": ["sql", "xss", "rce", "lfi", "bot"],
        "privacy_pii": ["pii", "id card", "mobile", "bank"],
    }
    hits = collections.Counter()
    total = 0
    for ev in iter_json_lines(pathlib.Path(args.input)):
        total += 1
        blob = json.dumps(ev).lower()
        for domain, kws in mapping.items():
            if any(k in blob for k in kws):
                hits[domain] += 1
    report = {
        "standard_refs": ["等保2.0-通用要求", "ISO27001-A.8/A.12", "GDPR-Art32", "SOX-ITGC"],
        "total_events": total,
        "control_domain_hits": dict(hits),
        "note": "本摘要仅供运营参考，不构成合规认证结论",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("filter")
    pf.add_argument("--input", required=True)
    pf.add_argument("--min-severity", default="WARNING")
    pf.set_defaults(func=cmd_filter)

    ps = sub.add_parser("hit-stats")
    ps.add_argument("--input", required=True)
    ps.add_argument("--top", type=int, default=20)
    ps.set_defaults(func=cmd_hit_stats)

    pc = sub.add_parser("compliance-summary")
    pc.add_argument("--input", required=True)
    pc.set_defaults(func=cmd_compliance_summary)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ma-WAF 规则管理工具：列表 / 语法粗检 / 启用禁用元数据 / 虚拟补丁过期处理。

兼容 Python 3.9+（Rocky 9 / openEuler）。
注意：完整 ModSecurity 语义校验依赖 nginx -t；本工具做静态检查与元数据管理。
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import sys
from typing import Dict, List, Optional, Tuple

META_RE = re.compile(
    r"#\s*META:\s*(?P<body>.+)$",
    re.IGNORECASE,
)
SECRULE_RE = re.compile(r'^\s*SecRule\b', re.IGNORECASE)
ID_RE = re.compile(r'\bid:(\d+)\b', re.IGNORECASE)


def parse_meta(line: str) -> Dict[str, str]:
    m = META_RE.search(line)
    if not m:
        return {}
    out: Dict[str, str] = {}
    for part in m.group("body").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip().lower()] = v.strip()
    return out


def scan_file(path: pathlib.Path) -> List[Dict]:
    rules: List[Dict] = []
    current_meta: Dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(text, 1):
        meta = parse_meta(line)
        if meta:
            current_meta = meta
            continue
        if SECRULE_RE.match(line) or line.strip().startswith("SecAction"):
            rid = None
            m = ID_RE.search(line)
            if m:
                rid = m.group(1)
            # 多行规则：向后看几行找 id
            if rid is None:
                chunk = "\n".join(text[i - 1 : i + 8])
                m2 = ID_RE.search(chunk)
                if m2:
                    rid = m2.group(1)
            enabled = current_meta.get("enabled", "true").lower() != "false"
            # 注释掉的规则视为禁用
            if line.lstrip().startswith("#"):
                enabled = False
            rules.append(
                {
                    "file": str(path),
                    "line": i,
                    "id": rid or "unknown",
                    "enabled": enabled,
                    "cve": current_meta.get("cve", ""),
                    "expire": current_meta.get("expire", ""),
                    "priority": int(current_meta.get("priority", "100")),
                }
            )
            current_meta = {}
    return rules


def validate_dir(rule_dir: pathlib.Path) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    files = sorted(rule_dir.glob("*.conf"))
    if not files:
        errors.append(f"目录无 .conf: {rule_dir}")
        return False, errors

    seen_ids = set()
    for f in files:
        content = f.read_text(encoding="utf-8", errors="replace")
        # 基础括号/引号平衡粗检
        if content.count('"') % 2 != 0:
            errors.append(f"{f}: 双引号可能未闭合")
        for rule in scan_file(f):
            rid = rule["id"]
            if rid != "unknown":
                if rid in seen_ids:
                    errors.append(f"重复规则 ID: {rid} @ {f}")
                seen_ids.add(rid)
            # 虚拟补丁过期检查
            exp = rule.get("expire") or ""
            if exp:
                try:
                    d = dt.date.fromisoformat(exp)
                    if d < dt.date.today() and rule["enabled"]:
                        errors.append(
                            f"虚拟补丁已过期但仍启用: id={rid} cve={rule.get('cve')} expire={exp}"
                        )
                except ValueError:
                    errors.append(f"无法解析 expire 日期: {exp} id={rid}")
        # SecRule 行应包含 id:
        for i, line in enumerate(content.splitlines(), 1):
            if SECRULE_RE.match(line) and not line.lstrip().startswith("#"):
                window = "\n".join(content.splitlines()[i - 1 : i + 10])
                if not ID_RE.search(window):
                    errors.append(f"{f}:{i} SecRule 缺少 id")

    return len(errors) == 0, errors


def cmd_list(args: argparse.Namespace) -> int:
    d = pathlib.Path(args.dir)
    all_rules: List[Dict] = []
    for f in sorted(d.glob("*.conf")):
        all_rules.extend(scan_file(f))
    all_rules.sort(key=lambda r: (r["priority"], r["id"]))
    for r in all_rules:
        flag = "ON " if r["enabled"] else "OFF"
        print(
            f"{flag} id={r['id']:<8} pri={r['priority']:<4} "
            f"cve={r['cve'] or '-':<16} expire={r['expire'] or '-':<12} {r['file']}:{r['line']}"
        )
    print(f"total={len(all_rules)}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    ok, errors = validate_dir(pathlib.Path(args.dir))
    for e in errors:
        print(f"[ERROR] {e}", file=sys.stderr)
    if ok:
        print("validate: OK")
        return 0
    print(f"validate: FAIL ({len(errors)} issues)")
    return 1


def _rewrite_rule_block(
    path: pathlib.Path,
    rule_id: str,
    *,
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
) -> bool:
    """按 id 更新 META 并可选注释/取消注释规则块。"""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    changed = False
    meta_idx = -1
    meta: Dict[str, str] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        m = parse_meta(line)
        if m:
            meta_idx = i
            meta = m
            i += 1
            continue
        if not (SECRULE_RE.match(line) or line.lstrip().startswith("SecAction") or line.lstrip().startswith("# SecRule") or line.lstrip().startswith("# SecAction")):
            if line.strip() and not line.lstrip().startswith("#"):
                meta_idx = -1
                meta = {}
            i += 1
            continue

        end = i
        while end < len(lines) and lines[end].rstrip("\n").endswith("\\"):
            end += 1
        window = "".join(lines[i : end + 1])
        mid = ID_RE.search(window)
        if not mid or mid.group(1) != rule_id:
            meta_idx = -1
            meta = {}
            i = end + 1
            continue

        if priority is not None:
            meta["priority"] = str(priority)
        if enabled is not None:
            meta["enabled"] = "true" if enabled else "false"
        if "priority" not in meta:
            meta["priority"] = "100"
        if "enabled" not in meta:
            meta["enabled"] = "true"

        meta_line = "# META: " + "; ".join(f"{k}={v}" for k, v in meta.items()) + "\n"
        if meta_idx >= 0:
            lines[meta_idx] = meta_line
        else:
            lines.insert(i, meta_line)
            end += 1
            i += 1
            meta_idx = i - 1

        if enabled is not None:
            for j in range(i, end + 1):
                raw = lines[j]
                indent = raw[: len(raw) - len(raw.lstrip(" \t"))]
                body = raw[len(indent) :]
                if enabled:
                    if body.startswith("#"):
                        body = body[1:]
                        if body.startswith(" "):
                            body = body[1:]
                        lines[j] = indent + body
                else:
                    if not body.startswith("#"):
                        lines[j] = indent + "# " + body
        changed = True
        meta_idx = -1
        meta = {}
        i = end + 1
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return changed


def cmd_enable(args: argparse.Namespace) -> int:
    d = pathlib.Path(args.dir)
    n = 0
    for f in sorted(d.glob("*.conf")):
        if _rewrite_rule_block(f, args.id, enabled=True):
            n += 1
    print(f"enabled id={args.id} files={n}")
    return 0 if n else 1


def cmd_disable(args: argparse.Namespace) -> int:
    d = pathlib.Path(args.dir)
    n = 0
    for f in sorted(d.glob("*.conf")):
        if _rewrite_rule_block(f, args.id, enabled=False):
            n += 1
    print(f"disabled id={args.id} files={n}")
    return 0 if n else 1


def cmd_set_priority(args: argparse.Namespace) -> int:
    d = pathlib.Path(args.dir)
    n = 0
    for f in sorted(d.glob("*.conf")):
        if _rewrite_rule_block(f, args.id, priority=args.priority):
            n += 1
    print(f"priority id={args.id} pri={args.priority} files={n}")
    return 0 if n else 1


def cmd_disable_expired(args: argparse.Namespace) -> int:
    """将过期虚拟补丁规则整段注释（生成到 --out 或原地）。"""
    d = pathlib.Path(args.dir)
    changed = 0
    for f in sorted(d.glob("*.conf")):
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        meta: Dict[str, str] = {}
        new_lines: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            m = parse_meta(line)
            if m:
                meta = m
                new_lines.append(line)
                i += 1
                continue
            if meta.get("expire") and SECRULE_RE.match(line) and not line.lstrip().startswith("#"):
                try:
                    if dt.date.fromisoformat(meta["expire"]) < dt.date.today():
                        # 注释连续续行
                        while i < len(lines):
                            new_lines.append("# EXPIRED " + lines[i])
                            cont = lines[i].rstrip("\n").endswith("\\")
                            i += 1
                            if not cont:
                                break
                        changed += 1
                        meta = {}
                        continue
                except ValueError:
                    pass
            new_lines.append(line)
            if SECRULE_RE.match(line) or line.strip().startswith("SecAction"):
                meta = {}
            i += 1
        out = pathlib.Path(args.out) / f.name if args.out else f
        if args.out:
            pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
        out.write_text("".join(new_lines), encoding="utf-8")
    print(f"disabled_expired_rules={changed}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Ma-WAF rule manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list")
    pl.add_argument("--dir", required=True)
    pl.set_defaults(func=cmd_list)

    pv = sub.add_parser("validate")
    pv.add_argument("--dir", required=True)
    pv.set_defaults(func=cmd_validate)

    pe = sub.add_parser("disable-expired")
    pe.add_argument("--dir", required=True)
    pe.add_argument("--out", default="")
    pe.set_defaults(func=cmd_disable_expired)

    pen = sub.add_parser("enable", help="启用规则 ID")
    pen.add_argument("--dir", required=True)
    pen.add_argument("--id", required=True)
    pen.set_defaults(func=cmd_enable)

    pdis = sub.add_parser("disable", help="禁用规则 ID（注释 + META）")
    pdis.add_argument("--dir", required=True)
    pdis.add_argument("--id", required=True)
    pdis.set_defaults(func=cmd_disable)

    ppri = sub.add_parser("set-priority", help="设置 META.priority")
    ppri.add_argument("--dir", required=True)
    ppri.add_argument("--id", required=True)
    ppri.add_argument("--priority", type=int, required=True)
    ppri.set_defaults(func=cmd_set_priority)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

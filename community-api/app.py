#!/usr/bin/env python3
"""Ma-WAF Community API — 只提供社区版能力：状态、事件、IP 黑名单。
专业版多站点 / 情报 / SIEM / 合规等不在此实现。
仅依赖 Python 标准库。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("API_HOST", "0.0.0.0")
PORT = int(os.environ.get("API_PORT", "8091"))
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", "/logs/modsec_audit.log"))
RULES_FILE = Path(os.environ.get("RULES_FILE", "/rules/REQUEST-900-ma-waf-community.conf"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
ENGINE_MODE = os.environ.get("MODSEC_RULE_ENGINE", "On")
WAF_PUBLIC_URL = os.environ.get("WAF_PUBLIC_URL", "http://127.0.0.1:8080")
# 容器内探测用（compose 服务名）；控制台展示仍用 WAF_PUBLIC_URL
WAF_INTERNAL_URL = os.environ.get("WAF_INTERNAL_URL", "http://waf:8080").rstrip("/")
DEMO_USER = os.environ.get("DEMO_USER", "admin")
DEMO_PASS = os.environ.get("DEMO_PASS", "admin")
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "200"))

IP_BEGIN = "# BEGIN MA-WAF-IP-DENY"
IP_END = "# END MA-WAF-IP-DENY"
SESSION_TOKENS: dict[str, float] = {}
LOCK = threading.Lock()


def _cors(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")


def _json(handler: BaseHTTPRequestHandler, code: int, payload: dict | list) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    _cors(handler)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _authed(handler: BaseHTTPRequestHandler) -> bool:
    auth = handler.headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        with LOCK:
            exp = SESSION_TOKENS.get(token)
            if exp and exp > time.time():
                return True
    return False


def _issue_token() -> str:
    token = f"c-{os.urandom(16).hex()}"
    with LOCK:
        SESSION_TOKENS[token] = time.time() + 12 * 3600
    return token


def _extract_json_objects(text: str) -> list[dict]:
    objs: list[dict] = []
    # 优先按行解析（Serial JSON 常见）
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            objs.append(json.loads(line))
        except Exception:
            pass
    if objs:
        return objs
    # 回退：扫描平衡花括号
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start : i + 1]
                try:
                    objs.append(json.loads(chunk))
                except Exception:
                    pass
                start = None
    return objs


def _parse_event(obj: dict) -> dict | None:
    tx = obj.get("transaction") or obj
    client = ""
    if isinstance(tx.get("client_ip"), str):
        client = tx["client_ip"]
    elif isinstance(tx.get("remote_address"), str):
        client = tx["remote_address"]
    request = tx.get("request") or {}
    uri = request.get("uri") or request.get("http") or obj.get("request", {}).get("uri") or ""
    method = request.get("method") or ""
    time_stamp = tx.get("time_stamp") or tx.get("time") or obj.get("time_stamp") or ""
    messages = tx.get("messages") or obj.get("messages") or []
    rule_ids: list[str] = []
    msgs: list[str] = []
    severities: list[str] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        details = m.get("details") or {}
        rid = str(details.get("ruleId") or details.get("id") or m.get("ruleId") or "")
        if rid:
            rule_ids.append(rid)
        msg = m.get("message") or details.get("msg") or ""
        if msg:
            msgs.append(str(msg))
        sev = details.get("severity") or m.get("severity") or ""
        if sev:
            severities.append(str(sev))
    response = tx.get("response") or {}
    status = response.get("http_code") or response.get("status") or 0
    if not rule_ids and not msgs and int(status or 0) not in (403, 429, 406):
        # 无规则命中且非拦截态，跳过噪声
        if not obj.get("audit_data"):
            return None
    primary = ""
    for msg in msgs:
        if "Host header is a numeric IP address" in msg:
            continue
        primary = msg
        break
    if not primary and msgs:
        primary = msgs[0]
    # 展示时弱化纯 Host 头噪声规则，优先攻击类 rule id
    show_ids = [r for r in rule_ids if r not in ("920350",)] or rule_ids[:8]
    return {
        "time": time_stamp,
        "client_ip": client,
        "method": method,
        "uri": uri if isinstance(uri, str) else str(uri),
        "status": status,
        "rule_ids": show_ids[:8],
        "message": primary or "ModSecurity event",
        "severity": (severities[0] if severities else ""),
    }


def read_events(limit: int = 50) -> list[dict]:
    if not AUDIT_LOG.exists():
        return []
    try:
        # 只读尾部，避免大文件拖垮社区版
        data = AUDIT_LOG.read_bytes()
        if len(data) > 2_000_000:
            data = data[-2_000_000:]
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    events: list[dict] = []
    for obj in _extract_json_objects(text):
        ev = _parse_event(obj)
        if ev:
            events.append(ev)
    return events[-limit:]


def read_stats() -> dict:
    events = read_events(MAX_EVENTS)
    by_rule: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for e in events:
        for rid in e.get("rule_ids") or ["unknown"]:
            by_rule[rid] = by_rule.get(rid, 0) + 1
        ip = e.get("client_ip") or "unknown"
        by_ip[ip] = by_ip.get(ip, 0) + 1
    top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:8]
    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:8]
    return {
        "event_count": len(events),
        "top_rules": [{"id": k, "count": v} for k, v in top_rules],
        "top_ips": [{"ip": k, "count": v} for k, v in top_ips],
        "engine": ENGINE_MODE,
        "waf_url": WAF_PUBLIC_URL,
        "edition": "community",
        "audit_log_present": AUDIT_LOG.exists(),
        "audit_log_size": AUDIT_LOG.stat().st_size if AUDIT_LOG.exists() else 0,
    }


def read_ip_list() -> list[str]:
    if not RULES_FILE.exists():
        return []
    text = RULES_FILE.read_text(encoding="utf-8", errors="ignore")
    m = re.search(
        re.escape(IP_BEGIN) + r"(.*?)" + re.escape(IP_END),
        text,
        flags=re.S,
    )
    if not m:
        return []
    ips: list[str] = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if "SecRule REMOTE_ADDR" in line and "@ipMatch" in line:
            mm = re.search(r'@ipMatch\s+([0-9a-fA-F\.:/]+)', line)
            if mm:
                ips.append(mm.group(1))
    # 也支持 data 文件
    data_file = DATA_DIR / "ip-blacklist.txt"
    if data_file.exists():
        for line in data_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line not in ips:
                ips.append(line)
    return ips


def _http_status(url: str, headers: dict[str, str] | None = None, timeout: float = 8.0) -> int:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as e:
        return int(e.code)
    except Exception:
        return 0


def run_selftest() -> dict:
    """从 API 容器打到 WAF，生成可在审计日志里看到的拦截样本。"""
    cases = [
        {"name": "normal", "path": "/", "headers": {}, "expect": 200},
        {
            "name": "xss",
            "path": "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "headers": {},
            "expect": 403,
        },
        {
            "name": "sqli",
            "path": "/?id=1%27%20OR%20%271%27%3D%271",
            "headers": {},
            "expect": 403,
        },
        {
            "name": "scanner_ua",
            "path": "/",
            "headers": {"User-Agent": "sqlmap/1.0"},
            "expect": 403,
        },
    ]
    results = []
    for c in cases:
        code = _http_status(WAF_INTERNAL_URL + c["path"], c["headers"])
        results.append(
            {
                "name": c["name"],
                "status": code,
                "expect": c["expect"],
                "ok": code == c["expect"],
            }
        )
    # 给 ModSecurity 一点落盘时间
    time.sleep(0.8)
    return {
        "ok": all(r["ok"] for r in results),
        "engine": ENGINE_MODE,
        "waf_internal": WAF_INTERNAL_URL,
        "waf_url": WAF_PUBLIC_URL,
        "results": results,
        "events": read_events(20),
        "hint": "若引擎为 DetectionOnly，攻击样例可能仍返回 200，但审计日志应有记录。",
    }


def write_ip_list(ips: list[str]) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cleaned: list[str] = []
    for raw in ips:
        ip = str(raw).strip()
        if not ip:
            continue
        if not re.fullmatch(r"[0-9a-fA-F\.:/]+", ip):
            continue
        if ip not in cleaned:
            cleaned.append(ip)
    (DATA_DIR / "ip-blacklist.txt").write_text(
        "\n".join(cleaned) + ("\n" if cleaned else ""),
        encoding="utf-8",
    )
    if not RULES_FILE.exists():
        return {"ok": False, "error": "rules file missing", "restart_required": False}
    text = RULES_FILE.read_text(encoding="utf-8", errors="ignore")
    block_lines = [
        IP_BEGIN,
        "# 由社区控制台维护；专业版可在 Web 中批量/情报联动管理。",
    ]
    rid = 110010
    for ip in cleaned:
        block_lines.append(
            f'SecRule REMOTE_ADDR "@ipMatch {ip}" \\\n'
            f'    "id:{rid},phase:1,deny,status:403,log,msg:\'Ma-WAF Community IP deny\','
            f"tag:'ma-waf-community',severity:'CRITICAL'\""
        )
        rid += 1
    block_lines.append(IP_END)
    block = "\n".join(block_lines) + "\n"
    if IP_BEGIN in text and IP_END in text:
        text = re.sub(
            re.escape(IP_BEGIN) + r".*?" + re.escape(IP_END),
            block.strip(),
            text,
            count=1,
            flags=re.S,
        )
    else:
        text = block + "\n" + text
    RULES_FILE.write_text(text, encoding="utf-8")
    return {
        "ok": True,
        "ips": cleaned,
        "restart_required": True,
        "hint": "规则已写入。请执行: docker compose restart waf",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "MaWAF-CommunityAPI/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        _cors(self)
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/api/health", "/healthz"):
            return _json(self, 200, {"ok": True, "edition": "community"})
        if path == "/api/status":
            return _json(self, 200, read_stats())
        if path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            limit = int((qs.get("limit") or ["50"])[0])
            limit = max(1, min(limit, MAX_EVENTS))
            return _json(self, 200, {"items": read_events(limit)})
        if path == "/api/iplist":
            if not _authed(self):
                return _json(self, 401, {"error": "unauthorized"})
            return _json(self, 200, {"ips": read_ip_list()})
        if path == "/api/edition":
            return _json(
                self,
                200,
                {
                    "edition": "community",
                    "features": {
                        "crs": True,
                        "scanner_ua_block": True,
                        "rate_limit": True,
                        "ip_blacklist": True,
                        "event_dashboard": True,
                        "multi_site": False,
                        "threat_intel": False,
                        "geo_block": False,
                        "siem": False,
                        "compliance_reports": False,
                        "bot_js_challenge": False,
                        "virtual_patch": False,
                    },
                    "upgrade": "/trial.html",
                },
            )
        return _json(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = _read_body(self)
        if path == "/api/login":
            user = str(body.get("username") or "")
            password = str(body.get("password") or "")
            ok = user == DEMO_USER and (password == DEMO_PASS or password == "change")
            if not ok:
                return _json(self, 401, {"error": "用户名或密码错误（默认 admin / admin）"})
            token = _issue_token()
            return _json(self, 200, {"token": token, "edition": "community", "user": DEMO_USER})
        if path == "/api/iplist":
            if not _authed(self):
                return _json(self, 401, {"error": "unauthorized"})
            ips = body.get("ips")
            if not isinstance(ips, list):
                return _json(self, 400, {"error": "ips must be a list"})
            return _json(self, 200, write_ip_list(ips))
        if path == "/api/selftest":
            if not _authed(self):
                return _json(self, 401, {"error": "unauthorized"})
            return _json(self, 200, run_selftest())
        return _json(self, 404, {"error": "not found"})


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    if not AUDIT_LOG.exists():
        AUDIT_LOG.touch()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Ma-WAF Community API on {HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

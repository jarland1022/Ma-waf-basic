#!/usr/bin/env bash
#===============================================================================
# 演示用：向 ModSecurity 审计写入「多国源 IP」攻击事件，丰富报表/国家热力截图。
#
# 说明（必读）:
#   - 仅用于自有 WAF / 已授权测试站的演示与验收截图。
#   - 本机真实 HTTP 请求的 remote_addr 都是实验室 IP（私网），GeoIP 补不到国家码；
#     因此默认向审计日志注入带公网 client_ip + country 的样例事件。
#   - 可选 --live：再对数据面发少量探针（真实拦截日志仍是实验室 IP）。
#
# 用法:
#   sudo ./scripts/demo_geo_attacks.sh
#   sudo ./scripts/demo_geo_attacks.sh --host www.mingansec.com --count 80
#   sudo ./scripts/demo_geo_attacks.sh --live --data-url http://127.0.0.1
#   sudo ./scripts/demo_geo_attacks.sh --clear-demo   # 仅删除本脚本标记的演示行后重写
#
# 环境变量:
#   MA_WAF_PREFIX  默认 /usr/local/Ma-waf
#   AUDIT_LOG      默认 /data/logs/nginx/modsec_audit.json
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
AUDIT_LOG="${AUDIT_LOG:-/data/logs/nginx/modsec_audit.json}"
HOST="${DEMO_HOST:-www.mingansec.com}"
COUNT=60
LIVE=0
DATA_URL="${DATA_URL:-http://127.0.0.1}"
CLEAR_DEMO=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --live) LIVE=1; shift ;;
    --data-url) DATA_URL="$2"; shift 2 ;;
    --audit) AUDIT_LOG="$2"; shift 2 ;;
    --clear-demo) CLEAR_DEMO=1; shift ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "请使用 sudo 运行（需写审计日志）"; exit 1; }

mkdir -p "$(dirname "$AUDIT_LOG")"
touch "$AUDIT_LOG"

if [[ "$CLEAR_DEMO" -eq 1 ]]; then
  if [[ -f "$AUDIT_LOG" ]]; then
    grep -v '"demo_geo_attacks":true' "$AUDIT_LOG" >"${AUDIT_LOG}.tmp" || true
    mv -f "${AUDIT_LOG}.tmp" "$AUDIT_LOG"
    echo "已清除旧演示事件标记行"
  fi
fi

# 公网样例 IP（常见公共服务/文档示例地址，仅用于 Geo 演示；country 字段显式写入，无 MMDB 也能出图）
python3 - "$AUDIT_LOG" "$HOST" "$COUNT" <<'PY'
import json, random, sys, uuid
from datetime import datetime, timezone, timedelta
from collections import Counter

audit_path, host, count = sys.argv[1], sys.argv[2], int(sys.argv[3])

SOURCES = [
    ("US", "8.8.8.8", "Google DNS"),
    ("US", "1.1.1.1", "Cloudflare DNS"),
    ("GB", "51.15.0.1", "EU sample"),
    ("DE", "139.59.1.1", "DE sample"),
    ("FR", "51.158.0.1", "FR sample"),
    ("NL", "45.33.32.156", "NL sample"),
    ("JP", "133.242.0.1", "JP sample"),
    ("KR", "168.126.63.1", "KR DNS"),
    ("SG", "139.180.0.1", "SG sample"),
    ("IN", "103.21.244.0", "IN sample"),
    ("AU", "1.1.1.3", "AU/CF"),
    ("BR", "200.160.0.1", "BR sample"),
    ("RU", "77.88.8.8", "RU sample"),
    ("UA", "91.198.174.192", "UA sample"),
    ("TR", "195.175.39.49", "TR sample"),
    ("AE", "2.49.0.1", "AE sample"),
    ("SA", "212.26.0.1", "SA sample"),
    ("ZA", "196.25.1.1", "ZA sample"),
    ("NG", "41.58.0.1", "NG sample"),
    ("CN", "223.5.5.5", "AliDNS"),
    ("HK", "1.1.1.2", "HK/CF"),
    ("TW", "168.95.1.1", "TW DNS"),
    ("CA", "24.244.4.2", "CA sample"),
    ("MX", "201.148.0.1", "MX sample"),
    ("ES", "80.58.61.250", "ES sample"),
    ("IT", "151.100.0.1", "IT sample"),
    ("SE", "195.67.0.1", "SE sample"),
    ("PL", "194.204.152.34", "PL sample"),
    ("ID", "118.98.0.1", "ID sample"),
    ("VN", "203.162.0.1", "VN sample"),
]

ATTACKS = [
    ("GET", "/?id=1'%20OR%20'1'%3D'1", ["942100", "942110"], "SQL Injection Attempt", "CRITICAL"),
    ("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", ["941100", "941110"], "XSS Attack Detected", "CRITICAL"),
    ("GET", "/../../etc/passwd", ["930100", "930110"], "Path Traversal Attack", "CRITICAL"),
    ("GET", "/?cmd=cat%20/etc/shadow", ["932100"], "OS Command Injection", "CRITICAL"),
    ("POST", "/login", ["942360", "110303"], "Credential stuffing / ATO probe", "WARNING"),
    ("GET", "/.env", ["920420", "930130"], "Sensitive file probe", "WARNING"),
    ("GET", "/wp-admin/install.php", ["920350"], "CMS scanner probe", "NOTICE"),
    ("GET", "/?file=php://filter", ["933100"], "PHP injection probe", "CRITICAL"),
    ("GET", "/api/v1/users?id=1)UNION%20SELECT", ["942190"], "SQLi UNION probe", "CRITICAL"),
    ("GET", "/?redirect=//evil.example/", ["922100"], "Open redirect style probe", "WARNING"),
]

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "curl/8.0.1",
]

random.seed()
now = datetime.now(timezone.utc)
lines = []
for i in range(count):
    cc, ip, note = random.choice(SOURCES)
    method, uri, rules, msg, sev = random.choice(ATTACKS)
    if random.random() < 0.25:
        cc, ip, note = random.choice([s for s in SOURCES if s[0] in ("US", "CN", "RU", "DE", "BR")])
    ts = now - timedelta(minutes=random.randint(0, 12 * 60))
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    uid = f"demo-{uuid.uuid4().hex[:16]}"
    status = 403
    rec = {
        "transaction": {
            "client_ip": ip,
            "time_stamp": ts_str,
            "timestamp": iso,
            "time": iso,
            "host": host,
            "unique_id": uid,
            "request_id": uid,
            "country": cc,
            "geoip_country_code": cc,
            "request": {
                "method": method,
                "uri": uri,
                "http_request_line": f"{method} {uri} HTTP/1.1",
                "headers": {
                    "Host": host,
                    "User-Agent": random.choice(UA_POOL),
                    "X-Demo-Source": note,
                },
            },
            "response": {"http_code": status, "status": status},
            "messages": [
                {
                    "message": msg,
                    "details": {
                        "ruleId": rid,
                        "severity": sev,
                        "file": "REQUEST-DEMO.conf",
                        "data": f"demo geo attack from {cc}",
                    },
                    "ruleId": rid,
                    "severity": sev,
                }
                for rid in rules
            ],
        },
        "demo_geo_attacks": True,
        "demo_note": note,
    }
    lines.append(json.dumps(rec, ensure_ascii=False))

with open(audit_path, "a", encoding="utf-8") as f:
    for ln in lines:
        f.write(ln + "\n")

preview = Counter()
for ln in lines:
    preview[json.loads(ln)["transaction"]["country"]] += 1
print(f"已写入 {len(lines)} 条演示审计 → {audit_path}")
print("国家分布预览:", ", ".join(f"{k}:{v}" for k, v in preview.most_common(12)))
print(f"Host={host}")
PY

if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://127.0.0.1:9090/api/v1/health 2>/dev/null | grep -q 200; then
  echo "提示: API 在线。控制台刷新「报表与分析 / 安全事件」即可（或重启 ma-waf-api 强制索引）。"
else
  echo "WARN: 9090 上 API 未响应；请先修复 ma-waf-api 后再看报表（审计文件已写好）。"
fi

if [[ "$LIVE" -eq 1 ]]; then
  echo "---- 可选 live 探针（源 IP 仍是本机，主要用于真实拦截页）----"
  for path in \
    "/?id=1'%20OR%20'1'%3D'1" \
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E" \
    "/../../etc/passwd"
  do
    code=$(curl -4 --http1.1 -sS -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 8 \
      -H "Host: ${HOST}" -A "Ma-WAF-DemoGeo/1.0" "${DATA_URL%/}${path}" || echo 000)
    echo "  live ${path:0:40}... -> HTTP $code"
  done
fi

echo
echo "完成。打开控制台 → 监控 → 报表与分析 / 安全事件，Ctrl+F5。"
echo "若国家仍为空：安装 Country MMDB 后重启 API："
echo "  sudo ${PREFIX}/scripts/update_geoip.sh --country-db /path/GeoLite2-Country.mmdb"
echo "  sudo systemctl restart ma-waf-api"
echo "本脚本已在每条事件写入 country 字段，通常无 MMDB 也能出热力。"

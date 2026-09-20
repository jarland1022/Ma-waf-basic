#!/usr/bin/env bash
#==============================================================================
# 轻量资源/攻击量告警 + 可选定时自动加黑（systemd timer）
#==============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
LOG="${PREFIX}/var/log/alert_check.log"
STATE="${PREFIX}/var/lib/alert_state"
OPS="${PREFIX}/var/lib/ops.json"
WEBHOOK="${MA_WAF_ALERT_WEBHOOK:-}"
API_HEALTH="${MA_WAF_METRICS_URL:-http://127.0.0.1:9090/api/v1/health}"
CRON_URL="${MA_WAF_CRON_AUTOBLOCK_URL:-http://127.0.0.1:9090/api/v1/cron/autoblock}"
AUDIT_LOG="${MA_WAF_AUDIT_LOG:-/data/logs/nginx/modsec_audit.json}"

LOAD_MAX="${ALERT_LOAD_MAX:-8}"
MEM_PCT_MAX="${ALERT_MEM_PCT_MAX:-90}"
NGINX_ACTIVE_MAX="${ALERT_NGINX_ACTIVE_MAX:-5000}"

mkdir -p "$(dirname "$LOG")" "$(dirname "$STATE")"
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

read_ops() {
  OPS_WEBHOOK=""; OPS_CRON_TOKEN=""; OPS_AUTOBLOCK_ENABLED="0"; OPS_ATTACK_MIN="100"; OPS_SIEM_ADDR=""; OPS_SIEM_PROTO="udp"
  if [[ -f "$OPS" ]]; then
    eval "$(OPS_FILE="$OPS" python3 - <<'PY'
import json, os
d={}
try:
  d=json.load(open(os.environ["OPS_FILE"]))
except Exception:
  pass
def esc(s):
  return str(s or "").replace("\\","\\\\").replace("'","'\\''")
print("OPS_WEBHOOK='%s'" % esc(d.get("alert_webhook")))
print("OPS_CRON_TOKEN='%s'" % esc(d.get("cron_token")))
print("OPS_AUTOBLOCK_ENABLED='%s'" % ("1" if d.get("autoblock_enabled") else "0"))
amin = d.get("attack_alert_min")
print("OPS_ATTACK_MIN='%s'" % (amin if amin is not None else 100))
print("OPS_SIEM_ADDR='%s'" % esc(d.get("siem_addr")))
print("OPS_SIEM_PROTO='%s'" % esc(d.get("siem_proto") or "udp"))
PY
)" || true
  fi
}

read_ops
if [[ -z "$WEBHOOK" ]]; then WEBHOOK="$OPS_WEBHOOK"; fi
if [[ -z "$WEBHOOK" && -f "${PREFIX}/conf/api.yaml" ]]; then
  WEBHOOK="$(awk -F'"' '/^alert_webhook:/{print $2}' "${PREFIX}/conf/api.yaml" 2>/dev/null || true)"
fi

alerts=()

if [[ -f /proc/loadavg ]]; then
  load1="$(awk '{print $1}' /proc/loadavg)"
  awk -v l="$load1" -v m="$LOAD_MAX" 'BEGIN{exit !(l+0 > m+0)}' && alerts+=("high_load1=${load1}") || true
fi

if [[ -f /proc/meminfo ]]; then
  eval "$(awk '/MemTotal:/{t=$2} /MemAvailable:/{a=$2} END{if(t>0) printf "MEM_PCT=%.1f\n", (t-a)*100/t}' /proc/meminfo)"
  if [[ -n "${MEM_PCT:-}" ]]; then
    awk -v p="$MEM_PCT" -v m="$MEM_PCT_MAX" 'BEGIN{exit !(p+0 > m+0)}' && alerts+=("high_mem_pct=${MEM_PCT}") || true
  fi
fi

if curl -fsS --max-time 2 http://127.0.0.1:8081/nginx_status >/tmp/ma-waf-nginx-status.$$ 2>/dev/null; then
  active="$(awk '/Active connections/{print $3}' /tmp/ma-waf-nginx-status.$$)"
  rm -f /tmp/ma-waf-nginx-status.$$
  if [[ -n "$active" ]]; then
    awk -v a="$active" -v m="$NGINX_ACTIVE_MAX" 'BEGIN{exit !(a+0 > m+0)}' && alerts+=("high_nginx_active=${active}") || true
  fi
fi

if ! curl -fsS --max-time 2 "$API_HEALTH" >/dev/null 2>&1; then
  alerts+=("api_health_down")
fi

# 攻击量：审计文件尾部行数近似（JSON 每事件一行或块；宽松统计含 transaction 的行）
ATTACK_MIN="${ALERT_ATTACK_MIN:-$OPS_ATTACK_MIN}"
if [[ -f "$AUDIT_LOG" && "${ATTACK_MIN}" =~ ^[0-9]+$ && "$ATTACK_MIN" -gt 0 ]]; then
  atk="$(tail -n 2000 "$AUDIT_LOG" 2>/dev/null | grep -c 'transaction' || true)"
  atk="${atk:-0}"
  if awk -v a="$atk" -v m="$ATTACK_MIN" 'BEGIN{exit !(a+0 >= m+0)}'; then
    alerts+=("high_attack_events=${atk}")
  fi
fi

# 定时自动加黑（需 ops.autoblock_enabled + cron_token）
if [[ "$OPS_AUTOBLOCK_ENABLED" == "1" && -n "$OPS_CRON_TOKEN" ]]; then
  ab_out="$(curl -fsS --max-time 15 -X POST -H "X-Ma-Waf-Cron: ${OPS_CRON_TOKEN}" "$CRON_URL" 2>/dev/null || echo fail)"
  log "cron_autoblock: ${ab_out}"
fi

# 定时清理过期威胁情报（有 cron_token 即执行）
INTEL_URL="${MA_WAF_CRON_INTEL_URL:-http://127.0.0.1:9090/api/v1/cron/intel-expire}"
if [[ -n "$OPS_CRON_TOKEN" ]]; then
  ie_out="$(curl -fsS --max-time 15 -X POST -H "X-Ma-Waf-Cron: ${OPS_CRON_TOKEN}" "$INTEL_URL" 2>/dev/null || echo fail)"
  log "cron_intel_expire: ${ie_out}"
fi

send_webhook() {
  local msg="$1"
  [[ -z "$WEBHOOK" ]] && return 0
  curl -fsS -X POST -H 'Content-Type: application/json' \
    -d "{\"text\":\"${msg}\"}" "$WEBHOOK" >>"$LOG" 2>&1 || log "webhook 发送失败"
}

send_siem() {
  local msg="$1"
  [[ -z "${OPS_SIEM_ADDR:-}" ]] && return 0
  local proto="${OPS_SIEM_PROTO:-udp}"
  python3 - "$proto" "$OPS_SIEM_ADDR" "$msg" <<'PY' >>"$LOG" 2>&1 || log "siem 发送失败"
import socket, sys
proto, addr, msg = sys.argv[1], sys.argv[2], sys.argv[3]
host, _, port = addr.rpartition(":")
port = int(port or 514)
kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
s = socket.socket(socket.AF_INET, kind)
s.settimeout(3)
cef = "CEF:0|Ma-WAF|WAF|1.0|100|%s|5|msg=%s\n" % (msg.replace("|"," "), msg.replace("|"," "))
if proto == "udp":
    s.sendto(cef.encode(), (host, port))
else:
    s.connect((host, port))
    s.sendall(cef.encode())
s.close()
PY
}

if [[ ${#alerts[@]} -eq 0 ]]; then
  echo "ok $(date -Iseconds)" >"$STATE"
  exit 0
fi

msg="Ma-WAF ALERT: ${alerts[*]}"
log "$msg"
echo "$msg" >"$STATE"
send_webhook "$msg"
send_siem "$msg"
exit 1

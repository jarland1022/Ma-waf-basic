#!/usr/bin/env bash
# 威胁情报更新：将 IOC IP 列表转换为 nginx geo 黑名单并 reload
# 用法: sudo ./update_threat_intel.sh /path/to/ip_list.txt
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
OUT="${NGINX_PREFIX}/conf/geo/blacklist_ips.conf"
SRC="${1:-}"
LOG="${PREFIX}/var/log/threat_intel.log"

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
[[ $EUID -eq 0 ]] || { echo "need root"; exit 1; }
[[ -n "$SRC" && -f "$SRC" ]] || { echo "用法: $0 ip_list.txt"; exit 1; }

mkdir -p "$(dirname "$LOG")" "${PREFIX}/backups"
tmp="$(mktemp)"
{
  echo "# generated $(date -Iseconds) from $SRC"
  # 支持纯 IP 或 CSV 第一列
  awk -F'[,;[:space:]]+' 'NF>=1 && $1 ~ /^[0-9a-fA-F:.]+$/ {print $1" 1;"}' "$SRC" | sort -u
} >"$tmp"

# 语法粗检：每行 IP 1;
if ! awk '/^#/||/^$/{next} $2!="1;"{exit 1}' "$tmp"; then
  log "格式校验失败"; rm -f "$tmp"; exit 1
fi

cp -a "$OUT" "${PREFIX}/backups/blacklist-$(date +%Y%m%d%H%M%S).conf" 2>/dev/null || true
install -m 644 "$tmp" "$OUT"
rm -f "$tmp"

CTL="${PREFIX}/scripts/waf_ctl.sh"
[[ -x "$CTL" ]] || CTL="$(dirname "$0")/waf_ctl.sh"
"$CTL" reload
log "威胁情报黑名单已更新: $OUT"

# cron/timer 示例（不自动安装）:
# * */6 * * * root ${PREFIX}/scripts/update_threat_intel.sh /path/ioc_ips.txt


#!/usr/bin/env bash
#===============================================================================
# 确保 Nginx stub_status（127.0.0.1:8081/nginx_status）可用
# 供 ma-waf-api 采集 Active 连接等指标；缺文件时控制台 Nginx Active 为空
# 用法: sudo ./ensure_nginx_status.sh [--check-only] [--no-reload]
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
STATUS_DST="${NGINX_PREFIX}/conf/conf.d/00-status.conf"
STATUS_URL="${NGINX_STATUS_URL:-http://127.0.0.1:8081/nginx_status}"
CHECK_ONLY=0
NO_RELOAD=0

for a in "$@"; do
  case "$a" in
    --check-only) CHECK_ONLY=1 ;;
    --no-reload) NO_RELOAD=1 ;;
    -h|--help)
      echo "用法: sudo $0 [--check-only] [--no-reload]"
      exit 0
      ;;
  esac
done

find_src() {
  local c
  for c in \
    "${PREFIX}/nginx/conf.d/00-status.conf" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/nginx/conf.d/00-status.conf"
  do
    if [[ -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

ok() { echo "OK: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
warn() { echo "WARN: $*"; }

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  if [[ ! -f "$STATUS_DST" ]]; then
    fail "缺少 $STATUS_DST （请运行: sudo ${PREFIX}/scripts/ensure_nginx_status.sh）"
  fi
  if ! curl -fsS --max-time 2 "$STATUS_URL" >/dev/null 2>&1; then
    fail "无法访问 $STATUS_URL （文件存在但未监听，请 nginx -t && reload）"
  fi
  ok "stub_status 可达: $STATUS_URL"
  curl -sS --max-time 2 "$STATUS_URL" || true
  exit 0
fi

SRC="$(find_src)" || fail "仓库中找不到 nginx/conf.d/00-status.conf（请先 git pull）"

mkdir -p "$(dirname "$STATUS_DST")"
install -m 644 "$SRC" "$STATUS_DST"
ok "已安装 $STATUS_DST （来自 $SRC）"

# 主配置需 include conf.d
if [[ -f "${NGINX_PREFIX}/conf/nginx.conf" ]]; then
  if ! grep -Eq 'include[[:space:]].*conf\.d' "${NGINX_PREFIX}/conf/nginx.conf"; then
    warn "nginx.conf 可能未 include conf.d/*.conf，请人工确认"
  fi
fi

NGINX_BIN="${NGINX_PREFIX}/sbin/nginx"
[[ -x "$NGINX_BIN" ]] || NGINX_BIN="$(command -v nginx || true)"
[[ -n "${NGINX_BIN}" && -x "$NGINX_BIN" ]] || fail "找不到 nginx 二进制"

if ! "$NGINX_BIN" -t 2>&1; then
  fail "nginx -t 失败。若提示 unknown directive stub_status，需带 --with-http_stub_status_module 重编 nginx"
fi

if [[ "$NO_RELOAD" -eq 0 ]]; then
  "$NGINX_BIN" -s reload
  ok "已 reload nginx"
  sleep 0.3
fi

if curl -fsS --max-time 2 "$STATUS_URL" >/tmp/ma-waf-nginx-status.$$ 2>/dev/null; then
  ok "stub_status 正常"
  cat /tmp/ma-waf-nginx-status.$$
  rm -f /tmp/ma-waf-nginx-status.$$
else
  rm -f /tmp/ma-waf-nginx-status.$$
  fail "reload 后仍无法访问 $STATUS_URL。检查: ss -lntp | grep 8081"
fi

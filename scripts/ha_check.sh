#!/usr/bin/env bash
# Keepalived 健康检查：Nginx 与关键健康端点可用则返回 0
set -euo pipefail
NGINX_BIN="${NGINX_BIN:-/usr/local/nginx/sbin/nginx}"
# 进程存在
pgrep -x nginx >/dev/null || exit 1
# 配置可解析
"$NGINX_BIN" -t >/dev/null 2>&1 || exit 1
# 本机健康
curl -fsS --max-time 2 http://127.0.0.1/waf-health >/dev/null 2>&1 || \
  curl -fsS --max-time 2 http://127.0.0.1:8081/healthz >/dev/null 2>&1 || exit 1
exit 0

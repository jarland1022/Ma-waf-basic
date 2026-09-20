#!/usr/bin/env bash
# 应用 IP 黑名单：重启 waf 使 REQUEST-900 规则生效
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose restart waf
echo "已重启 waf。黑名单规则应已生效。"

#!/usr/bin/env bash
# API 启动前完整性校验包装（由 systemd ExecStartPre 调用）
# 环境: MA_WAF_PREFIX, MA_WAF_INTEGRITY_CHECK=1|0（默认 1 告警不阻断；=strict 失败则退出非 0）
set -euo pipefail
resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}
PREFIX="$(resolve_prefix)"
MODE="${MA_WAF_INTEGRITY_CHECK:-1}"
[[ "$MODE" == "0" || "$MODE" == "off" ]] && exit 0

BASELINE="${PREFIX}/var/lib/integrity-baseline.json"
TOOL="${PREFIX}/tools/integrity_check.py"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"

if [[ ! -f "$TOOL" ]]; then
  echo "[integrity] WARN: missing $TOOL"
  [[ "$MODE" == "strict" ]] && exit 1
  exit 0
fi
if [[ ! -f "$BASELINE" ]]; then
  echo "[integrity] WARN: no baseline, run: python3 $TOOL --init --root $NGINX_PREFIX --product $PREFIX --out $BASELINE"
  [[ "$MODE" == "strict" ]] && exit 1
  exit 0
fi

set +e
python3 "$TOOL" --check --baseline "$BASELINE" --root "$NGINX_PREFIX" --product "$PREFIX"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  echo "[integrity] FAIL rc=$rc"
  logger -t ma-waf-integrity "integrity check failed rc=$rc" || true
  [[ "$MODE" == "strict" ]] && exit "$rc"
  exit 0
fi
echo "[integrity] OK"
exit 0

#!/usr/bin/env bash
# 在线/离线规则更新（CRS + 自定义包）
# 用法:
#   sudo ./update_rules.sh --online
#   sudo ./update_rules.sh --offline /path/to/rules_bundle.tgz
#   sudo ./update_rules.sh --crs-only [--offline ...]
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
STAGE="${PREFIX}/rules/staging"
LOG="${PREFIX}/var/log/update_rules.log"
STRICT="${MA_WAF_STRICT_AUTH:-0}"
CRS_ONLY=0

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
err(){ log "ERROR $*"; exit 1; }
[[ $EUID -eq 0 ]] || err "need root"

MODE=""; BUNDLE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --online) MODE=online; shift ;;
    --offline) MODE=offline; BUNDLE="$2"; shift 2 ;;
    --crs-only) CRS_ONLY=1; shift ;;
    *) err "unknown $1" ;;
  esac
done
[[ -n "$MODE" ]] || err "指定 --online 或 --offline DIR/TGZ"

mkdir -p "$STAGE" "$(dirname "$LOG")"
CTL="${PREFIX}/scripts/waf_ctl.sh"
[[ -x "$CTL" ]] || CTL="$(dirname "$0")/waf_ctl.sh"
"$CTL" backup

install_crs() {
  local args=()
  if [[ "$MODE" == "offline" && -n "$BUNDLE" ]]; then
    # bundle 可为完整 CRS tar 或含 crs/ 子目录的交付包
    if [[ -d "$BUNDLE/crs" ]]; then
      args+=(--offline "$BUNDLE/crs")
    elif [[ -f "$BUNDLE" ]] || [[ -d "$BUNDLE" ]]; then
      args+=(--offline "$BUNDLE")
    fi
  fi
  "${PREFIX}/scripts/install_crs.sh" "${args[@]}" || "$(dirname "$0")/install_crs.sh" "${args[@]}"
}

if [[ "$MODE" == "offline" ]]; then
  [[ -e "$BUNDLE" ]] || err "bundle 不存在"
  tmp=$(mktemp -d)
  if [[ -d "$BUNDLE" ]]; then
    cp -a "$BUNDLE"/. "$tmp/"
  else
    if [[ -f "${BUNDLE}.sig" && -f "${PREFIX}/conf/update-pubkey.pem" ]]; then
      openssl dgst -sha256 -verify "${PREFIX}/conf/update-pubkey.pem" \
        -signature "${BUNDLE}.sig" "$BUNDLE" || err "签名验证失败"
      log "签名验证通过"
    else
      if [[ "$STRICT" == "1" ]]; then
        err "STRICT: 缺少 ${BUNDLE}.sig 或 conf/update-pubkey.pem，拒绝更新"
      fi
      log "WARN: 未执行签名验证（缺少 .sig 或公钥）"
    fi
    tar -xzf "$BUNDLE" -C "$tmp"
  fi
  [[ -d "$tmp/custom" ]] && cp -a "$tmp/custom"/. "$STAGE/"
  if [[ -d "$tmp/rules" ]]; then
    cp -a "$tmp/rules"/. "${NGINX_PREFIX}/conf/modsecurity/rules/"
  elif [[ -d "$tmp/crs" ]] || [[ "$CRS_ONLY" -eq 1 ]]; then
    install_crs
  fi
  # 若 rules 仍为占位则尝试装 CRS
  if [[ -f "${NGINX_PREFIX}/conf/modsecurity/rules/000-placeholder.conf" ]]; then
    n="$(find "${NGINX_PREFIX}/conf/modsecurity/rules" -maxdepth 1 -name '*.conf' | wc -l)"
    if [[ "$n" -le 1 ]]; then
      log "检测到 CRS 占位，尝试安装..."
      install_crs || true
    fi
  fi
  rm -rf "$tmp"
else
  log "在线模式：安装/更新 OWASP CRS"
  install_crs
fi

if [[ "$CRS_ONLY" -eq 1 ]]; then
  "$CTL" reload
  log "CRS-only 更新完成"
  exit 0
fi

python3 "${PREFIX}/tools/rule_manager.py" validate --dir "$STAGE" || err "staging 校验失败"
python3 "${PREFIX}/tools/rule_manager.py" disable-expired --dir "$STAGE"
"$CTL" rules promote
python3 "${PREFIX}/tools/integrity_check.py" --init \
  --root "$NGINX_PREFIX" --product "$PREFIX" \
  --out "${PREFIX}/var/lib/integrity-baseline.json" || true
log "规则更新完成"

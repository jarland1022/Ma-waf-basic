#!/usr/bin/env bash
#===============================================================================
# Ma-WAF 自身完整性校验 (verify_waf.sh)
# 用法: sudo ./verify_waf.sh [--json] [--allow-placeholder]
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

readonly PREFIX="$(resolve_prefix)"
readonly NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
readonly BASELINE="${PREFIX}/var/lib/integrity-baseline.json"
readonly LOG_FILE="${PREFIX}/var/log/verify_waf.log"
JSON_OUT=0
ALLOW_PLACEHOLDER=0
FAILS=0

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
fail() { log "FAIL: $*"; FAILS=$((FAILS+1)); }
ok()   { log "OK: $*"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json) JSON_OUT=1; shift ;;
      --allow-placeholder) ALLOW_PLACEHOLDER=1; shift ;;
      *) echo "未知参数 $1"; exit 1 ;;
    esac
  done
}

check_baseline() {
  if [[ ! -f "$BASELINE" ]]; then
    fail "缺少完整性基线: $BASELINE （请先 deploy 或 integrity_check.py --init）"
    return
  fi
  if python3 "${PREFIX}/tools/integrity_check.py" --verify --baseline "$BASELINE"; then
    ok "文件完整性基线匹配"
  else
    fail "文件完整性校验未通过（可能被篡改或未授权变更）"
  fi
}

check_immutable() {
  command -v lsattr >/dev/null 2>&1 || { log "WARN: 无 lsattr"; return; }
  local f="${NGINX_PREFIX}/sbin/nginx"
  if [[ -f "$f" ]]; then
    if lsattr "$f" 2>/dev/null | grep -q 'i'; then
      ok "nginx 二进制已设置不可变属性"
    else
      fail "nginx 二进制未锁定 chattr +i"
    fi
  fi
}

check_process_user() {
  if pgrep -x nginx >/dev/null 2>&1; then
    if ps -o user= -C nginx | grep -qv '^root$'; then
      ok "存在非 root 的 nginx worker"
    else
      fail "未发现非 root nginx worker，请检查 user 指令"
    fi
  else
    fail "nginx 进程未运行"
  fi
}

check_mgmt_bind() {
  if command -v ss >/dev/null 2>&1; then
    if ss -lntp | grep -E ':9090' | grep -qE '127\.0\.0\.1|::1'; then
      ok "ma-waf-api 监听本地"
    elif ss -lntp | grep -qE ':9090'; then
      fail "ma-waf-api 可能对非本地址暴露，请检查绑定"
    else
      log "WARN: 未检测到 9090 监听（API 未启动？）"
    fi
  fi
}

check_engine_mode() {
  if [[ -f "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf" ]]; then
    local mode
    mode="$(grep -E '^SecRuleEngine' "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf" | awk '{print $2}')"
    ok "SecRuleEngine=${mode:-unknown}"
  else
    fail "缺少 modsecurity.conf"
  fi
}

check_permissions() {
  local conf="${NGINX_PREFIX}/conf/nginx.conf"
  if [[ -f "$conf" ]]; then
    local mode
    mode="$(stat -c '%a' "$conf" 2>/dev/null || stat -f '%OLp' "$conf")"
    if [[ "$mode" == "644" || "$mode" == "640" || "$mode" == "600" ]]; then
      ok "nginx.conf 权限 $mode"
    else
      fail "nginx.conf 权限过宽: $mode"
    fi
  fi
}

check_crs() {
  local rules="${NGINX_PREFIX}/conf/modsecurity/rules"
  local n=0
  if [[ -d "$rules" ]]; then
    n="$(find "$rules" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if [[ "$n" -le 1 ]] && [[ -f "$rules/000-placeholder.conf" ]]; then
    if [[ "$ALLOW_PLACEHOLDER" -eq 1 ]]; then
      log "WARN: 仅 CRS 占位规则（开发例外 --allow-placeholder）"
    else
      fail "CRS 未安装（仅 000-placeholder.conf）。请: scripts/install_crs.sh 或 update_rules.sh --online"
    fi
  elif [[ "$n" -ge 5 ]]; then
    ok "CRS/规则文件数量=$n"
  else
    fail "规则目录异常，conf 数量=$n"
  fi
}

check_license_layout() {
  local pub="${PREFIX}/conf/license/ma-waf-public.pem"
  if [[ -f "$pub" ]]; then
    ok "License 公钥存在"
  else
    log "WARN: 缺少 License 公钥 $pub（宽限期可用，生产请部署）"
  fi
  if [[ -f "${NGINX_PREFIX}/conf/modsecurity/custom/000-exceptions.conf" ]]; then
    ok "例外策略文件存在"
  else
    log "WARN: 缺少 000-exceptions.conf"
  fi
}

check_stub_status() {
  local conf="${NGINX_PREFIX}/conf/conf.d/00-status.conf"
  local url="http://127.0.0.1:8081/nginx_status"
  if [[ ! -f "$conf" ]]; then
    fail "缺少 stub_status 配置 $conf （修复: sudo ${PREFIX}/scripts/ensure_nginx_status.sh）"
    return
  fi
  if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
    ok "nginx stub_status 可达 ($url)"
  else
    fail "8081/nginx_status 不可达（文件在但未生效）。修复: sudo ${PREFIX}/scripts/ensure_nginx_status.sh"
  fi
}

main() {
  parse_args "$@"
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  log "======== WAF 完整性校验 ========"
  check_baseline
  check_immutable
  check_process_user
  check_mgmt_bind
  check_engine_mode
  check_permissions
  check_crs
  check_license_layout
  check_stub_status

  if [[ $JSON_OUT -eq 1 ]]; then
    printf '{"ok":%s,"failures":%d,"ts":"%s"}\n' \
      "$([[ $FAILS -eq 0 ]] && echo true || echo false)" "$FAILS" "$(date -Iseconds)"
  fi

  if [[ $FAILS -eq 0 ]]; then
    log "======== 全部通过 ========"
    exit 0
  else
    log "======== 失败项: $FAILS ========"
    exit 2
  fi
}

main "$@"

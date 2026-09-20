#!/usr/bin/env bash
#===============================================================================
# Ma-WAF 运维控制脚本 (waf_ctl.sh)
# 用法:
#   waf_ctl.sh {start|stop|reload|status|mode|rollback|backup|metrics|rules|test}
#===============================================================================
set -euo pipefail

readonly PREFIX="${MA_WAF_PREFIX:-}"
# shellcheck disable=SC2155
: "${PREFIX:=$( [[ -d /usr/local/Ma-waf ]] && echo /usr/local/Ma-waf || echo /usr/local/ma-waf )}"
# 上面在某些 bash 下不便，改用显式:
if [[ -z "${MA_WAF_PREFIX:-}" ]]; then
  if [[ -d /usr/local/Ma-waf ]]; then PREFIX=/usr/local/Ma-waf; else PREFIX=/usr/local/ma-waf; fi
else
  PREFIX="${MA_WAF_PREFIX}"
fi
readonly PREFIX
readonly NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
readonly NGINX_BIN="${NGINX_PREFIX}/sbin/nginx"
readonly MODSEC_CONF="${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf"
readonly BACKUP_DIR="${PREFIX}/backups"
readonly LOG_FILE="${PREFIX}/var/log/waf_ctl.log"
readonly TS="$(date +%Y%m%d%H%M%S)"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
err() { log "ERROR: $*"; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || err "需要 root"; }

usage() {
  cat <<EOF
Ma-WAF 运维工具
  start|stop|restart     启停 Nginx (+ API)
  reload                 配置检测后优雅重载
  status                 状态一览
  test                   nginx -t + 规则校验
  mode <On|DetectionOnly|Off>   切换 SecRuleEngine
  backup                 备份当前配置与规则
  rollback [timestamp]   回滚到指定/最近备份
  metrics                简易性能/拦截指标
  rules {list|promote|validate|enable <id>|disable <id>|set-priority <id> <n>}
  unlock-immutable       更新前解除 chattr +i
  lock-immutable         更新后重新锁定
EOF
}

cmd_start() {
  need_root
  systemctl start nginx
  systemctl start ma-waf-api 2>/dev/null || true
  log "已启动"
}

cmd_stop() {
  need_root
  systemctl stop ma-waf-api 2>/dev/null || true
  systemctl stop nginx
  log "已停止"
}

cmd_restart() {
  need_root
  systemctl restart nginx
  systemctl restart ma-waf-api 2>/dev/null || true
  log "已重启"
}

cmd_test() {
  "$NGINX_BIN" -t
  python3 "${PREFIX}/tools/rule_manager.py" validate \
    --dir "${NGINX_PREFIX}/conf/modsecurity/custom" || err "规则校验失败"
  log "检测通过"
}

cmd_reload() {
  need_root
  cmd_backup
  cmd_test
  if ! "$NGINX_BIN" -s reload; then
    log "reload 失败，尝试自动回滚..."
    cmd_rollback
    err "reload 失败并已回滚"
  fi
  log "reload 成功"
}

cmd_status() {
  echo "=== systemd ==="
  systemctl is-active nginx || true
  systemctl is-active ma-waf-api 2>/dev/null || echo "ma-waf-api: n/a"
  echo "=== SecRuleEngine ==="
  grep -E '^SecRuleEngine' "$MODSEC_CONF" 2>/dev/null || true
  echo "=== 连接 ==="
  ss -s 2>/dev/null | head -n 5 || true
  echo "=== 健康检查 ==="
  curl -fsS http://127.0.0.1/waf-health 2>/dev/null || echo "health endpoint unreachable"
}

cmd_mode() {
  need_root
  local m="${1:-}"
  [[ "$m" =~ ^(On|DetectionOnly|Off)$ ]] || err "mode 必须是 On|DetectionOnly|Off"
  cmd_backup
  # 更新前若文件被 +i 锁定则临时解锁
  chattr -i "$MODSEC_CONF" 2>/dev/null || true
  sed -i -E "s/^SecRuleEngine\s+.*/SecRuleEngine ${m}/" "$MODSEC_CONF"
  cmd_reload
  log "SecRuleEngine => ${m}"
}

cmd_backup() {
  need_root
  local dest="${BACKUP_DIR}/cfg-${TS}"
  mkdir -p "$dest"
  cp -a "${NGINX_PREFIX}/conf" "$dest/nginx-conf"
  cp -a "${PREFIX}/rules" "$dest/rules" 2>/dev/null || true
  echo "$TS" >"${BACKUP_DIR}/LATEST"
  log "备份完成: $dest"
}

cmd_rollback() {
  need_root
  local stamp="${1:-}"
  [[ -n "$stamp" ]] || stamp="$(cat "${BACKUP_DIR}/LATEST" 2>/dev/null || true)"
  [[ -n "$stamp" ]] || err "无可用备份"
  local src="${BACKUP_DIR}/cfg-${stamp}"
  [[ -d "$src/nginx-conf" ]] || err "备份不存在: $src"
  chattr -i "${NGINX_PREFIX}/conf/nginx.conf" 2>/dev/null || true
  chattr -R -i "${NGINX_PREFIX}/conf" 2>/dev/null || true
  cp -a "$src/nginx-conf/." "${NGINX_PREFIX}/conf/"
  [[ -d "$src/rules" ]] && cp -a "$src/rules/." "${PREFIX}/rules/"
  "$NGINX_BIN" -t && "$NGINX_BIN" -s reload
  log "已回滚到 $stamp"
}

cmd_metrics() {
  local access="/data/logs/nginx/access.json"
  local audit="/data/logs/nginx/modsec_audit.json"
  echo "=== 近量访问（行数近似）==="
  [[ -f "$access" ]] && wc -l "$access" || echo "no access log"
  echo "=== 审计事件 ==="
  [[ -f "$audit" ]] && wc -l "$audit" || echo "no audit log"
  if [[ -f "$access" ]]; then
    python3 - <<'PY'
import json, collections, pathlib
p=pathlib.Path("/data/logs/nginx/access.json")
st=collections.Counter(); n=0; t=0.0
for line in p.open(errors="ignore"):
    line=line.strip()
    if not line: continue
    try:
        o=json.loads(line)
    except Exception:
        continue
    n+=1
    st[str(o.get("status"))]+=1
    try: t+=float(o.get("request_time") or 0)
    except Exception: pass
print(f"samples={n} avg_request_time={t/n if n else 0:.4f}s")
print("status_top=", st.most_common(5))
PY
  fi
  curl -fsS http://127.0.0.1:9090/api/v1/metrics 2>/dev/null || true
}

cmd_rules() {
  local sub="${1:-list}"
  shift || true
  case "$sub" in
    list) python3 "${PREFIX}/tools/rule_manager.py" list --dir "${PREFIX}/rules/active" ;;
    validate) python3 "${PREFIX}/tools/rule_manager.py" validate --dir "${PREFIX}/rules/staging" ;;
    enable)
      need_root
      local rid="${1:?rule id}"
      python3 "${PREFIX}/tools/rule_manager.py" enable --dir "${PREFIX}/rules/active" --id "${rid}"
      python3 "${PREFIX}/tools/rule_manager.py" enable --dir "${NGINX_PREFIX}/conf/modsecurity/custom" --id "${rid}" || true
      cmd_reload
      ;;
    disable)
      need_root
      local rid="${1:?rule id}"
      python3 "${PREFIX}/tools/rule_manager.py" disable --dir "${PREFIX}/rules/active" --id "${rid}"
      python3 "${PREFIX}/tools/rule_manager.py" disable --dir "${NGINX_PREFIX}/conf/modsecurity/custom" --id "${rid}" || true
      cmd_reload
      ;;
    set-priority)
      need_root
      local rid="${1:?rule id}"
      local pri="${2:?priority}"
      python3 "${PREFIX}/tools/rule_manager.py" set-priority --dir "${PREFIX}/rules/active" --id "${rid}" --priority "${pri}"
      python3 "${PREFIX}/tools/rule_manager.py" set-priority --dir "${NGINX_PREFIX}/conf/modsecurity/custom" --id "${rid}" --priority "${pri}" || true
      ;;
    promote)
      need_root
      python3 "${PREFIX}/tools/rule_manager.py" validate --dir "${PREFIX}/rules/staging" || err "staging 校验失败"
      cmd_backup
      cp -a "${PREFIX}/rules/staging/." "${PREFIX}/rules/active/"
      cp -a "${PREFIX}/rules/active/." "${NGINX_PREFIX}/conf/modsecurity/custom/"
      cmd_reload
      ;;
    *) err "rules 子命令: list|validate|promote|enable|disable|set-priority" ;;
  esac
}

cmd_unlock() {
  need_root
  chattr -i "${NGINX_PREFIX}/sbin/nginx" 2>/dev/null || true
  chattr -i "${NGINX_PREFIX}/conf/nginx.conf" 2>/dev/null || true
  log "已解锁不可变属性"
}

cmd_lock() {
  need_root
  chattr +i "${NGINX_PREFIX}/sbin/nginx" 2>/dev/null || true
  chattr +i "${NGINX_PREFIX}/conf/nginx.conf" 2>/dev/null || true
  log "已锁定"
}

main() {
  mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    reload) cmd_reload ;;
    status) cmd_status ;;
    test) cmd_test ;;
    mode) cmd_mode "$@" ;;
    backup) need_root; cmd_backup ;;
    rollback) cmd_rollback "$@" ;;
    metrics) cmd_metrics ;;
    rules) cmd_rules "$@" ;;
    unlock-immutable) cmd_unlock ;;
    lock-immutable) cmd_lock ;;
    ""|-h|--help) usage ;;
    *) usage; err "未知命令: $cmd" ;;
  esac
}

main "$@"

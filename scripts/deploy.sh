#!/usr/bin/env bash
#===============================================================================
# Ma-WAF 一键部署脚本 (deploy.sh)
# 兼容: Rocky Linux 8/9, openEuler 22.03 LTS
# 用法: sudo ./deploy.sh [--offline /path/to/bundle] [--skip-build]
#===============================================================================
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 默认安装到源码树本身，避免 /usr/local/Ma-waf 与 /usr/local/ma-waf 大小写分裂
# 如需固定到其他路径: export MA_WAF_PREFIX=/opt/ma-waf
if [[ -n "${MA_WAF_PREFIX:-}" ]]; then
  PREFIX="${MA_WAF_PREFIX}"
else
  PREFIX="${REPO_ROOT}"
fi
readonly PREFIX
readonly NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
readonly LOG_DIR="${LOG_DIR:-/data/logs/nginx}"
readonly LOG_FILE="${PREFIX}/var/log/deploy.log"
readonly TS="$(date +%Y%m%d%H%M%S)"

OFFLINE_BUNDLE=""
SKIP_BUILD=0

log()  { echo "[$(date '+%F %T')] $*" | tee -a "${LOG_FILE:-/dev/stderr}"; }
err()  { log "ERROR: $*"; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || err "请使用 root 执行"; }

require_file() {
  local f="$1"
  [[ -f "$f" ]] || err "缺少文件: $f （请确认已完整同步仓库，含 configs/ templates/ management/）"
}

install_file() {
  local src="$1" dst="$2" mode="${3:-644}"
  require_file "$src"
  install -m "$mode" "$src" "$dst"
}

usage() {
  cat <<EOF
用法: $0 [选项]
  --offline DIR   离线包目录（含 rpm/wheels/src）
  --skip-build    跳过 Nginx/ModSecurity 编译（已安装时使用）
  -h, --help      帮助

环境变量:
  MA_WAF_PREFIX   产品安装前缀（默认=本仓库根目录: ${REPO_ROOT}）
  NGINX_PREFIX    Nginx 前缀（默认 /usr/local/nginx）
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --offline) OFFLINE_BUNDLE="${2:-}"; shift 2 ;;
      --skip-build) SKIP_BUILD=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) err "未知参数: $1" ;;
    esac
  done
}

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" ]]; then
    local b="${PREFIX}/backups/pre-deploy-${TS}/$(basename "$f").bak"
    mkdir -p "$(dirname "$b")"
    cp -a "$f" "$b"
    log "已备份: $f -> $b"
  fi
}

check_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    log "检测到系统: ${NAME:-unknown} ${VERSION_ID:-}"
    case "${ID:-}" in
      rocky|rhel|centos|almalinux|openEuler|openeuler|euler) ;;
      *) log "WARN: 未在验证列表中的发行版，继续尝试..." ;;
    esac
  else
    err "无法识别操作系统"
  fi
}

check_repo_layout() {
  log "检查仓库完整性: ${REPO_ROOT}"
  log "安装前缀 PREFIX=${PREFIX}"
  local need=(
    "${REPO_ROOT}/nginx/nginx.conf"
    "${REPO_ROOT}/nginx/modsecurity/modsecurity.conf"
    "${REPO_ROOT}/scripts/waf_ctl.sh"
    "${REPO_ROOT}/tools/rule_manager.py"
    "${REPO_ROOT}/systemd/nginx.service"
  )
  local f
  for f in "${need[@]}"; do
    require_file "$f"
  done
  if [[ ! -f "${REPO_ROOT}/configs/templates/api.yaml" ]]; then
    log "WARN: 缺少 configs/templates/api.yaml，将写入内置默认配置"
  fi
  if [[ ! -f "${REPO_ROOT}/management/console/index.html" ]]; then
    log "WARN: 缺少 Web 控制台 management/console/index.html"
  fi
}

check_deps() {
  log "检查基础依赖..."
  local missing=()
  for c in curl tar gzip sha256sum systemctl python3; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ((${#missing[@]})); then
    if [[ -n "$OFFLINE_BUNDLE" ]]; then
      log "离线模式: 缺少 ${missing[*]}，请确保离线包已提供对应工具"
    else
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl tar gzip coreutils python3 systemd || err "依赖安装失败"
      elif command -v yum >/dev/null 2>&1; then
        yum install -y curl tar gzip coreutils python3 systemd || err "依赖安装失败"
      else
        err "缺少包管理器且依赖不完整: ${missing[*]}"
      fi
    fi
  fi
  python3 - <<'PY' || err "需要 Python >= 3.9"
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY
  log "依赖检查通过"
}

install_build_deps() {
  [[ $SKIP_BUILD -eq 1 ]] && return 0
  log "安装编译依赖..."
  local pkgs=(gcc gcc-c++ make autoconf automake libtool pcre-devel
              zlib-devel openssl-devel libxml2-devel curl-devel
              yajl-devel geoip-devel lmdb-devel libmaxminddb-devel)
  if [[ -n "$OFFLINE_BUNDLE" && -d "$OFFLINE_BUNDLE/rpms" ]]; then
    dnf localinstall -y "$OFFLINE_BUNDLE"/rpms/*.rpm || yum localinstall -y "$OFFLINE_BUNDLE"/rpms/*.rpm
  else
    dnf install -y "${pkgs[@]}" 2>/dev/null || yum install -y "${pkgs[@]}"
  fi
}

hint_build() {
  [[ $SKIP_BUILD -eq 1 ]] && { log "跳过编译"; return 0; }
  if [[ -x "${NGINX_PREFIX}/sbin/nginx" ]]; then
    log "检测到已有 Nginx: ${NGINX_PREFIX}/sbin/nginx"
    "${NGINX_PREFIX}/sbin/nginx" -v 2>&1 | tee -a "$LOG_FILE" || true
    return 0
  fi
  cat <<EOF | tee -a "$LOG_FILE"
----------------------------------------------------------------------
未检测到 ${NGINX_PREFIX}/sbin/nginx。
请编译 Nginx + ModSecurity 后重跑，或使用: $0 --skip-build
----------------------------------------------------------------------
EOF
}

create_users_dirs() {
  log "创建用户与目录..."
  id nginx >/dev/null 2>&1 || useradd -r -s /sbin/nologin nginx
  id waf-mgr >/dev/null 2>&1 || useradd -r -s /sbin/nologin waf-mgr

  mkdir -p \
    "${PREFIX}"/{bin,conf/tls,conf/geoip,scripts,tools,rules/{active,staging},var/{log,run,lib},backups,share/console} \
    "${LOG_DIR}" \
    "${NGINX_PREFIX}/conf/modsecurity/custom" \
    "${NGINX_PREFIX}/conf/conf.d" \
    "${NGINX_PREFIX}/conf/snippets" \
    "${NGINX_PREFIX}/conf/bot" \
    "${NGINX_PREFIX}/html/error_pages" \
    /tmp/modsec/{data,upload}

  chown -R nginx:nginx "${LOG_DIR}" /tmp/modsec
  chmod 750 "${PREFIX}" "${LOG_DIR}"
  chmod 700 /tmp/modsec/upload
}

write_default_api_yaml() {
  local dest="$1"
  cat >"$dest" <<EOF
# 由 deploy.sh 自动生成 — 请修改 jwt_secret 与管理员密码
listen: "127.0.0.1:9090"
jwt_secret: "CHANGE_ME_$(head -c 16 /dev/urandom | sha256sum | cut -c1-32)"
admin_user: "admin"
admin_pass_hash: ""
totp_secret: ""
nginx_bin: "${NGINX_PREFIX}/sbin/nginx"
modsec_conf: "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf"
rules_active: "${PREFIX}/rules/active"
rules_staging: "${PREFIX}/rules/staging"
audit_log: "${LOG_DIR}/modsec_audit.json"
access_log: "${LOG_DIR}/access.json"
backup_dir: "${PREFIX}/backups"
allow_cidrs:
  - "127.0.0.1/32"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
max_login_fail: 5
lockout_seconds: 300
sqlite_path: "${PREFIX}/var/lib/ma-waf.db"
chain_audit_path: "${PREFIX}/var/lib/audit-chain.jsonl"
console_dir: "${PREFIX}/share/console"
product_root: "${PREFIX}"
license_public_key: "${PREFIX}/conf/license/ma-waf-public.pem"
license_file: "${PREFIX}/conf/license/license.lic"
nginx_status_url: "http://127.0.0.1:8081/nginx_status"
alert_webhook: ""
EOF
  chmod 640 "$dest"
}

install_configs() {
  log "安装 Nginx / ModSecurity 配置..."
  backup_if_exists "${NGINX_PREFIX}/conf/nginx.conf"

  install_file "${REPO_ROOT}/nginx/nginx.conf" "${NGINX_PREFIX}/conf/nginx.conf" 644
  # 模块加载占位（随后 repair 会按实际 so 重写）
  if [[ -f "${REPO_ROOT}/nginx/modules-ma-waf.conf" ]]; then
    install -m 644 "${REPO_ROOT}/nginx/modules-ma-waf.conf" "${NGINX_PREFIX}/conf/modules-ma-waf.conf"
  else
    echo "# placeholder" >"${NGINX_PREFIX}/conf/modules-ma-waf.conf"
  fi
  mkdir -p "${NGINX_PREFIX}/conf/geo"
  if [[ -d "${REPO_ROOT}/nginx/geo" ]]; then
    cp -a "${REPO_ROOT}/nginx/geo/." "${NGINX_PREFIX}/conf/geo/"
  fi
  cp -a "${REPO_ROOT}/nginx/conf.d/." "${NGINX_PREFIX}/conf/conf.d/"
  # geo 片段绝不能留在 conf.d（会被 include *.conf 当成独立指令）
  rm -f "${NGINX_PREFIX}/conf/conf.d/whitelist_ips.conf" \
        "${NGINX_PREFIX}/conf/conf.d/blacklist_ips.conf" \
        "${NGINX_PREFIX}/conf/conf.d/geo_block.conf"
  # stub_status：管理面指标依赖 127.0.0.1:8081；显式确保，避免漏拷/被清掉
  if [[ -f "${REPO_ROOT}/nginx/conf.d/00-status.conf" ]]; then
    install -m 644 "${REPO_ROOT}/nginx/conf.d/00-status.conf" \
      "${NGINX_PREFIX}/conf/conf.d/00-status.conf"
    log "已确保 stub_status: ${NGINX_PREFIX}/conf/conf.d/00-status.conf"
  else
    log "WARN: 仓库缺少 nginx/conf.d/00-status.conf，控制台 Nginx Active 将无法采集"
  fi
  if [[ -d "${REPO_ROOT}/nginx/snippets" ]]; then
    cp -a "${REPO_ROOT}/nginx/snippets/." "${NGINX_PREFIX}/conf/snippets/"
  fi
  mkdir -p "${NGINX_PREFIX}/conf/bot"
  if [[ -d "${REPO_ROOT}/nginx/bot" ]]; then
    cp -a "${REPO_ROOT}/nginx/bot/." "${NGINX_PREFIX}/conf/bot/"
  fi
  cp -a "${REPO_ROOT}/nginx/modsecurity/." "${NGINX_PREFIX}/conf/modsecurity/"
  cp -a "${REPO_ROOT}/nginx/html/error_pages/." "${NGINX_PREFIX}/html/error_pages/"

  # 将管理证书路径改写为当前 PREFIX（兼容 Ma-waf / ma-waf）
  if [[ -f "${NGINX_PREFIX}/conf/conf.d/app.conf" ]]; then
    sed -i -E "s|/usr/local/ma-waf/conf/tls/|${PREFIX}/conf/tls/|g" "${NGINX_PREFIX}/conf/conf.d/app.conf"
  fi

  cp -a "${REPO_ROOT}/nginx/modsecurity/custom/." "${PREFIX}/rules/active/"
  cp -a "${PREFIX}/rules/active/." "${PREFIX}/rules/staging/"

  if [[ -f "${REPO_ROOT}/configs/templates/logrotate-ma-waf" ]]; then
    install_file "${REPO_ROOT}/configs/templates/logrotate-ma-waf" /etc/logrotate.d/ma-waf 644
  else
    log "WARN: 跳过 logrotate 模板（文件不存在）"
  fi

  if [[ -f "${REPO_ROOT}/configs/templates/sysctl-ma-waf.conf" ]]; then
    install -m 644 "${REPO_ROOT}/configs/templates/sysctl-ma-waf.conf" /etc/sysctl.d/99-ma-waf.conf || true
  fi

  # 管理 API 配置（模板缺失时自动生成，不再中断部署）
  # 注意：configs/templates/api.yaml 只是模板；运行时必须是 ${PREFIX}/conf/api.yaml
  if [[ ! -f "${PREFIX}/conf/api.yaml" ]]; then
    if [[ -f "${REPO_ROOT}/configs/templates/api.yaml" ]]; then
      # 基于模板并替换路径占位
      sed -e "s|/usr/local/Ma-waf|${PREFIX}|g" \
          -e "s|/usr/local/ma-waf|${PREFIX}|g" \
          -e "s|/usr/local/nginx|${NGINX_PREFIX}|g" \
          "${REPO_ROOT}/configs/templates/api.yaml" >"${PREFIX}/conf/api.yaml"
      secret="$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)"
      sed -i "s|REPLACE_WITH_RANDOM_64_HEX|${secret}|g" "${PREFIX}/conf/api.yaml" 2>/dev/null || true
      if ! grep -q '^console_dir:' "${PREFIX}/conf/api.yaml"; then
        echo "console_dir: \"${PREFIX}/share/console\"" >>"${PREFIX}/conf/api.yaml"
      fi
      chmod 640 "${PREFIX}/conf/api.yaml"
      log "已安装 API 配置: ${PREFIX}/conf/api.yaml （来自 templates，非仓库 conf/）"
    else
      write_default_api_yaml "${PREFIX}/conf/api.yaml"
      log "已生成默认 API 配置: ${PREFIX}/conf/api.yaml"
    fi
  else
    log "保留已有 API 配置: ${PREFIX}/conf/api.yaml"
  fi
  [[ -f "${PREFIX}/conf/api.yaml" ]] || err "未能生成 ${PREFIX}/conf/api.yaml"

  # 允许 waf-mgr 热更新 ModSecurity / 规则（管理 API 需要写权限）
  if id waf-mgr >/dev/null 2>&1; then
    chgrp -R waf-mgr "${NGINX_PREFIX}/conf/modsecurity" "${PREFIX}/rules" "${PREFIX}/conf" 2>/dev/null || true
    chmod -R g+rX "${NGINX_PREFIX}/conf/modsecurity" "${PREFIX}/share" 2>/dev/null || true
    chmod -R g+rwX "${PREFIX}/rules" "${PREFIX}/var" "${PREFIX}/backups" 2>/dev/null || true
    chmod g+rw "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf" 2>/dev/null || true
  fi

  log "配置安装完成"
}

install_crs_rules() {
  log "安装 OWASP CRS（若可用）..."
  local rules="${NGINX_PREFIX}/conf/modsecurity/rules"
  local n
  n="$(find "$rules" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l || echo 0)"
  local data_n
  data_n="$(find "$rules" -maxdepth 1 -name '*.data' 2>/dev/null | wc -l || echo 0)"
  if [[ "$n" -gt 1 ]] && [[ ! -f "$rules/000-placeholder.conf" ]] && [[ "$data_n" -gt 0 ]]; then
    log "CRS 规则已存在（${n} 个 conf，${data_n} 个 data），跳过"
    return 0
  fi
  if [[ "$n" -gt 1 ]] && [[ "$data_n" -eq 0 ]]; then
    log "CRS conf 已在但缺少 .data（nginx -t 会失败），重新安装"
  fi
  local installer="${REPO_ROOT}/scripts/install_crs.sh"
  [[ -x "$installer" ]] || installer="${PREFIX}/scripts/install_crs.sh"
  if [[ ! -x "$installer" ]]; then
    log "WARN: 无 install_crs.sh，请稍后手动安装 CRS"
    return 0
  fi
  if [[ -n "${OFFLINE_BUNDLE:-}" ]]; then
    if [[ -d "${OFFLINE_BUNDLE}/crs" ]]; then
      bash "$installer" --offline "${OFFLINE_BUNDLE}/crs" || log "WARN: 离线 CRS 安装失败"
      return 0
    fi
    if [[ -f "${OFFLINE_BUNDLE}/coreruleset.tar.gz" ]]; then
      bash "$installer" --offline "${OFFLINE_BUNDLE}/coreruleset.tar.gz" || log "WARN: 离线 CRS 安装失败"
      return 0
    fi
    log "WARN: 离线包未含 crs/，尝试 vendor 或保留 placeholder"
  fi
  if [[ -f "${REPO_ROOT}/vendor/crs/coreruleset-4.26.0.tar.gz" ]]; then
    bash "$installer" --offline "${REPO_ROOT}/vendor/crs/coreruleset-4.26.0.tar.gz" || log "WARN: vendor CRS 安装失败"
    return 0
  fi
  if [[ -n "${OFFLINE_BUNDLE:-}" ]]; then
    log "WARN: 离线部署未提供 CRS 包，保留 placeholder；请放入 vendor/crs/ 后运行 install_crs.sh"
    return 0
  fi
  bash "$installer" || log "WARN: 在线 CRS 安装失败（网络/权限），可稍后: ${installer}"
}

install_console() {
  log "安装 Web 管理控制台..."
  mkdir -p "${PREFIX}/share/console"
  if [[ -d "${REPO_ROOT}/management/console" ]]; then
    cp -a "${REPO_ROOT}/management/console/." "${PREFIX}/share/console/"
    log "控制台已安装到 ${PREFIX}/share/console （访问 https://<IP>:8443/ ）"
  elif [[ -d "${REPO_ROOT}/management/frontend/dist" ]]; then
    cp -a "${REPO_ROOT}/management/frontend/dist/." "${PREFIX}/share/console/"
    log "已安装前端构建产物 dist/"
  else
    log "WARN: 未找到 management/console，跳过 Web UI 文件安装"
  fi
}

install_scripts_tools() {
  log "安装运维脚本与工具..."
  # 源码树即 PREFIX 时避免 cp 覆盖正在执行的脚本出问题：用 rsync 或逐项
  if [[ "${REPO_ROOT}" != "${PREFIX}" ]]; then
    cp -a "${REPO_ROOT}/scripts/." "${PREFIX}/scripts/"
    cp -a "${REPO_ROOT}/tools/." "${PREFIX}/tools/"
  else
    chmod 755 "${PREFIX}/scripts/"*.sh 2>/dev/null || true
    chmod 755 "${PREFIX}/tools/"*.py 2>/dev/null || true
  fi
  chmod 755 "${PREFIX}/scripts/"*.sh 2>/dev/null || true
  chmod 755 "${PREFIX}/tools/"*.py 2>/dev/null || true

  if [[ -f "${REPO_ROOT}/management/backend/bin/ma-waf-api" ]]; then
    install -m 755 "${REPO_ROOT}/management/backend/bin/ma-waf-api" "${PREFIX}/bin/ma-waf-api"
  elif [[ -n "$OFFLINE_BUNDLE" && -f "$OFFLINE_BUNDLE/bin/ma-waf-api" ]]; then
    install -m 755 "$OFFLINE_BUNDLE/bin/ma-waf-api" "${PREFIX}/bin/ma-waf-api"
  elif [[ -x "${PREFIX}/bin/ma-waf-api" ]]; then
    log "使用已有 ma-waf-api: ${PREFIX}/bin/ma-waf-api"
  else
    log "WARN: 未找到 ma-waf-api 二进制。Web 界面需要先构建:"
    log "       cd ${REPO_ROOT}/management/backend && ./build.sh"
    log "       然后将 bin/ma-waf-api 放到 ${PREFIX}/bin/"
  fi

  if [[ ! -f "${PREFIX}/conf/tls/admin.crt" ]]; then
    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "${PREFIX}/conf/tls/admin.key" \
        -out "${PREFIX}/conf/tls/admin.crt" \
        -subj "/CN=waf-admin.local" 2>/dev/null \
        && chmod 600 "${PREFIX}/conf/tls/admin.key" \
        && log "已生成管理端自签证书" \
        || log "WARN: openssl 生成证书失败"
    else
      log "WARN: 无 openssl，跳过证书生成"
    fi
  fi
}

install_systemd() {
  log "安装 systemd 单元..."
  # 单元文件内路径按 PREFIX 改写
  local tmp
  tmp="$(mktemp)"
  sed -e "s|/usr/local/ma-waf|${PREFIX}|g" \
      "${REPO_ROOT}/systemd/nginx.service" >"$tmp"
  install -m 644 "$tmp" /etc/systemd/system/nginx.service

  sed -e "s|/usr/local/ma-waf|${PREFIX}|g" -e "s|/usr/local/Ma-waf|${PREFIX}|g" \
      "${REPO_ROOT}/systemd/ma-waf-api.service" >"$tmp"
  install -m 644 "$tmp" /etc/systemd/system/ma-waf-api.service

  if [[ -f "${REPO_ROOT}/systemd/ma-waf-alert.service" ]]; then
    sed -e "s|/usr/local/Ma-waf|${PREFIX}|g" -e "s|/usr/local/ma-waf|${PREFIX}|g" \
      "${REPO_ROOT}/systemd/ma-waf-alert.service" >"$tmp"
    install -m 644 "$tmp" /etc/systemd/system/ma-waf-alert.service
    sed -e "s|/usr/local/Ma-waf|${PREFIX}|g" -e "s|/usr/local/ma-waf|${PREFIX}|g" \
      "${REPO_ROOT}/systemd/ma-waf-alert.timer" >"${tmp}.timer"
    install -m 644 "${tmp}.timer" /etc/systemd/system/ma-waf-alert.timer
    rm -f "${tmp}.timer"
    log "已安装 ma-waf-alert.timer（启动: systemctl enable --now ma-waf-alert.timer）"
  fi
  rm -f "$tmp"

  systemctl daemon-reload
  systemctl enable nginx 2>/dev/null || true
  systemctl enable ma-waf-api 2>/dev/null || true
}

init_integrity_baseline() {
  log "生成完整性基线..."
  if [[ -f "${PREFIX}/tools/integrity_check.py" ]]; then
    python3 "${PREFIX}/tools/integrity_check.py" --init \
      --root "${NGINX_PREFIX}" \
      --product "${PREFIX}" \
      --out "${PREFIX}/var/lib/integrity-baseline.json" || log "WARN: 基线生成失败"
  fi
}

validate_and_start() {
  # 修复模块加载 / 证书 / 无模块时的指令
  if [[ -x "${PREFIX}/scripts/repair_nginx_modules.sh" ]]; then
    bash "${PREFIX}/scripts/repair_nginx_modules.sh" || log "WARN: repair_nginx_modules 未完全成功"
  elif [[ -x "${REPO_ROOT}/scripts/repair_nginx_modules.sh" ]]; then
    bash "${REPO_ROOT}/scripts/repair_nginx_modules.sh" || log "WARN: repair_nginx_modules 未完全成功"
  fi

  if [[ -x "${NGINX_PREFIX}/sbin/nginx" ]]; then
    if "${NGINX_PREFIX}/sbin/nginx" -t; then
      systemctl restart nginx || err "nginx 启动失败"
      log "Nginx 已启动"
    else
      log "WARN: nginx -t 失败，请检查配置后手动启动"
      log "      运行: ${PREFIX}/scripts/diagnose.sh"
    fi
  else
    log "WARN: Nginx 未安装，跳过启动"
  fi
  if [[ -x "${PREFIX}/bin/ma-waf-api" && -f "${PREFIX}/bin/ma-waf-api" ]]; then
    systemctl restart ma-waf-api || log "WARN: ma-waf-api 启动失败"
    log "管理控制台: https://<本机IP>:8443/  默认账号 admin / admin（请立即修改）"
  elif [[ -d "${PREFIX}/bin/ma-waf-api" ]]; then
    log "ERROR: ${PREFIX}/bin/ma-waf-api 是目录不是二进制，请 rm -rf 后重新 build.sh"
  fi
}

main() {
  need_root
  parse_args "$@"
  mkdir -p "${PREFIX}/var/log" "${PREFIX}/backups"
  touch "$LOG_FILE"
  log "======== Ma-WAF 部署开始 ========"
  check_os
  check_repo_layout
  check_deps
  install_build_deps
  create_users_dirs
  hint_build
  install_configs
  install_crs_rules
  install_console
  install_scripts_tools
  install_systemd
  init_integrity_baseline
  validate_and_start
  log "======== 部署完成 ========"
  log "PREFIX=${PREFIX}"
  log "下一步: ${PREFIX}/scripts/harden_os.sh ； ${PREFIX}/scripts/verify_waf.sh"
  log "CRS: ${PREFIX}/scripts/install_crs.sh （若仍为 placeholder）"
  log "告警: systemctl enable --now ma-waf-alert.timer"
}

main "$@"

#!/usr/bin/env bash
#===============================================================================
# Ma-WAF 操作系统安全加固 (harden_os.sh)
# 目标: Rocky Linux 8/9 / openEuler 22.03
# 用法: sudo ./harden_os.sh [--dry-run]
# 注意: 会调整防火墙/内核参数等；不限制 SSH 登录方式（来源 IP 请用安全组控制）
# 请在维护窗口执行并确保有带外或已放通的 SSH 访问
#===============================================================================
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PREFIX="${MA_WAF_PREFIX:-/usr/local/ma-waf}"
readonly LOG_FILE="${PREFIX}/var/log/harden_os.log"
readonly TS="$(date +%Y%m%d%H%M%S)"
DRY_RUN=0

log() { echo "[$(date '+%F %T')] $*" | tee -a "${LOG_FILE}"; }
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: $*"
  else
    log "RUN: $*"
    eval "$@"
  fi
}

need_root() { [[ $EUID -eq 0 ]] || { echo "需要 root"; exit 1; }; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      *) echo "未知参数 $1"; exit 1 ;;
    esac
  done
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  mkdir -p "${PREFIX}/backups/harden-${TS}"
  cp -a "$f" "${PREFIX}/backups/harden-${TS}/"
  log "备份 $f"
}

disable_services() {
  log "关闭不必要服务..."
  local svcs=(postfix avahi-daemon cups bluetooth rpcbind nfs-server
              chronyd-wait ModemManager gssproxy)
  for s in "${svcs[@]}"; do
    if systemctl list-unit-files | grep -q "^${s}"; then
      run "systemctl disable --now ${s} 2>/dev/null || true"
    fi
  done
}

remove_packages() {
  log "卸载桌面/X11 等非必要包（若存在）..."
  # 不强制失败：最小化环境可能本无这些包
  run "dnf remove -y xorg-x11-* gnome-* kde-* 2>/dev/null || yum remove -y xorg-x11-* 2>/dev/null || true"
}

sysctl_harden() {
  log "应用内核参数加固..."
  backup_file /etc/sysctl.conf
  cat >/etc/sysctl.d/99-ma-waf-harden.conf <<'EOF'
# SYN Cookie / 网络抗扰
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_tw_reuse = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# ASLR / 核心转储
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
# 连接跟踪（按内存调整）
net.netfilter.nf_conntrack_max = 262144
EOF
  run "sysctl --system"
}

firewall_harden() {
  log "配置 firewalld 最小开放端口..."
  if ! command -v firewall-cmd >/dev/null 2>&1; then
    run "dnf install -y firewalld 2>/dev/null || yum install -y firewalld 2>/dev/null || true"
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    run "systemctl enable --now firewalld"
    # SSH 访问由云安全组/办公网 ACL 限制，本机 firewalld 保持放行 22
    run "firewall-cmd --permanent --add-service=ssh"
    run "firewall-cmd --permanent --add-service=http"
    run "firewall-cmd --permanent --add-service=https"
    run "firewall-cmd --permanent --add-port=8443/tcp"
    run "firewall-cmd --reload"
  fi
}

ssh_harden() {
  # 不修改 sshd 登录策略（密码/root/密钥等）。访问控制交给云安全组或上游防火墙（如仅办公 IP）。
  log "跳过 SSH 登录加固（由安全组限制来源 IP）"
  local drop="/etc/ssh/sshd_config.d/99-ma-waf.conf"
  if [[ -f "$drop" ]]; then
    backup_file "$drop"
    log "移除历史 SSH 限制片段: $drop"
    run "rm -f '$drop'"
    run "sshd -t && systemctl reload sshd"
  fi
}

sudo_minimize() {
  log "sudo 最小权限提示文件..."
  cat >/etc/sudoers.d/ma-waf <<'EOF'
# 仅示例：运维组可执行 waf_ctl，禁止 shell 逃逸
# %wafops ALL=(root) NOPASSWD: /usr/local/ma-waf/scripts/waf_ctl.sh, /usr/local/nginx/sbin/nginx
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
  chmod 440 /etc/sudoers.d/ma-waf
  run "visudo -cf /etc/sudoers.d/ma-waf"
}

fs_perms() {
  log "关键目录权限与不可变属性..."
  local nginx="${NGINX_PREFIX:-/usr/local/nginx}"
  run "chown -R root:root ${nginx}/conf ${PREFIX}/conf 2>/dev/null || true"
  run "chmod -R go-w ${nginx}/conf ${PREFIX}/conf 2>/dev/null || true"
  run "chmod 750 ${PREFIX} ${nginx}/conf"
  run "chmod 640 ${nginx}/conf/nginx.conf 2>/dev/null || true"
  # 核心二进制与主配置锁定（更新前需 chattr -i）
  if command -v chattr >/dev/null 2>&1; then
    [[ -f ${nginx}/sbin/nginx ]] && run "chattr +i ${nginx}/sbin/nginx" || true
    [[ -f ${nginx}/conf/nginx.conf ]] && run "chattr +i ${nginx}/conf/nginx.conf" || true
  fi
  # 审计日志只追加
  mkdir -p /data/logs/nginx
  touch /data/logs/nginx/modsec_audit.json /data/logs/nginx/access.json
  if command -v chattr >/dev/null 2>&1; then
    run "chattr +a /data/logs/nginx/modsec_audit.json 2>/dev/null || true"
  fi
}

enable_auditd() {
  log "启用 auditd..."
  run "dnf install -y audit 2>/dev/null || yum install -y audit 2>/dev/null || true"
  if command -v auditctl >/dev/null 2>&1; then
    cat >/etc/audit/rules.d/ma-waf.rules <<'EOF'
-w /usr/local/nginx/conf -p wa -k waf_conf
-w /usr/local/nginx/sbin/nginx -p x -k waf_bin
-w /usr/local/ma-waf/conf -p wa -k waf_product
-w /usr/local/ma-waf/rules -p wa -k waf_rules
-w /etc/ssh/sshd_config -p wa -k ssh_conf
EOF
    run "augenrules --load 2>/dev/null || service auditd restart"
    run "systemctl enable --now auditd"
  fi
}

ulimit_and_coredump() {
  cat >/etc/security/limits.d/99-ma-waf.conf <<'EOF'
nginx soft nofile 65535
nginx hard nofile 65535
* hard core 0
EOF
  mkdir -p /etc/systemd/coredump.conf.d
  cat >/etc/systemd/coredump.conf.d/ma-waf.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  run "systemctl daemon-reload"
}

main() {
  need_root
  parse_args "$@"
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  log "======== OS 加固开始 (dry_run=$DRY_RUN) ========"
  disable_services
  remove_packages
  sysctl_harden
  firewall_harden
  ssh_harden
  sudo_minimize
  fs_perms
  enable_auditd
  ulimit_and_coredump
  log "======== OS 加固完成 ========"
  log "SSH 登录策略未改动；请确认安全组已限制管理来源 IP"
}

main "$@"

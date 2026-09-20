#!/usr/bin/env bash
# 生成 / 修复 conf/api.yaml（管理 API 必需）
# 注意：不要用本脚本覆盖掉 install_api 写入的 ExecStart；203/EXEC 多为二进制缺失。
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
if [[ -z "$PREFIX" ]]; then
  [[ -d /usr/local/Ma-waf ]] && PREFIX=/usr/local/Ma-waf || PREFIX=/usr/local/ma-waf
fi
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
DEST="${PREFIX}/conf/api.yaml"
API_BIN="${PREFIX}/bin/ma-waf-api"
STRICT="${MA_WAF_STRICT_AUTH:-0}"

mkdir -p "${PREFIX}/conf" "${PREFIX}/var/lib" "${PREFIX}/share/console" \
         "${PREFIX}/bin" "${PREFIX}/rules/active" "${PREFIX}/rules/staging" "${PREFIX}/backups" \
         "${PREFIX}/conf/license"

# ---- 确保可执行文件存在（否则 systemd 报 203/EXEC，nginx:8443 → 502）----
ensure_api_bin() {
  if [[ -d "$API_BIN" ]]; then
    echo "WARN: $API_BIN 是目录，正在删除..."
    rm -rf "$API_BIN"
  fi
  if [[ -x "$API_BIN" && -f "$API_BIN" ]]; then
    echo "OK: API 二进制 $API_BIN"
    file "$API_BIN" || true
    return 0
  fi
  local cand
  for cand in \
    "${PREFIX}/management/backend/bin/ma-waf-api" \
    "${PREFIX}/management/backend/ma-waf-api"
  do
    if [[ -f "$cand" && -x "$cand" ]]; then
      echo "安装 API 二进制: $cand -> $API_BIN"
      install -m 755 "$cand" "$API_BIN"
      return 0
    fi
  done
  echo "ERROR: 找不到可执行的 ma-waf-api。"
  echo "      请先: sudo ${PREFIX}/scripts/install_api.sh"
  echo "      或: cd ${PREFIX}/management/backend && ./build.sh && install -m 755 bin/ma-waf-api $API_BIN"
  return 1
}

ensure_api_bin || exit 1

SECRET="$(head -c 32 /dev/urandom 2>/dev/null | sha256sum | cut -c1-64 || date +%s | sha256sum | cut -c1-64)"

if [[ -f "$DEST" ]]; then
  cp -a "$DEST" "${DEST}.bak.$(date +%Y%m%d%H%M%S)"
  echo "已备份旧配置"
fi

# 可选：首次生成 bcrypt（环境变量 MA_WAF_ADMIN_PASS）
HASH=""
if [[ -n "${MA_WAF_ADMIN_PASS:-}" ]] && command -v python3 >/dev/null; then
  HASH="$(python3 "${PREFIX}/tools/gen_admin_hash.py" "${MA_WAF_ADMIN_PASS}" 2>/dev/null || \
          python3 -c "import bcrypt; print(bcrypt.hashpw(b'''${MA_WAF_ADMIN_PASS}''', bcrypt.gensalt()).decode())" 2>/dev/null || true)"
fi

cat >"$DEST" <<EOF
listen: "127.0.0.1:9090"
jwt_secret: "${SECRET}"
admin_user: "admin"
admin_pass_hash: "${HASH}"
totp_secret: ""
nginx_bin: "${NGINX_PREFIX}/sbin/nginx"
modsec_conf: "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf"
rules_active: "${PREFIX}/rules/active"
rules_staging: "${PREFIX}/rules/staging"
audit_log: "/data/logs/nginx/modsec_audit.json"
access_log: "/data/logs/nginx/access.json"
backup_dir: "${PREFIX}/backups"
allow_cidrs:
  - "127.0.0.1/32"
  - "::1/128"
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
chmod 640 "$DEST"
echo "已写入 $DEST"

if [[ "$STRICT" == "1" && -z "$HASH" ]]; then
  echo "WARN: MA_WAF_STRICT_AUTH=1 但未设置 admin_pass_hash。"
  echo "      请: python3 tools/gen_admin_hash.py '密码' 写入 api.yaml，或 MA_WAF_ADMIN_PASS=... 重跑本脚本"
fi

# 控制台文件提醒
if [[ ! -f "${PREFIX}/share/console/index.html" ]]; then
  echo "WARN: 缺少 share/console/index.html，请执行: ${PREFIX}/scripts/sync_console.sh"
fi

mkdir -p /etc/systemd/system/ma-waf-api.service.d
# 保留 ExecStart，避免仅写 Environment 时与其它 drop-in 冲突后找不到二进制
cat >/etc/systemd/system/ma-waf-api.service.d/override.conf <<EOF
[Service]
Environment=MA_WAF_API_CONFIG=${DEST}
Environment=MA_WAF_CONSOLE_DIR=${PREFIX}/share/console
Environment=MA_WAF_ROOT=${PREFIX}
Environment=MA_WAF_STRICT_AUTH=${STRICT}
Environment=MA_WAF_INTEGRITY_CHECK=0
ExecStart=
ExecStart=${API_BIN}
WorkingDirectory=${PREFIX}
EOF
systemctl daemon-reload
systemctl reset-failed ma-waf-api 2>/dev/null || true
systemctl restart ma-waf-api || true
sleep 1
systemctl --no-pager status ma-waf-api | head -n 20 || true

echo "---- 探测 ----"
if [[ -x "$API_BIN" ]]; then
  # 前台试跑 1 秒看是否立刻退出
  timeout 1 "$API_BIN" 2>&1 | head -n 5 || true
fi
curl -s -o /dev/null -w "9090/health=%{http_code}\n" http://127.0.0.1:9090/api/v1/health || echo "9090/health=fail"
curl -sk -o /dev/null -w "8443/=%{http_code}\n" https://127.0.0.1:8443/ || echo "8443/=fail"
echo
echo "完成。若仍 203/EXEC: ls -la $API_BIN; file $API_BIN; journalctl -u ma-waf-api -n 30 --no-pager"
echo "生产建议: export MA_WAF_STRICT_AUTH=1 并配置 bcrypt 后重启"

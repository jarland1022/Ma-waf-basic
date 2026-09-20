#!/usr/bin/env bash
#===============================================================================
# 修复 test_waf_features.sh 常见环境缺口（证书 / 目录 / 控制台 / API 二进制）
# 用法: sudo ./scripts/fix_runtime.sh
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
NGINX_BIN="${NGINX_PREFIX}/sbin/nginx"
API_BIN="${PREFIX}/bin/ma-waf-api"
TLS_DIR="${PREFIX}/conf/tls"
CONSOLE_SRC="${PREFIX}/management/console"
CONSOLE_DST="${PREFIX}/share/console"

log() { echo "[fix] $*"; }
ok()  { echo "[ OK ] $*"; }
warn(){ echo "[WARN] $*"; }

[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

log "PREFIX=$PREFIX"

# ---- 1) 目录 ----
mkdir -p \
  "${PREFIX}/bin" \
  "${PREFIX}/var/"{log,lib,run} \
  "${PREFIX}/rules/"{active,staging} \
  "${PREFIX}/backups" \
  "${PREFIX}/conf/"{tls,license} \
  "${PREFIX}/share/console/assets" \
  "${NGINX_PREFIX}/conf/modsecurity/custom" \
  "${NGINX_PREFIX}/conf/geo" \
  "${NGINX_PREFIX}/conf/bot" \
  "${NGINX_PREFIX}/conf/snippets"
ok "运行时目录已就绪（含 rules/active、rules/staging）"

# ---- 2) 管理面 TLS ----
if [[ ! -f "${TLS_DIR}/admin.crt" || ! -f "${TLS_DIR}/admin.key" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "${TLS_DIR}/admin.key" \
      -out "${TLS_DIR}/admin.crt" \
      -subj "/CN=waf-admin.local/O=Ma-WAF/C=CN"
    chmod 600 "${TLS_DIR}/admin.key"
    chmod 644 "${TLS_DIR}/admin.crt"
    ok "已生成自签证书 ${TLS_DIR}/admin.crt"
  else
    warn "无 openssl，无法生成证书"
  fi
else
  ok "管理面证书已存在"
fi

# ---- 3) 控制台 ----
if [[ -d "$CONSOLE_SRC" ]]; then
  mkdir -p "${CONSOLE_DST}/assets"
  cp -a "${CONSOLE_SRC}/index.html" "${CONSOLE_DST}/index.html"
  [[ -f "${CONSOLE_SRC}/manual.html" ]] && cp -a "${CONSOLE_SRC}/manual.html" "${CONSOLE_DST}/manual.html"
  cp -a "${CONSOLE_SRC}/assets/." "${CONSOLE_DST}/assets/"
  ok "控制台已同步 → $CONSOLE_DST"
else
  warn "缺少 $CONSOLE_SRC，跳过控制台同步"
fi

# ---- 4) API 二进制 ----
ensure_api_bin() {
  if [[ -x "$API_BIN" && ! -d "$API_BIN" ]]; then
    ok "API 二进制存在: $API_BIN"
    return
  fi
  if [[ -d "$API_BIN" ]]; then
    warn "$API_BIN 是目录，将移走"
    mv "$API_BIN" "${API_BIN}.bak.$(date +%s)"
  fi
  local cand
  for cand in \
    "${PREFIX}/management/backend/bin/ma-waf-api" \
    "${PREFIX}/management/backend/ma-waf-api" \
    "$(command -v ma-waf-api 2>/dev/null || true)"
  do
    if [[ -n "$cand" && -x "$cand" && ! -d "$cand" ]]; then
      install -m 755 "$cand" "$API_BIN"
      ok "已安装 API: $cand → $API_BIN"
      return
    fi
  done
  if [[ -d "${PREFIX}/management/backend" ]] && command -v go >/dev/null 2>&1; then
    log "尝试本地编译 API…"
    (
      cd "${PREFIX}/management/backend"
      export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
      if [[ -x ./build.sh ]]; then
        ./build.sh
      else
        mkdir -p bin
        go build -o bin/ma-waf-api ./cmd/server
      fi
    )
    if [[ -x "${PREFIX}/management/backend/bin/ma-waf-api" ]]; then
      install -m 755 "${PREFIX}/management/backend/bin/ma-waf-api" "$API_BIN"
      ok "编译并安装 API → $API_BIN"
      return
    fi
  fi
  # systemd 仍在跑旧路径时给出提示
  if systemctl is-active --quiet ma-waf-api 2>/dev/null; then
    local exe
    exe="$(systemctl show -p ExecStart ma-waf-api 2>/dev/null || true)"
    warn "未能写入 $API_BIN，但服务仍在运行。ExecStart=$exe"
    warn "请手动: cd ${PREFIX}/management/backend && ./build.sh && install -m 755 bin/ma-waf-api $API_BIN"
  else
    warn "缺少 API 二进制且服务未运行"
  fi
}
ensure_api_bin

# ---- 5) nginx -t / reload ----
if [[ -x "$NGINX_BIN" ]]; then
  if "$NGINX_BIN" -t; then
    "$NGINX_BIN" -s reload || true
    ok "nginx -t 通过并已 reload"
  else
    warn "nginx -t 仍失败，请检查其它配置错误"
  fi
fi

# ---- 6) 重启 API ----
if systemctl list-unit-files | grep -q '^ma-waf-api'; then
  systemctl restart ma-waf-api || true
  sleep 1
  systemctl --no-pager --full status ma-waf-api | head -n 20 || true
fi

echo
ok "修复完成。建议再跑:"
echo "  sudo ${PREFIX}/scripts/test_waf_features.sh"
echo "说明: 数据面 HTTP 502 表示 nginx 可达但 upstream 业务未启动，属正常告警级现象。"

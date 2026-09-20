#!/usr/bin/env bash
# 一键诊断 ma-waf-api / nginx 启动失败
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
if [[ -z "$PREFIX" ]]; then
  if [[ -d /usr/local/Ma-waf ]]; then PREFIX=/usr/local/Ma-waf
  elif [[ -d /usr/local/ma-waf ]]; then PREFIX=/usr/local/ma-waf
  else PREFIX=/usr/local/Ma-waf
  fi
fi
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
API_BIN="${PREFIX}/bin/ma-waf-api"
NGINX_BIN="${NGINX_PREFIX}/sbin/nginx"

echo "======== Ma-WAF 诊断 ========"
echo "PREFIX=$PREFIX"
echo

echo "---- 1) ma-waf-api 二进制 ----"
if [[ -d "$API_BIN" ]]; then
  echo "FAIL: $API_BIN 是目录，不是可执行文件"
  echo "  修复:"
  echo "    rm -rf $API_BIN"
  echo "    cd $PREFIX/management/backend && ./build.sh"
  echo "    install -m 755 bin/ma-waf-api $API_BIN"
elif [[ ! -e "$API_BIN" ]]; then
  echo "FAIL: 不存在 $API_BIN"
  echo "  修复: cd $PREFIX/management/backend && ./build.sh && install -m 755 bin/ma-waf-api $API_BIN"
elif [[ ! -x "$API_BIN" ]]; then
  echo "FAIL: 存在但不可执行: $API_BIN"
  ls -l "$API_BIN"
  echo "  修复: chmod 755 $API_BIN"
else
  echo "OK: $API_BIN"
  ls -l "$API_BIN"
  file "$API_BIN" || true
  # 快速试跑（前台，2秒超时）
  timeout 2 "$API_BIN" 2>&1 | head -n 20 || true
fi

echo
echo "---- 2) systemd ma-waf-api ----"
systemctl cat ma-waf-api 2>/dev/null | sed -n '1,20p' || true
journalctl -u ma-waf-api -n 30 --no-pager || true

echo
echo "---- 3) nginx -t ----"
if [[ ! -x "$NGINX_BIN" ]]; then
  echo "FAIL: 无 $NGINX_BIN"
else
  "$NGINX_BIN" -t 2>&1 || true
  echo
  echo "模块文件:"
  ls -l "${NGINX_PREFIX}/modules/" 2>/dev/null || echo "  (无 modules 目录)"
  echo "load_module 配置:"
  grep -n load_module "${NGINX_PREFIX}/conf/nginx.conf" "${NGINX_PREFIX}/conf/modules-ma-waf.conf" 2>/dev/null || true
  echo "证书:"
  ls -l "${PREFIX}/conf/tls/" 2>/dev/null || echo "  缺 TLS 证书目录"
fi

echo
echo "---- 4) journal nginx ----"
journalctl -u nginx -n 40 --no-pager || true

echo
echo "---- 5) 建议修复顺序 ----"
cat <<EOF
A. 修复 API:
   rm -rf ${PREFIX}/bin/ma-waf-api
   cd ${PREFIX}/management/backend
   ./build.sh
   install -m 755 bin/ma-waf-api ${PREFIX}/bin/ma-waf-api
   # 确认是文件:
   file ${PREFIX}/bin/ma-waf-api
   systemctl restart ma-waf-api
   systemctl status ma-waf-api --no-pager

B. 修复 Nginx（先看 nginx -t 完整错误）:
   ${NGINX_BIN} -t
   # 若报 modsecurity 模块不存在，临时注释 load_module 或运行:
   ${PREFIX}/scripts/repair_nginx_modules.sh
   systemctl restart nginx
EOF

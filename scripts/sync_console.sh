#!/usr/bin/env bash
# 将管理控制台同步到 share/console，并可选重启 API
set -euo pipefail
PREFIX="${MA_WAF_PREFIX:-}"
[[ -z "$PREFIX" ]] && { [[ -d /usr/local/Ma-waf ]] && PREFIX=/usr/local/Ma-waf || PREFIX=/usr/local/ma-waf; }
SRC="${PREFIX}/management/console"
DST="${PREFIX}/share/console"

[[ -d "$SRC" ]] || { echo "缺少 $SRC"; exit 1; }
mkdir -p "${PREFIX}/share" "$DST/assets"
cp -a "${SRC}/." "$DST/"
# 确保关键文件存在
[[ -f "${SRC}/index.html" ]] && cp -a "${SRC}/index.html" "$DST/index.html"
[[ -f "${SRC}/manual.html" ]] && cp -a "${SRC}/manual.html" "$DST/manual.html"
[[ -d "${SRC}/assets" ]] && cp -a "${SRC}/assets/." "$DST/assets/"
echo "console synced -> $DST"
ls -l "$DST" "$DST/assets" | head

if [[ ! -f "${PREFIX}/conf/api.yaml" ]]; then
  echo "WARN: 缺少 ${PREFIX}/conf/api.yaml（模板在 configs/templates，不会自动进 conf/）"
  echo "      请执行: sudo ${PREFIX}/scripts/init_api_config.sh"
fi

# 新版静态路由需要较新的 ma-waf-api；若二进制较旧建议重建
if systemctl is-active --quiet ma-waf-api; then
  systemctl restart ma-waf-api
  sleep 1
  curl -sk -o /dev/null -w "console_http=%{http_code}\n" https://127.0.0.1:8443/ || true
  curl -s -o /dev/null -w "assets_css=%{http_code}\n" http://127.0.0.1:9090/assets/app.css || true
fi
echo "OK: 浏览器强制刷新 https://<IP>:8443/  (Ctrl+F5)"

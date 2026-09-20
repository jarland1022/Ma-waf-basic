#!/usr/bin/env bash
# 一键升级：同步企业级控制台 + 重建 ma-waf-api
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
[[ -z "$PREFIX" ]] && { [[ -d /usr/local/Ma-waf ]] && PREFIX=/usr/local/Ma-waf || PREFIX=/usr/local/ma-waf; }

echo "======== 升级 Ma-WAF 控制台 ========"
echo "PREFIX=$PREFIX"

# 1) 同步静态控制台
mkdir -p "${PREFIX}/share/console/assets"
cp -a "${PREFIX}/management/console/index.html" "${PREFIX}/share/console/index.html"
cp -a "${PREFIX}/management/console/assets/." "${PREFIX}/share/console/assets/"
echo "[OK] console files"

# 2) 重建 API（含 /sites 与 /assets 路由）
command -v go >/dev/null || dnf install -y golang
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export CGO_ENABLED=0
cd "${PREFIX}/management/backend"
mkdir -p bin
[[ -d bin/ma-waf-api ]] && rm -rf bin/ma-waf-api
go mod tidy
go build -trimpath -ldflags="-s -w" -o bin/ma-waf-api ./cmd/server
mkdir -p "${PREFIX}/bin"
install -m 755 bin/ma-waf-api "${PREFIX}/bin/ma-waf-api"
file "${PREFIX}/bin/ma-waf-api"
echo "[OK] ma-waf-api rebuilt"

# 3) 确保 api.yaml console_dir
if [[ -f "${PREFIX}/conf/api.yaml" ]] && ! grep -q '^console_dir:' "${PREFIX}/conf/api.yaml"; then
  echo "console_dir: \"${PREFIX}/share/console\"" >>"${PREFIX}/conf/api.yaml"
fi

systemctl restart ma-waf-api
sleep 1
systemctl --no-pager --full status ma-waf-api | head -n 20 || true

echo "---- 探测 ----"
curl -s http://127.0.0.1:9090/api/v1/health || true
echo
curl -s -o /dev/null -w "assets_css=%{http_code}\n" http://127.0.0.1:9090/assets/app.css || true
curl -s -o /dev/null -w "sites_api=%{http_code}\n" \
  -H "Authorization: Bearer x" http://127.0.0.1:9090/api/v1/sites || true

echo
echo "完成。请浏览器打开 https://<IP>:8443/ 并 Ctrl+F5 强制刷新"
echo "新菜单：受保护站点 / 安全事件详情抽屉 / 仪表盘自动刷新"

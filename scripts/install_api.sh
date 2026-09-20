#!/usr/bin/env bash
# 构建并安装 ma-waf-api 到产品 PREFIX/bin
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
if [[ -z "$PREFIX" ]]; then
  if [[ -d /usr/local/Ma-waf ]]; then PREFIX=/usr/local/Ma-waf
  elif [[ -d /usr/local/ma-waf ]]; then PREFIX=/usr/local/ma-waf
  else PREFIX="$(cd "$(dirname "$0")/.." && pwd)"
  fi
fi

BACKEND="${PREFIX}/management/backend"
DEST="${PREFIX}/bin/ma-waf-api"

echo "PREFIX=$PREFIX"
mkdir -p "${PREFIX}/bin"

if ! command -v go >/dev/null 2>&1; then
  echo "安装 golang..."
  dnf install -y golang || yum install -y golang || {
    echo "ERROR: 请先安装 Go 1.21+"; exit 1
  }
fi
# Rocky 自带 golang 可能 < 1.21，给出提示但不立刻退出（部分可降级 go.mod）
GO_VER="$(go env GOVERSION 2>/dev/null || go version)"
echo "检测到 ${GO_VER}"

# 清掉错误的目录占位
[[ -d "$DEST" ]] && rm -rf "$DEST"
[[ -d "${BACKEND}/bin/ma-waf-api" ]] && rm -rf "${BACKEND}/bin/ma-waf-api"

cd "$BACKEND"
chmod +x build.sh
./build.sh

install -m 755 "${BACKEND}/bin/ma-waf-api" "$DEST"
file "$DEST"
# 确认不是目录
[[ -f "$DEST" && -x "$DEST" ]] || { echo "ERROR: 安装失败"; exit 1; }

# 控制台静态文件：API 仅当 share/console 存在时才注册 / 与 /assets，否则浏览器 404
CONSOLE_SRC="${PREFIX}/management/console"
CONSOLE_DST="${PREFIX}/share/console"
if [[ ! -f "${CONSOLE_DST}/index.html" || ! -f "${CONSOLE_DST}/assets/app.js" ]]; then
  echo "同步 Web 控制台 → ${CONSOLE_DST}"
  if [[ -f "${CONSOLE_SRC}/index.html" ]]; then
    mkdir -p "${CONSOLE_DST}/assets"
    cp -a "${CONSOLE_SRC}/." "${CONSOLE_DST}/"
    [[ -d "${CONSOLE_SRC}/assets" ]] && cp -a "${CONSOLE_SRC}/assets/." "${CONSOLE_DST}/assets/"
  elif [[ -x "${PREFIX}/scripts/sync_console.sh" ]]; then
    bash "${PREFIX}/scripts/sync_console.sh"
  else
    echo "ERROR: 缺少 ${CONSOLE_SRC}/index.html，无法提供 Web 界面"
    exit 1
  fi
fi
[[ -f "${CONSOLE_DST}/index.html" ]] || { echo "ERROR: ${CONSOLE_DST}/index.html 仍缺失"; exit 1; }
echo "console: ${CONSOLE_DST} (index.html OK)"

# 运行时配置必须在 conf/api.yaml（模板在 configs/templates，不会随仓库同步进 conf/）
if [[ ! -f "${PREFIX}/conf/api.yaml" ]]; then
  echo "缺少 ${PREFIX}/conf/api.yaml，正在从模板/内置默认生成..."
  if [[ -x "${PREFIX}/scripts/init_api_config.sh" ]]; then
    bash "${PREFIX}/scripts/init_api_config.sh"
  elif [[ -f "${PREFIX}/configs/templates/api.yaml" ]]; then
    mkdir -p "${PREFIX}/conf"
    secret="$(head -c 32 /dev/urandom 2>/dev/null | sha256sum | cut -c1-64 || date +%s | sha256sum | cut -c1-64)"
    sed -e "s|/usr/local/Ma-waf|${PREFIX}|g" \
        -e "s|/usr/local/ma-waf|${PREFIX}|g" \
        -e "s|REPLACE_WITH_RANDOM_64_HEX|${secret}|g" \
        "${PREFIX}/configs/templates/api.yaml" >"${PREFIX}/conf/api.yaml"
    chmod 640 "${PREFIX}/conf/api.yaml"
    echo "已写入 ${PREFIX}/conf/api.yaml"
  else
    echo "ERROR: 无 init_api_config.sh 且无 templates/api.yaml，无法生成配置"
    exit 1
  fi
fi

# 确保 api.yaml 中 console_dir 指向实际目录
if grep -q '^console_dir:' "${PREFIX}/conf/api.yaml" 2>/dev/null; then
  sed -i "s|^console_dir:.*|console_dir: \"${PREFIX}/share/console\"|" "${PREFIX}/conf/api.yaml"
else
  echo "console_dir: \"${PREFIX}/share/console\"" >>"${PREFIX}/conf/api.yaml"
fi

mkdir -p /etc/systemd/system/ma-waf-api.service.d
cat >/etc/systemd/system/ma-waf-api.service.d/override.conf <<EOF
[Service]
Environment=MA_WAF_API_CONFIG=${PREFIX}/conf/api.yaml
Environment=MA_WAF_CONSOLE_DIR=${PREFIX}/share/console
Environment=MA_WAF_ROOT=${PREFIX}
ExecStart=
ExecStart=${DEST}
WorkingDirectory=${PREFIX}
EOF
systemctl daemon-reload

systemctl stop ma-waf-api 2>/dev/null || true
systemctl reset-failed ma-waf-api 2>/dev/null || true
systemctl start ma-waf-api
sleep 1
systemctl --no-pager --full status ma-waf-api || true
echo "OK: $DEST"
echo "API config: ${PREFIX}/conf/api.yaml"
echo "Probe:"
curl -s -o /dev/null -w "  http://127.0.0.1:9090/        -> %{http_code}\n" http://127.0.0.1:9090/ || true
curl -s -o /dev/null -w "  http://127.0.0.1:9090/assets/app.js -> %{http_code}\n" http://127.0.0.1:9090/assets/app.js || true
curl -sk -o /dev/null -w "  https://127.0.0.1:8443/      -> %{http_code}\n" https://127.0.0.1:8443/ || true
echo "浏览器打开: https://<WAF_IP>:8443/  （Ctrl+F5 强刷）"

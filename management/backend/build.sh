#!/usr/bin/env bash
# 构建 ma-waf-api 二进制（必须在目标 Linux 上执行，或交叉编译后拷贝）
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
OUT_DIR="${ROOT}/bin"
OUT_BIN="${OUT_DIR}/ma-waf-api"

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: 未安装 Go。Rocky 9 示例:"
  echo "  dnf install -y golang"
  echo "  或安装官网 Go 1.21+ 后重试"
  exit 1
fi

echo "go version: $(go version)"
echo "GOOS=${GOOS:-$(go env GOOS)} GOARCH=${GOARCH:-$(go env GOARCH)}"

# 若误建成目录，先清掉
if [[ -d "${OUT_BIN}" ]]; then
  echo "WARN: ${OUT_BIN} 是目录（常见误操作），正在删除..."
  rm -rf "${OUT_BIN}"
fi
mkdir -p "${OUT_DIR}"

# 默认：本机原生架构（不要强行 amd64，否则 aarch64 会 203/EXEC）
export CGO_ENABLED=0
export GO111MODULE=on
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOPATH="${GOPATH:-${ROOT}/.gopath}"
mkdir -p "${GOPATH}"

echo "GOPROXY=${GOPROXY}"
go version | awk '{print}'

# 依赖下载；缓存损坏时清理后重试（常见 pelletier/go-toml 缺文件）
download_deps() {
  go mod download && go mod tidy
}
if ! download_deps 2>/tmp/ma-waf-gomod.err; then
  echo "WARN: go mod 失败，清理本项目 module 缓存后重试…"
  cat /tmp/ma-waf-gomod.err 2>/dev/null || true
  rm -rf "${GOPATH}/pkg/mod/github.com/pelletier" \
         "${GOPATH}/pkg/mod/cache/download/github.com/pelletier" 2>/dev/null || true
  if ! download_deps; then
    echo "ERROR: 依赖仍失败。请执行:"
    echo "  rm -rf ${ROOT}/.gopath && GOPROXY=https://goproxy.cn,direct ./build.sh"
    exit 1
  fi
fi

go build -trimpath -ldflags="-s -w" -o "${OUT_BIN}" ./cmd/server

if [[ ! -f "${OUT_BIN}" ]]; then
  echo "ERROR: 构建失败，未生成文件 ${OUT_BIN}"
  exit 1
fi
if [[ -d "${OUT_BIN}" ]]; then
  echo "ERROR: 输出仍是目录，请检查 go build 参数"
  exit 1
fi

chmod 755 "${OUT_BIN}"
file "${OUT_BIN}" || true
ls -l "${OUT_BIN}"
echo "OK: ${OUT_BIN}"
echo "安装: sudo install -m 755 ${OUT_BIN} /usr/local/Ma-waf/bin/ma-waf-api"

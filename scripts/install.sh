#!/usr/bin/env bash
# Ma-WAF Community 一键安装（Docker）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "需要先安装 Docker: https://docs.docker.com/get-docker/"
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "已创建 .env（可按需修改 BACKEND / 端口 / 密码）"
fi

mkdir -p logs data
# Docker 把文件挂成目录的坑：审计日志文件必须事先存在
if [[ ! -f logs/modsec_audit.log ]]; then
  : > logs/modsec_audit.log
fi

# 从 .env 读端口用于提示
WAF_PORT=8080
CONSOLE_PORT=8090
# shellcheck disable=SC1091
set -a; source .env; set +a
WAF_PORT="${WAF_HTTP_PORT:-8080}"
CONSOLE_PORT="${CONSOLE_PORT:-8090}"

docker compose pull
docker compose up -d

echo ""
echo "安装完成。"
echo "  防护入口:   http://127.0.0.1:${WAF_PORT}/"
echo "  社区控制台: http://127.0.0.1:${CONSOLE_PORT}/   (默认 admin / admin)"
echo "  自检:       sh scripts/smoke-test.sh"
echo "接到真实业务: 编辑 .env 中 BACKEND=http://你的应用:端口 后执行 docker compose up -d"

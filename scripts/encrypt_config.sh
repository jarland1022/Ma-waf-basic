#!/usr/bin/env bash
#==============================================================================
# 配置加密辅助：age 或 sops
# 用法:
#   ./encrypt_config.sh init-age                 # 生成身份密钥
#   ./encrypt_config.sh age-encrypt api.yaml      # -> api.yaml.age
#   ./encrypt_config.sh age-decrypt api.yaml.age  # 输出明文到 stdout
#   ./encrypt_config.sh sops-encrypt api.yaml     # 原地 sops 加密（需 SOPS_* 环境）
#==============================================================================
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-/usr/local/ma-waf}"
IDENT="${MA_WAF_AGE_IDENTITY:-${PREFIX}/conf/age-identity.txt}"
RECIPIENTS="${PREFIX}/conf/age-recipients.txt"

need() { command -v "$1" >/dev/null || { echo "缺少命令: $1"; exit 1; }; }

cmd="${1:-}"
shift || true

case "${cmd}" in
  init-age)
    need age-keygen
    mkdir -p "$(dirname "${IDENT}")"
    if [[ -f "${IDENT}" ]]; then
      echo "已存在 ${IDENT}"; exit 0
    fi
    age-keygen -o "${IDENT}"
    chmod 600 "${IDENT}"
    grep '^# public key:' "${IDENT}" | sed 's/^# public key: //' > "${RECIPIENTS}"
    chmod 644 "${RECIPIENTS}"
    echo "identity=${IDENT}"
    echo "recipients=${RECIPIENTS}"
    ;;
  age-encrypt)
    need age
    src="${1:?path}"
    [[ -f "${RECIPIENTS}" ]] || { echo "先运行 init-age"; exit 1; }
    dest="${src}.age"
    age -e -R "${RECIPIENTS}" -o "${dest}" "${src}"
    chmod 600 "${dest}"
    echo "encrypted=${dest}"
    echo "提示: 将 systemd/启动参数指向 ${dest}；设置 MA_WAF_AGE_IDENTITY=${IDENT}"
    ;;
  age-decrypt)
    need age
    src="${1:?path}"
    age -d -i "${IDENT}" "${src}"
    ;;
  sops-encrypt)
    need sops
    src="${1:?path}"
    sops -e -i "${src}"
    echo "sops encrypted in-place: ${src}"
    echo "启动前 export MA_WAF_USE_SOPS=1"
    ;;
  *)
    sed -n '2,12p' "$0"
    exit 1
    ;;
esac

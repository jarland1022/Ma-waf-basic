#!/usr/bin/env bash
# 强制用仓库内自定义规则覆盖 Nginx，并验证 nginx -t
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
[[ -z "$PREFIX" ]] && { [[ -d /usr/local/Ma-waf ]] && PREFIX=/usr/local/Ma-waf || PREFIX=/usr/local/ma-waf; }
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
SRC="${PREFIX}/nginx/modsecurity"
DST="${NGINX_PREFIX}/conf/modsecurity"

echo "sync $SRC -> $DST"
mkdir -p "$DST/custom" "$DST/rules" /tmp/modsec/upload /data/logs/nginx

# 主配置
cp -a "${SRC}/modsecurity.conf" "${DST}/modsecurity.conf"
[[ -f "${SRC}/main.conf" ]] && cp -a "${SRC}/main.conf" "${DST}/main.conf"
[[ -f "${SRC}/crs-setup.conf" ]] && cp -a "${SRC}/crs-setup.conf" "${DST}/crs-setup.conf"

# 先清空 custom，避免旧坏文件残留
rm -f "${DST}/custom/"*.conf
cp -a "${SRC}/custom/." "${DST}/custom/"

# rules 占位
mkdir -p "${DST}/rules"
if [[ -d "${SRC}/rules" ]]; then
  cp -a "${SRC}/rules/." "${DST}/rules/"
fi

# 清理 MS3 不支持指令
sed -i -E \
  -e 's/^[[:space:]]*SecServerSignature\b.*/# removed/' \
  -e 's/^[[:space:]]*SecStatusEngine\b.*/# removed/' \
  -e 's/^[[:space:]]*SecConnEngine\b.*/# removed/' \
  -e 's/^[[:space:]]*SecDataDir\b.*/# removed/' \
  "${DST}/modsecurity.conf"

echo "---- custom rules now ----"
ls -l "${DST}/custom/"

echo "---- nginx -t ----"
# 同步主配置与站点配置
if [[ -f "${PREFIX}/nginx/nginx.conf" ]]; then
  cp -a "${PREFIX}/nginx/nginx.conf" "${NGINX_PREFIX}/conf/nginx.conf"
fi
# modules-ma-waf.conf 必须存在（nginx.conf include 它）
if [[ -f "${PREFIX}/nginx/modules-ma-waf.conf" ]]; then
  cp -a "${PREFIX}/nginx/modules-ma-waf.conf" "${NGINX_PREFIX}/conf/modules-ma-waf.conf"
elif [[ ! -f "${NGINX_PREFIX}/conf/modules-ma-waf.conf" ]]; then
  cat >"${NGINX_PREFIX}/conf/modules-ma-waf.conf" <<'EOF'
# placeholder — run scripts/repair_nginx_modules.sh to autodetect .so
EOF
fi
# 若有 repair 脚本则按实际模块重写
if [[ -x "${PREFIX}/scripts/repair_nginx_modules.sh" ]]; then
  bash "${PREFIX}/scripts/repair_nginx_modules.sh" || true
fi
if [[ -d "${PREFIX}/nginx/geo" ]]; then
  mkdir -p "${NGINX_PREFIX}/conf/geo"
  cp -a "${PREFIX}/nginx/geo/." "${NGINX_PREFIX}/conf/geo/"
fi
if [[ -d "${PREFIX}/nginx/conf.d" ]]; then
  mkdir -p "${NGINX_PREFIX}/conf/conf.d" "${NGINX_PREFIX}/conf/snippets"
  cp -a "${PREFIX}/nginx/conf.d/." "${NGINX_PREFIX}/conf/conf.d/"
  # 证书路径按实际 PREFIX 改写
  if [[ -f "${NGINX_PREFIX}/conf/conf.d/app.conf" ]]; then
    sed -i -E "s|/usr/local/[Mm]a-waf/conf/tls/|${PREFIX}/conf/tls/|g" \
      "${NGINX_PREFIX}/conf/conf.d/app.conf"
  fi
  [[ -d "${PREFIX}/nginx/snippets" ]] && cp -a "${PREFIX}/nginx/snippets/." "${NGINX_PREFIX}/conf/snippets/"
fi
# 必须清掉误放在 conf.d 的 geo 片段，否则 nginx -t 报 unknown directive IP
rm -f "${NGINX_PREFIX}/conf/conf.d/whitelist_ips.conf" \
      "${NGINX_PREFIX}/conf/conf.d/blacklist_ips.conf" \
      "${NGINX_PREFIX}/conf/conf.d/geo_block.conf"

# 管理端 TLS 证书（8443）缺失时自动生成自签证书
TLS_DIR="${PREFIX}/conf/tls"
mkdir -p "${TLS_DIR}"
if [[ ! -f "${TLS_DIR}/admin.crt" || ! -f "${TLS_DIR}/admin.key" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "${TLS_DIR}/admin.key" \
      -out "${TLS_DIR}/admin.crt" \
      -subj "/CN=waf-admin.local" 2>/dev/null
    chmod 600 "${TLS_DIR}/admin.key"
    chmod 644 "${TLS_DIR}/admin.crt"
    echo "已生成自签管理证书: ${TLS_DIR}/admin.crt"
  else
    echo "ERROR: 缺少 openssl，无法生成 ${TLS_DIR}/admin.crt"
    exit 1
  fi
fi
# 确保 app.conf 证书路径指向当前 PREFIX
if [[ -f "${NGINX_PREFIX}/conf/conf.d/app.conf" ]]; then
  sed -i -E "s|/usr/local/[Mm]a-waf/conf/tls/|${PREFIX}/conf/tls/|g" \
    "${NGINX_PREFIX}/conf/conf.d/app.conf"
fi

"${NGINX_PREFIX}/sbin/nginx" -t
echo "OK"

#!/usr/bin/env bash
#==============================================================================
# 更新 GeoIP2 MMDB 并启用国家封锁策略片段
# 用法:
#   sudo ./update_geoip.sh --country-db /path/GeoLite2-Country.mmdb
#   sudo ./update_geoip.sh --country-db /path/GeoLite2-Country.mmdb --city-db /path/GeoLite2-City.mmdb
#   sudo ./update_geoip.sh --from-url 'https://...'   # 需已授权下载源
# 说明:
#   - 报表「国家热力」只需 Country.mmdb（放到 conf/geoip/）+ 重启 ma-waf-api
#   - City.mmdb 可选，当前控制台未做城市地图，可一并存放备用
#   - 国家封锁另需 ngx_http_geoip2_module
#==============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
GEO_DIR="${PREFIX}/conf/geoip"
DEST="${GEO_DIR}/GeoLite2-Country.mmdb"
CITY_DEST="${GEO_DIR}/GeoLite2-City.mmdb"
COUNTRY_DB=""
CITY_DB=""
FROM_URL=""
ENABLE_CONF=1

log() { echo "[$(date '+%F %T')] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --country-db) COUNTRY_DB="$2"; shift 2 ;;
    --city-db) CITY_DB="$2"; shift 2 ;;
    --from-url) FROM_URL="$2"; shift 2 ;;
    --no-enable) ENABLE_CONF=0; shift ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "需要 root"; exit 1; }
mkdir -p "${GEO_DIR}" "${NGINX_PREFIX}/conf/conf.d"

if [[ -n "${COUNTRY_DB}" ]]; then
  install -m 644 "${COUNTRY_DB}" "${DEST}"
  log "已安装本地 Country MMDB -> ${DEST}"
elif [[ -n "${FROM_URL}" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  log "下载 ${FROM_URL}"
  curl -fsSL "${FROM_URL}" -o "${tmp}/geo.tgz" || curl -fsSL "${FROM_URL}" -o "${tmp}/geo.mmdb"
  if [[ -f "${tmp}/geo.tgz" ]]; then
    tar -xzf "${tmp}/geo.tgz" -C "${tmp}"
    find "${tmp}" -name 'GeoLite2-Country.mmdb' -exec cp -f {} "${DEST}" \;
    find "${tmp}" -name 'GeoLite2-City.mmdb' -exec cp -f {} "${CITY_DEST}" \; || true
  else
    cp -f "${tmp}/geo.mmdb" "${DEST}"
  fi
  chmod 644 "${DEST}"
  log "下载安装完成 -> ${DEST}"
else
  if [[ ! -f "${DEST}" ]]; then
    cat <<EOF
未找到 ${DEST}
请任选其一:
  1) 将 GeoLite2-Country.mmdb 放到该路径
  2) sudo $0 --country-db /path/to/GeoLite2-Country.mmdb
  3) sudo $0 --from-url '<已授权下载 URL>'
EOF
    exit 1
  fi
  log "使用已有 MMDB: ${DEST}"
fi

if [[ -n "${CITY_DB}" ]]; then
  install -m 644 "${CITY_DB}" "${CITY_DEST}"
  log "已安装本地 City MMDB -> ${CITY_DEST}（报表城市地图暂未启用，仅备用）"
fi

# geo_block.conf：国家码 -> 1 表示封锁（按客户策略编辑）
GEO_BLOCK="${NGINX_PREFIX}/conf/geo/geo_block.conf"
if [[ ! -f "${GEO_BLOCK}" ]]; then
  cat > "${GEO_BLOCK}" <<'EOF'
# Ma-WAF Geo 封锁清单（被 map $geo_block 引用）
# 格式: ISO 国家码 1;
# 示例（请按合规与业务策略调整，切勿盲目封锁）:
# RU 1;
# KP 1;
EOF
  chmod 644 "${GEO_BLOCK}"
  log "已生成 ${GEO_BLOCK}"
fi

MARKER_BEGIN="# BEGIN ma-waf-geoip2"
MARKER_END="# END ma-waf-geoip2"
NGINX_CONF="${NGINX_PREFIX}/conf/nginx.conf"

if [[ $ENABLE_CONF -eq 1 ]]; then
  MAPF="${NGINX_PREFIX}/conf/geo/geo_block_map.conf"
  mkdir -p "${NGINX_PREFIX}/conf/geo"
  cat > "${MAPF}" <<EOF
# written by update_geoip.sh
geoip2 ${DEST} {
    \$geoip2_country_code country iso_code;
}
map \$geoip2_country_code \$geo_block {
    default 0;
    include geo/geo_block.conf;
}
EOF
  log "已写入 ${MAPF}（nginx.conf 须 include geo/geo_block_map.conf）"
  if ! grep -q 'ngx_http_geoip2_module.so' "${NGINX_CONF}" && ! grep -q 'geoip2' "${NGINX_PREFIX}/conf/modules-ma-waf.conf" 2>/dev/null; then
    log "警告: 未检测到 geoip2 模块，nginx -t 可能失败"
  fi

  APP="${NGINX_PREFIX}/conf/conf.d/app.conf"
  if [[ -f "${APP}" ]]; then
    sed -i 's|# if ($geo_block) { return 403; }|if ($geo_block) { return 403; }|' "${APP}" || true
  fi
fi

if [[ -x "${NGINX_PREFIX}/sbin/nginx" ]]; then
  "${NGINX_PREFIX}/sbin/nginx" -t && "${NGINX_PREFIX}/sbin/nginx" -s reload
  log "nginx reload 完成"
else
  log "未找到 nginx 二进制，跳过 reload"
fi

log "GeoIP 更新完成"

#!/usr/bin/env bash
#===============================================================================
# 安装 OWASP CRS 4.x 到 Nginx ModSecurity rules 目录
# 用法:
#   sudo ./install_crs.sh                         # 在线拉取（需网络）
#   sudo ./install_crs.sh --offline /path/to/crs  # 目录或 .tar.gz
#   sudo ./install_crs.sh --version 4.26.0
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then
    echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then
    echo /usr/local/Ma-waf
  else
    echo /usr/local/ma-waf
  fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
RULES_DST="${NGINX_PREFIX}/conf/modsecurity/rules"
CRS_VERSION="${CRS_VERSION:-4.26.0}"
OFFLINE=""
LOG="${PREFIX}/var/log/install_crs.log"

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
err(){ log "ERROR $*"; exit 1; }
[[ $EUID -eq 0 ]] || err "need root"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --offline) OFFLINE="$2"; shift 2 ;;
    --version) CRS_VERSION="$2"; shift 2 ;;
    -h|--help)
      echo "用法: $0 [--offline DIR|TGZ] [--version 4.26.0]"; exit 0 ;;
    *) err "unknown $1" ;;
  esac
done

mkdir -p "$(dirname "$LOG")" "$RULES_DST" "${PREFIX}/var/lib/crs" "${PREFIX}/vendor/crs"

extract_crs() {
  local src="$1" tmp
  tmp="$(mktemp -d)"
  if [[ -d "$src" ]]; then
    cp -a "$src"/. "$tmp/"
  else
    tar -xzf "$src" -C "$tmp"
  fi
  # 解压后常见: coreruleset-4.26.0/ 或 rules/ 在顶层
  local root="$tmp"
  if [[ -d "$tmp/rules" ]]; then
    root="$tmp"
  else
    root="$(find "$tmp" -maxdepth 2 -type d -name 'coreruleset*' | head -1 || true)"
    [[ -n "$root" && -d "$root/rules" ]] || root="$(find "$tmp" -maxdepth 3 -type d -name rules | head -1 | xargs -r dirname)"
  fi
  [[ -d "$root/rules" ]] || err "离线包中未找到 rules/ 目录"
  echo "$root"
}

fetch_online() {
  local url="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
  local tgz="${PREFIX}/vendor/crs/coreruleset-${CRS_VERSION}.tar.gz"
  if [[ -f "$tgz" ]]; then
    log "使用已缓存: $tgz"
  else
    log "下载 CRS ${CRS_VERSION} ..."
    if command -v curl >/dev/null; then
      curl -fsSL -o "$tgz" "$url" || err "下载失败: $url"
    elif command -v wget >/dev/null; then
      wget -q -O "$tgz" "$url" || err "下载失败"
    else
      err "需要 curl 或 wget，或使用 --offline"
    fi
  fi
  echo "$tgz"
}

install_from_root() {
  local root="$1"
  local stamp
  stamp="$(date +%Y%m%d%H%M%S)"
  if [[ -d "$RULES_DST" ]] && ls "$RULES_DST"/*.conf >/dev/null 2>&1; then
    mkdir -p "${PREFIX}/backups/crs-rules-${stamp}"
    cp -a "$RULES_DST"/. "${PREFIX}/backups/crs-rules-${stamp}/" || true
  fi
  mkdir -p "$RULES_DST"
  # 清空旧 CRS（保留备份），再拷贝。*.data 与 *.conf 必须同目录，
  # 否则 @pmFromFile（如 scanners-user-agents.data）会导致 nginx -t 失败。
  find "$RULES_DST" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.data' \) -delete
  cp -a "$root/rules/"*.conf "$RULES_DST/"
  local data_n=0
  shopt -s nullglob
  local data_files=( "$root/rules/"*.data )
  shopt -u nullglob
  if ((${#data_files[@]})); then
    cp -a "${data_files[@]}" "$RULES_DST/"
    data_n="${#data_files[@]}"
  else
    log "WARN: CRS rules/ 中没有 .data，@pmFromFile 规则将无法加载"
  fi
  # 可选：同步推荐 crs-setup（不覆盖已有定制）
  if [[ -f "$root/crs-setup.conf.example" && ! -f "${NGINX_PREFIX}/conf/modsecurity/crs-setup.conf" ]]; then
    cp -a "$root/crs-setup.conf.example" "${NGINX_PREFIX}/conf/modsecurity/crs-setup.conf"
  fi
  local count
  count="$(find "$RULES_DST" -maxdepth 1 -name '*.conf' | wc -l)"
  log "已安装 CRS 规则文件数: $count ，数据文件数: $data_n -> $RULES_DST"
  if [[ "$count" -lt 5 ]]; then
    err "CRS 安装后规则过少，疑似失败"
  fi
  # 移除纯占位标记文件若仍存在且仅有占位
  if [[ -f "$RULES_DST/000-placeholder.conf" ]] && [[ "$count" -gt 1 ]]; then
    rm -f "$RULES_DST/000-placeholder.conf"
    log "已移除 placeholder"
  fi
}

main() {
  local pack root
  if [[ -n "$OFFLINE" ]]; then
    [[ -e "$OFFLINE" ]] || err "offline 路径不存在: $OFFLINE"
    root="$(extract_crs "$OFFLINE")"
  else
    # 优先 vendor 离线包
    if [[ -f "${PREFIX}/vendor/crs/coreruleset-${CRS_VERSION}.tar.gz" ]]; then
      pack="${PREFIX}/vendor/crs/coreruleset-${CRS_VERSION}.tar.gz"
    elif [[ -d "${PREFIX}/vendor/crs/coreruleset-${CRS_VERSION}" ]]; then
      pack="${PREFIX}/vendor/crs/coreruleset-${CRS_VERSION}"
    elif [[ -f "${PREFIX}/../vendor/crs/coreruleset-${CRS_VERSION}.tar.gz" ]]; then
      pack="${PREFIX}/../vendor/crs/coreruleset-${CRS_VERSION}.tar.gz"
    else
      pack="$(fetch_online)"
    fi
    root="$(extract_crs "$pack")"
  fi
  install_from_root "$root"
  # 持久化一份到 product
  mkdir -p "${PREFIX}/var/lib/crs/${CRS_VERSION}"
  cp -a "$root/rules" "${PREFIX}/var/lib/crs/${CRS_VERSION}/" 2>/dev/null || true
  log "CRS ${CRS_VERSION} 安装完成"
}

main

#!/usr/bin/env bash
# 按实际模块文件生成/修复 nginx modules include，避免 nginx -t 失败
set -euo pipefail

PREFIX="${MA_WAF_PREFIX:-}"
if [[ -z "$PREFIX" ]]; then
  [[ -d /usr/local/Ma-waf ]] && PREFIX=/usr/local/Ma-waf || PREFIX=/usr/local/ma-waf
fi
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
CONF_DIR="${NGINX_PREFIX}/conf"
MOD_CONF="${CONF_DIR}/modules-ma-waf.conf"
NGINX_MAIN="${CONF_DIR}/nginx.conf"

mkdir -p "${CONF_DIR}" "${NGINX_PREFIX}/logs" /data/logs/nginx

found=0
mod_line=""
for cand in \
  "${NGINX_PREFIX}/modules/ngx_http_modsecurity_module.so" \
  "${NGINX_PREFIX}/lib/ngx_http_modsecurity_module.so" \
  /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so
do
  if [[ -f "$cand" ]]; then
    if [[ "$cand" == "${NGINX_PREFIX}/modules/"* ]]; then
      mod_line="load_module modules/$(basename "$cand");"
    else
      mod_line="load_module $cand;"
    fi
    found=1
    break
  fi
done

# 生成 modules-ma-waf.conf
{
  echo "# 由 repair_nginx_modules.sh 自动生成 — 勿手改后忘记重跑"
  if [[ $found -eq 1 ]]; then
    echo "$mod_line"
  else
    echo "# WARNING: 未找到 ModSecurity 动态模块，已跳过 load_module"
    echo "# 业务防护需先编译安装 ngx_http_modsecurity_module.so"
  fi
} >"${MOD_CONF}"

# 无模块时注释 conf.d 中的 modsecurity 指令，否则 nginx -t 报 unknown directive
if [[ $found -eq 0 ]]; then
  echo "WARN: 未检测到 ModSecurity 模块，将临时注释 conf.d 中的 modsecurity 指令"
  for f in "${CONF_DIR}"/conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *.example.conf ]] && continue
    cp -a "$f" "${f}.bak.nomodsec.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    sed -i -E \
      -e 's/^([[:space:]]*)modsecurity[[:space:]]+/\1# modsecurity /' \
      -e 's/^([[:space:]]*)modsecurity_rules_file[[:space:]]+/\1# modsecurity_rules_file /' \
      "$f"
  done
fi

echo "已写入 ${MOD_CONF}:"
cat "${MOD_CONF}"

# 将主配置中的硬编码 load_module 换成 include（若尚未替换）
if [[ -f "$NGINX_MAIN" ]]; then
  if grep -q 'load_module modules/ngx_http_modsecurity_module.so' "$NGINX_MAIN"; then
    cp -a "$NGINX_MAIN" "${NGINX_MAIN}.bak.$(date +%Y%m%d%H%M%S)"
    # 注释原 load_module，插入 include
    sed -i -E 's|^[[:space:]]*load_module modules/ngx_http_modsecurity_module.so;|# load_module moved to modules-ma-waf.conf\ninclude modules-ma-waf.conf;|' "$NGINX_MAIN"
    # 若 sed 产生重复 include，去重由人工看；更稳妥用 python
    python3 - "$NGINX_MAIN" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1])
t = p.read_text(encoding="utf-8", errors="replace")
# 确保有且仅有一处 include modules-ma-waf.conf
t2 = re.sub(r'(?m)^\s*include\s+modules-ma-waf\.conf;\s*\n?', '', t)
# 在 user 指令后插入
if "include modules-ma-waf.conf;" not in t2:
    t2 = re.sub(r'(?m)^(user\s+[^;]+;)', r'\1\ninclude modules-ma-waf.conf;', t2, count=1)
# 注释残留 load_module modsecurity
t2 = re.sub(r'(?m)^\s*load_module\s+modules/ngx_http_modsecurity_module\.so;\s*$',
            r'# load_module modules/ngx_http_modsecurity_module.so;  # managed by modules-ma-waf.conf', t2)
p.write_text(t2, encoding="utf-8")
print("nginx.conf 已适配 include modules-ma-waf.conf")
PY
  elif ! grep -q 'modules-ma-waf.conf' "$NGINX_MAIN"; then
    # 在文件前部插入
    sed -i '1a include modules-ma-waf.conf;' "$NGINX_MAIN"
  fi
fi

# 管理证书缺失时补齐，避免 8443 server 启动失败
TLS_DIR="${PREFIX}/conf/tls"
mkdir -p "$TLS_DIR"
if [[ ! -f "${TLS_DIR}/admin.crt" || ! -f "${TLS_DIR}/admin.key" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "${TLS_DIR}/admin.key" -out "${TLS_DIR}/admin.crt" \
      -subj "/CN=waf-admin.local"
    chmod 600 "${TLS_DIR}/admin.key"
    echo "已生成 ${TLS_DIR}/admin.crt"
  fi
fi

# 若配置里仍写 /usr/local/ma-waf 而实际是 Ma-waf，改写证书路径
if [[ -f "${CONF_DIR}/conf.d/app.conf" ]]; then
  sed -i -E "s|/usr/local/ma-waf/conf/tls/|${PREFIX}/conf/tls/|gi" "${CONF_DIR}/conf.d/app.conf"
fi

# mime.types / logs
[[ -d "${NGINX_PREFIX}/logs" ]] || mkdir -p "${NGINX_PREFIX}/logs"
if [[ ! -f "${CONF_DIR}/mime.types" && -f /etc/nginx/mime.types ]]; then
  cp -a /etc/nginx/mime.types "${CONF_DIR}/mime.types"
fi

echo
echo "执行配置检测:"
"${NGINX_PREFIX}/sbin/nginx" -t

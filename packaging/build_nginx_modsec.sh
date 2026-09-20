#!/usr/bin/env bash
# 编译 Nginx + ModSecurity 动态模块（需源码目录）
# 用法: ./build_nginx_modsec.sh /usr/local/src
set -euo pipefail
SRC="${1:-/usr/local/src}"
NGINX_VER="${NGINX_VER:-1.24.0}"

cd "$SRC"
[[ -d "nginx-${NGINX_VER}" ]] || { echo "缺少 nginx-${NGINX_VER} 源码"; exit 1; }
[[ -d ModSecurity ]] || { echo "缺少 libmodsecurity 源码目录 ModSecurity"; exit 1; }
[[ -d ModSecurity-nginx ]] || { echo "缺少 ModSecurity-nginx"; exit 1; }

# 构建 libmodsecurity
(
  cd ModSecurity
  ./build.sh
  ./configure --prefix=/usr/local/modsecurity
  make -j"$(nproc)"
  make install
)

cd "nginx-${NGINX_VER}"
./configure \
  --prefix=/usr/local/nginx \
  --with-compat \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --add-dynamic-module=../ModSecurity-nginx
make -j"$(nproc)"
make install
echo "构建完成: /usr/local/nginx ；请确认 modules/ngx_http_modsecurity_module.so"

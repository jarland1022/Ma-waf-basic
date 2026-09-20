#!/bin/sh
# 确认社区版会放行正常页面，并拦截 XSS 与扫描器 UA。
set -eu
base="${WAF_URL:-http://127.0.0.1:8080}"

code() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

ok=$(code "$base/")
xss=$(code -g -- "$base/?q=<script>alert(1)</script>")
scan=$(code -A sqlmap "$base/")

echo "normal=$ok xss=$xss sqlmap=$scan"
test "$ok" = "200"
test "$xss" = "403"
test "$scan" = "403"
echo "smoke ok"

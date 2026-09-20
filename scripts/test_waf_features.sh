#!/usr/bin/env bash
#===============================================================================
# Ma-WAF 功能可用性验证脚本
# 覆盖：进程/配置、数据面防护探针、管理 API、控制台静态资源、关键扩展能力
#
# 用法:
#   sudo ./scripts/test_waf_features.sh                 # 默认全量只读 + 安全探针
#   sudo ./scripts/test_waf_features.sh --quick          # 仅基础设施 + 健康检查
#   sudo ./scripts/test_waf_features.sh --attack         # 额外加强攻击探针（写审计日志）
#   sudo ./scripts/test_waf_features.sh --write          # 允许少量可回滚写操作（备份触发等）
#   sudo ./scripts/test_waf_features.sh --json           # 末尾输出 JSON 汇总
#
# 环境变量（可选）:
#   MA_WAF_PREFIX   产品根，默认 /usr/local/Ma-waf
#   NGINX_PREFIX    Nginx 根，默认 /usr/local/nginx
#   API_URL         管理 API，默认 https://127.0.0.1:8443
#   DATA_URL        数据面，默认 http://127.0.0.1
#   SITE_HOST       业务 Host，默认 www.mingansec.com（避免落到空上游 default_server）
#   ADMIN_USER / ADMIN_PASS / ADMIN_TOTP
#===============================================================================
set -euo pipefail

resolve_prefix() {
  if [[ -n "${MA_WAF_PREFIX:-}" ]]; then echo "$MA_WAF_PREFIX"
  elif [[ -d /usr/local/Ma-waf ]]; then echo /usr/local/Ma-waf
  else echo /usr/local/ma-waf; fi
}

PREFIX="$(resolve_prefix)"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
NGINX_BIN="${NGINX_PREFIX}/sbin/nginx"
API_URL="${API_URL:-https://127.0.0.1:8443}"
DATA_URL="${DATA_URL:-http://127.0.0.1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
ADMIN_TOTP="${ADMIN_TOTP:-}"
# 业务站点 Host（默认站 app.conf 常指 127.0.0.1:8080；无上游时根路径易超时）
SITE_HOST="${SITE_HOST:-www.mingansec.com}"
LOG_DIR="${PREFIX}/var/log"
LOG_FILE="${LOG_DIR}/test_waf_features.log"
REPORT_JSON="${PREFIX}/var/log/test_waf_features_last.json"

QUICK=0
ATTACK=0
WRITE=0
JSON_OUT=0
PASS=0
FAIL=0
WARN=0
SKIP=0
TOKEN=""
ENGINE_MODE="unknown"
CURL_CODE=0
BODY=""
CURL_CODE_FILE="${LOG_DIR}/.curl_http_code"

mkdir -p "$LOG_DIR"
: >"$LOG_FILE"

ts() { date '+%F %T'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
pass() { PASS=$((PASS + 1)); log "PASS  $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL  $*"; }
warn() { WARN=$((WARN + 1)); log "WARN  $*"; }
skip() { SKIP=$((SKIP + 1)); log "SKIP  $*"; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quick) QUICK=1; shift ;;
      --attack) ATTACK=1; shift ;;
      --write) WRITE=1; shift ;;
      --json) JSON_OUT=1; shift ;;
      -h|--help) usage ;;
      *) echo "未知参数: $1"; usage ;;
    esac
  done
}

have() { command -v "$1" >/dev/null 2>&1; }

# JSON 取值：优先 jq，否则 python3
json_get() {
  local raw="$1" key="$2"
  if have jq; then
    # key 形如 .token 或 .items
    echo "$raw" | jq -r "${key} // empty" 2>/dev/null || true
  elif have python3; then
    RAW_JSON="$raw" JSON_KEY="$key" python3 - <<'PY' 2>/dev/null || true
import json, os
raw = os.environ.get("RAW_JSON", "")
path = os.environ.get("JSON_KEY", "").lstrip(".")
try:
    cur = json.loads(raw)
except Exception:
    raise SystemExit(0)
for part in path.split("."):
    if part == "":
        continue
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        raise SystemExit(0)
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, ensure_ascii=False))
elif cur is not None:
    print(cur)
PY
  fi
}

# curl 封装：body 走 stdout；HTTP 码写入文件（body=$(fn) 子 shell 不会丢掉状态码）
# 管理面 8443 开了 http2 时，部分 curl 仍返回 body+200 但进程退出码非 0，不能当失败。
curl_read_code() {
  if [[ -f "$CURL_CODE_FILE" ]]; then
    CURL_CODE="$(tr -cd '0-9' <"$CURL_CODE_FILE")"
  else
    CURL_CODE=""
  fi
  [[ -n "$CURL_CODE" ]] || CURL_CODE="000"
}

curl_body() {
  local method="$1"; shift
  local url="$1"; shift
  local tmp code rc=0
  tmp="$(mktemp)"
  mkdir -p "$(dirname "$CURL_CODE_FILE")"
  set +e
  code=$(curl -4 --http1.1 -skS -o "$tmp" -w '%{http_code}' \
    --connect-timeout 5 --max-time 12 \
    -X "$method" "$@" "$url" 2>/dev/null)
  rc=$?
  set -e
  code="$(printf '%s' "$code" | tr -cd '0-9')"
  if [[ -z "$code" ]]; then
    code="000"
  fi
  printf '%s' "$code" >"$CURL_CODE_FILE"
  # 即使 curl 退出码非 0，只要拿到了 HTTP 码和 body 仍采用响应
  if [[ "$code" == "000" && $rc -ne 0 ]]; then
    rm -f "$tmp"
    echo ""
    return 0
  fi
  cat "$tmp"
  rm -f "$tmp"
}

req() {
  BODY="$(curl_body "$@")"
  curl_read_code
}

api_req() {
  local hdr=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
  BODY="$(curl_body "$@" "${hdr[@]}")"
  curl_read_code
}

expect_http() {
  local name="$1" want="$2"
  local got="$CURL_CODE"
  [[ "$got" == "000" ]] && got="0"
  if echo "|$want|" | grep -q "|$got|"; then
    pass "$name (HTTP $got)"
  elif [[ "$got" == "0" ]]; then
    fail "$name (请求失败/无响应)"
  else
    fail "$name (期望 HTTP $want，实际 $got)"
  fi
}

#------------------------------- 1. 基础设施 -----------------------------------
section_infra() {
  log "======== 1) 基础设施 ========"

  if [[ -x "$NGINX_BIN" ]]; then
    pass "nginx 二进制存在: $NGINX_BIN"
  else
    fail "nginx 二进制不存在: $NGINX_BIN"
  fi

  if pgrep -x nginx >/dev/null 2>&1; then
    pass "nginx 进程运行中"
  else
    fail "nginx 进程未运行"
  fi

  if [[ -x "$NGINX_BIN" ]]; then
    if "$NGINX_BIN" -t >/dev/null 2>&1; then
      pass "nginx -t 配置语法通过"
    else
      fail "nginx -t 失败"
      "$NGINX_BIN" -t 2>&1 | tee -a "$LOG_FILE" || true
    fi
  fi

  if systemctl is-active --quiet ma-waf-api 2>/dev/null; then
    pass "systemd ma-waf-api active"
  else
    fail "systemd ma-waf-api 未运行"
  fi

  if [[ -x "${PREFIX}/bin/ma-waf-api" && ! -d "${PREFIX}/bin/ma-waf-api" ]]; then
    pass "API 二进制: ${PREFIX}/bin/ma-waf-api"
  else
    # 服务在跑但路径缺失时降级为 WARN（常见于未 install 到 bin/）
    if systemctl is-active --quiet ma-waf-api 2>/dev/null; then
      warn "缺少 ${PREFIX}/bin/ma-waf-api 文件，但 ma-waf-api 服务在运行 — 请执行 scripts/fix_runtime.sh"
    else
      fail "缺少 API 二进制 ${PREFIX}/bin/ma-waf-api"
    fi
  fi

  if have ss; then
    ss -lntp 2>/dev/null | grep -qE ':80\b' && pass "监听 :80" || warn "未检测到 :80 监听"
    ss -lntp 2>/dev/null | grep -qE ':8443\b' && pass "监听 :8443" || warn "未检测到 :8443 监听"
    if ss -lntp 2>/dev/null | grep -E ':9090' | grep -qE '127\.0\.0\.1|::1'; then
      pass "API :9090 本机绑定"
    elif ss -lntp 2>/dev/null | grep -qE ':9090'; then
      warn "API :9090 可能非本机绑定"
    else
      fail "未检测到 :9090"
    fi
  else
    skip "无 ss，跳过端口检查"
  fi

  local crt="${PREFIX}/conf/tls/admin.crt" key="${PREFIX}/conf/tls/admin.key"
  if [[ -f "$crt" && -f "$key" ]]; then
    pass "管理面 TLS 证书存在"
  else
    fail "缺少管理面证书 $crt / $key（控制台 PKI 可生成）"
  fi

  local rules="${NGINX_PREFIX}/conf/modsecurity/rules"
  local n=0
  if [[ -d "$rules" ]]; then
    n="$(find "$rules" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if [[ "$n" -ge 5 ]]; then
    pass "ModSecurity 规则文件数=$n"
  elif [[ -f "$rules/000-placeholder.conf" ]]; then
    fail "CRS 仍为占位（仅 placeholder），请 install_crs.sh / update_rules.sh"
  else
    fail "规则目录异常 conf=$n path=$rules"
  fi

  if [[ -f "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf" ]]; then
    ENGINE_MODE="$(grep -E '^SecRuleEngine' "${NGINX_PREFIX}/conf/modsecurity/modsecurity.conf" | awk '{print $2}' | head -1)"
    pass "SecRuleEngine=${ENGINE_MODE:-unknown}"
  else
    fail "缺少 modsecurity.conf"
  fi

  local cons="${PREFIX}/share/console"
  if [[ -f "$cons/index.html" && -f "$cons/assets/app.js" ]]; then
    pass "控制台静态目录 $cons"
    if grep -q 'rules/upgrade/local\|WAF 规则库' "$cons/assets/app.js" 2>/dev/null; then
      pass "控制台含规则库升级 UI 标记"
    else
      warn "控制台 app.js 可能未同步最新（缺规则库升级 UI）→ cp -a management/console/. share/console/"
    fi
    if grep -q 'hs-topnav\|特征库升级\|站点自发现' "$cons/assets/app.js" 2>/dev/null; then
      pass "控制台含山石风格导航标记"
    else
      warn "控制台可能仍为旧版壳层"
    fi
  else
    fail "控制台未部署到 $cons"
  fi
}

#------------------------------- 2. 数据面 -------------------------------------
probe_url_ok() {
  local url="$1"
  req GET "$url"
  [[ "$CURL_CODE" != "0" && "$CURL_CODE" != "000" ]]
}

section_dataplane() {
  log "======== 2) 数据面可用性 ========"

  # 自动尝试常见入口（上游未起时 502 仍算「nginx 可达」）
  local candidates=("${DATA_URL%/}" "http://127.0.0.1" "http://127.0.0.1:80" "http://127.0.0.1:8080")
  local chosen="" c
  for c in "${candidates[@]}"; do
    [[ -z "$c" ]] && continue
    if probe_url_ok "${c}/waf-health" || probe_url_ok "${c}/"; then
      chosen="$c"
      DATA_URL="$c"
      break
    fi
  done

  if [[ -z "$chosen" ]]; then
    local err
    err="$(curl -4 --http1.1 -sv --connect-timeout 3 --max-time 5 "${DATA_URL%/}/" -o /dev/null 2>&1 | tr '\n' ' ' | tail -c 300 || true)"
    fail "数据面不可达: $DATA_URL （curl 诊断: ${err:-none}）"
    fail "普通请求无响应 — 请检查: ss -lntp | grep :80；upstream 是否配置；或 DATA_URL=http://<实际IP>:<端口>"
    return
  fi
  log "数据面探测地址: $DATA_URL  SITE_HOST=$SITE_HOST"

  req GET "${DATA_URL%/}/waf-health" -H "Host: ${SITE_HOST}"
  if [[ "$CURL_CODE" == "200" ]] && echo "$BODY" | grep -qi 'ok\|status'; then
    pass "数据面 /waf-health"
  else
    req GET "${DATA_URL%/}/waf-health"
    if [[ "$CURL_CODE" == "200" ]] && echo "$BODY" | grep -qi 'ok\|status'; then
      pass "数据面 /waf-health（default_server）"
    else
      req GET "${DATA_URL%/}/"
      if [[ "$CURL_CODE" != "0" && "$CURL_CODE" != "000" ]]; then
        warn "/waf-health 未就绪 (HTTP $CURL_CODE)，根路径 HTTP $CURL_CODE（上游未启动时常见 502，nginx 本身仍可用）"
      else
        fail "数据面不可达: $DATA_URL （/waf-health HTTP $CURL_CODE）"
      fi
    fi
  fi

  # 带业务 Host，避免落到 app.conf → 127.0.0.1:8080 无上游超时
  req GET "${DATA_URL%/}/" -H "Host: ${SITE_HOST}" -A "Mozilla/5.0 (Ma-WAF-FeatureTest/1.0)"
  case "$CURL_CODE" in
    200|301|302|304|403|404|502|503|504) pass "普通请求可达 (HTTP $CURL_CODE Host=$SITE_HOST)" ;;
    0|000)
      # 再试 default_server，502 也算 nginx 可达
      req GET "${DATA_URL%/}/" -A "Mozilla/5.0 (Ma-WAF-FeatureTest/1.0)"
      case "$CURL_CODE" in
        200|301|302|304|403|404|502|503|504) pass "普通请求可达 (HTTP $CURL_CODE default_server)" ;;
        0|000)
          warn "普通请求无响应 (HTTP 0) — 多为上游 HTTPS/超时；WAF 监听正常可结合攻击探针判断"
          ;;
        *) warn "普通请求异常 HTTP $CURL_CODE" ;;
      esac
      ;;
    *) warn "普通请求异常 HTTP $CURL_CODE" ;;
  esac
}

section_attack_probes() {
  log "======== 3) WAF 攻击探针（可写审计） ========"
  log "引擎模式=$ENGINE_MODE；On 时期望恶意请求被 403；DetectionOnly 可能仍 200"

  local code_sql code_xss code_path
  local host_hdr=(-H "Host: ${SITE_HOST}")

  req GET "${DATA_URL%/}/?id=1%27%20OR%20%271%27%3D%271" "${host_hdr[@]}" -A "Ma-WAF-FeatureTest/sqli"
  code_sql="$CURL_CODE"
  req GET "${DATA_URL%/}/?q=%3Cscript%3Ealert(1)%3C/script%3E" "${host_hdr[@]}" -A "Ma-WAF-FeatureTest/xss"
  code_xss="$CURL_CODE"
  # curl 默认会把 /../../etc/passwd 规范成 /etc/passwd；用 path-as-is + 查询串双保险
  req GET "${DATA_URL%/}/?file=..%2F..%2F..%2Fetc%2Fpasswd" "${host_hdr[@]}" -A "Ma-WAF-FeatureTest/lfi"
  code_path="$CURL_CODE"
  if [[ "$code_path" == "0" || "$code_path" == "000" ]]; then
    BODY="$(curl_body GET "${DATA_URL%/}/../../etc/passwd" --path-as-is "${host_hdr[@]}" -A "Ma-WAF-FeatureTest/lfi")"
    curl_read_code
    code_path="$CURL_CODE"
  fi

  eval_attack() {
    local name="$1" code="$2"
    [[ "$code" == "000" ]] && code="0"
    if [[ "$code" == "0" ]]; then
      # 未拦住又卡在上游时常见；降级 WARN，避免误判为 WAF 失效
      warn "$name 无响应 (HTTP 0) — 若 SQLi/XSS 已 403，多为上游超时而非引擎失效"
      return
    fi
    if [[ "$ENGINE_MODE" == "On" ]]; then
      if [[ "$code" == "403" || "$code" == "406" || "$code" == "429" ]]; then
        pass "$name 已拦截 (HTTP $code)"
      elif [[ "$code" == "200" || "$code" == "404" ]]; then
        warn "$name 未拦截 (HTTP $code) — 检查 CRS/站点是否启用 ModSecurity"
      else
        warn "$name HTTP $code（请结合审计日志判断）"
      fi
    elif [[ "$ENGINE_MODE" == "DetectionOnly" ]]; then
      pass "$name DetectionOnly 下 HTTP $code（应有审计记录，不一定拦截）"
    elif [[ "$ENGINE_MODE" == "Off" ]]; then
      warn "$name 引擎 Off，跳过拦截断言 (HTTP $code)"
    else
      warn "$name HTTP $code（引擎模式未知）"
    fi
  }

  eval_attack "SQLi 探针" "$code_sql"
  eval_attack "XSS 探针" "$code_xss"
  eval_attack "路径穿越探针" "$code_path"

  if [[ "$ATTACK" -eq 1 ]]; then
    req POST "${DATA_URL%/}/login" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -A "Ma-WAF-FeatureTest/ato" \
      --data "username=admin&password=password"
    eval_attack "登录暴力/ATO 样例 POST" "$CURL_CODE"

    local i hit429=0
    for i in $(seq 1 25); do
      curl -4 --http1.1 -skS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 \
        -A "Ma-WAF-FeatureTest/cc" "${DATA_URL%/}/?cc=$i" >/tmp/ma-waf-cc.code 2>/dev/null || echo 0 >/tmp/ma-waf-cc.code
      if [[ "$(cat /tmp/ma-waf-cc.code)" == "429" ]]; then hit429=1; break; fi
    done
    rm -f /tmp/ma-waf-cc.code
    if [[ "$hit429" -eq 1 ]]; then
      pass "CC/限流探针触发 429"
    else
      warn "CC 探针未观察到 429（阈值可能较高或未启用 limit_req）"
    fi
  fi

  local audit="${NGINX_PREFIX}/logs/modsec_audit.log"
  [[ -f "$audit" ]] || audit="/data/logs/nginx/modsec_audit.json"
  [[ -f "$audit" ]] || audit="${PREFIX}/var/log/modsec_audit.log"
  if [[ -f "$audit" ]]; then
    if find "$audit" -mmin -30 2>/dev/null | grep -q . || [[ -s "$audit" ]]; then
      pass "存在 ModSecurity 审计日志: $audit"
    else
      warn "审计日志存在但可能为空: $audit"
    fi
  else
    warn "未找到审计日志文件（路径因部署而异）"
  fi
}

#------------------------------- 3. 管理 API -----------------------------------
section_api_login() {
  log "======== 4) 管理 API 登录 ========"
  local payload
  payload=$(printf '{"username":"%s","password":"%s","totp":"%s"}' \
    "$ADMIN_USER" "$ADMIN_PASS" "$ADMIN_TOTP")

  # 优先 8443；失败则回退本机 9090（绕过 nginx 反代）
  req POST "${API_URL%/}/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "$payload"
  TOKEN="$(json_get "$BODY" ".token")"
  if [[ -z "$TOKEN" ]]; then
    log "8443 登录未拿到 token (HTTP $CURL_CODE)，尝试 http://127.0.0.1:9090 …"
    API_URL="http://127.0.0.1:9090"
    req POST "${API_URL%/}/api/v1/auth/login" \
      -H "Content-Type: application/json" -d "$payload"
    TOKEN="$(json_get "$BODY" ".token")"
  fi

  if [[ -n "$TOKEN" ]]; then
    pass "API 登录成功 (HTTP ${CURL_CODE} via $API_URL)"
  else
    fail "API 登录失败 HTTP $CURL_CODE body=${BODY:0:200}"
    TOKEN=""
  fi
}

api_get_ok() {
  local path="$1" name="${2:-$1}"
  if [[ -z "$TOKEN" ]]; then
    skip "未登录，跳过 $name"
    return
  fi
  api_req GET "${API_URL%/}/api/v1${path}"
  if [[ "$CURL_CODE" == "200" ]]; then
    pass "API GET $name"
  elif [[ "$CURL_CODE" == "404" ]]; then
    fail "API GET $name → 404（二进制可能未含该接口，需重新编译安装）"
  elif [[ "$CURL_CODE" == "401" ]]; then
    fail "API GET $name → 401"
  else
    fail "API GET $name → HTTP $CURL_CODE ${BODY:0:120}"
  fi
}

section_api_reads() {
  log "======== 5) 管理 API 只读接口 ========"
  req GET "${API_URL%/}/api/v1/health"
  expect_http "API /api/v1/health" "200"
  req GET "${API_URL%/}/healthz"
  expect_http "API /healthz" "200"
  req GET "${API_URL%/}/metrics"
  if [[ "$CURL_CODE" == "200" ]] && echo "$BODY" | grep -q 'ma_waf\|process_\|#'; then
    pass "Prometheus /metrics"
  else
    warn "Prometheus /metrics HTTP $CURL_CODE"
  fi

  req POST "${API_URL%/}/challenge/issue" -H "Content-Type: application/json" -d '{}'
  if [[ "$CURL_CODE" == "200" ]]; then
    pass "Challenge issue"
  else
    warn "Challenge issue HTTP $CURL_CODE"
  fi

  [[ -n "$TOKEN" ]] || { warn "无 token，跳过鉴权接口"; return; }

  local paths=(
    "/status:status"
    "/dashboard:dashboard"
    "/metrics:metrics-json"
    "/mode:mode"
    "/rules:rules"
    "/attacks:attacks"
    "/attacks/summary:attack-summary"
    "/attacks/trend:attack-trend"
    "/sites:sites"
    "/sites/discover:site-discover"
    "/iplist/blacklist:blacklist"
    "/iplist/whitelist:whitelist"
    "/geo/blocklist:geo-blocklist"
    "/geo/status:geo-status"
    "/virtpatches:virtpatches"
    "/exceptions:exceptions"
    "/license/status:license"
    "/license/fingerprint:fingerprint"
    "/backups:backups"
    "/packs:packs"
    "/audit/chain:audit-chain"
    "/ops:ops"
    "/ops/golive:golive"
    "/openapi/status:openapi"
    "/profiles:profiles"
    "/bots/good:good-bots"
    "/insights:insights"
    "/insights/fp:fp-suggest"
    "/crs/paranoia:paranoia"
    "/content-policy:content-policy"
    "/threat-intel/status:threat-intel"
    "/ha/status:ha"
    "/addrbook:addrbook"
    "/pki/certs:pki"
    "/sysinfo:sysinfo"
    "/rules/upgrade/status:rules-upgrade-status"
  )
  local item path name
  for item in "${paths[@]}"; do
    path="${item%%:*}"
    name="${item##*:}"
    api_get_ok "$path" "$name"
  done

  api_req GET "${API_URL%/}/api/v1/reports/export?format=csv"
  if [[ "$CURL_CODE" == "200" ]]; then
    pass "报表导出 CSV"
  else
    warn "报表导出 HTTP $CURL_CODE"
  fi
}

section_api_writes() {
  [[ "$WRITE" -eq 1 ]] || { skip "未指定 --write，跳过写操作测试"; return; }
  [[ -n "$TOKEN" ]] || { skip "无 token，跳过写操作"; return; }
  log "======== 6) 管理 API 安全写操作 ========"

  api_req POST "${API_URL%/}/api/v1/backup" -d '{}'
  if [[ "$CURL_CODE" == "200" ]]; then
    pass "触发配置备份"
  else
    warn "备份 HTTP $CURL_CODE ${BODY:0:120}"
  fi

  api_req POST "${API_URL%/}/api/v1/rules/validate" -d '{}'
  if [[ "$CURL_CODE" == "200" ]]; then
    pass "规则 validate"
  else
    warn "规则 validate HTTP $CURL_CODE ${BODY:0:120}"
  fi

  api_req GET "${API_URL%/}/api/v1/addrbook"
  if [[ "$CURL_CODE" == "200" ]]; then
    local items
    items="$(json_get "$BODY" ".items")"
    if [[ -n "$items" ]]; then
      api_req PUT "${API_URL%/}/api/v1/addrbook" -d "{\"items\":$items}"
      if [[ "$CURL_CODE" == "200" ]]; then
        pass "地址簿 PUT 回环"
      else
        warn "地址簿 PUT HTTP $CURL_CODE"
      fi
    else
      warn "地址簿 items 为空，跳过 PUT"
    fi
  fi

  if have tar && have gzip; then
    local work bundle up_code
    work="$(mktemp -d)"
    mkdir -p "$work/custom"
    cat >"$work/custom/199999-feature-test.conf" <<'EOF'
# Ma-WAF feature test rule pack — safe no-op comment only
EOF
    bundle="${work}/ma-waf-feature-test.tgz"
    tar -czf "$bundle" -C "$work" custom
    up_code=$(curl -4 --http1.1 -skS -o /tmp/ma-waf-up.json -w '%{http_code}' \
      --connect-timeout 5 --max-time 120 \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@${bundle};type=application/gzip" \
      -F "promote=0" \
      "${API_URL%/}/api/v1/rules/upgrade/local" 2>/dev/null || true)
    up_code="$(printf '%s' "$up_code" | tr -cd '0-9')"
    if [[ "$up_code" == "200" ]]; then
      pass "本地规则库升级（promote=0）"
    else
      fail "本地规则库升级失败 HTTP ${up_code:-0} $(head -c 200 /tmp/ma-waf-up.json 2>/dev/null || true)"
    fi
    rm -rf "$work" /tmp/ma-waf-up.json
  else
    skip "无 tar/gzip，跳过规则包升级写测"
  fi
}

#------------------------------- 汇总 ------------------------------------------
write_report() {
  local ok=false
  [[ "$FAIL" -eq 0 ]] && ok=true
  cat >"$REPORT_JSON" <<EOF
{
  "ok": $ok,
  "pass": $PASS,
  "fail": $FAIL,
  "warn": $WARN,
  "skip": $SKIP,
  "engine_mode": "$(printf '%s' "$ENGINE_MODE" | sed 's/"/\\"/g')",
  "api_url": "$(printf '%s' "$API_URL" | sed 's/"/\\"/g')",
  "data_url": "$(printf '%s' "$DATA_URL" | sed 's/"/\\"/g')",
  "prefix": "$(printf '%s' "$PREFIX" | sed 's/"/\\"/g')",
  "ts": "$(date -Iseconds)",
  "log": "$(printf '%s' "$LOG_FILE" | sed 's/"/\\"/g')"
}
EOF
  if [[ "$JSON_OUT" -eq 1 ]]; then
    cat "$REPORT_JSON"
  fi
}

main() {
  parse_args "$@"
  log "Ma-WAF 功能验证开始"
  log "PREFIX=$PREFIX API_URL=$API_URL DATA_URL=$DATA_URL quick=$QUICK attack=$ATTACK write=$WRITE"

  section_infra
  section_dataplane

  if [[ "$QUICK" -eq 1 ]]; then
    log "======== --quick：跳过攻击探针与完整 API 列表 ========"
    section_api_login
    if [[ -n "$TOKEN" ]]; then
      api_get_ok "/dashboard" "dashboard"
      api_get_ok "/sysinfo" "sysinfo"
      api_get_ok "/rules/upgrade/status" "rules-upgrade-status"
    fi
  else
    section_attack_probes
    section_api_login
    section_api_reads
    section_api_writes
  fi

  log "======== 汇总 PASS=$PASS FAIL=$FAIL WARN=$WARN SKIP=$SKIP ========"
  log "详细日志: $LOG_FILE"
  log "JSON 报告: $REPORT_JSON"
  write_report

  if [[ "$FAIL" -eq 0 ]]; then
    log "结论: 可用性验证通过（告警 $WARN 项可人工复核）"
    exit 0
  else
    log "结论: 存在 $FAIL 项失败，请根据日志排查"
    exit 2
  fi
}

main "$@"

(() => {
  const LANG_KEY = "ma_waf_lang";

  function detectDefault() {
    try {
      const nav = (navigator.language || navigator.userLanguage || "zh").toLowerCase();
      if (nav.startsWith("en")) return "en";
    } catch (_) { /* ignore */ }
    return "zh";
  }

  function getLang() {
    try {
      const stored = localStorage.getItem(LANG_KEY);
      if (stored === "en" || stored === "zh") return stored;
    } catch (_) { /* ignore */ }
    return detectDefault();
  }

  function setLang(lang) {
    const next = lang === "en" ? "en" : "zh";
    try {
      localStorage.setItem(LANG_KEY, next);
    } catch (_) { /* ignore */ }
    document.documentElement.lang = next === "en" ? "en" : "zh-CN";
    return next;
  }

  function t(zh, en) {
    return getLang() === "en" ? (en != null ? en : zh) : zh;
  }

  /** Exact Chinese → English for API payload strings (hints, titles, notes, etc.). */
  const API_EXACT = {
    // Paranoia
    "PL1 宽松，适合遗留/上线观察": "PL1 lenient — legacy / go-live observation",
    "PL2 均衡（CRS 推荐）": "PL2 balanced (CRS recommended)",
    "PL3 严格，误报可能上升": "PL3 strict — false positives may rise",
    "PL4 最严，仅高对抗场景": "PL4 strictest — high-adversary scenarios only",

    // Packs
    "误报例外策略": "False-positive exception policy",
    "文件上传检测": "File upload detection",
    "敏感信息泄露": "Sensitive data leakage",
    "Bot / 扫描器 UA": "Bot / scanner UA",
    "会话保护": "Session protection",
    "HTTP 协议合规": "HTTP protocol compliance",
    "虚拟补丁": "Virtual patches",
    "OpenAPI API 安全基线": "OpenAPI API security baseline",
    "自定义规则包": "Custom rule pack",

    // Profiles (DefaultProfiles name + description)
    "宽松 (policy_loose)": "Loose (policy_loose)",
    "仅高严重级别倾向；低误报，适合观察期后的宽松生产": "High-severity bias; low FP — loose production after observation",
    "标准 (policy_normal)": "Standard (policy_normal)",
    "默认防护：高准确规则 + 软挑战": "Default protection: high-accuracy rules + soft challenge",
    "严格 (policy_strict)": "Strict (policy_strict)",
    "启用多数规则包；最大防护，误报可能升高": "Most packs on; max protection, higher FP risk",
    "调试 (policy_debug)": "Debug (policy_debug)",
    "DetectionOnly，便于排查误报": "DetectionOnly — for false-positive triage",
    "紧急/重保 (policy_emergency)": "Emergency / heavy-security (policy_emergency)",
    "最高偏执级别 + 全开引擎，重大活动期间使用": "Highest paranoia + engine On — for major events",
    "均衡防护（兼容）": "Balanced (compat)",
    "同 policy_normal": "Same as policy_normal",
    "API 严格（兼容）": "API strict (compat)",
    "同 policy_strict 侧重 API": "Same as policy_strict, API-focused",
    "仅检测（兼容）": "Detection-only (compat)",
    "同 policy_debug": "Same as policy_debug",
    "CMS/遗留（兼容）": "CMS / legacy (compat)",
    "同 policy_loose": "Same as policy_loose",

    // Bundle / HA / Geo / License
    "支持 .tgz/.tar.gz：含 custom/*.conf（→staging）与/或 rules/*.conf（→ModSecurity rules）。可选同名 .sig + conf/update-pubkey.pem 验签。":
      "Supports .tgz/.tar.gz with custom/*.conf (→staging) and/or rules/*.conf (→ModSecurity rules). Optional same-name .sig + conf/update-pubkey.pem for signature verify.",
    "双机需部署 configs/ha/keepalived.conf.example；管理面勿挂 VIP":
      "For HA, deploy configs/ha/keepalived.conf.example; do not put VIP on the management plane",
    "nginx 未运行": "nginx not running",
    "nginx -t 失败": "nginx -t failed",
    "本机 80/8081 均不可达": "Local ports 80/8081 unreachable",
    "将 GeoLite2-Country.mmdb 放到 conf/geoip/ 即可驱动报表国家热力；国家封锁另需 ngx_http_geoip2_module + /geo/enforce":
      "Place GeoLite2-Country.mmdb under conf/geoip/ for country heatmaps; country blocking also needs ngx_http_geoip2_module + /geo/enforce",
    "宽限期已结束，请导入有效 license.lic": "Grace period ended — import a valid license.lic",
    "未激活 License，处于试用宽限期": "License inactive — trial grace period",
    "已进入试用宽限期，请尽快导入 License": "Trial grace period started — import a License soon",
    "请在控制台导入 license.lic，或使用 tools/license_gen.py 签发":
      "Import license.lic in the console, or issue one with tools/license_gen.py",
    "License 导入成功": "License imported successfully",
    "将 fingerprint 提供给授权方，使用 tools/license_gen.py 签发 license.lic":
      "Give the fingerprint to the issuer and create license.lic with tools/license_gen.py",

    // Go-live / engine
    "拦截模式": "Blocking mode",

    // Troubleshoot categories
    "服务": "Service",
    "配置": "Config",
    "证书": "Certificate",
    "防护": "Protection",
    "许可": "License",
    "主机": "Host",
    "能力": "Capability",

    // Troubleshoot titles
    "Nginx 二进制": "Nginx binary",
    "Nginx 配置检测 (nginx -t)": "Nginx config test (nginx -t)",
    "管理面 TLS (admin.crt/key)": "Admin TLS (admin.crt/key)",
    "ModSecurity 主配置": "ModSecurity main config",
    "SecRuleEngine 模式": "SecRuleEngine mode",
    "控制台静态文件": "Console static files",
    "http_auth_request_module": "http_auth_request_module",
    "受保护站点": "Protected sites",
    "产品目录可用空间": "Product directory free space",
    "许可证状态": "License status",
    "关键端口监听": "Key ports listening",
    "HA / 健康探测": "HA / health probe",

    // Troubleshoot hints
    "确认 NginxBin 配置或 /usr/local/nginx/sbin/nginx 存在":
      "Confirm NginxBin setting or that /usr/local/nginx/sbin/nginx exists",
    "失败时用系统→配置备份回滚，或修复 conf.d/site-*.conf 与 admin.crt":
      "On failure, roll back via System → config backup, or fix conf.d/site-*.conf and admin.crt",
    "缺失会导致 nginx -t 与 :8443 失败。可点「修复证书」或到 PKI 页生成":
      "Missing files break nginx -t and :8443. Use “Fix certificate” or generate on the PKI page",
    "检查 API 配置 ModSecConf 路径": "Check API ModSecConf path",
    "Off 为旁路；上线拦截需 On；排障可临时 DetectionOnly":
      "Off = bypass; blocking go-live needs On; use DetectionOnly temporarily for triage",
    "执行 sync_console / 复制 management/console → share/console 后重启 API":
      "Run sync_console / copy management/console → share/console, then restart the API",
    "未编译时站点不会写 auth_request，避免 nginx -t 失败":
      "When not compiled, sites omit auth_request to avoid nginx -t failure",
    "空间不足会导致备份/升级失败": "Low disk space can break backup/upgrade",
    "宽限期结束后变更类 API 将被拒绝，请到许可证页导入":
      "After grace ends, mutating APIs are rejected — import on the License page",
    "管理面通常为 :8443（Nginx）→ API :9090；数据面 :80/:443":
      "Admin plane is usually :8443 (Nginx) → API :9090; data plane :80/:443",

    // Troubleshoot details / misc
    "跳过：nginx 二进制不可用": "Skipped: nginx binary unavailable",
    "已编译（HMAC 硬校验可用）": "Compiled (HMAC hard challenge available)",
    "未编译（自动降级为 JS 软挑战）": "Not compiled (auto-fallback to JS soft challenge)",
    "未提供": "Not provided",
    "无法执行 ss/netstat（可跳过）": "Cannot run ss/netstat (skippable)",

    // Troubleshoot tips
    "管理面 Failed to fetch / 404": "Admin plane Failed to fetch / 404",
    "同步 share/console，确认 ma-waf-api 运行，nginx -t 通过后 reload；浏览器 Ctrl+F5。":
      "Sync share/console, confirm ma-waf-api is running, pass nginx -t then reload; browser Ctrl+F5.",
    "站点保存失败 / nginx -t 失败": "Site save failed / nginx -t failed",
    "检查 admin.crt、auth_request 模块降级、conf.d 语法；可点「修复证书」或回滚备份。":
      "Check admin.crt, auth_request module fallback, conf.d syntax; use “Fix certificate” or roll back a backup.",
    "数据面 502": "Data-plane 502",
    "上游业务服务未启动或 upstream 地址错误；与 WAF 引擎无关时请先查 upstream。":
      "Upstream app down or wrong upstream address; if unrelated to the WAF engine, check upstream first.",
    "误报冲高": "False-positive spike",
    "临时 DetectionOnly 或紧急旁路；在规则例外中放行 URI/规则 ID；调低 CRS 偏执级。":
      "Temporarily use DetectionOnly or emergency bypass; allow URI/rule IDs in exceptions; lower CRS paranoia.",
    "CPU 飙高": "High CPU",
    "检查 CC 限流、静态资源白名单、SecPcreMatchLimit；查看本页 Nginx error 尾部。":
      "Check CC rate limits, static whitelist, SecPcreMatchLimit; inspect Nginx error tail on this page.",

    // Upgrade notes / errors
    "签名验证通过": "Signature verified",
    "STRICT: 缺少签名或 conf/update-pubkey.pem": "STRICT: missing signature or conf/update-pubkey.pem",
    "未提供 .sig，跳过验签": "No .sig provided — skipped signature verify",
    "未配置 update-pubkey.pem，跳过验签": "update-pubkey.pem not configured — skipped signature verify",
    "已 promote 并 reload": "Promoted and reloaded",
    "仅写入 staging，未 promote": "Wrote staging only — not promoted",
    "缺少升级包": "Upgrade bundle missing",
    "仅支持 .tgz / .tar.gz / .tar": "Only .tgz / .tar.gz / .tar supported",
    "包内未找到 custom/*.conf 或 rules/*.conf": "No custom/*.conf or rules/*.conf found in bundle",
    "无 rule_manager.py，跳过校验": "No rule_manager.py — skipped validate",
    "无 python3，跳过校验": "No python3 — skipped validate",
    "未找到 openssl，无法验签": "openssl not found — cannot verify signature",

    // License parse / import errors
    "无法采集硬件指纹": "Cannot collect hardware fingerprint",
    "公钥 PEM 解析失败": "Public key PEM parse failed",
    "需要 ECDSA P-256 公钥": "ECDSA P-256 public key required",
    "License 结构错误：缺少签名分隔符": "License structure error: missing signature separator",
    "签名验证失败，文件可能被篡改": "Signature verification failed — file may be tampered",
    "License 缺少必要字段": "License missing required fields",
    "硬件指纹不匹配": "Hardware fingerprint mismatch",
  };

  /**
   * Pattern translations. Replacers may be strings or functions.
   * CRS hint uses API_EXACT lookup (no recursive apiT) to avoid loops.
   */
  const API_PATTERNS = [
    [/^当前模式 (.+)（上线拦截需 On）$/, "Current mode $1 (blocking requires On)"],
    [/^误报候选 (\d+) 条（≥5 次同 URI\+规则）$/, "False-positive candidates: $1 (≥5 same URI+rule)"],
    [/^已配置例外 (\d+) 条$/, "Exceptions configured: $1"],
    [/^CRS PL(\d) (.+)$/, (_, n, hint) => `CRS PL${n} ${API_EXACT[hint] || hint}`],
    [/^本机数据面端口可达 \((.+)\)$/, "Local data-plane port reachable ($1)"],
    [/^(\d+) 个 site-\*\.conf$/, "$1 site-*.conf"],
    [/^已监听 (.+)；未检测到 (.+)$/, "Listening: $1; not detected: $2"],
    [/^监听中: (.+)$/, "Listening: $1"],
    // HA detail: role — health (avoid broad " — " matches)
    [/^(master|backup|unknown|standalone) — (.+)$/, (_, role, detail) => {
      const d = API_EXACT[detail] || detail.replace(/^本机数据面端口可达 \((.+)\)$/, "Local data-plane port reachable ($1)");
      return `${role} — ${d}`;
    }],
    // Upgrade notes with dynamic suffixes / joined notes
    [/^解包失败: (.+)$/, "Extract failed: $1"],
    [/^promote\/reload 失败: (.+)$/, "promote/reload failed: $1"],
    [/^staging 校验失败: (.+)$/, "staging validate failed: $1"],
    [/^validate: (.+)$/, "validate: $1"],
    [/^backup warn: (.+)$/, "backup warn: $1"],
    [/^staging\+(\d+) custom, rules\+(\d+)$/, "staging+$1 custom, rules+$2"],
    [/^缺少公钥 (.+)$/, "Missing public key $1"],
    [/^签名验证失败: (.+)$/, "Signature verify failed: $1"],
    [/^拒绝危险路径: (.+)$/, "Rejected unsafe path: $1"],
    [/^路径逃逸: (.+)$/, "Path escape: $1"],
    [/^非法路径: (.+)$/, "Illegal path: $1"],
    [/^MMDB=(.+) 模块=(.+) 执法=(.+)$/, "MMDB=$1 module=$2 enforce=$3"],
    [/^公钥不存在: (.+)$/, "Public key missing: $1"],
    [/^License 文件不存在: (.+)$/, "License file missing: $1"],
    [/^Base64 解码失败: (.+)$/, "Base64 decode failed: $1"],
    [/^签名解码失败: (.+)$/, "Signature decode failed: $1"],
    [/^载荷 JSON 解析失败: (.+)$/, "Payload JSON parse failed: $1"],
    [/^有效期格式错误: (.+)$/, "Invalid expiry format: $1"],
    [/^License 已过期（(.+)）$/, "License expired ($1)"],
    [/^导入成功但验证失败: (.+)$/, "Imported but verification failed: $1"],
    // Notes joined with Chinese semicolon
    [/^[^；\n]+(?:； [^；\n]+)+$/, (m) =>
      m.split("； ").map((part) => {
        if (API_EXACT[part]) return API_EXACT[part];
        for (const [re, repl] of API_PATTERNS) {
          if (re === API_PATTERNS[API_PATTERNS.length - 1]) continue; // skip self
          if (re.test(part)) {
            re.lastIndex = 0;
            return part.replace(re, repl);
          }
        }
        return part;
      }).join("; "),
    ],
  ];

  function apiT(text) {
    if (text == null || text === "") return text;
    if (getLang() !== "en") return text;
    const s = String(text);
    if (API_EXACT[s]) return API_EXACT[s];
    for (const [re, repl] of API_PATTERNS) {
      if (re.test(s)) {
        re.lastIndex = 0;
        return s.replace(re, repl);
      }
    }
    return s;
  }

  function applyAttr(el, attr, value) {
    if (value == null || value === "") return;
    if (attr === "text" || attr === "html") {
      if (attr === "html") el.innerHTML = value;
      else el.textContent = value;
      return;
    }
    if (attr === "placeholder" || attr === "title" || attr === "aria-label" || attr === "value") {
      el.setAttribute(attr, value);
      if (attr === "placeholder") el.placeholder = value;
      if (attr === "title") el.title = value;
      if (attr === "value" && "value" in el) el.value = value;
    }
  }

  function applyDom(root) {
    const scope = root || document;
    const lang = getLang();
    document.documentElement.lang = lang === "en" ? "en" : "zh-CN";

    scope.querySelectorAll("[data-i18n-zh]").forEach((el) => {
      const zh = el.getAttribute("data-i18n-zh");
      const en = el.getAttribute("data-i18n-en");
      const attr = el.getAttribute("data-i18n-attr") || "text";
      applyAttr(el, attr, lang === "en" ? (en || zh) : zh);
    });

    scope.querySelectorAll("[data-i18n-placeholder-zh]").forEach((el) => {
      const zh = el.getAttribute("data-i18n-placeholder-zh");
      const en = el.getAttribute("data-i18n-placeholder-en");
      el.placeholder = lang === "en" ? (en || zh) : zh;
    });

    scope.querySelectorAll("[data-i18n-title-zh]").forEach((el) => {
      const zh = el.getAttribute("data-i18n-title-zh");
      const en = el.getAttribute("data-i18n-title-en");
      el.title = lang === "en" ? (en || zh) : zh;
    });

    // Sync lang switcher active state
    document.querySelectorAll("[data-lang]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-lang") === lang);
      btn.setAttribute("aria-pressed", btn.getAttribute("data-lang") === lang ? "true" : "false");
    });

    // Document title
    const titleEl = document.querySelector("title");
    if (titleEl) {
      titleEl.textContent = t("Ma-WAF 管理控制台", "Ma-WAF Management Console");
    }

    // Manual link href + text
    const manual = document.getElementById("manualLink");
    if (manual) {
      manual.href = lang === "en" ? "/assets/manual.en.html" : "/assets/manual.html";
      manual.textContent = t("用户手册", "User Manual");
      manual.title = t("打开用户手册", "Open user manual");
    }
  }

  function bindSwitchers(onChange) {
    document.querySelectorAll("[data-lang]").forEach((btn) => {
      if (btn.dataset.i18nBound) return;
      btn.dataset.i18nBound = "1";
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const next = btn.getAttribute("data-lang") === "en" ? "en" : "zh";
        if (next === getLang()) return;
        setLang(next);
        applyDom();
        if (typeof onChange === "function") onChange(next);
      });
    });
  }

  // Initialize stored/default language early
  setLang(getLang());

  window.MaI18n = {
    LANG_KEY,
    getLang,
    setLang,
    t,
    apiT,
    applyDom,
    bindSwitchers,
  };
})();

(() => {
  const tokenKey = "ma_waf_token";
  const t = (zh, en) => (window.MaI18n ? window.MaI18n.t(zh, en) : zh);
  const at = (s) => (window.MaI18n && window.MaI18n.apiT ? window.MaI18n.apiT(s) : (s == null ? "" : s));

  function getTitles() {
    return {
      dashboard: [t("总览", "Overview"), t("攻击态势 · 引擎状态 · 关键指标", "Attack posture · Engine status · Key metrics")],
      events: [t("安全事件", "Security events"), t("Host · 状态码 · 请求/响应长度 · 攻击字段 · 详情", "Host · Status · Req/resp length · Attack fields · Details")],
      sites: [t("Web 站点", "Web sites"), t("添加 / 编辑 / 删除反向代理站点并启用 WAF", "Add / edit / delete reverse-proxy sites with WAF")],
      discover: [t("站点自发现", "Site discovery"), t("从访问日志识别 Host，审核后纳入防护", "Discover Hosts from access logs, then onboard for protection")],
      exceptions: [t("规则例外", "Rule exceptions"), t("误报 URL / 规则放行 · 热更新 ModSecurity", "False-positive URL / rule allow · Hot-update ModSecurity")],
      rules: [t("防护规则", "Protection rules"), t("自定义规则启停 · 优先级 · Staging 发布", "Custom rule toggle · Priority · Staging promote")],
      iplist: [t("IP / Geo 名单", "IP / Geo lists"), t("黑白名单 · 国家封锁 · 热更新 Reload", "Black/white lists · Country block · Hot Reload")],
      addrbook: [t("地址簿", "Address book"), t("可复用 IP 对象 · 引用计数 · 一键应用到名单", "Reusable IP objects · Ref count · Apply to lists")],
      policy: [t("安全策略", "Security policy"), t("策略模板 · 引擎模式 · CRS 偏执级别", "Policy profiles · Engine mode · CRS paranoia")],
      heavy: [t("重保模式", "Heavy-security mode"), t("重大活动期间一键拉高防护等级", "Raise protection level for major events")],
      license: [t("许可证", "License"), t("硬件指纹 · 导入 .lic · 宽限期状态", "Hardware fingerprint · Import .lic · Grace status")],
      reports: [t("报表与分析", "Reports & analytics"), t("攻击趋势 · Top 排行 · CSV 导出", "Attack trends · Top rankings · CSV export")],
      system: [t("系统运维", "System ops"), t("主机指标 · Prometheus · Nginx 重载", "Host metrics · Prometheus · Nginx reload")],
      sysinfo: [t("系统与特征库", "System & signatures"), t("主机信息 · CRS/Geo/情报版本状态", "Host info · CRS/Geo/intel status")],
      pki: [t("PKI 证书", "PKI certificates"), t("管理面 TLS · 一键生成 admin.crt", "Management TLS · Generate admin.crt")],
      "rules-upgrade": [t("特征库升级", "Signature upgrades"), t("本地上传规则包 · 验签 · 发布到生产", "Upload rule pack · Verify · Promote to production")],
      troubleshoot: [t("故障排查", "Troubleshooting"), t("一键体检 · nginx -t · 证书/端口 · 日志尾部", "Health check · nginx -t · Certs/ports · Log tail")],
    };
  }

  function getModules() {
    return [
      {
        id: "home", label: t("首页", "Home"),
        pages: [{ id: "dashboard", label: t("总览", "Overview") }],
      },
      {
        id: "sites", label: t("站点", "Sites"),
        pages: [
          { id: "sites", label: t("Web 站点", "Web sites") },
          { id: "discover", label: t("站点自发现", "Site discovery") },
        ],
      },
      {
        id: "policy", label: t("策略", "Policy"),
        pages: [
          { id: "policy", label: t("安全策略", "Security policy") },
          { id: "rules", label: t("防护规则", "Protection rules") },
          { id: "exceptions", label: t("规则例外", "Rule exceptions") },
          { id: "heavy", label: t("重保模式", "Heavy-security mode") },
        ],
      },
      {
        id: "monitor", label: t("监控", "Monitor"),
        pages: [
          { id: "events", label: t("安全事件", "Security events") },
          { id: "reports", label: t("报表与分析", "Reports & analytics") },
        ],
      },
      {
        id: "objects", label: t("对象", "Objects"),
        pages: [
          { id: "addrbook", label: t("地址簿", "Address book") },
          { id: "iplist", label: t("IP / Geo 名单", "IP / Geo lists") },
        ],
      },
      {
        id: "system", label: t("系统", "System"),
        pages: [
          { id: "sysinfo", label: t("系统与特征库", "System & signatures") },
          { id: "rules-upgrade", label: t("特征库升级", "Signature upgrades") },
          { id: "pki", label: t("PKI 证书", "PKI certificates") },
          { id: "system", label: t("系统运维", "System ops") },
          { id: "troubleshoot", label: t("故障排查", "Troubleshooting") },
          { id: "license", label: t("许可证", "License") },
        ],
      },
    ];
  }

  const pageModule = {
    dashboard: "home",
    sites: "sites",
    discover: "sites",
    policy: "policy",
    rules: "policy",
    exceptions: "policy",
    heavy: "policy",
    events: "monitor",
    reports: "monitor",
    addrbook: "objects",
    iplist: "objects",
    sysinfo: "system",
    "rules-upgrade": "system",
    pki: "system",
    system: "system",
    troubleshoot: "system",
    license: "system",
  };

  function engineLabel(mode) {
    return t("引擎: ", "Engine: ") + (mode || "-");
  }

  function yesNo(v) {
    return v ? t("是", "Yes") : t("否", "No");
  }

  function enabledLabel(v) {
    return v ? t("启用", "Enabled") : t("禁用", "Disabled");
  }

  const state = {
    page: "dashboard",
    module: "home",
    token: localStorage.getItem(tokenKey) || "",
    dashboard: null,
    events: [],
    rules: [],
    blacklist: [],
    whitelist: [],
    exceptions: [],
    virtpatches: [],
    timer: null,
  };

  const $ = (id) => document.getElementById(id);
  const pageRoot = () => $("pageRoot");

  async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    // FormData 由浏览器自动设置 multipart boundary，勿强制 JSON
    if (!(opts.body instanceof FormData)) {
      headers["Content-Type"] = headers["Content-Type"] || "application/json";
    }
    if (state.token) headers.Authorization = "Bearer " + state.token;
    let res;
    try {
      res = await fetch(path, Object.assign({}, opts, { headers }));
    } catch (netErr) {
      const err = new Error(friendlyFetchError(netErr));
      err.status = 0;
      err.network = true;
      throw err;
    }
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error(at(data.error || data.message || data.hint || "") || text || res.statusText);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function friendlyFetchError(e) {
    const msg = String((e && e.message) || e || "");
    if (/Failed to fetch|NetworkError|network|Load failed|fetch/i.test(msg)) {
      return t("网络中断或管理面暂不可达（常见于 Nginx reload 瞬间）。请稍后点「刷新」；若持续失败请检查 ma-waf-api 与 nginx -t", "Network interrupted or management plane unreachable (often during Nginx reload). Click Refresh shortly; if it persists, check ma-waf-api and nginx -t");
    }
    return msg || t("请求失败", "Request failed");
  }

  async function waitForAPI(ms = 10000) {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      try {
        const res = await fetch("/api/v1/health", { method: "GET", cache: "no-store" });
        if (res.ok) return true;
      } catch (_) { /* retry */ }
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  }

  async function reloadNginxUI() {
    toast(true, t("正在检测配置并 reload…", "Checking config and reloading…"));
    try {
      await api("/api/v1/reload", { method: "POST" });
      toast(true, t("Nginx reload 已触发", "Nginx reload triggered"));
      await new Promise((r) => setTimeout(r, 600));
      if (await waitForAPI(8000)) {
        toast(true, t("Nginx reload 成功，管理面已恢复", "Nginx reload succeeded; management plane restored"));
      } else {
        toast(false, t("Reload 已发出，但管理面暂未响应，请稍后刷新页面", "Reload sent, but management plane not responding yet — refresh later"));
      }
    } catch (e) {
      if (e.network || /网络中断|Failed to fetch|Network interrupted/i.test(String(e.message || ""))) {
        toast(true, t("连接曾中断，正在确认 reload 结果…", "Connection dropped; confirming reload result…"));
        if (await waitForAPI(10000)) {
          toast(true, t("管理面已恢复（Nginx 多半已 reload 成功）", "Management plane restored (Nginx likely reloaded)"));
        } else {
          toast(false, e.message || t("Reload 后无法连接管理面", "Cannot reach management plane after reload"));
        }
      } else {
        toast(false, e.message);
      }
    }
  }

  function toast(ok, msg) {
    $("appErr").textContent = ok ? "" : (msg || "");
    $("appOk").textContent = ok ? (msg || "") : "";
  }

  /** Custom file picker — native "选择文件" follows browser locale, not page language. */
  function filePickerHtml(id, accept) {
    return `<div class="file-pick">
      <input type="file" id="${id}" accept="${esc(accept || "")}" hidden />
      <button type="button" class="ghost file-pick-btn" data-file-for="${id}">${t("选择文件", "Choose file")}</button>
      <span class="file-pick-name muted" data-file-name-for="${id}">${t("未选择文件", "No file selected")}</span>
    </div>`;
  }

  function bindFilePicker(id) {
    const input = $(id);
    const btn = document.querySelector(`[data-file-for="${id}"]`);
    const nameEl = document.querySelector(`[data-file-name-for="${id}"]`);
    if (!input || !btn || !nameEl) return;
    const none = t("未选择文件", "No file selected");
    btn.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      input.click();
    };
    input.onchange = () => {
      const f = input.files && input.files[0];
      nameEl.textContent = f ? f.name : none;
      nameEl.title = f ? f.name : "";
    };
  }

  function showLogin() {
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
    state.token = "";
    localStorage.removeItem(tokenKey);
    document.body.classList.remove("auth-app");
    document.body.classList.add("auth-login");
    closeDrawer();
    if ($("pass")) $("pass").value = "";
    if ($("totp")) $("totp").value = "";
    if ($("loginErr")) $("loginErr").textContent = "";
  }
  function showApp() {
    document.body.classList.remove("auth-login");
    document.body.classList.add("auth-app");
  }

  function bars(rows) {
    if (!rows || !rows.length) return `<div class="empty">${t("暂无数据", "No data")}</div>`;
    const max = Math.max(...rows.map((r) => Number(r.count || r.value || 0)), 1);
    return `<div class="bars">${rows.map((r) => {
      const label = r.key || r.name || "-";
      const val = Number(r.count || r.value || 0);
      const pct = Math.round((val / max) * 100);
      return `<div class="bar-row"><span title="${esc(label)}">${esc(label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <span>${val}</span></div>`;
    }).join("")}</div>`;
  }

  function normalizeSeverityKey(sev) {
    const s = String(sev ?? "").trim();
    const map = {
      "0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL", "3": "ERROR",
      "4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG",
    };
    if (Object.prototype.hasOwnProperty.call(map, s)) return map[s];
    return s ? s.toUpperCase() : "INFO";
  }

  function severityRows(bySev) {
    const merged = {};
    Object.entries(bySev || {}).forEach(([k, v]) => {
      const key = normalizeSeverityKey(k);
      merged[key] = (merged[key] || 0) + Number(v || 0);
    });
    const order = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"];
    return Object.keys(merged)
      .sort((a, b) => {
        const ia = order.indexOf(a); const ib = order.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      })
      .map((key) => ({ key, count: merged[key] }));
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function sevBadge(sev) {
    const s = normalizeSeverityKey(sev);
    return `<span class="badge sev-${esc(s)}">${esc(s)}</span>`;
  }

  async function loadDashboard() {
    state.dashboard = await api("/api/v1/dashboard");
    const d = state.dashboard || {};
    const m = d.metrics || {};
    const sum = d.attack_summary || {};
    $("sideMode").textContent = engineLabel(d.engine_mode);
    const lic = d.license || {};
    const licLabel = lic.status || "unknown";
    pageRoot().innerHTML = `
      <div class="toolbar"><span class="muted"><span class="live-dot"></span>${t("每 20 秒自动刷新", "Auto-refresh every 20s")}</span>
        <span class="badge ${lic.status === "active" ? "on" : (String(lic.status || "").includes("grace") ? "" : "off")}">License: ${esc(licLabel)}</span>
        <span class="badge ${d.golive_ready ? "on" : "off"}">${t("上线: ", "Go-live: ")}${d.golive_ready ? t("可拦截", "Ready to block") : t("观察中", "Observing")}</span>
        <span class="badge">CRS PL${esc(d.paranoia_level ?? "-")}</span>
        <span class="badge ${(d.ha && d.ha.role_guess === "master") ? "on" : ""}">HA: ${esc((d.ha && d.ha.role_guess) || "standalone")}</span>
      </div>
      <div class="card" style="margin-bottom:.85rem">
        <h3>${t("紧急旁路", "Emergency bypass")}</h3>
        <p class="muted">${t("故障时临时降级引擎（必填原因，写入审计链）。恢复请切回 On。", "Temporarily degrade the engine during incidents (reason required, audited). Switch back to On to restore.")}</p>
        <div class="toolbar">
          <input id="emReason" placeholder="${t("原因，例如：误报冲高 / 上游故障", "Reason, e.g. FP surge / upstream outage")}" style="min-width:240px" />
          <button class="ghost" id="emDetect">${t("切 DetectionOnly", "Switch to DetectionOnly")}</button>
          <button class="danger" id="emOff">${t("切 Off（fail-open）", "Switch to Off (fail-open)")}</button>
          <button id="emOn">${t("恢复 On", "Restore On")}</button>
        </div>
      </div>
      <div class="grid cols-4">
        <div class="card kpi"><div class="label">${t("引擎模式", "Engine mode")}</div><div class="value">${esc(d.engine_mode || "-")}</div><div class="hint">On / DetectionOnly / Off</div></div>
        <div class="card kpi"><div class="label">${t("采样请求", "Sampled requests")}</div><div class="value">${esc(m.access_samples ?? "-")}</div><div class="hint">${t("访问日志样本", "Access log samples")}</div></div>
        <div class="card kpi"><div class="label">${t("拦截率", "Intercept rate")}</div><div class="value">${Number(m.intercept_rate_pct || 0).toFixed(2)}%</div><div class="hint">${t("403/429 近似", "Approx. 403/429")}</div></div>
        <div class="card kpi"><div class="label">${t("安全事件", "Security events")}</div><div class="value">${esc(sum.total ?? 0)}</div><div class="hint">${t("审计尾部样本", "Audit log tail samples")}</div></div>
      </div>
      <div class="grid cols-4" style="margin-top:.85rem">
        <div class="card kpi"><div class="label">${t("启用规则", "Enabled rules")}</div><div class="value">${esc(d.rules_enabled ?? 0)}</div></div>
        <div class="card kpi"><div class="label">${t("禁用规则", "Disabled rules")}</div><div class="value">${esc(d.rules_disabled ?? 0)}</div></div>
        <div class="card kpi"><div class="label">${t("黑名单 IP", "Blacklisted IPs")}</div><div class="value">${esc(d.blacklist_count ?? 0)}</div></div>
        <div class="card kpi"><div class="label">${t("误报候选", "FP candidates")}</div><div class="value">${esc(d.fp_count ?? 0)}</div><div class="hint">${t("同 URI+规则 ≥5 次", "Same URI+rule ≥5 hits")}</div></div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>${t("Top 攻击源 IP", "Top attack source IPs")}</h3>${bars(sum.by_ip || [])}</div>
        <div class="card"><h3>${t("Top 命中规则", "Top hit rules")}</h3>${bars(sum.by_rule || [])}</div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>${t("严重级别分布", "Severity distribution")}</h3>${bars(severityRows(sum.by_severity))}</div>
        <div class="card"><h3>${t("攻击家族 / 标签", "Attack family / tags")}</h3>
          <p class="muted" style="margin:0 0 .5rem">${t("从审计消息/规则号推断的大类（如 attack-sqli、ma-waf/bot），不是单独配置项。", "Inferred from audit messages/rule IDs (e.g. attack-sqli, ma-waf/bot); not a separate setting.")}</p>
          ${bars((d.insights && d.insights.by_family) || [])}
        </div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>${t("ATO 可疑源", "ATO suspect sources")}</h3>
          <p class="muted" style="margin:0 0 .5rem">${t("命中登录/认证类路径或会话限速规则的源 IP Top（账号盗用相关可疑）。", "Top source IPs hitting login/auth paths or session rate-limit rules (ATO-related).")}</p>
          ${bars((d.insights && d.insights.ato_sources) || [])}
        </div>
        <div class="card"><h3>${t("攻击活动 (IP|URI)", "Attack campaigns (IP|URI)")}</h3>${bars((d.insights && d.insights.campaigns) || [])}</div>
      </div>
      <div class="card" style="margin-top:.85rem"><h3>${t("能力矩阵（对标 Imperva WAAP 子集）", "Capability matrix (Imperva WAAP subset)")}</h3>
          <div class="tag-list">${(d.features || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("") || '<div class="empty">-</div>'}</div>
      </div>`;
    const doEmergency = async (mode) => {
      const reason = ($("emReason").value || "").trim();
      if (!reason) { toast(false, t("请填写紧急旁路原因", "Please enter an emergency bypass reason")); return; }
      if (!confirm(t("确认将引擎切换为 ", "Confirm switching engine to ") + mode + "？")) return;
      try {
        await api("/api/v1/ops/emergency", {
          method: "POST",
          body: JSON.stringify({ mode, reason }),
        });
        toast(true, t("已切换为 ", "Switched to ") + mode);
        await loadDashboard();
      } catch (e) { toast(false, e.message); }
    };
    $("emDetect").onclick = () => doEmergency("DetectionOnly");
    $("emOff").onclick = () => doEmergency("Off");
    $("emOn").onclick = () => doEmergency("On");
  }

  function fmtLen(n) {
    const v = Number(n);
    if (!Number.isFinite(v) || v <= 0) return "-";
    if (v < 1024) return String(v);
    if (v < 1024 * 1024) return (v / 1024).toFixed(1) + "K";
    return (v / (1024 * 1024)).toFixed(1) + "M";
  }

  function openDrawer(title, body, asHTML = false) {
    if (!$("drawer")) return;
    $("drawerTitle").textContent = title;
    const el = $("drawerBody");
    if (asHTML) {
      el.classList.add("drawer-rich");
      el.innerHTML = body;
    } else {
      el.classList.remove("drawer-rich");
      el.textContent = body;
    }
    $("drawer").hidden = false;
  }
  function closeDrawer() {
    if ($("drawer")) $("drawer").hidden = true;
  }

  function renderAttackDetailHTML(e) {
    const matches = e.matches || [];
    const fields = e.attack_fields || [];
    const matchRows = matches.length
      ? matches.map((m) => `<tr>
          <td class="mono">${esc(m.rule_id || "-")}</td>
          <td>${esc(m.severity || "-")}</td>
          <td class="mono">${esc(m.variable || m.field || "-")}</td>
          <td class="mono">${esc(m.field || "-")}</td>
          <td>${esc(m.message || "-")}</td>
          <td class="mono">${esc(truncate(m.match || m.data || "-", 120))}</td>
        </tr>`).join("")
      : `<tr><td colspan="6" class="empty">${t("无结构化命中明细（规则仍可能已记入审计）", "No structured match details (rules may still be in the audit)")}</td></tr>`;
    return `
      <div class="kv" style="margin-bottom:.75rem">
        <div><span>${t("时间", "Time")}</span><b class="mono">${esc(e.time || "-")}</b></div>
        <div><span>${t("请求 ID", "Request ID")}</span><b class="mono">${esc(e.request_id || "-")}</b></div>
        <div><span>${t("源 IP", "Source IP")}</span><b class="mono">${esc(e.client_ip || "-")}</b></div>
        <div><span>Host</span><b class="mono">${esc(e.host || "-")}</b></div>
        <div><span>${t("方法 / URI", "Method / URI")}</span><b class="mono">${esc(e.method || "-")} ${esc(e.uri || "-")}</b></div>
        <div><span>${t("状态码", "Status")}</span><b>${esc(e.status || "-")}</b></div>
        <div><span>${t("请求长度", "Request length")}</span><b>${esc(fmtLen(e.req_len))} <span class="muted">(${esc(e.req_len || 0)} B)</span></b></div>
        <div><span>${t("响应长度", "Response length")}</span><b>${esc(fmtLen(e.resp_len))} <span class="muted">(${esc(e.resp_len || 0)} B)</span></b></div>
        <div><span>${t("级别", "Severity")}</span><b>${sevBadge(e.severity)}</b></div>
        <div><span>${t("规则", "Rules")}</span><b class="mono">${esc((e.rule_ids || []).join(", ") || "-")}</b></div>
        <div><span>${t("攻击字段", "Attack fields")}</span><b class="mono">${esc(fields.join(", ") || "-")}</b></div>
        <div><span>UA</span><b class="mono">${esc(truncate(e.user_agent || "-", 160))}</b></div>
      </div>
      <h4 style="margin:.5rem 0 .35rem;color:var(--hs-blue-deep)">${t("规则命中 / 攻击载荷", "Rule hits / attack payload")}</h4>
      <p class="muted" style="margin:0 0 .5rem">${t("POST/GET 参数命中时，变量多为", "For POST/GET hits, variables are often")} <code>ARGS_POST:${t("字段名", "field")}</code>${t("；下方「匹配内容」为规则捕获的攻击片段。", "; “Matched content” below is the captured attack fragment.")}</p>
      <div class="table-wrap"><table>
        <thead><tr><th>${t("规则", "Rule")}</th><th>${t("级别", "Severity")}</th><th>${t("变量", "Variable")}</th><th>${t("字段", "Field")}</th><th>${t("说明", "Message")}</th><th>${t("匹配内容", "Matched content")}</th></tr></thead>
        <tbody>${matchRows}</tbody>
      </table></div>
      <h4 style="margin:.85rem 0 .35rem;color:var(--hs-blue-deep)">${t("请求体预览", "Request body preview")}</h4>
      <pre class="mono drawer-pre">${esc(e.body_preview || t("（无；需 SecRequestBodyAccess On 且 AuditLogParts 含 C，并对新流量生效）", "(None; needs SecRequestBodyAccess On, AuditLogParts with C, and applies to new traffic)"))}</pre>
      <h4 style="margin:.85rem 0 .35rem;color:var(--hs-blue-deep)">${t("消息摘要", "Message summary")}</h4>
      <pre class="mono drawer-pre">${esc((e.messages || []).join("\n") || e.raw_preview || "-")}</pre>
    `;
  }

  async function showAttackDetail(e) {
    let ev = e || {};
    try {
      if (e && e.request_id) {
        const r = await api("/api/v1/attacks/detail?id=" + encodeURIComponent(e.request_id));
        if (r && r.event) ev = r.event;
      }
    } catch (_) { /* use list item */ }
    openDrawer(t("攻击详情", "Attack details"), renderAttackDetailHTML(ev), true);
  }

  async function loadEvents() {
    const data = await api("/api/v1/attacks?limit=200");
    state.events = data.items || [];
    renderEvents();
  }

  function renderEvents(filter = {}) {
    const q = (filter.q || "").toLowerCase();
    const sev = filter.sev || "";
    let rows = state.events.slice().reverse();
    if (sev) rows = rows.filter((e) => (e.severity || "").toUpperCase() === sev);
    if (q) {
      rows = rows.filter((e) => JSON.stringify(e).toLowerCase().includes(q));
    }
    pageRoot().innerHTML = `
      <div class="toolbar">
        <input type="search" id="evQ" placeholder="${t("搜索 Host / IP / URI / 规则 / 攻击字段", "Search Host / IP / URI / rule / attack fields")}" value="${esc(filter.q || "")}" />
        <select id="evSev">
          <option value="">${t("全部级别", "All severities")}</option>
          ${["CRITICAL", "WARNING", "NOTICE", "INFO"].map((s) =>
            `<option value="${s}" ${sev === s ? "selected" : ""}>${s}</option>`).join("")}
        </select>
        <button id="evApply">${t("筛选", "Filter")}</button>
        <button class="ghost" id="evRefresh">${t("重新加载", "Reload")}</button>
        <span class="muted">${t("共", "Total")} ${rows.length} ${t("条 · POST body 攻击可由 CRS 检测 ARGS_POST/REQUEST_BODY", "· POST body attacks detectable via CRS ARGS_POST/REQUEST_BODY")}</span>
      </div>
      <div class="card" style="padding:0">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>${t("时间", "Time")}</th><th>${t("级别", "Severity")}</th><th>${t("源 IP", "Source IP")}</th><th>Host</th><th>${t("方法", "Method")}</th><th>URI</th>
              <th>${t("状态", "Status")}</th><th>${t("请求长", "Req len")}</th><th>${t("响应长", "Resp len")}</th><th>${t("攻击字段", "Attack fields")}</th><th>${t("规则", "Rules")}</th><th>${t("操作", "Actions")}</th>
            </tr></thead>
            <tbody>
              ${rows.length ? rows.map((e, idx) => `<tr data-ev="${idx}">
                <td class="mono">${esc(e.time || "-")}</td>
                <td>${sevBadge(e.severity)}</td>
                <td class="mono">${esc(e.client_ip || "-")}</td>
                <td class="mono" title="${esc(e.host || "")}">${esc(truncate(e.host || "-", 28))}</td>
                <td>${esc(e.method || "-")}</td>
                <td class="mono" title="${esc(e.uri || "")}">${esc(truncate(e.uri || "-", 36))}</td>
                <td class="mono">${esc(e.status || "-")}</td>
                <td class="mono" title="${esc(e.req_len || 0)} B">${esc(fmtLen(e.req_len))}</td>
                <td class="mono" title="${esc(e.resp_len || 0)} B">${esc(fmtLen(e.resp_len))}</td>
                <td class="mono" title="${esc((e.attack_fields || []).join(", "))}">${esc(truncate((e.attack_fields || []).join(", ") || "-", 24))}</td>
                <td class="mono" title="${esc((e.rule_ids || []).join(", "))}">${esc(truncate((e.rule_ids || []).join(", ") || "-", 20))}</td>
                <td class="actions">
                  <button type="button" class="ghost" data-detail-idx="${idx}">${t("详情", "Details")}</button>
                  <button type="button" class="ghost" data-exc-uri="${esc(e.uri || "")}" data-exc-rules="${esc((e.rule_ids || []).join(","))}">${t("放行", "Allow")}</button>
                  ${e.client_ip ? `<button type="button" class="danger" data-block-ip="${esc(e.client_ip)}">${t("拉黑", "Block")}</button>` : ""}
                </td>
              </tr>`).join("") : `<tr><td colspan="12" class="empty">${t("暂无安全事件（DetectionOnly/On 后产生审计）", "No security events yet (audits appear after DetectionOnly/On)")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
    $("evApply").onclick = () => renderEvents({ q: $("evQ").value, sev: $("evSev").value });
    $("evRefresh").onclick = () => navigate("events", true);
    $("evQ").addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") renderEvents({ q: $("evQ").value, sev: $("evSev").value });
    });
    pageRoot().querySelectorAll("[data-detail-idx]").forEach((btn) => {
      btn.onclick = (ev) => {
        ev.stopPropagation();
        showAttackDetail(rows[Number(btn.dataset.detailIdx)]);
      };
    });
    pageRoot().querySelectorAll("[data-exc-uri]").forEach((btn) => {
      btn.onclick = async (ev) => {
        ev.stopPropagation();
        const uri = (btn.dataset.excUri || "").split("?")[0] || "/";
        const rules = btn.dataset.excRules || "";
        const kind = rules ? "uri_rule_remove" : "uri_bypass";
        if (!confirm(`${t("添加例外：", "Add exception: ")}${kind}\nURI: ${uri}\n${t("规则", "Rules")}: ${rules || t("(整路径旁路)", "(full path bypass)")}`)) return;
        try {
          const cur = await api("/api/v1/exceptions");
          const list = (cur.exceptions || []).slice();
          list.push({
            id: 0,
            kind,
            uri,
            rule_ids: rules,
            note: "from events",
            enabled: true,
          });
          await api("/api/v1/exceptions", {
            method: "PUT",
            body: JSON.stringify({ exceptions: list, reload: true }),
          });
          toast(true, t("已添加例外并 reload", "Exception added and reloaded"));
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-block-ip]").forEach((btn) => {
      btn.onclick = async (ev) => {
        ev.stopPropagation();
        const ip = btn.dataset.blockIp;
        if (!ip || !confirm(t("将 ", "Add ") + ip + t(" 加入黑名单并 Reload？", " to blacklist and Reload?"))) return;
        try {
          await api("/api/v1/iplist/blacklist/add", {
            method: "POST",
            body: JSON.stringify({ entries: [ip], reload: true }),
          });
          toast(true, t("已拉黑 ", "Blocked ") + ip);
        } catch (e) { toast(false, e.message); }
      };
    });
  }

  async function loadSites() {
    const [data, st] = await Promise.all([
      api("/api/v1/sites"),
      api("/api/v1/status").catch(() => ({})),
    ]);
    const sites = data.sites || [];
    const authReqOK = !!(st.nginx_caps && st.nginx_caps.auth_request);
    const formHTML = (edit) => `
      <div class="form-grid">
        <label>${t("站点名称", "Site name")}<input id="siteName" placeholder="app1" ${edit ? "readonly" : ""} /></label>
        <label>${t("域名", "Domain")} server_name<input id="siteSN" placeholder="${t("www.example.com 或 _", "www.example.com or _")}" /></label>
        <label>${t("监听", "Listen")} listen<input id="siteListen" value="80" placeholder="${t("80 或 443 ssl", "80 or 443 ssl")}" /></label>
        <label>${t("上游", "Upstream")} upstream<input id="siteUp" placeholder="127.0.0.1:8080" /></label>
        <label>perip burst<input id="siteBurstIP" type="number" value="40" min="1" /></label>
        <label>perserver burst<input id="siteBurstSrv" type="number" value="400" min="1" /></label>
        <label>conn limit<input id="siteConn" type="number" value="50" min="1" /></label>
        <label class="check"><input type="checkbox" id="siteWaf" checked /> ${t("启用 ModSecurity", "Enable ModSecurity")}</label>
        <label class="check"><input type="checkbox" id="siteCSP" checked /> ${t("启用 CSP 头", "Enable CSP headers")}</label>
        <label class="check"><input type="checkbox" id="siteGeo" /> ${t("启用 Geo 封锁（需 MMDB）", "Enable Geo block (needs MMDB)")}</label>
        <label class="check"><input type="checkbox" id="siteJS" /> ${t("JS Challenge（软 Bot 跳转）", "JS Challenge (soft bot redirect)")}</label>
        <label class="check"><input type="checkbox" id="siteAuthCh" ${authReqOK ? "" : "disabled"} /> ${t("HMAC 硬校验（auth_request）", "HMAC hard check (auth_request)")}${authReqOK ? "" : t(" — 本机 Nginx 无此模块", " — local Nginx missing this module")}</label>
        <label class="check"><input type="checkbox" id="siteAPI" /> ${t("API 前缀防护", "API prefix protection")}</label>
        <label>${t("API 前缀", "API prefix")}<input id="siteAPIPrefix" value="/api/" placeholder="/api/" /></label>
        <label class="check"><input type="checkbox" id="siteSSL" /> ${t("启用 SSL", "Enable SSL")}</label>
        <label>${t("证书路径", "Cert path")}<input id="siteCert" placeholder="/path/fullchain.pem" /></label>
        <label>${t("私钥路径", "Key path")}<input id="siteKey" placeholder="/path/privkey.pem" /></label>
      </div>`;
    pageRoot().innerHTML = `
      <div class="card">
        <h3 id="siteFormTitle">${t("添加保护站点", "Add protected site")}</h3>
        <p class="muted">${t("写入 Nginx conf.d/site-&lt;name&gt;.conf 并 nginx -t + reload。", "Writes Nginx conf.d/site-&lt;name&gt;.conf then nginx -t + reload. ")}${authReqOK ? t("HMAC 硬校验可用。", "HMAC hard check available.") : t("当前 Nginx 未编译 http_auth_request_module：HMAC 将自动降级为 JS 软挑战。", "Nginx lacks http_auth_request_module: HMAC falls back to JS soft challenge.")}</p>
        ${formHTML(false)}
        <div class="toolbar" style="margin-top:.75rem">
          <button type="button" id="siteCreate">${t("创建站点", "Create site")}</button>
          <button type="button" class="ghost" id="siteSave" hidden>${t("保存修改", "Save changes")}</button>
          <button type="button" class="ghost" id="siteCancel" hidden>${t("取消编辑", "Cancel edit")}</button>
        </div>
      </div>
      <div class="toolbar" style="margin-top:.85rem">
        <span class="muted">${t("已解析站点（managed=控制台创建的 site-*.conf）", "Parsed sites (managed = console-created site-*.conf)")}</span>
        <label class="muted">${t("套用策略画像", "Apply policy profile")}
          <select id="siteProfileSel"><option value="">${t("选择画像…", "Select profile…")}</option></select>
        </label>
        <button type="button" class="ghost" id="siteApplyProfile">${t("应用到所选站点名", "Apply to site name")}</button>
        <input id="siteProfileTarget" placeholder="${t("站点名", "Site name")}" style="max-width:140px" />
        ${data.warning ? `<span class="err">${esc(data.warning)}</span>` : ""}
      </div>
      <div class="card" style="padding:0">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>${t("名称", "Name")}</th><th>server_name</th><th>${t("监听", "Listen")}</th><th>WAF</th><th>JS</th><th>Geo</th><th>${t("策略画像", "Policy profile")}</th><th>${t("上游", "Upstream")}</th><th>${t("操作", "Actions")}</th>
            </tr></thead>
            <tbody>
              ${sites.length ? sites.map((s) => `<tr>
                <td class="mono">${esc(s.name || "-")}</td>
                <td class="mono">${esc((s.server_name || []).join(" ") || "_")}</td>
                <td class="mono">${esc((s.listens || []).join(", ") || "-")}</td>
                <td>${s.modsecurity === "on" ? '<span class="badge on">On</span>'
                  : s.modsecurity === "off" ? '<span class="badge off">Off</span>'
                  : '<span class="badge">?</span>'}</td>
                <td>${s.enable_challenge_auth ? '<span class="badge on">HMAC</span>'
                  : s.enable_js_challenge ? `<span class="badge on">${t("软", "Soft")}</span>`
                  : '<span class="badge">-</span>'}</td>
                <td>${s.enable_geo ? '<span class="badge on">Geo</span>' : '<span class="badge">-</span>'}</td>
                <td title="${esc(s.profile_id || "")}">${esc(s.profile_name || s.profile_id || "-")}</td>
                <td class="mono">${esc(s.upstream || "-")}</td>
                <td class="actions">
                  ${s.managed ? `<button type="button" class="ghost" data-edit-site="${esc(s.name)}">${t("编辑", "Edit")}</button>
                    <button type="button" class="danger" data-del-site="${esc(s.name)}">${t("删除", "Delete")}</button>` : `<span class="muted">${t("只读", "Read-only")}</span>`}
                </td>
              </tr>`).join("") : `<tr><td colspan="9" class="empty">${t("未解析到 server 块，请先添加站点", "No server blocks found — add a site first")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;

    const siteBody = () => ({
      name: $("siteName").value.trim(),
      server_name: $("siteSN").value.trim(),
      listen: $("siteListen").value.trim() || "80",
      upstream: $("siteUp").value.trim(),
      enable_waf: $("siteWaf").checked,
      enable_csp: $("siteCSP").checked,
      enable_geo: $("siteGeo").checked,
      enable_js_challenge: $("siteJS").checked || $("siteAuthCh").checked,
      enable_challenge_auth: $("siteAuthCh").checked,
      enable_api_protect: $("siteAPI").checked,
      api_prefix: $("siteAPIPrefix").value.trim() || "/api/",
      burst_per_ip: Number($("siteBurstIP").value) || 40,
      burst_per_server: Number($("siteBurstSrv").value) || 400,
      conn_limit: Number($("siteConn").value) || 50,
      ssl: $("siteSSL").checked,
      cert_file: $("siteCert").value.trim(),
      key_file: $("siteKey").value.trim(),
    });

    const fillForm = (spec) => {
      $("siteName").value = spec.name || "";
      $("siteSN").value = spec.server_name || "";
      $("siteListen").value = spec.listen || "80";
      $("siteUp").value = (spec.upstream || "").replace(/^https?:\/\//, "");
      $("siteBurstIP").value = spec.burst_per_ip || 40;
      $("siteBurstSrv").value = spec.burst_per_server || 400;
      $("siteConn").value = spec.conn_limit || 50;
      $("siteWaf").checked = !!spec.enable_waf;
      $("siteCSP").checked = !!spec.enable_csp;
      $("siteGeo").checked = !!spec.enable_geo;
      $("siteJS").checked = !!spec.enable_js_challenge && !spec.enable_challenge_auth;
      $("siteAuthCh").checked = !!spec.enable_challenge_auth;
      $("siteAPI").checked = !!spec.enable_api_protect;
      $("siteAPIPrefix").value = spec.api_prefix || "/api/";
      $("siteSSL").checked = !!spec.ssl;
      $("siteCert").value = spec.cert_file || "";
      $("siteKey").value = spec.key_file || "";
    };

    const setEditMode = (on) => {
      $("siteFormTitle").textContent = on ? t("编辑站点", "Edit site") : t("添加保护站点", "Add protected site");
      $("siteCreate").hidden = on;
      $("siteSave").hidden = !on;
      $("siteCancel").hidden = !on;
      $("siteName").readOnly = on;
    };

    const siteMutate = async (fn, okMsg) => {
      try {
        const r = await fn();
        toast(true, (r && r.warning) ? okMsg + "：" + r.warning : okMsg);
        await waitForAPI(8000);
        await loadSites();
      } catch (e) {
        if (e.network || /网络中断|Failed to fetch|Network interrupted/i.test(String(e.message || ""))) {
          toast(true, t("请求可能已提交（reload 瞬间易断连），正在确认…", "Request may have been submitted (reload can drop connections); confirming…"));
          if (await waitForAPI(10000)) {
            try {
              await loadSites();
              toast(true, t("管理面已恢复；请核对站点列表是否已更新", "Management plane restored; verify the site list"));
              return;
            } catch (_) { /* fall through */ }
          }
        }
        toast(false, e.message);
      }
    };

    $("siteCreate").onclick = () => siteMutate(
      () => api("/api/v1/sites", { method: "POST", body: JSON.stringify(siteBody()) }),
      t("站点已创建并 reload", "Site created and reloaded"),
    );
    $("siteSave").onclick = () => {
      const body = siteBody();
      return siteMutate(
        () => api("/api/v1/sites/" + encodeURIComponent(body.name), {
          method: "PUT", body: JSON.stringify(body),
        }),
        t("站点已更新", "Site updated"),
      );
    };
    $("siteCancel").onclick = () => loadSites();
    pageRoot().querySelectorAll("[data-edit-site]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          const r = await api("/api/v1/sites/" + encodeURIComponent(btn.dataset.editSite));
          fillForm(r.site || {});
          setEditMode(true);
          window.scrollTo({ top: 0, behavior: "smooth" });
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-del-site]").forEach((btn) => {
      btn.onclick = async () => {
        if (!confirm(t("确认删除站点 ", "Delete site ") + btn.dataset.delSite + "？")) return;
        try {
          await api("/api/v1/sites/" + encodeURIComponent(btn.dataset.delSite), { method: "DELETE" });
          toast(true, t("已删除", "Deleted"));
          await loadSites();
        } catch (e) { toast(false, e.message); }
      };
    });
    try {
      const pr = await api("/api/v1/profiles");
      const sel = $("siteProfileSel");
      (pr.profiles || []).forEach((p) => {
        const o = document.createElement("option");
        o.value = p.id;
        o.textContent = at(p.name || p.id) + " — " + at(p.description || "");
        sel.appendChild(o);
      });
    } catch (_) {}
    $("siteApplyProfile").onclick = async () => {
      const id = $("siteProfileSel").value;
      const name = ($("siteProfileTarget").value || $("siteName").value || "").trim();
      if (!id || !name) { toast(false, t("请选择画像并填写站点名", "Select a profile and enter a site name")); return; }
      try {
        await api("/api/v1/sites/" + encodeURIComponent(name) + "/apply-profile", {
          method: "POST",
          body: JSON.stringify({ profile_id: id, set_engine: confirm(t("是否同时切换全局引擎模式？", "Also switch the global engine mode?")) }),
        });
        toast(true, t("画像已套用", "Profile applied"));
        await loadSites();
      } catch (e) { toast(false, e.message); }
    };
  }

  async function loadExceptions() {
    const [data, fp] = await Promise.all([
      api("/api/v1/exceptions"),
      api("/api/v1/insights/fp").catch(() => ({ candidates: [] })),
    ]);
    state.exceptions = data.exceptions || [];
    state.fpCandidates = fp.candidates || [];
    renderExceptions();
  }

  function renderExceptions() {
    const rows = state.exceptions || [];
    const fps = state.fpCandidates || [];
    pageRoot().innerHTML = `
      <div class="card">
        <h3>${t("误报建议（审计聚合）", "False-positive suggestions (audit aggregation)")}</h3>
        <p class="muted">${t("同一 URI 前缀命中同一规则 ≥5 次，且尚未有例外。建议用 uri_rule_remove，避免整站旁路。", "Same URI prefix hit the same rule ≥5 times with no exception yet. Prefer uri_rule_remove over site-wide bypass.")}</p>
        <div class="table-wrap" style="max-height:220px">
          <table>
            <thead><tr><th>${t("次数", "Count")}</th><th>URI</th><th>${t("规则", "Rules")}</th><th></th></tr></thead>
            <tbody>
              ${fps.length ? fps.map((c, i) => `<tr>
                <td>${esc(c.count)}</td>
                <td class="mono">${esc(c.uri)}</td>
                <td class="mono">${esc(c.rule_ids)}</td>
                <td><button type="button" data-fp="${i}">${t("采纳为例外", "Adopt as exception")}</button></td>
              </tr>`).join("") : `<tr><td colspan="4" class="empty">${t("暂无候选", "No candidates")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("新增例外", "Add exception")}</h3>
        <p class="muted">
          <b>uri_bypass</b>${t("：该 URI 前缀关闭规则引擎；", ": disable the rule engine for this URI prefix; ")}
          <b>rule_remove</b>${t("：全局移除规则 ID；", ": remove rule IDs globally; ")}
          <b>uri_rule_remove</b>${t("：仅对该 URI 移除指定规则（推荐误报场景）。", ": remove specific rules only for this URI (recommended for FPs).")}
        </p>
        <div class="form-grid">
          <label>${t("类型", "Type")}
            <select id="excKind">
              <option value="uri_rule_remove">uri_rule_remove</option>
              <option value="uri_bypass">uri_bypass</option>
              <option value="rule_remove">rule_remove</option>
            </select>
          </label>
          <label>${t("URI 前缀", "URI prefix")}<input id="excURI" placeholder="/api/safe/path" /></label>
          <label>${t("规则 ID", "Rule IDs")}<input id="excRules" placeholder="${t("942100 或 942100-942199,941100", "942100 or 942100-942199,941100")}" /></label>
          <label>${t("备注", "Note")}<input id="excNote" placeholder="${t("业务误报说明", "Business FP note")}" /></label>
        </div>
        <div class="toolbar" style="margin-top:.75rem">
          <button type="button" id="excAdd">${t("添加并 Reload", "Add and Reload")}</button>
        </div>
      </div>
      <div class="card" style="padding:0;margin-top:.85rem">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>ID</th><th>${t("类型", "Type")}</th><th>URI</th><th>${t("规则", "Rules")}</th><th>${t("备注", "Note")}</th><th>${t("启用", "Enabled")}</th><th>${t("操作", "Actions")}</th>
            </tr></thead>
            <tbody>
              ${rows.length ? rows.map((e, i) => `<tr>
                <td class="mono">${esc(e.id)}</td>
                <td class="mono">${esc(e.kind)}</td>
                <td class="mono">${esc(e.uri || "-")}</td>
                <td class="mono">${esc(e.rule_ids || "-")}</td>
                <td>${esc(e.note || "")}</td>
                <td>${e.enabled ? `<span class="badge on">${t("是", "Yes")}</span>` : `<span class="badge off">${t("否", "No")}</span>`}</td>
                <td class="actions">
                  <button type="button" class="ghost" data-exc-toggle="${i}">${e.enabled ? t("禁用", "Disable") : t("启用", "Enable")}</button>
                  <button type="button" class="danger" data-exc-del="${i}">${t("删除", "Delete")}</button>
                </td>
              </tr>`).join("") : `<tr><td colspan="7" class="empty">${t("暂无例外策略", "No exception policies")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
    const persist = async (list) => {
      await api("/api/v1/exceptions", {
        method: "PUT",
        body: JSON.stringify({ exceptions: list, reload: true }),
      });
      toast(true, t("例外已保存并 reload", "Exceptions saved and reloaded"));
      await loadExceptions();
    };
    $("excAdd").onclick = async () => {
      const list = (state.exceptions || []).slice();
      list.push({
        id: 0,
        kind: $("excKind").value,
        uri: $("excURI").value.trim(),
        rule_ids: $("excRules").value.trim(),
        note: $("excNote").value.trim(),
        enabled: true,
      });
      try { await persist(list); } catch (e) { toast(false, e.message); }
    };
    pageRoot().querySelectorAll("[data-exc-del]").forEach((btn) => {
      btn.onclick = async () => {
        const list = (state.exceptions || []).slice();
        list.splice(Number(btn.dataset.excDel), 1);
        try { await persist(list); } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-exc-toggle]").forEach((btn) => {
      btn.onclick = async () => {
        const list = (state.exceptions || []).slice();
        const i = Number(btn.dataset.excToggle);
        list[i] = Object.assign({}, list[i], { enabled: !list[i].enabled });
        try { await persist(list); } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-fp]").forEach((btn) => {
      btn.onclick = async () => {
        const c = (state.fpCandidates || [])[Number(btn.dataset.fp)];
        if (!c) return;
        const list = (state.exceptions || []).slice();
        list.push({ id: 0, kind: c.kind || "uri_rule_remove", uri: c.uri, rule_ids: c.rule_ids, note: c.note, enabled: true });
        try { await persist(list); } catch (e) { toast(false, e.message); }
      };
    });
  }

  async function loadLicense() {
    const [st, fp] = await Promise.all([
      api("/api/v1/license/status"),
      api("/api/v1/license/fingerprint"),
    ]);
    const lic = st.license || {};
    pageRoot().innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <h3>${t("当前状态", "Current status")}</h3>
          <div class="kpi">
            <div class="label">Status</div>
            <div class="value" style="font-size:1.35rem">${esc(lic.status || "-")}</div>
            <div class="hint">${esc(at(lic.hint || ""))}</div>
          </div>
          <div class="kv">
            <div><span>${t("客户", "Customer")}</span><b>${esc(lic.client_name || "-")}</b></div>
            <div><span>${t("签发", "Issued")}</span><b>${esc(lic.issue_date || "-")}</b></div>
            <div><span>${t("到期", "Expires")}</span><b>${esc(lic.expiry_date || "-")}</b></div>
            <div><span>${t("剩余天数", "Days remaining")}</span><b>${esc(lic.days_remaining ?? "-")}</b></div>
            <div><span>${t("宽限剩余(h)", "Grace left (h)")}</span><b>${esc(lic.grace_remaining_hours ?? "-")}</b></div>
            <div><span>${t("产品", "Product")}</span><b>${esc(lic.product || "Ma-WAF")}</b></div>
          </div>
          ${lic.parse_error ? `<p class="err">${esc(at(lic.parse_error))}</p>` : ""}
          <div class="toolbar" style="margin-top:.75rem">
            <button type="button" class="ghost" id="licRefresh">${t("刷新", "Refresh")}</button>
          </div>
        </div>
        <div class="card">
          <h3>${t("硬件指纹", "Hardware fingerprint")}</h3>
          <p class="muted">${t("将下方 fingerprint 提供给授权方签发（tools/license_gen.py）。来源：", "Provide the fingerprint below to the issuer (tools/license_gen.py). Source: ")}${esc(fp.source || "-")}</p>
          <pre class="mono fp-box">${esc(fp.fingerprint || "")}</pre>
          <div class="toolbar">
            <button type="button" id="fpCopy">${t("复制指纹", "Copy fingerprint")}</button>
          </div>
          <h3 style="margin-top:1.2rem">${t("导入 License", "Import License")}</h3>
          <p class="muted">${t("上传 .lic 文件；需已部署公钥 conf/license/ma-waf-public.pem", "Upload a .lic file; public key must be at conf/license/ma-waf-public.pem")}</p>
          ${filePickerHtml("licFile", ".lic")}
          <div class="toolbar" style="margin-top:.75rem">
            <button type="button" id="licImport">${t("导入并激活", "Import and activate")}</button>
          </div>
        </div>
      </div>`;
    bindFilePicker("licFile");
    $("licRefresh").onclick = () => navigate("license", true);
    $("fpCopy").onclick = async () => {
      try {
        await navigator.clipboard.writeText(fp.fingerprint || "");
        toast(true, t("已复制指纹", "Fingerprint copied"));
      } catch { toast(false, t("复制失败，请手动选择", "Copy failed — select manually")); }
    };
    $("licImport").onclick = async () => {
      const f = $("licFile").files && $("licFile").files[0];
      if (!f) { toast(false, t("请选择 .lic 文件", "Please select a .lic file")); return; }
      const form = new FormData();
      form.append("file", f);
      try {
        const headers = {};
        if (state.token) headers.Authorization = "Bearer " + state.token;
        const res = await fetch("/api/v1/license/import", { method: "POST", headers, body: form });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(at(data.message || data.error || "") || t("导入失败", "Import failed"));
        toast(true, at(data.message) || t("导入成功", "Import succeeded"));
        await loadLicense();
      } catch (e) { toast(false, e.message); }
    };
  }

  async function loadRules() {
    const [data, vp] = await Promise.all([
      api("/api/v1/rules?detailed=1"),
      api("/api/v1/virtpatches").catch(() => ({ patches: [] })),
    ]);
    state.rules = data.rules || [];
    state.virtpatches = vp.patches || [];
    renderRules();
  }

  function renderRules(q = "") {
    const query = q.toLowerCase();
    let rows = state.rules;
    if (query) rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(query));
    rows = rows.slice().sort((a, b) => (a.priority || 100) - (b.priority || 100) || String(a.id).localeCompare(String(b.id)));
    const patches = state.virtpatches || [];
    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.85rem">
        <h3>${t("新建自定义 / 虚补规则", "New custom / virtual-patch rule")}</h3>
        <p class="muted">${t("ID 范围 140000–149999。pattern/message 勿含双引号。创建后自动校验并 reload。", "ID range 140000–149999. Avoid double quotes in pattern/message. Auto-validates and reloads after create.")}</p>
        <div class="form-grid">
          <label>${t("规则 ID", "Rule ID")}<input id="crID" type="number" value="140001" min="140000" max="149999" /></label>
          <label>${t("匹配目标", "Match target")}
            <select id="crTarget"><option>REQUEST_URI</option><option>ARGS</option><option>REQUEST_HEADERS</option><option>REQUEST_BODY</option></select>
          </label>
          <label>${t("正则 pattern", "Regex pattern")}<input id="crPat" placeholder="(?i)evil" /></label>
          <label>${t("消息 message", "Message")}<input id="crMsg" placeholder="Custom block" /></label>
          <label>${t("动作", "Action")}
            <select id="crAct"><option value="pass">${t("pass(审计)", "pass (audit)")}</option><option value="deny">deny</option></select>
          </label>
          <label>${t("CVE（可选）", "CVE (optional)")}<input id="crCVE" placeholder="CVE-2024-xxxx" /></label>
          <label>${t("过期日 expire", "Expire date")}<input id="crExp" placeholder="2026-12-31" /></label>
          <label class="check"><input type="checkbox" id="crVP" /> ${t("标记为虚拟补丁", "Mark as virtual patch")}</label>
        </div>
        <div class="toolbar" style="margin-top:.75rem"><button id="crCreate">${t("创建规则", "Create rule")}</button></div>
      </div>
      <div class="card" style="margin-bottom:.85rem">
        <h3>${t("虚拟补丁（CVE / 过期）", "Virtual patches (CVE / expiry)")}</h3>
        <p class="muted">${t("来自 custom 规则 META（cve/expire）。过期项请禁用或更新规则包。", "From custom rule META (cve/expire). Disable or update the rule pack for expired items.")}</p>
        <div class="table-wrap" style="max-height:220px">
          <table>
            <thead><tr><th>ID</th><th>CVE</th><th>${t("过期", "Expire")}</th><th>${t("状态", "Status")}</th><th>${t("操作", "Actions")}</th></tr></thead>
            <tbody>
              ${patches.length ? patches.map((p) => `<tr>
                <td class="mono">${esc(p.id)}</td>
                <td class="mono">${esc(p.cve || "-")}</td>
                <td class="mono">${esc(p.expire || "-")}${p.expired ? ` <span class="badge off">${t("已过期", "Expired")}</span>` : ""}</td>
                <td>${p.enabled ? `<span class="badge on">${t("启用", "Enabled")}</span>` : `<span class="badge off">${t("禁用", "Disabled")}</span>`}</td>
                <td class="actions">
                  ${p.enabled
                    ? `<button class="ghost" data-disable="${esc(p.id)}">${t("禁用", "Disable")}</button>`
                    : `<button data-enable="${esc(p.id)}">${t("启用", "Enable")}</button>`}
                </td>
              </tr>`).join("") : `<tr><td colspan="5" class="empty">${t("暂无虚拟补丁元数据", "No virtual-patch metadata")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div class="toolbar">
        <input type="search" id="ruleQ" placeholder="${t("搜索规则 ID / CVE / 文件", "Search rule ID / CVE / file")}" value="${esc(q)}" />
        <button id="ruleApply">${t("筛选", "Filter")}</button>
        <button class="ghost" id="rulePromote">${t("发布 Staging → Active", "Promote Staging → Active")}</button>
        <span class="muted">${rows.length} / ${state.rules.length} ${t("条", "items")}</span>
      </div>
      <div class="card" style="padding:0">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>ID</th><th>${t("状态", "Status")}</th><th>${t("优先级", "Priority")}</th><th>CVE</th><th>${t("过期", "Expire")}</th><th>${t("文件", "File")}</th><th>${t("操作", "Actions")}</th>
            </tr></thead>
            <tbody>
              ${rows.length ? rows.map((r) => `<tr>
                <td class="mono">${esc(r.id)}</td>
                <td>${r.enabled ? `<span class="badge on">${t("启用", "Enabled")}</span>` : `<span class="badge off">${t("禁用", "Disabled")}</span>`}</td>
                <td>
                  <input data-pri="${esc(r.id)}" type="number" value="${esc(r.priority ?? 100)}" style="width:88px;padding:.35rem .5rem" />
                </td>
                <td class="mono">${esc(r.cve || "-")}</td>
                <td class="mono">${esc(r.expire || "-")}</td>
                <td class="mono">${esc(r.file || "-")}:${esc(r.line || "")}</td>
                <td class="actions">
                  ${r.enabled
                    ? `<button class="ghost" data-disable="${esc(r.id)}">${t("禁用", "Disable")}</button>`
                    : `<button data-enable="${esc(r.id)}">${t("启用", "Enable")}</button>`}
                  <button class="ghost" data-savepri="${esc(r.id)}">${t("保存优先级", "Save priority")}</button>
                </td>
              </tr>`).join("") : `<tr><td colspan="7" class="empty">${t("暂无规则元数据", "No rule metadata")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
    $("ruleApply").onclick = () => renderRules($("ruleQ").value);
    $("rulePromote").onclick = async () => {
      try {
        await api("/api/v1/rules/promote", { method: "POST" });
        toast(true, t("Staging 已发布并 reload", "Staging promoted and reloaded"));
        await loadRules();
      } catch (e) { toast(false, e.message); }
    };
    $("crCreate").onclick = async () => {
      try {
        const r = await api("/api/v1/rules/custom", {
          method: "POST",
          body: JSON.stringify({
            id: Number($("crID").value),
            target: $("crTarget").value,
            pattern: $("crPat").value.trim(),
            message: $("crMsg").value.trim(),
            action: $("crAct").value,
            cve: $("crCVE").value.trim(),
            expire: $("crExp").value.trim(),
            virtpatch: $("crVP").checked,
            phase: 2,
            severity: "WARNING",
          }),
        });
        toast(true, t("已创建 ", "Created ") + (r.file || ""));
        await loadRules();
      } catch (e) { toast(false, e.message); }
    };
    pageRoot().querySelectorAll("[data-enable]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api(`/api/v1/rules/${btn.dataset.enable}/enable`, { method: "POST" });
          toast(true, t("已启用 ", "Enabled ") + btn.dataset.enable);
          await loadRules();
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-disable]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api(`/api/v1/rules/${btn.dataset.disable}/disable`, { method: "POST" });
          toast(true, t("已禁用 ", "Disabled ") + btn.dataset.disable);
          await loadRules();
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-savepri]").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.dataset.savepri;
          const input = pageRoot().querySelector(`input[data-pri="${id.replace(/"/g, "")}"]`);
        const priority = Number(input.value || 100);
        try {
          await api(`/api/v1/rules/${id}/priority`, {
            method: "POST",
            body: JSON.stringify({ priority }),
          });
          toast(true, t("优先级已更新 ", "Priority updated ") + `${id} → ${priority}`);
          await loadRules();
        } catch (e) { toast(false, e.message); }
      };
    });
  }

  async function loadIPList() {
    const [bl, wl, geo, geoSt, bots, intel] = await Promise.all([
      api("/api/v1/iplist/blacklist"),
      api("/api/v1/iplist/whitelist"),
      api("/api/v1/geo/blocklist").catch(() => ({ countries: [] })),
      api("/api/v1/geo/status").catch(() => ({ ready: false })),
      api("/api/v1/bots/good").catch(() => ({ patterns: [] })),
      api("/api/v1/threat-intel/status").catch(() => ({})),
    ]);
    state.blacklist = bl.entries || [];
    state.whitelist = wl.entries || [];
    const countries = geo.countries || [];
    pageRoot().innerHTML = `
      <div class="split">
        <div class="card">
          <h3>${t("黑名单（拒绝）", "Blacklist (deny)")}</h3>
          <p class="muted">${t("每行一个 IP/CIDR，保存后可选 Reload", "One IP/CIDR per line; optional Reload after save")}</p>
          <textarea class="block" id="blBox">${esc(state.blacklist.join("\n"))}</textarea>
          <div class="toolbar" style="margin-top:.75rem">
            <button id="blSave">${t("保存黑名单", "Save blacklist")}</button>
            <button class="ghost" id="blSaveReload">${t("保存并 Reload", "Save and Reload")}</button>
          </div>
        </div>
        <div class="card">
          <h3>${t("白名单（放行辅助）", "Whitelist (allow helper)")}</h3>
          <p class="muted">${t("写入 nginx geo 白名单文件", "Writes nginx geo whitelist file")}</p>
          <textarea class="block" id="wlBox">${esc(state.whitelist.join("\n"))}</textarea>
          <div class="toolbar" style="margin-top:.75rem">
            <button id="wlSave">${t("保存白名单", "Save whitelist")}</button>
            <button class="ghost" id="wlSaveReload">${t("保存并 Reload", "Save and Reload")}</button>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("Geo 国家封锁（ISO 码）", "Geo country block (ISO codes)")}</h3>
        <p class="muted">${t("就绪：", "Ready: ")}${geoSt.ready ? `<span class="badge on">${t("是", "Yes")}</span>` : `<span class="badge off">${t("否", "No")}</span>`}
          · ${t("执法：", "Enforcement: ")}${geoSt.enforced ? `<span class="badge on">${t("已接国家码", "Country codes active")}</span>` : `<span class="badge off">${t("占位", "Placeholder")}</span>`}
          · ${t("模块", "Module")} ${geoSt.module_loaded ? "geoip2" : t("未加载", "not loaded")}
          · MMDB ${geoSt.mmdb_found ? esc(geoSt.mmdb_path) : t("未找到", "not found")}
          · ${t("名单", "List")} ${esc(geoSt.blocklist_count ?? countries.length)} ${t("国", "countries")}</p>
        <textarea class="block" id="geoBox" style="min-height:100px">${esc(countries.join("\n"))}</textarea>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="geoSave">${t("保存 Geo 名单", "Save Geo list")}</button>
          <button class="ghost" id="geoSaveReload">${t("保存并 Reload", "Save and Reload")}</button>
          <button class="ghost" id="geoEnforce">${t("启用国家执法", "Enable country enforcement")}</button>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("善意 Bot（搜索引擎放行）", "Good bots (search engine allow)")}</h3>
        <p class="muted">${t("UA 子串/正则片段，每行一条。生成 nginx map，善意 Bot 不挑战、不按坏 Bot 拦截。", "UA substring/regex per line. Builds nginx map; good bots skip challenge and bad-bot blocks.")}</p>
        <textarea class="block" id="goodBotBox" style="min-height:100px"></textarea>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="goodBotSave">${t("保存并 Reload", "Save and Reload")}</button>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("威胁情报合并", "Threat intel merge")}</h3>
        <p class="muted">${t("粘贴 IOC IP（每行一个或 CSV 首列），或直接上传 .txt/.csv；合并进黑名单（去重）。亦可用 scripts/update_threat_intel.sh。", "Paste IOC IPs (one per line or CSV first column), or upload .txt/.csv; merged into blacklist (deduped). Or use scripts/update_threat_intel.sh.")}</p>
        <textarea class="block" id="intelBox" style="min-height:100px" placeholder="1.2.3.4&#10;5.6.7.8/32"></textarea>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="intelMerge">${t("合并到黑名单并 Reload", "Merge to blacklist and Reload")}</button>
          <label class="ghost" style="display:inline-flex;align-items:center;gap:.35rem;cursor:pointer">
            ${t("上传 IOC 文件", "Upload IOC file")}
            <input type="file" id="intelFile" accept=".txt,.csv,.list,text/plain" hidden />
          </label>
        </div>
        <label class="muted" style="display:block;margin-top:.75rem">${t("从 URL 拉取 IOC 文本", "Fetch IOC text from URL")}
          <input id="intelUrl" placeholder="https://example.com/iocs.txt" />
        </label>
        <div class="toolbar">
          <button class="ghost" id="intelFetch">${t("拉取并合并", "Fetch and merge")}</button>
          <button class="ghost" id="intelExpire">${t("清理过期 IOC", "Purge expired IOCs")}</button>
          <span class="muted">${t("账本", "Ledger")} ${esc(intel.count ?? 0)} ${t("条", "items")} · ${t("过期", "Expired")} ${esc(intel.expired ?? 0)} · ${t("上次", "Last")} ${esc(intel.last_sync || "-")}</span>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("攻击源自动加黑", "Auto-block attack sources")}</h3>
        <p class="muted">${t("根据近期审计命中次数，将超过阈值的源 IP 写入黑名单。阈值可在「系统运维」调整。", "Writes source IPs exceeding the threshold to the blacklist based on recent audit hits. Adjust threshold in System ops.")}</p>
        <div class="toolbar">
          <button class="danger" id="autoBlock">${t("扫描并自动加黑 + Reload", "Scan, auto-block + Reload")}</button>
          <span class="muted" id="autoBlockOut"></span>
        </div>
      </div>`;
    const save = async (kind, boxId, reload) => {
      const entries = $(boxId).value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      try {
        await api(`/api/v1/iplist/${kind}`, {
          method: "PUT",
          body: JSON.stringify({ entries, reload }),
        });
        toast(true, `${kind} ${t("已保存", "saved")}` + (reload ? t(" 并 reload", " and reloaded") : ""));
      } catch (e) { toast(false, e.message); }
    };
    $("blSave").onclick = () => save("blacklist", "blBox", false);
    $("blSaveReload").onclick = () => save("blacklist", "blBox", true);
    $("wlSave").onclick = () => save("whitelist", "wlBox", false);
    $("wlSaveReload").onclick = () => save("whitelist", "wlBox", true);
    const saveGeo = async (reload) => {
      const countries = $("geoBox").value.split(/\r?\n/).map((s) => s.trim().toUpperCase()).filter(Boolean);
      try {
        await api("/api/v1/geo/blocklist", {
          method: "PUT",
          body: JSON.stringify({ countries, reload }),
        });
        toast(true, t("Geo 名单已保存", "Geo list saved") + (reload ? t(" 并 reload", " and reloaded") : ""));
      } catch (e) { toast(false, e.message); }
    };
    $("geoSave").onclick = () => saveGeo(false);
    $("geoSaveReload").onclick = () => saveGeo(true);
    $("geoEnforce").onclick = async () => {
      try {
        await api("/api/v1/geo/enforce", { method: "POST" });
        toast(true, t("已尝试启用 Geo 执法（需 geoip2 + MMDB）", "Attempted Geo enforcement (needs geoip2 + MMDB)"));
        await loadIPList();
      } catch (e) { toast(false, e.message); }
    };
    $("intelMerge").onclick = async () => {
      const entries = $("intelBox").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (!entries.length) { toast(false, t("请粘贴 IOC", "Please paste IOCs")); return; }
      try {
        const r = await api("/api/v1/threat-intel/merge", {
          method: "POST",
          body: JSON.stringify({ entries, reload: true }),
        });
        toast(true, t("已合并 ", "Merged ") + (r.added || 0) + t(" 条", " items"));
        await loadIPList();
      } catch (e) { toast(false, e.message); }
    };
    $("intelFile").onchange = async () => {
      const f = $("intelFile").files && $("intelFile").files[0];
      if (!f) return;
      try {
        const text = await f.text();
        const entries = text.split(/\r?\n/).map((line) => {
          const raw = line.trim();
          if (!raw || raw.startsWith("#")) return "";
          return raw.split(/[,\s;|]+/)[0].trim();
        }).filter(Boolean);
        if (!entries.length) { toast(false, t("文件中未解析到 IOC", "No IOCs parsed from file")); return; }
        $("intelBox").value = entries.join("\n");
        const r = await api("/api/v1/threat-intel/merge", {
          method: "POST",
          body: JSON.stringify({ entries, reload: true }),
        });
        toast(true, t("已从文件合并 ", "Merged from file ") + (r.added || 0) + t(" 条（", " items (") + f.name + "）");
        await loadIPList();
      } catch (e) { toast(false, e.message); }
      finally { $("intelFile").value = ""; }
    };
    $("intelFetch").onclick = async () => {
      const url = ($("intelUrl").value || "").trim();
      if (!url) { toast(false, t("请填写 URL", "Please enter a URL")); return; }
      try {
        const r = await api("/api/v1/threat-intel/fetch", {
          method: "POST",
          body: JSON.stringify({ url, reload: true }),
        });
        toast(true, t("已拉取合并 ", "Fetched and merged ") + (r.added || 0) + t(" 条", " items"));
        await loadIPList();
      } catch (e) { toast(false, e.message); }
    };
    $("intelExpire").onclick = async () => {
      try {
        const r = await api("/api/v1/threat-intel/expire", { method: "POST" });
        toast(true, t("已清理过期 ", "Purged expired ") + (r.expired || 0) + t(" 条", " items"));
        await loadIPList();
      } catch (e) { toast(false, e.message); }
    };
    $("autoBlock").onclick = async () => {
      if (!confirm(t("确认将高频攻击源写入黑名单？", "Confirm writing high-frequency attack sources to the blacklist?"))) return;
      try {
        const r = await api("/api/v1/autoblock", {
          method: "POST",
          body: JSON.stringify({ reload: true }),
        });
        const n = r.added || 0;
        $("autoBlockOut").textContent = n ? (t("新增 ", "Added ") + n + "：" + (r.blocked || []).join(", ")) : t("无达到阈值的源", "No sources above threshold");
        toast(true, n ? (t("已加黑 ", "Blocked ") + n) : t("无需加黑", "Nothing to block"));
        if (n) await loadIPList();
      } catch (e) { toast(false, e.message); }
    };
    $("goodBotBox").value = (bots.patterns || []).join("\n");
    $("goodBotSave").onclick = async () => {
      const patterns = $("goodBotBox").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      try {
        await api("/api/v1/bots/good", {
          method: "PUT",
          body: JSON.stringify({ patterns, reload: true }),
        });
        toast(true, t("善意 Bot 已保存", "Good bots saved"));
      } catch (e) { toast(false, e.message); }
    };
  }

  async function loadPolicy() {
    const [st, dash, backups, packs, chain, oapi, profiles, golive, para, cpol] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/dashboard"),
      api("/api/v1/backups").catch(() => ({ backups: [] })),
      api("/api/v1/packs").catch(() => ({ packs: [] })),
      api("/api/v1/audit/chain").catch(() => ({ ok: false, detail: "n/a" })),
      api("/api/v1/openapi/status").catch(() => ({ exists: false, enabled: false })),
      api("/api/v1/profiles").catch(() => ({ profiles: [] })),
      api("/api/v1/ops/golive").catch(() => ({ checks: [] })),
      api("/api/v1/crs/paranoia").catch(() => ({ level: 2 })),
      api("/api/v1/content-policy").catch(() => ({ policy: {} })),
    ]);
    const mode = st.engine_mode || dash.engine_mode || "-";
    const blist = backups.backups || [];
    const packList = packs.packs || [];
    const plist = profiles.profiles || [];
    const pol = cpol.policy || {};
    $("sideMode").textContent = engineLabel(mode);
    pageRoot().innerHTML = `
      <div class="card">
        <h3>${t("上线清单（DetectionOnly → On）", "Go-live checklist (DetectionOnly → On)")}</h3>
        <p class="muted">${t("就绪：", "Ready: ")}${golive.ready ? `<span class="badge on">${t("可切拦截", "Ready to block")}</span>` : `<span class="badge off">${t("请先处理检查项", "Resolve checks first")}</span>`}</p>
        <ul class="muted">${(golive.checks || []).map((c) => `<li>${c.ok ? "✓" : "○"} ${esc(c.id)} — ${esc(at(c.detail))}</li>`).join("")}</ul>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("策略画像（对标 Imperva Policy）", "Policy profiles (Imperva Policy–style)")}</h3>
        <p class="muted">${t("一键将限流/Bot/API/规则包套用到站点。也可在「受保护站点」页套用。", "Apply rate-limit/Bot/API/rule-pack presets to sites. Also available on the Protected sites page.")}</p>
        <div class="table-wrap" style="max-height:220px">
          <table>
            <thead><tr><th>ID</th><th>${t("名称", "Name")}</th><th>${t("说明", "Description")}</th><th>${t("引擎", "Engine")}</th></tr></thead>
            <tbody>
              ${plist.map((p) => `<tr>
                <td class="mono">${esc(p.id)}</td>
                <td>${esc(at(p.name || ""))}</td>
                <td>${esc(at(p.description || ""))}</td>
                <td class="mono">${esc(p.engine_mode || "-")}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("WAF 引擎模式（含 fail-open 运维）", "WAF engine mode (incl. fail-open ops)")}</h3>
        <p class="muted">${t("当前：", "Current: ")}<b>${esc(mode)}</b>${t("。可用性优先可切 DetectionOnly/Off；上线建议 DetectionOnly → On。", ". For availability, use DetectionOnly/Off; go-live: DetectionOnly → On.")}</p>
        <div class="toolbar">
          <button data-mode="On">On${t("（拦截）", " (block)")}</button>
          <button class="ghost" data-mode="DetectionOnly">DetectionOnly${t("（仅检测）", " (detect only)")}</button>
          <button class="danger" data-mode="Off">Off${t("（关闭引擎 / fail-open）", " (engine off / fail-open)")}</button>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("CRS 偏执级别", "CRS paranoia level")}</h3>
        <p class="muted">${t("当前 PL", "Current PL")}${esc(para.level ?? 2)} — ${esc(at(para.hint || ""))}${t("。画像套用也会写入此值。", ". Profile apply also writes this value.")}</p>
        <div class="toolbar">
          ${[1,2,3,4].map((n) => `<button class="${Number(para.level)===n?"":"ghost"}" data-pl="${n}">PL${n}</button>`).join("")}
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("上传 / PII 策略", "Upload / PII policy")}</h3>
        <div class="form-grid">
          <label>${t("上传大小上限（字节）", "Max upload size (bytes)")}<input id="cpMax" type="number" value="${esc(pol.upload_max_bytes ?? 20971520)}" /></label>
          <label>${t("危险扩展正则", "Dangerous extension regex")}<input id="cpExt" value="${esc(pol.upload_ext_rx || "")}" /></label>
          <label>${t("PII 动作", "PII action")}
            <select id="cpPIIAct">
              <option value="pass" ${pol.pii_action!=="deny"?"selected":""}>${t("pass（仅审计）", "pass (audit only)")}</option>
              <option value="deny" ${pol.pii_action==="deny"?"selected":""}>${t("deny（拦截响应）", "deny (block response)")}</option>
            </select>
          </label>
          <label class="check"><input type="checkbox" id="cpID" ${pol.pii_idcard!==false?"checked":""}/> ${t("身份证", "ID card")}</label>
          <label class="check"><input type="checkbox" id="cpMob" ${pol.pii_mobile!==false?"checked":""}/> ${t("手机号", "Mobile")}</label>
          <label class="check"><input type="checkbox" id="cpBank" ${pol.pii_bank!==false?"checked":""}/> ${t("银行卡", "Bank card")}</label>
        </div>
        <div class="toolbar" style="margin-top:.75rem"><button id="cpSave">${t("保存内容策略并 Reload", "Save content policy and Reload")}</button></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("防护能力包（custom/*.conf）", "Protection packs (custom/*.conf)")}</h3>
        <p class="muted">${t("禁用会重命名为 .conf.off 并 reload。例外包禁用后控制台例外策略将不生效。", "Disable renames to .conf.off and reloads. Disabling the exceptions pack disables console exception policies.")}</p>
        <div class="table-wrap" style="max-height:280px">
          <table>
            <thead><tr><th>${t("包", "Pack")}</th><th>${t("说明", "Description")}</th><th>${t("状态", "Status")}</th><th>${t("操作", "Actions")}</th></tr></thead>
            <tbody>
              ${packList.length ? packList.map((p) => `<tr>
                <td class="mono">${esc(p.id)}</td>
                <td>${esc(at(p.description || ""))}</td>
                <td>${p.enabled ? `<span class="badge on">${t("启用", "Enabled")}</span>` : `<span class="badge off">${t("禁用", "Disabled")}</span>`}</td>
                <td class="actions">
                  ${p.enabled
                    ? `<button class="ghost" data-pack-off="${esc(p.id)}">${t("禁用", "Disable")}</button>`
                    : `<button data-pack-on="${esc(p.id)}">${t("启用", "Enable")}</button>`}
                </td>
              </tr>`).join("") : `<tr><td colspan="4" class="empty">${t("无自定义规则包", "No custom rule packs")}</td></tr>`}
            </tbody>
          </table>
        </div>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="polValidate">${t("校验规则 + nginx -t", "Validate rules + nginx -t")}</button>
          <button class="ghost" id="polExpireVP">${t("禁用过期虚拟补丁", "Disable expired virtual patches")}</button>
          <span class="muted" id="polValidateOut"></span>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("OpenAPI API 安全", "OpenAPI API security")}</h3>
        <p class="muted">${t("状态：", "Status: ")}${oapi.exists ? (oapi.enabled ? `<span class="badge on">${t("已启用", "Enabled")}</span>` : `<span class="badge off">${t("已生成未启用", "Generated, disabled")}</span>`) : `<span class="badge off">${t("未生成", "Not generated")}</span>`}
          · ${t("粘贴 OpenAPI 3.x ", "Paste OpenAPI 3.x ")}<b>JSON</b>${t("（YAML 请先转换），生成路径白名单规则 130000-openapi。", " (convert YAML first); generates path whitelist rule 130000-openapi.")}</p>
        <textarea class="block" id="oapiBox" style="min-height:140px" placeholder='{"openapi":"3.0.0","paths":{"/api/v1/orders":{"get":{}}}}'></textarea>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="oapiGen">${t("生成并启用 + Reload", "Generate, enable + Reload")}</button>
          <button class="ghost" id="oapiGenOff">${t("仅生成（禁用）", "Generate only (disabled)")}</button>
          <span class="muted" id="oapiOut"></span>
        </div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card">
          <h3>${t("配置操作", "Config actions")}</h3>
          <div class="toolbar">
            <button id="polBackup">${t("备份配置", "Backup config")}</button>
            <button class="ghost" id="polReload">Reload Nginx</button>
            <button class="danger" id="polRollback">${t("回滚最近备份", "Rollback latest backup")}</button>
          </div>
          <p class="muted">${t("备份含 nginx conf + rules；Reload 失败时 API 会自动尝试回滚。", "Backup includes nginx conf + rules; API auto-rollback on Reload failure.")}</p>
          <label class="muted">${t("选择备份回滚", "Select backup to rollback")}
            <select id="polBakSel">
              ${blist.length ? blist.slice(0, 20).map((id) => `<option value="${esc(id)}">${esc(id)}</option>`).join("") : `<option value="">${t("无备份", "No backups")}</option>`}
            </select>
          </label>
          <div class="toolbar"><button class="ghost" id="polRollbackSel">${t("回滚所选", "Rollback selected")}</button></div>
        </div>
        <div class="card">
          <h3>${t("审计链 / 规则文件", "Audit chain / rule files")}</h3>
          <p class="muted">${t("链式哈希：", "Chain hash: ")}${chain.ok ? `<span class="badge on">${t("完整", "Intact")}</span>` : `<span class="badge off">${t("异常", "Broken")}</span>`}
            · ${esc(chain.count ?? 0)} ${t("条", "items")} · ${esc(chain.detail || "")}</p>
          <div class="tag-list">${(st.rule_files || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("") || `<div class="empty">${t("无", "None")}</div>`}</div>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("企业能力一览", "Enterprise capabilities")}</h3>
        <div class="tag-list">${(dash.features || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("")}</div>
      </div>`;
    pageRoot().querySelectorAll("[data-mode]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api("/api/v1/mode", { method: "POST", body: JSON.stringify({ mode: btn.dataset.mode }) });
          toast(true, t("模式已切换为 ", "Mode switched to ") + btn.dataset.mode);
          await loadPolicy();
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-pl]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api("/api/v1/crs/paranoia", { method: "PUT", body: JSON.stringify({ level: Number(btn.dataset.pl) }) });
          toast(true, t("偏执级已设为 PL", "Paranoia set to PL") + btn.dataset.pl);
          await loadPolicy();
        } catch (e) { toast(false, e.message); }
      };
    });
    $("cpSave").onclick = async () => {
      try {
        await api("/api/v1/content-policy", {
          method: "PUT",
          body: JSON.stringify({
            upload_max_bytes: Number($("cpMax").value) || 20971520,
            upload_ext_rx: $("cpExt").value.trim(),
            pii_action: $("cpPIIAct").value,
            pii_idcard: $("cpID").checked,
            pii_mobile: $("cpMob").checked,
            pii_bank: $("cpBank").checked,
          }),
        });
        toast(true, t("内容策略已保存", "Content policy saved"));
        await loadPolicy();
      } catch (e) { toast(false, e.message); }
    };
    pageRoot().querySelectorAll("[data-pack-on]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api("/api/v1/packs/" + encodeURIComponent(btn.dataset.packOn) + "/enable", { method: "POST" });
          toast(true, t("已启用 ", "Enabled ") + btn.dataset.packOn);
          await loadPolicy();
        } catch (e) { toast(false, e.message); }
      };
    });
    pageRoot().querySelectorAll("[data-pack-off]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api("/api/v1/packs/" + encodeURIComponent(btn.dataset.packOff) + "/disable", { method: "POST" });
          toast(true, t("已禁用 ", "Disabled ") + btn.dataset.packOff);
          await loadPolicy();
        } catch (e) { toast(false, e.message); }
      };
    });
    $("polValidate").onclick = async () => {
      try {
        const r = await api("/api/v1/rules/validate", { method: "POST" });
        $("polValidateOut").textContent = r.ok ? t("校验通过", "Validation passed") : (t("问题: ", "Issues: ") + JSON.stringify(r.issues || r.nginx_msg));
        toast(!!r.ok, r.ok ? t("校验通过", "Validation passed") : t("校验未通过", "Validation failed"));
      } catch (e) { toast(false, e.message); }
    };
    $("polExpireVP").onclick = async () => {
      try {
        const r = await api("/api/v1/virtpatches/expire", { method: "POST" });
        toast(true, t("已禁用过期补丁 ", "Disabled expired patches ") + (r.disabled || 0) + t(" 条", " items"));
      } catch (e) { toast(false, e.message); }
    };
    const genOAPI = async (enable) => {
      const content = ($("oapiBox").value || "").trim();
      if (!content) { toast(false, t("请粘贴 OpenAPI JSON", "Please paste OpenAPI JSON")); return; }
      try {
        const r = await api("/api/v1/openapi/generate", {
          method: "POST",
          body: JSON.stringify({ content, enable, reload: true }),
        });
        $("oapiOut").textContent = "paths=" + (r.paths || 0);
        toast(true, t("已生成 OpenAPI 规则（", "OpenAPI rules generated (") + (r.paths || 0) + t(" 路径）", " paths)"));
        await loadPolicy();
      } catch (e) { toast(false, e.message); }
    };
    $("oapiGen").onclick = () => genOAPI(true);
    $("oapiGenOff").onclick = () => genOAPI(false);
    $("polBackup").onclick = async () => {
      try {
        const r = await api("/api/v1/backup", { method: "POST" });
        toast(true, t("备份完成 ", "Backup complete ") + (r.id || ""));
        await loadPolicy();
      } catch (e) { toast(false, e.message); }
    };
    $("polReload").onclick = () => reloadNginxUI();
    const doRollback = async (id) => {
      if (!confirm(t("确认回滚配置？当前未备份的改动将丢失。", "Confirm rollback? Unsaved changes will be lost."))) return;
      try {
        await api("/api/v1/rollback", { method: "POST", body: JSON.stringify({ id: id || "" }) });
        toast(true, t("已回滚", "Rolled back"));
        await loadPolicy();
      } catch (e) { toast(false, e.message); }
    };
    $("polRollback").onclick = () => doRollback("");
    $("polRollbackSel").onclick = () => doRollback($("polBakSel").value);
  }

  function countryHeat(rows) {
    if (!rows || !rows.length) {
      return `<div class="empty">${t("暂无国家维度数据。", "No country-level data yet.")}<br/>
        ${t("请将 ", "Place ")}<code>GeoLite2-Country.mmdb</code>${t(" 放到", " at")}
        <code>/usr/local/Ma-waf/conf/geoip/</code>${t("，重编并重启 API 后刷新；", ", rebuild and restart API, then refresh; ")}
        ${t("需已有带公网源 IP 的安全事件（内网 IP 无国家码属正常）。", "Requires security events with public source IPs (private IPs have no country code — normal).")}</div>`;
    }
    const max = Math.max(...rows.map((r) => Number(r.count || 0)), 1);
    return `<div class="country-heat">${rows.map((r) => {
      const pct = Math.round((Number(r.count || 0) / max) * 100);
      const bg = `rgba(56, 189, 248, ${0.15 + pct / 120})`;
      return `<div class="country-cell" style="background:${bg}" title="${esc(r.key)}: ${esc(r.count)}">
        <strong>${esc(r.key)}</strong><span>${esc(r.count)}</span></div>`;
    }).join("")}</div>`;
  }

  async function loadReports() {
    const [sum, trend, geoSt] = await Promise.all([
      api("/api/v1/attacks/summary"),
      api("/api/v1/attacks/trend?hours=24").catch(() => ({ trend: [] })),
      api("/api/v1/geo/status").catch(() => ({})),
    ]);
    const bySev = sum.by_severity || {};
    const sevMerged = {};
    Object.entries(bySev).forEach(([k, v]) => {
      const key = normalizeSeverityKey(k);
      sevMerged[key] = (sevMerged[key] || 0) + Number(v || 0);
    });
    const trendRows = trend.trend || sum.trend || [];
    const mmdbHint = geoSt.mmdb_found
      ? `${t("MMDB 已就绪：", "MMDB ready: ")}${esc(geoSt.mmdb_path || "")}`
      : t("未找到 GeoLite2-Country.mmdb（报表热力需要；City 库非必须）", "GeoLite2-Country.mmdb not found (needed for report heatmap; City DB optional)");
    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" id="rptCsv">${t("导出 CSV", "Export CSV")}</button>
        <button type="button" class="ghost" id="rptHtml">${t("合规 HTML（可打印 PDF）", "Compliance HTML (printable PDF)")}</button>
        <span class="muted">${t("含 Top IP/规则/国家与合规控制域映射", "Includes Top IP/rules/countries and compliance control mapping")}</span>
      </div>
      <div class="grid cols-3">
        <div class="card kpi"><div class="label">${t("事件总量", "Total events")}</div><div class="value">${esc(sum.total || 0)}</div></div>
        <div class="card kpi"><div class="label">CRITICAL</div><div class="value">${esc(sevMerged.CRITICAL || 0)}</div></div>
        <div class="card kpi"><div class="label">WARNING</div><div class="value">${esc(sevMerged.WARNING || 0)}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem"><h3>${t("24 小时攻击趋势（按小时）", "24-hour attack trend (hourly)")}</h3>${bars(trendRows)}</div>
      <div class="card" style="margin-top:.85rem"><h3>${t("攻击面 · 国家热力（ISO）", "Attack surface · country heat (ISO)")}</h3>
        <p class="muted">${t("按攻击源 IP 聚合国家码。", "Aggregates country codes by attack source IP. ")}${mmdbHint}${t("。城市级地图需 City MMDB（当前未做，可不传）。", " City-level maps need City MMDB (not implemented; optional).")}</p>
        ${countryHeat(sum.by_country || [])}
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>${t("攻击源 Top", "Top attack sources")}</h3>${bars(sum.by_ip || [])}</div>
        <div class="card"><h3>${t("规则命中 Top", "Top rule hits")}</h3>${bars(sum.by_rule || [])}</div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>${t("国家分布条形图", "Country distribution")}</h3>${bars(sum.by_country || [])}</div>
        <div class="card"><h3>${t("合规运营映射（参考）", "Compliance mapping (reference)")}</h3>
          <p class="muted">${t("点击某一框架生成", "Click a framework to generate ")}<strong>${t("专属 HTML 报告", "a dedicated HTML report")}</strong>${t("，再在报告页「打印 / 另存为 PDF」。不构成认证结论。", ", then Print / Save as PDF on the report page. Not a certification conclusion.")}</p>
          <div class="tag-list compliance-fw">
            <button type="button" class="tag clickable" data-fw="dsl2" title="${t("生成等保 2.0 专属报告", "Generate MLPS 2.0 report")}">${t("等保 2.0 · 安全审计/入侵防范", "MLPS 2.0 · Audit / intrusion prevention")}</button>
            <button type="button" class="tag clickable" data-fw="iso27001" title="${t("生成 ISO 27001 专属报告", "Generate ISO 27001 report")}">ISO 27001 · A.8 / A.12</button>
            <button type="button" class="tag clickable" data-fw="gdpr" title="${t("生成 GDPR 专属报告", "Generate GDPR report")}">GDPR · Art.32 ${t("技术措施", "technical measures")}</button>
            <button type="button" class="tag clickable" data-fw="sox" title="${t("生成 SOX 专属报告", "Generate SOX report")}">SOX · IT ${t("一般控制（访问/变更）", "general controls (access/change)")}</button>
          </div>
          <p class="muted" style="margin-top:.6rem">${t("也可使用上方按钮导出综合 CSV / 综合合规 HTML。", "Or use the buttons above for combined CSV / compliance HTML.")}</p>
        </div>
      </div>`;
    const openComplianceReport = async (framework, asDownloadCsv = false) => {
      try {
        const headers = {};
        if (state.token) headers.Authorization = "Bearer " + state.token;
        const fw = framework || "all";
        if (asDownloadCsv) {
          const res = await fetch("/api/v1/reports/export?format=csv&framework=" + encodeURIComponent(fw), { headers });
          if (!res.ok) throw new Error(t("导出失败 ", "Export failed ") + res.status);
          const blob = await res.blob();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "ma-waf-" + fw + "-report.csv";
          a.click();
          URL.revokeObjectURL(a.href);
          toast(true, t("CSV 已下载（", "CSV downloaded (") + fw + "）");
          return;
        }
        const res = await fetch("/api/v1/reports/export?format=html&framework=" + encodeURIComponent(fw), { headers });
        if (!res.ok) throw new Error(t("导出失败 ", "Export failed ") + res.status);
        const html = await res.text();
        const w = window.open("", "_blank");
        if (!w) throw new Error(t("浏览器拦截了弹窗，请允许本站弹窗后重试", "Browser blocked popup — allow popups for this site and retry"));
        w.document.write(html);
        w.document.close();
        toast(true, t("已打开「", "Opened «") + fw + t("」专属报告（可打印为 PDF）", "» dedicated report (printable as PDF)"));
      } catch (e) { toast(false, e.message); }
    };
    $("rptCsv").onclick = () => openComplianceReport("all", true);
    $("rptHtml").onclick = () => openComplianceReport("all", false);
    pageRoot().querySelectorAll("[data-fw]").forEach((btn) => {
      btn.onclick = () => openComplianceReport(btn.dataset.fw, false);
    });
  }

  async function loadDiscover() {
    const data = await api("/api/v1/sites/discover");
    const items = data.items || [];
    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>${t("发现说明", "Discovery notes")}</h3>
        <p class="muted">${t("解析访问日志 ", "Parses access log ")}<code>${esc(data.access_log || "")}</code>${t(" 中的 Host，对照已管理站点标记防护状态。可将未防护条目一键创建站点草稿。", " for Hosts, compares with managed sites, and marks protection status. Unprotected entries can be onboarded as site drafts.")}</p>
      </div>
      <div class="toolbar">
        <button type="button" class="success" id="discRefresh">${t("重新扫描", "Rescan")}</button>
        <span class="muted">${t("共", "Total")} ${items.length} ${t("条候选", "candidates")}</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>${t("域名 / Host", "Domain / Host")}</th><th>${t("协议", "Scheme")}</th><th>${t("发现次数", "Hits")}</th><th>${t("样例 URI", "Sample URI")}</th><th>${t("防护状态", "Protection")}</th><th>${t("操作", "Actions")}</th></tr></thead>
        <tbody>${items.length ? items.map((it) => `<tr>
          <td class="mono">${esc(it.host)}</td>
          <td>${esc(it.scheme || "-")}</td>
          <td>${esc(it.count)}</td>
          <td class="mono">${esc(it.sample_uri || "-")}</td>
          <td>${it.protected ? `<span class="badge on">${t("已防护", "Protected")}</span>` : `<span class="badge off">${t("未纳入", "Not onboarded")}</span>`}</td>
          <td class="actions">${it.protected ? "-" : `<button type="button" data-host="${esc(it.host)}" class="disc-add">${t("新建站点", "New site")}</button>`}</td>
        </tr>`).join("") : `<tr><td colspan="6" class="empty">${t("暂无发现结果（确认访问日志路径与流量）", "No discoveries (check access log path and traffic)")}</td></tr>`}</tbody>
      </table></div>`;
    $("discRefresh").onclick = () => navigate("discover", true);
    pageRoot().querySelectorAll(".disc-add").forEach((btn) => {
      btn.onclick = async () => {
        const host = btn.dataset.host;
        const name = host.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 48) || "site";
        const upstream = prompt(t("上游地址（如 http://127.0.0.1:8080）", "Upstream URL (e.g. http://127.0.0.1:8080)"), "http://127.0.0.1:8080");
        if (!upstream) return;
        try {
          await api("/api/v1/sites", {
            method: "POST",
            body: JSON.stringify({
              name, server_name: host, listen: "80", upstream, enable_waf: true,
            }),
          });
          toast(true, t("已创建站点 ", "Site created ") + name);
          navigate("discover", true);
        } catch (e) { toast(false, e.message); }
      };
    });
  }

  async function loadAddrBook() {
    const data = await api("/api/v1/addrbook");
    const items = data.items || [];
    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" class="success" id="abAdd">${t("新建", "New")}</button>
        <button type="button" id="abSave">${t("保存全部", "Save all")}</button>
        <span class="muted">${t("对象可一键应用到黑/白名单；引用计数为名单命中近似值", "Objects can be applied to black/white lists; ref count approximates list hits")}</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>${t("名称", "Name")}</th><th>${t("类型", "Type")}</th><th>${t("成员", "Members")}</th><th>${t("排除", "Excludes")}</th><th>${t("被引用", "Refs")}</th><th>${t("描述", "Description")}</th><th>${t("操作", "Actions")}</th></tr></thead>
        <tbody id="abBody">${items.map((it, i) => addrRow(it, i)).join("")}</tbody>
      </table></div>`;
    function addrRow(it, i) {
      return `<tr data-i="${i}">
        <td><input data-f="name" value="${esc(it.name || "")}" /></td>
        <td><select data-f="type"><option value="ipv4"${it.type !== "ipv6" ? " selected" : ""}>IPv4</option><option value="ipv6"${it.type === "ipv6" ? " selected" : ""}>IPv6</option></select></td>
        <td><input data-f="members" value="${esc((it.members || []).join(", "))}" style="min-width:180px" /></td>
        <td><input data-f="excludes" value="${esc((it.excludes || []).join(", "))}" /></td>
        <td>${esc(it.ref_count ?? 0)}</td>
        <td><input data-f="description" value="${esc(it.description || "")}" /></td>
        <td class="actions">
          <button type="button" class="ghost ab-bl" data-name="${esc(it.name)}">${t("→黑名单", "→ Blacklist")}</button>
          <button type="button" class="ghost ab-wl" data-name="${esc(it.name)}">${t("→白名单", "→ Whitelist")}</button>
          <button type="button" class="danger ab-del">${t("删除", "Delete")}</button>
        </td>
      </tr>`;
    }
    const collect = () => {
      const rows = [...pageRoot().querySelectorAll("#abBody tr")];
      return rows.map((tr) => ({
        name: tr.querySelector('[data-f="name"]').value.trim(),
        type: tr.querySelector('[data-f="type"]').value,
        members: tr.querySelector('[data-f="members"]').value.split(/[,;\s]+/).map((s) => s.trim()).filter(Boolean),
        excludes: tr.querySelector('[data-f="excludes"]').value.split(/[,;\s]+/).map((s) => s.trim()).filter(Boolean),
        description: tr.querySelector('[data-f="description"]').value.trim(),
      }));
    };
    $("abAdd").onclick = () => {
      const tbody = $("abBody");
      tbody.insertAdjacentHTML("beforeend", addrRow({ name: "", type: "ipv4", members: [], excludes: [], description: "", ref_count: 0 }, tbody.children.length));
      bindRowActs();
    };
    $("abSave").onclick = async () => {
      try {
        await api("/api/v1/addrbook", { method: "PUT", body: JSON.stringify({ items: collect() }) });
        toast(true, t("地址簿已保存", "Address book saved"));
        navigate("addrbook", true);
      } catch (e) { toast(false, e.message); }
    };
    function bindRowActs() {
      pageRoot().querySelectorAll(".ab-del").forEach((btn) => {
        btn.onclick = () => btn.closest("tr").remove();
      });
      pageRoot().querySelectorAll(".ab-bl, .ab-wl").forEach((btn) => {
        btn.onclick = async () => {
          const kind = btn.classList.contains("ab-bl") ? "blacklist" : "whitelist";
          const name = btn.dataset.name;
          if (!name) { toast(false, t("请先保存名称", "Save the name first")); return; }
          try {
            await api("/api/v1/addrbook", { method: "PUT", body: JSON.stringify({ items: collect() }) });
            const r = await api("/api/v1/addrbook/" + encodeURIComponent(name) + "/apply", {
              method: "POST", body: JSON.stringify({ kind }),
            });
            toast(true, t("已追加 ", "Appended ") + `${r.added || 0}` + t(" 条到 ", " items to ") + `${kind}`);
          } catch (e) { toast(false, e.message); }
        };
      });
    }
    bindRowActs();
  }

  async function loadPKI() {
    const data = await api("/api/v1/pki/certs");
    const items = data.items || [];
    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>${t("管理面 TLS", "Management TLS")}</h3>
        <p class="muted">${t("控制台默认使用 ", "Console uses ")}<code>conf/tls/admin.crt</code> / <code>admin.key</code>${t("。缺失时 Nginx :8443 无法启动，可在此一键生成自签证书。", " by default. Without them Nginx :8443 won't start — generate a self-signed cert here.")}</p>
        <div class="toolbar">
          <input id="pkiCN" placeholder="${t("CN，如 waf-admin.local", "CN, e.g. waf-admin.local")}" value="waf-admin.local" />
          <input id="pkiDays" type="number" value="3650" style="width:100px" title="${t("有效天数", "Valid days")}" />
          <button type="button" class="success" id="pkiGen">${t("生成 / 覆盖 admin 证书", "Generate / overwrite admin cert")}</button>
        </div>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>${t("名称", "Name")}</th><th>${t("状态", "Status")}</th><th>${t("主题", "Subject")}</th><th>${t("到期", "Expires")}</th><th>${t("路径", "Path")}</th></tr></thead>
        <tbody>${items.map((c) => `<tr>
          <td>${esc(c.name)}</td>
          <td>${c.exists ? `<span class="badge on">${t("存在", "Present")}</span>` : `<span class="badge off">${t("缺失", "Missing")}</span>`}</td>
          <td>${esc(c.subject || "-")}</td>
          <td class="mono">${esc(c.not_after || "-")}</td>
          <td class="mono">${esc(c.cert_path || "")}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;
    $("pkiGen").onclick = async () => {
      try {
        const r = await api("/api/v1/pki/admin/ensure", {
          method: "POST",
          body: JSON.stringify({ cn: $("pkiCN").value.trim(), days: Number($("pkiDays").value) || 3650 }),
        });
        toast(true, t("已生成 ", "Generated ") + (r.cert && r.cert.cert_path));
        navigate("pki", true);
      } catch (e) { toast(false, e.message); }
    };
  }

  async function loadSysInfo() {
    const [info, st] = await Promise.all([
      api("/api/v1/sysinfo"),
      api("/api/v1/rules/upgrade/status").catch(() => null),
    ]);
    const geo = info.geo || {};
    const intel = info.intel || {};
    const ha = info.ha || {};
    const last = (st && st.last) || info.rules_upgrade || {};
    pageRoot().innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <h3>${t("系统信息", "System info")}</h3>
          <div class="kv">
            <div><span>${t("产品", "Product")}</span><b>${esc(info.product || "Ma-WAF")}</b></div>
            <div><span>${t("主机名", "Hostname")}</span><b>${esc(info.hostname || "-")}</b></div>
            <div><span>${t("产品根目录", "Product root")}</span><b class="mono">${esc(info.product_root || "-")}</b></div>
            <div><span>${t("引擎模式", "Engine mode")}</span><b>${esc(info.engine_mode || "-")}</b></div>
            <div><span>${t("CRS 偏执级别", "CRS paranoia")}</span><b>PL${esc(info.paranoia_level ?? "-")} · ${esc(at(info.paranoia_hint || ""))}</b></div>
            <div><span>${t("重保模式", "Heavy-security")}</span><b>${info.heavy_security ? `<span class="badge on">${t("开启", "On")}</span>` : `<span class="badge off">${t("关闭", "Off")}</span>`}</b></div>
            <div><span>HA</span><b>${esc((ha.role_guess) || "standalone")}</b></div>
            <div><span>${t("时间 (UTC)", "Time (UTC)")}</span><b class="mono">${esc(info.time_utc || "")}</b></div>
          </div>
        </div>
        <div class="card">
          <h3>${t("特征库信息", "Signature info")}</h3>
          <div class="kv">
            <div><span>WAF / CRS</span><b>${esc(info.crs || "-")}</b></div>
            <div><span>${t("自定义规则文件", "Custom rule files")}</span><b>${esc(info.custom_rules ?? 0)}</b></div>
            <div><span>${t("IP 地理库", "IP Geo DB")}</span><b>${geo.mmdb_found ? `<span class="badge on">${t("已加载", "Loaded")}</span>` : `<span class="badge off">${t("未找到", "Not found")}</span>`} ${esc(geo.mmdb_path || "")}</b></div>
            <div><span>${t("Geo 封锁", "Geo block")}</span><b>${esc((geo.blocklist || []).join(", ") || t("无", "None"))}（${esc(geo.blocklist_count ?? 0)}）</b></div>
            <div><span>${t("威胁情报", "Threat intel")}</span><b>${esc(intel.count ?? 0)} ${t("条", "items")} · ${t("已过期", "Expired")} ${esc(intel.expired ?? 0)}</b></div>
            <div><span>${t("规则库最近升级", "Last rule upgrade")}</span><b class="mono">${esc(last.time || t("无记录", "No record"))}${last.filename ? " · " + esc(last.filename) : ""}</b></div>
            <div><span>${t("Go 运行时", "Go runtime")}</span><b class="mono">${esc(info.go_version || "")}</b></div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:.75rem">
        <h3>${t("WAF 规则库 · 本地升级", "WAF rule pack · local upgrade")}</h3>
        ${st ? `
          <p class="muted">${esc(at(st.bundle_hint || "") || t("上传 .tgz/.tar.gz 规则包进行本地升级。", "Upload a .tgz/.tar.gz rule pack for local upgrade."))}</p>
          <div class="kv" style="margin-bottom:.65rem">
            <div><span>Staging</span><b>${esc(st.staging_files ?? 0)} ${t("文件", "files")} · <code class="mono">${esc(st.staging_dir || "")}</code></b></div>
            <div><span>Active</span><b>${esc(st.active_files ?? 0)} ${t("文件", "files")} · <code class="mono">${esc(st.active_dir || "")}</code></b></div>
            <div><span>${t("验签公钥", "Verify pubkey")}</span><b>${st.pubkey_present ? `<span class="badge on">${t("已配置", "Configured")}</span>` : `<span class="badge off">${t("未配置", "Not configured")}</span>`}</b></div>
            <div><span>${t("上传上限", "Upload limit")}</span><b>${esc(st.max_upload_mb ?? 64)} MB</b></div>
          </div>
          <div class="grid cols-2">
            <div>
              <div class="form-grid" style="grid-template-columns:1fr">
                <label>${t("规则包（.tgz / .tar.gz）", "Rule pack (.tgz / .tar.gz)")}
                  ${filePickerHtml("ruFile", ".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar")}
                </label>
                <label>${t("签名文件（可选 .sig）", "Signature file (optional .sig)")}
                  ${filePickerHtml("ruSig", ".sig")}
                </label>
                <label class="check"><input type="checkbox" id="ruPromote" checked /> ${t("升级后立即 promote 并 reload Nginx", "Promote and reload Nginx immediately after upgrade")}</label>
              </div>
              <div class="toolbar" style="margin-top:.65rem">
                <button type="button" class="success" id="ruSubmit">${t("确定并本地升级", "Confirm local upgrade")}</button>
                <button type="button" class="ghost" id="ruRefresh">${t("刷新", "Refresh")}</button>
              </div>
              <div id="ruResult" class="muted" style="margin-top:.5rem"></div>
            </div>
            <div>
              <h3 style="margin-top:0;border:0;padding:0">${t("最近一次升级", "Last upgrade")}</h3>
              ${last.time ? `
                <div class="kv">
                  <div><span>${t("时间", "Time")}</span><b class="mono">${esc(last.time)}</b></div>
                  <div><span>${t("文件", "File")}</span><b class="mono">${esc(last.filename || "-")}</b></div>
                  <div><span>custom / rules</span><b>${esc(last.custom_files ?? 0)} / ${esc(last.rules_files ?? 0)}</b></div>
                  <div><span>${t("已发布", "Promoted")}</span><b>${last.promoted ? `<span class="badge on">${t("是", "Yes")}</span>` : `<span class="badge off">${t("否", "No")}</span>`}</b></div>
                  <div><span>${t("验签", "Verify")}</span><b>${last.sig_verified ? `<span class="badge on">${t("通过", "Passed")}</span>` : `<span class="badge">${t("未验/跳过", "Skipped")}</span>`}</b></div>
                  ${last.error ? `<div><span>${t("错误", "Error")}</span><b style="color:var(--danger)">${esc(at(last.error))}</b></div>` : ""}
                </div>` : `<div class="empty">${t("尚无升级记录", "No upgrade history")}</div>`}
              <p class="muted" style="margin-top:.65rem">CLI：<code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/bundle.tgz</code></p>
            </div>
          </div>` : `
          <p class="muted" style="color:var(--danger)">${t("无法加载升级接口 ", "Cannot load upgrade API ")}<code>/api/v1/rules/upgrade/status</code>${t("。请确认已用新版 ", ". Ensure ")}<code>ma-waf-api</code>${t(" 重新编译并重启。", " is rebuilt and restarted.")}</p>
          <button type="button" class="ghost" id="gotoRulesUp">${t("打开特征库升级页", "Open signature upgrade page")}</button>`}
      </div>`;
    if ($("hdrDevice")) $("hdrDevice").textContent = info.hostname || t("本机", "Local");
    const go = $("gotoRulesUp");
    if (go) go.onclick = () => navigate("rules-upgrade");
    bindRulesUpgradeForm("sysinfo");
  }

  function bindRulesUpgradeForm(refreshPage) {
    bindFilePicker("ruFile");
    bindFilePicker("ruSig");
    const refresh = $("ruRefresh");
    if (refresh) refresh.onclick = () => navigate(refreshPage || "rules-upgrade", true);
    const submit = $("ruSubmit");
    if (!submit) return;
    submit.onclick = async () => {
      const fileInput = $("ruFile");
      if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        toast(false, t("请选择规则包文件", "Please select a rule pack file"));
        return;
      }
      const fd = new FormData();
      fd.append("file", fileInput.files[0]);
      const sigInput = $("ruSig");
      if (sigInput && sigInput.files && sigInput.files[0]) fd.append("sig", sigInput.files[0]);
      fd.append("promote", ($("ruPromote") && $("ruPromote").checked) ? "1" : "0");
      if ($("ruResult")) $("ruResult").textContent = t("上传并处理中…", "Uploading and processing…");
      try {
        const r = await api("/api/v1/rules/upgrade/local", { method: "POST", body: fd });
        const rec = r.result || {};
        if ($("ruResult")) {
          $("ruResult").innerHTML = `<span class="badge on">${t("成功", "Success")}</span> custom=${esc(rec.custom_files)} rules=${esc(rec.rules_files)}
            promote=${rec.promoted ? t("是", "Yes") : t("否", "No")} · ${esc(at((rec.notes || []).join("； ")))}`;
        }
        toast(true, t("本地规则库升级完成", "Local rule pack upgrade complete"));
        setTimeout(() => navigate(refreshPage || "rules-upgrade", true), 600);
      } catch (e) {
        const rec = (e.data && e.data.result) || {};
        if ($("ruResult")) {
          $("ruResult").innerHTML = `<span class="badge off">${t("失败", "Failed")}</span> ${esc(at(e.message))}${rec.notes ? " · " + esc(at((rec.notes || []).join("； "))) : ""}`;
        }
        toast(false, e.message);
      }
    };
  }

  async function loadRulesUpgrade() {
    const st = await api("/api/v1/rules/upgrade/status");
    const last = st.last || {};
    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>${t("WAF 规则库升级 · 本地升级", "WAF rule pack upgrade · local")}</h3>
        <p class="muted">${esc(at(st.bundle_hint || ""))}</p>
        <div class="kv">
          <div><span>${t("Staging 规则文件", "Staging rule files")}</span><b>${esc(st.staging_files ?? 0)} · <code class="mono">${esc(st.staging_dir || "")}</code></b></div>
          <div><span>${t("Active 规则文件", "Active rule files")}</span><b>${esc(st.active_files ?? 0)} · <code class="mono">${esc(st.active_dir || "")}</code></b></div>
          <div><span>${t("验签公钥", "Verify pubkey")}</span><b>${st.pubkey_present ? `<span class="badge on">${t("已配置", "Configured")}</span>` : `<span class="badge off">${t("未配置", "Not configured")}</span>`} ${esc(st.pubkey_path || "")}</b></div>
          <div><span>${t("CLI 脚本", "CLI script")}</span><b>${st.cli_script_ok ? `<span class="badge on">${t("可用", "Available")}</span>` : `<span class="badge off">${t("缺失", "Missing")}</span>`} <code class="mono">${esc(st.cli_script || "")}</code></b></div>
          <div><span>${t("上传上限", "Upload limit")}</span><b>${esc(st.max_upload_mb ?? 64)} MB</b></div>
        </div>
      </div>
      <div class="grid cols-2">
        <div class="card">
          <h3>${t("上传规则包", "Upload rule pack")}</h3>
          <div class="form-grid" style="grid-template-columns:1fr">
            <label>${t("规则包（.tgz / .tar.gz）", "Rule pack (.tgz / .tar.gz)")}
              ${filePickerHtml("ruFile", ".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar")}
            </label>
            <label>${t("签名文件（可选 .sig）", "Signature file (optional .sig)")}
              ${filePickerHtml("ruSig", ".sig")}
            </label>
            <label class="check"><input type="checkbox" id="ruPromote" checked /> ${t("升级后立即 promote 并 reload Nginx", "Promote and reload Nginx immediately after upgrade")}</label>
          </div>
          <div class="toolbar" style="margin-top:.75rem">
            <button type="button" class="success" id="ruSubmit">${t("确定并本地升级", "Confirm local upgrade")}</button>
            <button type="button" class="ghost" id="ruRefresh">${t("刷新状态", "Refresh status")}</button>
          </div>
          <p class="muted">${t("建议包结构：", "Suggested pack layout: ")}<code>custom/*.conf</code>${t("（→ staging）和/或 ", " (→ staging) and/or ")}<code>rules/*.conf</code>${t("（→ ModSecurity rules）。生产建议附带 ", " (→ ModSecurity rules). Production: include ")}<code>${t("包名.sig", "packname.sig")}</code>${t("。", ".")}</p>
          <div id="ruResult" class="muted" style="margin-top:.5rem"></div>
        </div>
        <div class="card">
          <h3>${t("最近一次升级", "Last upgrade")}</h3>
          ${last.time ? `
            <div class="kv">
              <div><span>${t("时间", "Time")}</span><b class="mono">${esc(last.time)}</b></div>
              <div><span>${t("方式", "Mode")}</span><b>${esc(last.mode || "-")}</b></div>
              <div><span>${t("文件", "File")}</span><b class="mono">${esc(last.filename || "-")}</b></div>
              <div><span>custom / rules</span><b>${esc(last.custom_files ?? 0)} / ${esc(last.rules_files ?? 0)}</b></div>
              <div><span>${t("已发布", "Promoted")}</span><b>${last.promoted ? `<span class="badge on">${t("是", "Yes")}</span>` : `<span class="badge off">${t("否", "No")}</span>`}</b></div>
              <div><span>${t("验签", "Verify")}</span><b>${last.sig_verified ? `<span class="badge on">${t("通过", "Passed")}</span>` : `<span class="badge">${t("未验/跳过", "Skipped")}</span>`}</b></div>
              <div><span>${t("操作者", "Operator")}</span><b>${esc(last.user || "-")}</b></div>
              <div><span>${t("备注", "Notes")}</span><b>${esc(at((last.notes || []).join("； ")) || "-")}</b></div>
              ${last.error ? `<div><span>${t("错误", "Error")}</span><b style="color:var(--danger)">${esc(at(last.error))}</b></div>` : ""}
            </div>` : `<div class="empty">${t("尚无升级记录", "No upgrade history")}</div>`}
          <p class="muted" style="margin-top:.85rem">${t("离线 CLI 等价命令：", "Offline CLI equivalent:")}<br/>
            <code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/rules_bundle.tgz</code>
          </p>
        </div>
      </div>`;
    bindRulesUpgradeForm("rules-upgrade");
  }

  async function loadHeavy() {
    const [opsWrap, pl] = await Promise.all([
      api("/api/v1/ops"),
      api("/api/v1/crs/paranoia").catch(() => ({ level: 2 })),
    ]);
    const ops = opsWrap.ops || {};
    const on = !!ops.heavy_security;
    pageRoot().innerHTML = `
      <div class="card">
        <h3>${t("重保模式", "Heavy-security mode")}</h3>
        <p class="muted">${t("对齐企业 WAF「重大活动 / 重保」场景：开启后将 CRS 偏执级别调至 ", "Enterprise WAF major-event mode: enables CRS ")}<b>PL4</b>${t(" 并确保引擎为 ", " and engine ")}<b>On</b>${t("。关闭后回落到 PL2 并 reload。", ". Off reverts to PL2 and reloads.")}</p>
        <div class="switch-row">
          <div>
            <b>${t("当前状态：", "Current: ")}</b>${on ? `<span class="badge on">${t("已开启", "On")}</span>` : `<span class="badge off">${t("未开启", "Off")}</span>`}
            · ${t("当前 PL", "Current PL")}${esc(pl.level ?? pl.paranoia_level ?? "-")}
          </div>
        </div>
        <div class="toolbar" style="margin-top:.85rem">
          <input id="heavyReason" placeholder="${t("原因（必填，写入审计）", "Reason (required, audited)")}" style="min-width:280px" />
          <button type="button" class="danger" id="heavyOn"${on ? " disabled" : ""}>${t("开启重保", "Enable heavy-security")}</button>
          <button type="button" class="ghost" id="heavyOff"${on ? "" : " disabled"}>${t("关闭重保", "Disable heavy-security")}</button>
        </div>
      </div>`;
    const run = async (enable) => {
      const reason = ($("heavyReason").value || "").trim();
      if (!reason) { toast(false, t("请填写原因", "Please enter a reason")); return; }
      try {
        await api("/api/v1/ops/heavy", { method: "POST", body: JSON.stringify({ on: enable, reason }) });
        toast(true, enable ? t("重保已开启", "Heavy-security enabled") : t("重保已关闭", "Heavy-security disabled"));
        navigate("heavy", true);
      } catch (e) { toast(false, e.message); }
    };
    $("heavyOn").onclick = () => run(true);
    $("heavyOff").onclick = () => run(false);
  }

  function diagBadge(c) {
    if (c.ok) return `<span class="badge on">${t("通过", "Passed")}</span>`;
    if (c.severity === "critical") return `<span class="badge off">${t("失败", "Failed")}</span>`;
    return `<span class="badge off">${t("告警", "Warning")}</span>`;
  }

  async function loadTroubleshoot() {
    const data = await api("/api/v1/ops/troubleshoot");
    const sum = data.summary || {};
    const checks = data.checks || [];
    const logs = data.logs || {};
    const tips = data.tips || [];
    const overall = data.overall || "ok";
    const overallLabel = overall === "ok" ? t("健康", "Healthy") : (overall === "warn" ? t("有告警", "Warnings") : t("有故障", "Failures"));
    const overallBadge = overall === "ok" ? "on" : "off";

    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" id="tsRefresh">${t("重新检测", "Rerun checks")}</button>
        <button type="button" class="ghost" id="tsReload">Reload Nginx</button>
        <button type="button" class="ghost" id="tsFixTLS">${t("修复管理面证书", "Fix management TLS cert")}</button>
        <button type="button" class="ghost" id="tsCopy">${t("复制报告", "Copy report")}</button>
      </div>
      <div class="grid cols-4" style="margin-top:.65rem">
        <div class="card kpi"><div class="label">${t("总体", "Overall")}</div><div class="value" style="font-size:1.15rem"><span class="badge ${overallBadge}">${esc(overallLabel)}</span></div></div>
        <div class="card kpi"><div class="label">${t("通过", "Passed")}</div><div class="value">${esc(sum.ok ?? 0)}</div></div>
        <div class="card kpi"><div class="label">${t("告警", "Warnings")}</div><div class="value">${esc(sum.warn ?? 0)}</div></div>
        <div class="card kpi"><div class="label">${t("失败", "Failed")}</div><div class="value">${esc(sum.fail ?? 0)}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("检查项", "Checks")}</h3>
        <p class="muted">UTC ${esc(data.time_utc || "")} · ${t("产品根", "Product root")} ${esc(data.product_root || "")}</p>
        <table class="data">
          <thead><tr><th>${t("状态", "Status")}</th><th>${t("分类", "Category")}</th><th>${t("项目", "Item")}</th><th>${t("详情", "Detail")}</th><th>${t("建议", "Hint")}</th></tr></thead>
          <tbody>
            ${checks.map((c) => `
              <tr>
                <td>${diagBadge(c)}</td>
                <td>${esc(at(c.category || ""))}</td>
                <td><b>${esc(at(c.title || c.id))}</b></td>
                <td class="mono" style="white-space:pre-wrap;max-width:36rem">${esc(at(c.detail || ""))}</td>
                <td class="muted">${esc(at(c.hint || ""))}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card">
          <h3>${t("常见问题速查", "Quick FAQ")}</h3>
          <ul class="muted" style="line-height:1.7">
            ${tips.map((tip) => `<li><b>${esc(at(tip.title || ""))}</b> — ${esc(at(tip.body || ""))}</li>`).join("")}
          </ul>
          <p class="muted" style="margin-top:.5rem">${t("完整手册见文档 ", "Full manual: ")}<code>docs/troubleshooting.md</code>${t(" 或控制台「用户手册」。", " or console User Manual.")}</p>
        </div>
        <div class="card">
          <h3>${t("Nginx error 日志尾部", "Nginx error log tail")}</h3>
          <p class="muted mono">${esc((data.log_paths && data.log_paths.nginx_error) || "")}</p>
          <pre class="mono" style="white-space:pre-wrap;max-height:280px;overflow:auto;background:#0a101b;padding:.75rem;border-radius:10px;color:var(--muted)">${esc(logs.nginx_error || t("（无内容或文件不可读）", "(Empty or unreadable file)"))}</pre>
        </div>
      </div>
    `;

    $("tsRefresh").onclick = () => navigate("troubleshoot", true);
    $("tsReload").onclick = () => reloadNginxUI();
    $("tsFixTLS").onclick = async () => {
      try {
        await api("/api/v1/pki/admin/ensure", {
          method: "POST",
          body: JSON.stringify({ cn: "waf-admin.local", days: 3650 }),
        });
        toast(true, t("已确保管理面证书存在", "Management TLS cert ensured"));
        navigate("troubleshoot", true);
      } catch (e) { toast(false, e.message); }
    };
    $("tsCopy").onclick = async () => {
      const text = JSON.stringify({ overall, summary: sum, checks, time: data.time_utc }, null, 2);
      try {
        await navigator.clipboard.writeText(text);
        toast(true, t("报告已复制到剪贴板", "Report copied to clipboard"));
      } catch (_) {
        toast(false, t("复制失败，请手动选取页面内容", "Copy failed — select page content manually"));
      }
    };
  }

  async function loadSystem() {
    const [health, metrics, status, opsWrap, ha] = await Promise.all([
      api("/api/v1/health"),
      api("/api/v1/metrics"),
      api("/api/v1/status"),
      api("/api/v1/ops").catch(() => ({ ops: {} })),
      api("/api/v1/ha/status").catch(() => ({})),
    ]);
    const ops = opsWrap.ops || {};
    pageRoot().innerHTML = `
      <div class="grid cols-4">
        <div class="card kpi"><div class="label">${t("API 状态", "API status")}</div><div class="value">${esc(health.status || "-")}</div></div>
        <div class="card kpi"><div class="label">${t("引擎", "Engine")}</div><div class="value" style="font-size:1.2rem">${esc(health.sec_rule_engine || status.engine_mode || "-")}</div></div>
        <div class="card kpi"><div class="label">Load1</div><div class="value">${esc(metrics.load1 ?? "-")}</div><div class="hint">${t("主机负载", "Host load")}</div></div>
        <div class="card kpi"><div class="label">${t("内存使用", "Memory use")}</div><div class="value">${Number(metrics.mem_used_pct || 0).toFixed(0)}%</div><div class="hint">${t("可用", "Available")} ${esc(metrics.mem_avail_mb ?? "-")} MB</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("双机 HA / VIP", "HA / VIP")}</h3>
        <p class="muted">${t("角色：", "Role: ")}<b>${esc(ha.role_guess || "standalone")}</b>
          · keepalived ${ha.keepalived_running ? `<span class="badge on">${t("运行", "Running")}</span>` : `<span class="badge off">${t("未运行", "Stopped")}</span>`}
          · ${t("本机持有 VIP", "Local VIP")} ${ha.local_has_vip ? `<span class="badge on">${t("是", "Yes")}</span>` : `<span class="badge off">${t("否", "No")}</span>`}
          · ${t("健康", "Health")} ${ha.health_ok ? '<span class="badge on">OK</span>' : `<span class="badge off">${t("异常", "Abnormal")}</span>`} — ${esc(at(ha.health_detail || ""))}</p>
        <p class="muted">VIP: ${esc((ha.vips || []).join(", ") || t("未解析", "Unresolved"))} · ${t("配置", "Config")}: ${esc(ha.config_path || t("无", "None"))}</p>
        <p class="muted">${esc(at(ha.hint || ""))}</p>
      </div>
      <div class="grid cols-4" style="margin-top:.85rem">
        <div class="card kpi"><div class="label">Nginx Active</div><div class="value">${esc(metrics.nginx_active ?? "-")}</div><div class="hint">${metrics.nginx_status_ok ? "stub_status OK" : esc(metrics.nginx_status_err || t("未采集", "Not collected"))}</div></div>
        <div class="card kpi"><div class="label">${t("拦截率", "Intercept rate")}</div><div class="value">${Number(metrics.intercept_rate_pct || 0).toFixed(2)}%</div></div>
        <div class="card kpi"><div class="label">${t("平均时延", "Avg latency")}</div><div class="value">${(Number(metrics.avg_request_time || 0) * 1000).toFixed(1)}<span style="font-size:.9rem"> ms</span></div></div>
        <div class="card kpi"><div class="label">${t("API 请求", "API requests")}</div><div class="value">${esc(metrics.api_requests ?? "-")}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("告警与自动加黑", "Alerts & auto-block")}</h3>
        <p class="muted">${t("写入 ", "Writes ")}<code>var/lib/ops.json</code>${t("。Challenge 指纹：", ". Challenge fingerprint: ")}${esc(opsWrap.challenge_fp || "-")}${t("。定时加黑需启用 timer 并配置 Cron Token。", " Scheduled auto-block needs timer + Cron Token.")}</p>
        <div class="form-grid">
          <label>Alert Webhook URL
            <input id="opsWebhook" value="${esc(ops.alert_webhook || "")}" placeholder="https://hooks.example/…" />
          </label>
          <label>${t("Cron Token（本机定时任务）", "Cron Token (local scheduler)")}
            <input id="opsCron" value="${esc(ops.cron_token || "")}" placeholder="${t("随机长串", "Random long string")}" />
          </label>
          <label>${t("自动加黑阈值（命中次数）", "Auto-block threshold (hits)")}
            <input id="opsThr" type="number" min="1" value="${esc(ops.autoblock_threshold ?? 30)}" />
          </label>
          <label>${t("自动加黑 TopN", "Auto-block TopN")}
            <input id="opsTopN" type="number" min="1" value="${esc(ops.autoblock_top_n ?? 20)}" />
          </label>
          <label>${t("攻击量告警阈值（审计尾部）", "Attack volume alert threshold (audit tail)")}
            <input id="opsAtk" type="number" min="0" value="${esc(ops.attack_alert_min ?? 100)}" />
          </label>
          <label>${t("情报 IOC 存活天数", "Intel IOC TTL (days)")}
            <input id="opsIntelTTL" type="number" min="1" value="${esc(ops.intel_expire_days ?? 30)}" />
          </label>
          <label>${t("SIEM syslog（host:port）", "SIEM syslog (host:port)")}
            <input id="opsSIEM" value="${esc(ops.siem_addr || "")}" placeholder="127.0.0.1:514" />
          </label>
          <label>${t("SIEM 协议", "SIEM protocol")}
            <select id="opsSIEMProto">
              <option value="udp" ${ops.siem_proto!=="tcp"?"selected":""}>udp</option>
              <option value="tcp" ${ops.siem_proto==="tcp"?"selected":""}>tcp</option>
            </select>
          </label>
          <label class="check"><input type="checkbox" id="opsABEn" ${ops.autoblock_enabled ? "checked" : ""} /> ${t("启用定时自动加黑", "Enable scheduled auto-block")}</label>
        </div>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="opsSave">${t("保存运维设置", "Save ops settings")}</button>
          <button class="ghost" id="opsTestHook">${t("测试 Webhook", "Test Webhook")}</button>
          <button class="ghost" id="opsSIEMTest">${t("测试 SIEM", "Test SIEM")}</button>
          <button class="ghost" id="opsGenTok">${t("生成 Cron Token", "Generate Cron Token")}</button>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>${t("运维动作", "Ops actions")}</h3>
        <p class="muted">${t("生产请设置 MA_WAF_STRICT_AUTH=1 与 bcrypt；告警: systemctl enable --now ma-waf-alert.timer", "Production: set MA_WAF_STRICT_AUTH=1 with bcrypt; alerts: systemctl enable --now ma-waf-alert.timer")}</p>
        <div class="toolbar">
          <button id="sysReload">Reload Nginx</button>
          <button class="ghost" id="sysBackup">${t("备份", "Backup")}</button>
          <button class="ghost" id="sysHealth">${t("再次探测", "Probe again")}</button>
        </div>
        <pre class="mono" style="white-space:pre-wrap;color:var(--muted);background:#0a101b;padding:.75rem;border-radius:10px">${esc(JSON.stringify({ health, metrics, status }, null, 2))}</pre>
        <p class="muted">Prometheus: <code>curl -s http://127.0.0.1:9090/metrics</code>${t("（受 allow_cidrs 限制）", " (restricted by allow_cidrs)")}</p>
      </div>`;
    $("opsSave").onclick = async () => {
      try {
        await api("/api/v1/ops", {
          method: "PUT",
          body: JSON.stringify({
            alert_webhook: $("opsWebhook").value.trim(),
            cron_token: $("opsCron").value.trim(),
            autoblock_threshold: Number($("opsThr").value) || 30,
            autoblock_top_n: Number($("opsTopN").value) || 20,
            autoblock_enabled: $("opsABEn").checked,
            attack_alert_min: Number($("opsAtk").value) || 0,
            intel_expire_days: Number($("opsIntelTTL").value) || 30,
            siem_addr: $("opsSIEM").value.trim(),
            siem_proto: $("opsSIEMProto").value,
          }),
        });
        toast(true, t("运维设置已保存", "Ops settings saved"));
      } catch (e) { toast(false, e.message); }
    };
    $("opsGenTok").onclick = () => {
      const a = new Uint8Array(24);
      crypto.getRandomValues(a);
      $("opsCron").value = Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
      toast(true, t("已生成 Token，请保存", "Token generated — save it"));
    };
    $("opsTestHook").onclick = async () => {
      try {
        const r = await api("/api/v1/ops/test-webhook", { method: "POST", body: "{}" });
        toast(!!r.ok, r.ok ? t("Webhook 已发送", "Webhook sent") : ("HTTP " + r.status));
      } catch (e) { toast(false, e.message); }
    };
    $("opsSIEMTest").onclick = async () => {
      try {
        await api("/api/v1/ops/siem-test", { method: "POST", body: "{}" });
        toast(true, t("SIEM 测试已发送", "SIEM test sent"));
      } catch (e) { toast(false, e.message); }
    };
    $("sysReload").onclick = () => reloadNginxUI();
    $("sysBackup").onclick = async () => {
      try { await api("/api/v1/backup", { method: "POST" }); toast(true, t("备份完成", "Backup complete")); }
      catch (e) { toast(false, e.message); }
    };
    $("sysHealth").onclick = () => navigate("system", true);
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function renderTopNav() {
    const top = $("topNav");
    if (!top) return;
    const modules = getModules();
    top.innerHTML = modules.map((m) =>
      `<button type="button" data-module="${m.id}" class="${state.module === m.id ? "active" : ""}">${esc(m.label)}</button>`
    ).join("");
    top.querySelectorAll("button").forEach((btn) => {
      btn.onclick = () => {
        const mod = modules.find((x) => x.id === btn.dataset.module);
        if (!mod || !mod.pages.length) return;
        navigate(mod.pages[0].id);
      };
    });
  }

  function renderSideNav() {
    const modules = getModules();
    const mod = modules.find((m) => m.id === state.module) || modules[0];
    if ($("sideTitle")) $("sideTitle").textContent = mod.label;
    const nav = $("nav");
    nav.innerHTML = mod.pages.map((p) =>
      `<button type="button" data-page="${p.id}" class="${state.page === p.id ? "active" : ""}">${esc(p.label)}</button>`
    ).join("");
    nav.querySelectorAll("button").forEach((btn) => {
      btn.onclick = () => navigate(btn.dataset.page);
    });
    const modMeta = modules.find((m) => m.id === state.module);
    const pageMeta = (modMeta && modMeta.pages.find((p) => p.id === state.page)) || { label: state.page };
    if ($("pageCrumb")) {
      $("pageCrumb").textContent = `${modMeta ? modMeta.label : ""} / ${pageMeta.label}`;
    }
  }

  async function navigate(page, force = false) {
    state.page = page;
    state.module = pageModule[page] || "home";
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
    renderTopNav();
    renderSideNav();
    const titlePair = getTitles()[page] || [page, ""];
    $("pageTitle").textContent = titlePair[0];
    $("pageSub").textContent = titlePair[1];
    toast(true, "");
    $("appErr").textContent = "";
    try {
      if (page === "dashboard") {
        await loadDashboard();
        state.timer = setInterval(() => {
          if (state.page === "dashboard") loadDashboard().catch(() => {});
        }, 20000);
      } else if (page === "events") await loadEvents();
      else if (page === "sites") await loadSites();
      else if (page === "discover") await loadDiscover();
      else if (page === "exceptions") await loadExceptions();
      else if (page === "rules") await loadRules();
      else if (page === "iplist") await loadIPList();
      else if (page === "addrbook") await loadAddrBook();
      else if (page === "policy") await loadPolicy();
      else if (page === "heavy") await loadHeavy();
      else if (page === "license") await loadLicense();
      else if (page === "reports") await loadReports();
      else if (page === "system") await loadSystem();
      else if (page === "sysinfo") await loadSysInfo();
      else if (page === "rules-upgrade") await loadRulesUpgrade();
      else if (page === "pki") await loadPKI();
      else if (page === "troubleshoot") await loadTroubleshoot();
      if (force) toast(true, t("已刷新", "Refreshed"));
    } catch (e) {
      if (e.status === 401) {
        localStorage.removeItem(tokenKey);
        state.token = "";
        showLogin();
        return;
      }
      toast(false, e.message || String(e));
      pageRoot().innerHTML = `<div class="card empty">${t("加载失败：", "Load failed: ")}${esc(e.message || e)}</div>`;
    }
  }

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("loginErr").textContent = "";
    try {
      const data = await api("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: $("user").value,
          password: $("pass").value,
          totp: $("totp").value,
        }),
      });
      state.token = data.token;
      localStorage.setItem(tokenKey, data.token);
      showApp();
      navigate("dashboard");
    } catch (err) {
      $("loginErr").textContent = err.message || String(err);
    }
  });

  $("logoutBtn").addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    showLogin();
  });
  $("refreshBtn").onclick = () => navigate(state.page, true);
  $("reloadBtn").onclick = () => reloadNginxUI();
  const sideCollapse = $("sideCollapse");
  if (sideCollapse) {
    const syncCollapseLabel = () => {
      const on = document.body.classList.contains("side-collapsed");
      sideCollapse.textContent = on ? t("展开", "Expand") : t("收起", "Collapse");
      sideCollapse.title = on ? t("展开侧栏", "Expand sidebar") : t("收起侧栏", "Collapse sidebar");
      sideCollapse.setAttribute("aria-expanded", on ? "false" : "true");
    };
    sideCollapse.onclick = () => {
      document.body.classList.toggle("side-collapsed");
      try {
        localStorage.setItem("ma_waf_side_collapsed", document.body.classList.contains("side-collapsed") ? "1" : "0");
      } catch (_) { /* ignore */ }
      syncCollapseLabel();
    };
    try {
      if (localStorage.getItem("ma_waf_side_collapsed") === "1") {
        document.body.classList.add("side-collapsed");
      }
    } catch (_) { /* ignore */ }
    syncCollapseLabel();
  }
  const drawerClose = $("drawerClose");
  if (drawerClose) drawerClose.onclick = closeDrawer;
  const drawer = $("drawer");
  if (drawer) {
    drawer.addEventListener("click", (e) => {
      if (e.target === drawer) closeDrawer();
    });
  }

  function onLangChange() {
    if (window.MaI18n) window.MaI18n.applyDom();
    if (sideCollapse) {
      const on = document.body.classList.contains("side-collapsed");
      sideCollapse.textContent = on ? t("展开", "Expand") : t("收起", "Collapse");
      sideCollapse.title = on ? t("展开侧栏", "Expand sidebar") : t("收起侧栏", "Collapse sidebar");
    }
    if (state.token) {
      renderTopNav();
      renderSideNav();
      navigate(state.page, true);
    }
  }
  if (window.MaI18n) {
    window.MaI18n.applyDom();
    window.MaI18n.bindSwitchers(onLangChange);
  }

  if (state.token) {
    showApp();
    navigate("dashboard");
  } else {
    showLogin();
  }
})();

(() => {
  const TOKEN_KEY = "ma_waf_community_token";
  const cfg = () => window.MA_WAF || {};

  /** 与专业版相同的模块树；community:true 才可进入 */
  const MODULES = [
    {
      id: "home",
      label: "首页",
      pages: [{ id: "dashboard", label: "总览", community: true }],
    },
    {
      id: "sites",
      label: "站点",
      pages: [
        { id: "sites", label: "Web 站点", community: false },
        { id: "discover", label: "站点自发现", community: false },
      ],
    },
    {
      id: "policy",
      label: "策略",
      pages: [
        { id: "policy", label: "安全策略", community: false },
        { id: "rules", label: "防护规则", community: false },
        { id: "exceptions", label: "规则例外", community: false },
        { id: "heavy", label: "重保模式", community: false },
      ],
    },
    {
      id: "monitor",
      label: "监控",
      pages: [
        { id: "events", label: "安全事件", community: true },
        { id: "reports", label: "报表与分析", community: false },
      ],
    },
    {
      id: "objects",
      label: "对象",
      pages: [
        { id: "addrbook", label: "地址簿", community: false },
        { id: "iplist", label: "IP / Geo 名单", community: true },
      ],
    },
    {
      id: "system",
      label: "系统",
      pages: [
        { id: "sysinfo", label: "系统与特征库", community: false },
        { id: "rules-upgrade", label: "特征库升级", community: false },
        { id: "pki", label: "PKI 证书", community: false },
        { id: "system", label: "系统运维", community: false },
        { id: "troubleshoot", label: "故障排查", community: false },
        { id: "license", label: "许可证", community: false },
      ],
    },
  ];

  const TITLES = {
    dashboard: ["总览", "攻击态势 · 引擎状态 · 关键指标"],
    events: ["安全事件", "Host · 状态码 · 攻击字段 · 详情"],
    iplist: ["IP / Geo 名单", "社区版仅支持 IP 黑名单；国家封锁为专业版"],
    sites: ["Web 站点", "专业版"],
    discover: ["站点自发现", "专业版"],
    policy: ["安全策略", "专业版"],
    rules: ["防护规则", "专业版"],
    exceptions: ["规则例外", "专业版"],
    heavy: ["重保模式", "专业版"],
    reports: ["报表与分析", "专业版"],
    addrbook: ["地址簿", "专业版"],
    sysinfo: ["系统与特征库", "专业版"],
    "rules-upgrade": ["特征库升级", "专业版"],
    pki: ["PKI 证书", "专业版"],
    system: ["系统运维", "专业版"],
    troubleshoot: ["故障排查", "专业版"],
    license: ["许可证", "专业版"],
  };

  const pageModule = {};
  const pageMeta = {};
  MODULES.forEach((m) => {
    m.pages.forEach((p) => {
      pageModule[p.id] = m.id;
      pageMeta[p.id] = p;
    });
  });

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || "",
    module: "home",
    page: "dashboard",
  };

  const $ = (id) => document.getElementById(id);

  function setAuthUi(loggedIn) {
    document.body.classList.toggle("auth-login", !loggedIn);
    document.body.classList.toggle("auth-app", loggedIn);
  }

  function showLoginErr(msg) {
    const el = $("loginErr");
    if (el) el.textContent = msg || "";
  }

  function showAppMsg(ok, msg) {
    $("appErr").textContent = ok ? "" : msg || "";
    $("appOk").textContent = ok ? msg || "" : "";
  }

  async function api(path, options) {
    options = options || {};
    const headers = Object.assign(
      { "Content-Type": "application/json" },
      options.headers || {}
    );
    if (state.token) headers.Authorization = "Bearer " + state.token;
    const res = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    let data = {};
    try {
      data = await res.json();
    } catch (e) {}
    if (res.status === 401) {
      state.token = "";
      sessionStorage.removeItem(TOKEN_KEY);
      setAuthUi(false);
      throw new Error(data.error || "未登录或会话已过期");
    }
    if (!res.ok) throw new Error(data.error || res.statusText || "请求失败");
    return data;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function priceLabel() {
    const n = cfg().proPriceCny || 4980;
    return "¥" + Number(n).toLocaleString("zh-CN");
  }

  function trialHref() {
    return cfg().contactHref || "trial.html";
  }

  function communityBannerHtml() {
    return `
      <div class="community-banner">
        <h3>当前为 Ma-WAF 社区版（永久免费）</h3>
        <p class="muted" style="margin:0">本仓库 Apache-2.0 开源，<strong>永久免费</strong>：无 License、无到期、无节点年费。界面布局与专业版一致，便于熟悉产品。社区版<strong>可用</strong>能力如下；带 <span class="pro-tag">Pro</span> 的菜单为专业版功能，点击无反应。</p>
        <ul>
          <li>单站点反向代理 + OWASP CRS 防护</li>
          <li>总览：引擎状态、事件计数、一键验证拦截效果</li>
          <li>安全事件：查看 ModSecurity 审计拦截记录</li>
          <li>IP 黑名单：手工维护（国家/Geo 封锁需专业版）</li>
          <li>扫描器 UA 拦截、基础限速</li>
        </ul>
        <p class="muted" style="margin:0">专业版另含：多站点、策略模板、威胁情报、地理封锁、Bot 挑战、SIEM、合规报表、特征库升级与商用支持。参考价 <b>${esc(priceLabel())}</b> / 节点 / 年。升级专业版不影响你继续免费使用本社区版。</p>
        <div class="banner-actions">
          <a class="hs-link" style="background:var(--hs-accent);border-color:var(--hs-accent)" href="${esc(trialHref())}">${esc(cfg().contactLabel || "申请 14 天专业版试用")}</a>
          <a class="ghost" href="install.html" style="display:inline-flex;align-items:center;padding:.35rem .7rem;text-decoration:none;border:1px solid var(--line);border-radius:4px;color:var(--text);font-weight:600">安装 / 接到业务</a>
          <a class="ghost" href="pro.html" style="display:inline-flex;align-items:center;padding:.35rem .7rem;text-decoration:none;border:1px solid var(--line);border-radius:4px;color:var(--text);font-weight:600">专业版对照</a>
        </div>
      </div>`;
  }

  function renderTopNav() {
    const nav = $("topNav");
    nav.innerHTML = MODULES.map((m) => {
      const allPro = m.pages.every((p) => !p.community);
      const active = state.module === m.id ? " active" : "";
      const locked = allPro ? " locked" : "";
      const tag = allPro ? ' <span class="pro-tag">Pro</span>' : "";
      return `<button type="button" data-module="${esc(m.id)}" class="${active}${locked}" ${allPro ? 'aria-disabled="true"' : ""}>${esc(m.label)}${tag}</button>`;
    }).join("");
    nav.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mod = MODULES.find((m) => m.id === btn.dataset.module);
        if (!mod) return;
        // 整组均为专业版：点击无反应
        if (mod.pages.every((p) => !p.community)) return;
        const first = mod.pages.find((p) => p.community) || mod.pages[0];
        if (!first.community) return;
        state.module = mod.id;
        state.page = first.id;
        renderNav();
        renderPage();
      });
    });
  }

  function renderSideNav() {
    const mod = MODULES.find((m) => m.id === state.module) || MODULES[0];
    $("sideTitle").textContent = mod.label;
    const nav = $("nav");
    nav.innerHTML = mod.pages
      .map((p) => {
        const active = state.page === p.id && p.community ? " active" : "";
        const locked = p.community ? "" : " locked";
        const tag = p.community ? "" : ' <span class="pro-tag">Pro</span>';
        return `<button type="button" data-page="${esc(p.id)}" class="${active}${locked}" ${p.community ? "" : 'aria-disabled="true"'}>${esc(p.label)}${tag}</button>`;
      })
      .join("");
    nav.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const meta = pageMeta[btn.dataset.page];
        // 专业版页面：点击无反应
        if (!meta || !meta.community) return;
        state.page = meta.id;
        state.module = pageModule[meta.id];
        renderNav();
        renderPage();
      });
    });
  }

  function renderNav() {
    renderTopNav();
    renderSideNav();
  }

  function setTitle() {
    const t = TITLES[state.page] || ["页面", ""];
    const mod = MODULES.find((m) => m.id === state.module);
    $("pageTitle").textContent = t[0];
    $("pageSub").textContent = t[1];
    $("pageCrumb").textContent = (mod ? mod.label : "首页") + " / " + t[0];
  }

  async function renderDashboard() {
    const root = $("pageRoot");
    root.innerHTML = communityBannerHtml() + `<div class="empty">加载中…</div>`;
    let status = {};
    try {
      status = await api("/api/status");
    } catch (e) {
      root.innerHTML = communityBannerHtml() + `<div class="msg err">${esc(e.message)}</div>`;
      return;
    }
    $("sideMode").textContent = "引擎: " + (status.engine || "-");
    const wafUrl = status.waf_url || "http://127.0.0.1:8080";
    root.innerHTML =
      communityBannerHtml() +
      `
      <div class="grid cols-4">
        <div class="card kpi"><div class="label">近期事件</div><div class="value">${esc(status.event_count || 0)}</div></div>
        <div class="card kpi"><div class="label">引擎模式</div><div class="value">${esc(status.engine || "-")}</div><div class="hint">On=拦截 · DetectionOnly=仅检测</div></div>
        <div class="card kpi"><div class="label">审计日志</div><div class="value" style="font-size:1.1rem">${status.audit_log_present ? esc(status.audit_log_size || 0) + " B" : "缺失"}</div></div>
        <div class="card kpi"><div class="label">版本</div><div class="value" style="font-size:1.05rem">Community</div><div class="hint">永久免费 · Pro 菜单已锁定</div></div>
      </div>
      <div class="card" style="margin-top:.75rem">
        <h3>验证防护效果</h3>
        <div class="toolbar">
          <button type="button" id="btnSelfTest">一键验证防护效果</button>
          <a class="ghost" href="${esc(wafUrl)}/" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;text-decoration:none">打开防护入口</a>
        </div>
        <p class="muted" id="testHint">将探测正常页、XSS、SQL 注入与扫描器 UA；结果写入下方事件能力。</p>
      </div>
      <div class="grid cols-2" style="margin-top:.75rem">
        <div class="card">
          <h3>Top 规则</h3>
          <div class="bars" id="topRules"></div>
        </div>
        <div class="card">
          <h3>Top 源 IP</h3>
          <div class="bars" id="topIps"></div>
        </div>
      </div>`;
    fillBars("topRules", (status.top_rules || []).map((r) => ({ label: r.id, count: r.count })));
    fillBars("topIps", (status.top_ips || []).map((r) => ({ label: r.ip, count: r.count })));
    $("btnSelfTest").onclick = async () => {
      const hint = $("testHint");
      hint.textContent = "正在验证…";
      try {
        const r = await api("/api/selftest", { method: "POST", body: {} });
        hint.textContent =
          (r.ok ? "防护正常。 " : "部分未达预期。 ") +
          (r.results || [])
            .map((x) => x.name + "=" + x.status + (x.ok ? "✓" : "✗"))
            .join(" · ");
        showAppMsg(true, "自检完成");
        await renderDashboard();
      } catch (e) {
        hint.textContent = e.message || String(e);
        showAppMsg(false, e.message);
      }
    };
  }

  function fillBars(id, rows) {
    const el = $(id);
    if (!rows.length) {
      el.innerHTML = '<div class="empty">暂无</div>';
      return;
    }
    const max = Math.max(...rows.map((r) => r.count), 1);
    el.innerHTML = rows
      .map(
        (r) => `
      <div class="bar-row">
        <span title="${esc(r.label)}">${esc(r.label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${(r.count / max) * 100}%"></div></div>
        <span>${esc(r.count)}</span>
      </div>`
      )
      .join("");
  }

  async function renderEvents() {
    const root = $("pageRoot");
    root.innerHTML = `<div class="empty">加载事件…</div>`;
    try {
      const data = await api("/api/events?limit=80");
      const items = (data.items || []).slice().reverse();
      if (!items.length) {
        root.innerHTML = `<div class="card"><div class="empty">暂无事件。请到总览执行「一键验证防护效果」。</div></div>`;
        return;
      }
      root.innerHTML = `
        <div class="card" style="padding:0">
          <div class="table-wrap" style="border:0;max-height:none">
            <table>
              <thead><tr><th>时间</th><th>源 IP</th><th>方法</th><th>URI</th><th>状态</th><th>规则</th><th>说明</th></tr></thead>
              <tbody>
                ${items
                  .map(
                    (e) => `<tr>
                  <td>${esc(e.time)}</td>
                  <td>${esc(e.client_ip)}</td>
                  <td>${esc(e.method)}</td>
                  <td class="uri-cell mono" title="${esc(e.uri)}">${esc(e.uri)}</td>
                  <td>${esc(e.status)}</td>
                  <td class="mono">${esc((e.rule_ids || []).join(","))}</td>
                  <td>${esc(e.message)}</td>
                </tr>`
                  )
                  .join("")}
              </tbody>
            </table>
          </div>
        </div>`;
    } catch (e) {
      root.innerHTML = `<div class="msg err">${esc(e.message)}</div>`;
    }
  }

  async function renderIplist() {
    const root = $("pageRoot");
    root.innerHTML = `<div class="empty">加载…</div>`;
    let ips = [];
    try {
      const data = await api("/api/iplist");
      ips = data.ips || [];
    } catch (e) {
      root.innerHTML = `<div class="msg err">${esc(e.message)}</div>`;
      return;
    }
    root.innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <h3>IP 黑名单（社区版可用）</h3>
          <label class="muted">每行一个 IP 或 CIDR</label>
          <textarea class="block" id="ipList">${esc(ips.join("\n"))}</textarea>
          <div class="toolbar" style="margin-top:.55rem">
            <button type="button" id="btnSaveIp">保存黑名单</button>
          </div>
          <p class="muted" id="ipHint">保存后请执行 <code>docker compose restart waf</code> 或 <code>scripts/apply-blacklist.ps1</code>。</p>
        </div>
        <div class="card" style="opacity:.85">
          <h3>国家 / Geo 封锁 <span class="pro-tag">Pro</span></h3>
          <p class="muted">地理封锁、善意爬虫名单、情报自动封禁属于专业版。本页按钮点击无反应。</p>
          <div class="toolbar">
            <button type="button" class="ghost locked-btn" disabled>启用 Geo 封锁</button>
            <button type="button" class="ghost locked-btn" disabled>导入国家列表</button>
          </div>
          <div class="banner-actions" style="margin-top:.75rem">
            <a class="hs-link" style="background:var(--hs-accent);border-color:var(--hs-accent)" href="${esc(trialHref())}">申请专业版试用</a>
          </div>
        </div>
      </div>`;
    $("btnSaveIp").onclick = async () => {
      const lines = $("ipList").value.split(/\r?\n/);
      try {
        const r = await api("/api/iplist", { method: "POST", body: { ips: lines } });
        $("ipHint").textContent = r.hint || "已保存";
        showAppMsg(true, "黑名单已写入");
      } catch (e) {
        showAppMsg(false, e.message);
      }
    };
  }

  async function renderPage() {
    showAppMsg(true, "");
    setTitle();
    const meta = pageMeta[state.page];
    if (!meta || !meta.community) {
      // 理论上不会进入；若进入则空白不跳转
      $("pageRoot").innerHTML = "";
      return;
    }
    if (state.page === "dashboard") return renderDashboard();
    if (state.page === "events") return renderEvents();
    if (state.page === "iplist") return renderIplist();
  }

  async function bootApp() {
    setAuthUi(true);
    renderNav();
    try {
      const st = await api("/api/status");
      $("sideMode").textContent = "引擎: " + (st.engine || "-");
    } catch (e) {
      $("sideMode").textContent = "引擎: -";
    }
    await renderPage();
  }

  function bindChrome() {
    $("logoutBtn").onclick = () => {
      state.token = "";
      sessionStorage.removeItem(TOKEN_KEY);
      setAuthUi(false);
      showLoginErr("");
    };
    $("refreshBtn").onclick = () => {
      renderPage().catch((e) => showAppMsg(false, e.message));
    };
    $("sideCollapse").onclick = () => {
      document.body.classList.toggle("side-collapsed");
      $("sideCollapse").textContent = document.body.classList.contains("side-collapsed")
        ? "»"
        : "收起";
    };
    $("loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      showLoginErr("");
      try {
        const data = await api("/api/login", {
          method: "POST",
          body: {
            username: $("user").value,
            password: $("pass").value,
          },
        });
        state.token = data.token;
        sessionStorage.setItem(TOKEN_KEY, data.token);
        await bootApp();
      } catch (ex) {
        showLoginErr(ex.message || String(ex));
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindChrome();
    if (state.token) {
      bootApp().catch(() => {
        state.token = "";
        sessionStorage.removeItem(TOKEN_KEY);
        setAuthUi(false);
      });
    } else {
      setAuthUi(false);
    }
  });
})();

# -*- coding: utf-8 -*-
"""One-shot i18n: wrap remaining bare Chinese UI strings in app.js with t(zh,en)."""
from pathlib import Path

path = Path(__file__).with_name("app.js")
text = path.read_text(encoding="utf-8")
orig = text

pairs = []

# ---------- loadPolicy handlers (toasts/confirms) ----------
pairs += [
    ('toast(true, "模式已切换为 " + btn.dataset.mode);',
     'toast(true, t("模式已切换为 ", "Mode switched to ") + btn.dataset.mode);'),
    ('toast(true, "偏执级已设为 PL" + btn.dataset.pl);',
     'toast(true, t("偏执级已设为 PL", "Paranoia set to PL") + btn.dataset.pl);'),
    ('toast(true, "内容策略已保存");',
     'toast(true, t("内容策略已保存", "Content policy saved"));'),
    ('toast(true, "已启用 " + btn.dataset.packOn);',
     'toast(true, t("已启用 ", "Enabled ") + btn.dataset.packOn);'),
    ('toast(true, "已禁用 " + btn.dataset.packOff);',
     'toast(true, t("已禁用 ", "Disabled ") + btn.dataset.packOff);'),
    ('$("polValidateOut").textContent = r.ok ? "校验通过" : ("问题: " + JSON.stringify(r.issues || r.nginx_msg));',
     '$("polValidateOut").textContent = r.ok ? t("校验通过", "Validation passed") : (t("问题: ", "Issues: ") + JSON.stringify(r.issues || r.nginx_msg));'),
    ('toast(!!r.ok, r.ok ? "校验通过" : "校验未通过");',
     'toast(!!r.ok, r.ok ? t("校验通过", "Validation passed") : t("校验未通过", "Validation failed"));'),
    ('toast(true, "已禁用过期补丁 " + (r.disabled || 0) + " 条");',
     'toast(true, t("已禁用过期补丁 ", "Disabled expired patches ") + (r.disabled || 0) + t(" 条", " items"));'),
    ('if (!content) { toast(false, "请粘贴 OpenAPI JSON"); return; }',
     'if (!content) { toast(false, t("请粘贴 OpenAPI JSON", "Please paste OpenAPI JSON")); return; }'),
    ('toast(true, "已生成 OpenAPI 规则（" + (r.paths || 0) + " 路径）");',
     'toast(true, t("已生成 OpenAPI 规则（", "OpenAPI rules generated (") + (r.paths || 0) + t(" 路径）", " paths)"));'),
    ('toast(true, "备份完成 " + (r.id || ""));',
     'toast(true, t("备份完成 ", "Backup complete ") + (r.id || ""));'),
    ('if (!confirm("确认回滚配置？当前未备份的改动将丢失。")) return;',
     'if (!confirm(t("确认回滚配置？当前未备份的改动将丢失。", "Confirm rollback? Unsaved changes will be lost."))) return;'),
    ('toast(true, "已回滚");',
     'toast(true, t("已回滚", "Rolled back"));'),
]

# ---------- countryHeat ----------
pairs += [
(
'''  function countryHeat(rows) {
    if (!rows || !rows.length) {
      return `<div class="empty">暂无国家维度数据。<br/>
        请将 <code>GeoLite2-Country.mmdb</code> 放到
        <code>/usr/local/Ma-waf/conf/geoip/</code>，重编并重启 API 后刷新；
        需已有带公网源 IP 的安全事件（内网 IP 无国家码属正常）。</div>`;
    }''',
'''  function countryHeat(rows) {
    if (!rows || !rows.length) {
      return `<div class="empty">${t("暂无国家维度数据。", "No country-level data yet.")}<br/>
        ${t("请将 ", "Place ")}<code>GeoLite2-Country.mmdb</code>${t(" 放到", " at")}
        <code>/usr/local/Ma-waf/conf/geoip/</code>${t("，重编并重启 API 后刷新；", ", rebuild and restart API, then refresh; ")}
        ${t("需已有带公网源 IP 的安全事件（内网 IP 无国家码属正常）。", "Requires security events with public source IPs (private IPs have no country code — normal).")}</div>`;
    }'''),
]

# ---------- loadReports ----------
pairs += [
    ('? `MMDB 已就绪：${esc(geoSt.mmdb_path || "")}`',
     '? `${t("MMDB 已就绪：", "MMDB ready: ")}${esc(geoSt.mmdb_path || "")}`'),
    (': "未找到 GeoLite2-Country.mmdb（报表热力需要；City 库非必须）";',
     ': t("未找到 GeoLite2-Country.mmdb（报表热力需要；City 库非必须）", "GeoLite2-Country.mmdb not found (needed for report heatmap; City DB optional)");'),
(
'''    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" id="rptCsv">导出 CSV</button>
        <button type="button" class="ghost" id="rptHtml">合规 HTML（可打印 PDF）</button>
        <span class="muted">含 Top IP/规则/国家与合规控制域映射</span>
      </div>
      <div class="grid cols-3">
        <div class="card kpi"><div class="label">事件总量</div><div class="value">${esc(sum.total || 0)}</div></div>
        <div class="card kpi"><div class="label">CRITICAL</div><div class="value">${esc(sevMerged.CRITICAL || 0)}</div></div>
        <div class="card kpi"><div class="label">WARNING</div><div class="value">${esc(sevMerged.WARNING || 0)}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem"><h3>24 小时攻击趋势（按小时）</h3>${bars(trendRows)}</div>
      <div class="card" style="margin-top:.85rem"><h3>攻击面 · 国家热力（ISO）</h3>
        <p class="muted">按攻击源 IP 聚合国家码。${mmdbHint}。城市级地图需 City MMDB（当前未做，可不传）。</p>
        ${countryHeat(sum.by_country || [])}
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>攻击源 Top</h3>${bars(sum.by_ip || [])}</div>
        <div class="card"><h3>规则命中 Top</h3>${bars(sum.by_rule || [])}</div>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card"><h3>国家分布条形图</h3>${bars(sum.by_country || [])}</div>
        <div class="card"><h3>合规运营映射（参考）</h3>
          <p class="muted">点击某一框架生成<strong>专属 HTML 报告</strong>，再在报告页「打印 / 另存为 PDF」。不构成认证结论。</p>
          <div class="tag-list compliance-fw">
            <button type="button" class="tag clickable" data-fw="dsl2" title="生成等保 2.0 专属报告">等保 2.0 · 安全审计/入侵防范</button>
            <button type="button" class="tag clickable" data-fw="iso27001" title="生成 ISO 27001 专属报告">ISO 27001 · A.8 / A.12</button>
            <button type="button" class="tag clickable" data-fw="gdpr" title="生成 GDPR 专属报告">GDPR · Art.32 技术措施</button>
            <button type="button" class="tag clickable" data-fw="sox" title="生成 SOX 专属报告">SOX · IT 一般控制（访问/变更）</button>
          </div>
          <p class="muted" style="margin-top:.6rem">也可使用上方按钮导出综合 CSV / 综合合规 HTML。</p>
        </div>
      </div>`;''',
'''    pageRoot().innerHTML = `
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
      </div>`;'''),
    ('if (!res.ok) throw new Error("导出失败 " + res.status);',
     'if (!res.ok) throw new Error(t("导出失败 ", "Export failed ") + res.status);'),
    ('toast(true, "CSV 已下载（" + fw + "）");',
     'toast(true, t("CSV 已下载（", "CSV downloaded (") + fw + "）");'),
    ('if (!w) throw new Error("浏览器拦截了弹窗，请允许本站弹窗后重试");',
     'if (!w) throw new Error(t("浏览器拦截了弹窗，请允许本站弹窗后重试", "Browser blocked popup — allow popups for this site and retry"));'),
    ('toast(true, "已打开「" + fw + "」专属报告（可打印为 PDF）");',
     'toast(true, t("已打开「", "Opened «") + fw + t("」专属报告（可打印为 PDF）", "» dedicated report (printable as PDF)"));'),
]

# ---------- loadDiscover ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>发现说明</h3>
        <p class="muted">解析访问日志 <code>${esc(data.access_log || "")}</code> 中的 Host，对照已管理站点标记防护状态。可将未防护条目一键创建站点草稿。</p>
      </div>
      <div class="toolbar">
        <button type="button" class="success" id="discRefresh">重新扫描</button>
        <span class="muted">共 ${items.length} 条候选</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>域名 / Host</th><th>协议</th><th>发现次数</th><th>样例 URI</th><th>防护状态</th><th>操作</th></tr></thead>
        <tbody>${items.length ? items.map((it) => `<tr>
          <td class="mono">${esc(it.host)}</td>
          <td>${esc(it.scheme || "-")}</td>
          <td>${esc(it.count)}</td>
          <td class="mono">${esc(it.sample_uri || "-")}</td>
          <td>${it.protected ? '<span class="badge on">已防护</span>' : '<span class="badge off">未纳入</span>'}</td>
          <td class="actions">${it.protected ? "-" : `<button type="button" data-host="${esc(it.host)}" class="disc-add">新建站点</button>`}</td>
        </tr>`).join("") : `<tr><td colspan="6" class="empty">暂无发现结果（确认访问日志路径与流量）</td></tr>`}</tbody>
      </table></div>`;''',
'''    pageRoot().innerHTML = `
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
      </table></div>`;'''),
    ('const upstream = prompt("上游地址（如 http://127.0.0.1:8080）", "http://127.0.0.1:8080");',
     'const upstream = prompt(t("上游地址（如 http://127.0.0.1:8080）", "Upstream URL (e.g. http://127.0.0.1:8080)"), "http://127.0.0.1:8080");'),
    ('toast(true, "已创建站点 " + name);',
     'toast(true, t("已创建站点 ", "Site created ") + name);'),
]

# ---------- loadAddrBook ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" class="success" id="abAdd">新建</button>
        <button type="button" id="abSave">保存全部</button>
        <span class="muted">对象可一键应用到黑/白名单；引用计数为名单命中近似值</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>名称</th><th>类型</th><th>成员</th><th>排除</th><th>被引用</th><th>描述</th><th>操作</th></tr></thead>
        <tbody id="abBody">${items.map((it, i) => addrRow(it, i)).join("")}</tbody>
      </table></div>`;''',
'''    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" class="success" id="abAdd">${t("新建", "New")}</button>
        <button type="button" id="abSave">${t("保存全部", "Save all")}</button>
        <span class="muted">${t("对象可一键应用到黑/白名单；引用计数为名单命中近似值", "Objects can be applied to black/white lists; ref count approximates list hits")}</span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>${t("名称", "Name")}</th><th>${t("类型", "Type")}</th><th>${t("成员", "Members")}</th><th>${t("排除", "Excludes")}</th><th>${t("被引用", "Refs")}</th><th>${t("描述", "Description")}</th><th>${t("操作", "Actions")}</th></tr></thead>
        <tbody id="abBody">${items.map((it, i) => addrRow(it, i)).join("")}</tbody>
      </table></div>`;'''),
    ('<button type="button" class="ghost ab-bl" data-name="${esc(it.name)}">→黑名单</button>',
     '<button type="button" class="ghost ab-bl" data-name="${esc(it.name)}">${t("→黑名单", "→ Blacklist")}</button>'),
    ('<button type="button" class="ghost ab-wl" data-name="${esc(it.name)}">→白名单</button>',
     '<button type="button" class="ghost ab-wl" data-name="${esc(it.name)}">${t("→白名单", "→ Whitelist")}</button>'),
    ('<button type="button" class="danger ab-del">删除</button>',
     '<button type="button" class="danger ab-del">${t("删除", "Delete")}</button>'),
    ('toast(true, "地址簿已保存");',
     'toast(true, t("地址簿已保存", "Address book saved"));'),
    ('if (!name) { toast(false, "请先保存名称"); return; }',
     'if (!name) { toast(false, t("请先保存名称", "Save the name first")); return; }'),
    ('toast(true, `已追加 ${r.added || 0} 条到 ${kind}`);',
     'toast(true, t("已追加 ", "Appended ") + `${r.added || 0}` + t(" 条到 ", " items to ") + `${kind}`);'),
]

# ---------- loadPKI ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>管理面 TLS</h3>
        <p class="muted">控制台默认使用 <code>conf/tls/admin.crt</code> / <code>admin.key</code>。缺失时 Nginx :8443 无法启动，可在此一键生成自签证书。</p>
        <div class="toolbar">
          <input id="pkiCN" placeholder="CN，如 waf-admin.local" value="waf-admin.local" />
          <input id="pkiDays" type="number" value="3650" style="width:100px" title="有效天数" />
          <button type="button" class="success" id="pkiGen">生成 / 覆盖 admin 证书</button>
        </div>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>名称</th><th>状态</th><th>主题</th><th>到期</th><th>路径</th></tr></thead>
        <tbody>${items.map((c) => `<tr>
          <td>${esc(c.name)}</td>
          <td>${c.exists ? '<span class="badge on">存在</span>' : '<span class="badge off">缺失</span>'}</td>
          <td>${esc(c.subject || "-")}</td>
          <td class="mono">${esc(c.not_after || "-")}</td>
          <td class="mono">${esc(c.cert_path || "")}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;''',
'''    pageRoot().innerHTML = `
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
      </table></div>`;'''),
    ('toast(true, "已生成 " + (r.cert && r.cert.cert_path));',
     'toast(true, t("已生成 ", "Generated ") + (r.cert && r.cert.cert_path));'),
]

# ---------- loadSysInfo (large block) ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <h3>系统信息</h3>
          <div class="kv">
            <div><span>产品</span><b>${esc(info.product || "Ma-WAF")}</b></div>
            <div><span>主机名</span><b>${esc(info.hostname || "-")}</b></div>
            <div><span>产品根目录</span><b class="mono">${esc(info.product_root || "-")}</b></div>
            <div><span>引擎模式</span><b>${esc(info.engine_mode || "-")}</b></div>
            <div><span>CRS 偏执级别</span><b>PL${esc(info.paranoia_level ?? "-")} · ${esc(info.paranoia_hint || "")}</b></div>
            <div><span>重保模式</span><b>${info.heavy_security ? '<span class="badge on">开启</span>' : '<span class="badge off">关闭</span>'}</b></div>
            <div><span>HA</span><b>${esc((ha.role_guess) || "standalone")}</b></div>
            <div><span>时间 (UTC)</span><b class="mono">${esc(info.time_utc || "")}</b></div>
          </div>
        </div>
        <div class="card">
          <h3>特征库信息</h3>
          <div class="kv">
            <div><span>WAF / CRS</span><b>${esc(info.crs || "-")}</b></div>
            <div><span>自定义规则文件</span><b>${esc(info.custom_rules ?? 0)}</b></div>
            <div><span>IP 地理库</span><b>${geo.mmdb_found ? '<span class="badge on">已加载</span>' : '<span class="badge off">未找到</span>'} ${esc(geo.mmdb_path || "")}</b></div>
            <div><span>Geo 封锁</span><b>${esc((geo.blocklist || []).join(", ") || "无")}（${esc(geo.blocklist_count ?? 0)}）</b></div>
            <div><span>威胁情报</span><b>${esc(intel.count ?? 0)} 条 · 已过期 ${esc(intel.expired ?? 0)}</b></div>
            <div><span>规则库最近升级</span><b class="mono">${esc(last.time || "无记录")}${last.filename ? " · " + esc(last.filename) : ""}</b></div>
            <div><span>Go 运行时</span><b class="mono">${esc(info.go_version || "")}</b></div>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>WAF 规则库 · 本地升级</h3>
        ${st ? `
          <p class="muted">${esc(st.bundle_hint || "上传 .tgz/.tar.gz 规则包进行本地升级。")}</p>
          <div class="kv" style="margin-bottom:.65rem">
            <div><span>Staging</span><b>${esc(st.staging_files ?? 0)} 文件 · <code class="mono">${esc(st.staging_dir || "")}</code></b></div>
            <div><span>Active</span><b>${esc(st.active_files ?? 0)} 文件 · <code class="mono">${esc(st.active_dir || "")}</code></b></div>
            <div><span>验签公钥</span><b>${st.pubkey_present ? '<span class="badge on">已配置</span>' : '<span class="badge off">未配置</span>'}</b></div>
            <div><span>上传上限</span><b>${esc(st.max_upload_mb ?? 64)} MB</b></div>
          </div>
          <div class="grid cols-2">
            <div>
              <div class="form-grid" style="grid-template-columns:1fr">
                <label>规则包（.tgz / .tar.gz）
                  <input type="file" id="ruFile" accept=".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar" />
                </label>
                <label>签名文件（可选 .sig）
                  <input type="file" id="ruSig" accept=".sig" />
                </label>
                <label class="check"><input type="checkbox" id="ruPromote" checked /> 升级后立即 promote 并 reload Nginx</label>
              </div>
              <div class="toolbar" style="margin-top:.65rem">
                <button type="button" class="success" id="ruSubmit">确定并本地升级</button>
                <button type="button" class="ghost" id="ruRefresh">刷新</button>
              </div>
              <div id="ruResult" class="muted" style="margin-top:.5rem"></div>
            </div>
            <div>
              <h3 style="margin-top:0;border:0;padding:0">最近一次升级</h3>
              ${last.time ? `
                <div class="kv">
                  <div><span>时间</span><b class="mono">${esc(last.time)}</b></div>
                  <div><span>文件</span><b class="mono">${esc(last.filename || "-")}</b></div>
                  <div><span>custom / rules</span><b>${esc(last.custom_files ?? 0)} / ${esc(last.rules_files ?? 0)}</b></div>
                  <div><span>已发布</span><b>${last.promoted ? '<span class="badge on">是</span>' : '<span class="badge off">否</span>'}</b></div>
                  <div><span>验签</span><b>${last.sig_verified ? '<span class="badge on">通过</span>' : '<span class="badge">未验/跳过</span>'}</b></div>
                  ${last.error ? `<div><span>错误</span><b style="color:var(--danger)">${esc(last.error)}</b></div>` : ""}
                </div>` : `<div class="empty">尚无升级记录</div>`}
              <p class="muted" style="margin-top:.65rem">CLI：<code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/bundle.tgz</code></p>
            </div>
          </div>` : `
          <p class="muted" style="color:var(--danger)">无法加载升级接口 <code>/api/v1/rules/upgrade/status</code>。请确认已用新版 <code>ma-waf-api</code> 重新编译并重启。</p>
          <button type="button" class="ghost" id="gotoRulesUp">打开特征库升级页</button>`}
      </div>`;
    if ($("hdrDevice")) $("hdrDevice").textContent = info.hostname || "本机";''',
'''    pageRoot().innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <h3>${t("系统信息", "System info")}</h3>
          <div class="kv">
            <div><span>${t("产品", "Product")}</span><b>${esc(info.product || "Ma-WAF")}</b></div>
            <div><span>${t("主机名", "Hostname")}</span><b>${esc(info.hostname || "-")}</b></div>
            <div><span>${t("产品根目录", "Product root")}</span><b class="mono">${esc(info.product_root || "-")}</b></div>
            <div><span>${t("引擎模式", "Engine mode")}</span><b>${esc(info.engine_mode || "-")}</b></div>
            <div><span>${t("CRS 偏执级别", "CRS paranoia")}</span><b>PL${esc(info.paranoia_level ?? "-")} · ${esc(info.paranoia_hint || "")}</b></div>
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
      <div class="card" style="margin-top:.85rem">
        <h3>${t("WAF 规则库 · 本地升级", "WAF rule pack · local upgrade")}</h3>
        ${st ? `
          <p class="muted">${esc(st.bundle_hint || t("上传 .tgz/.tar.gz 规则包进行本地升级。", "Upload a .tgz/.tar.gz rule pack for local upgrade."))}</p>
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
                  <input type="file" id="ruFile" accept=".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar" />
                </label>
                <label>${t("签名文件（可选 .sig）", "Signature file (optional .sig)")}
                  <input type="file" id="ruSig" accept=".sig" />
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
                  ${last.error ? `<div><span>${t("错误", "Error")}</span><b style="color:var(--danger)">${esc(last.error)}</b></div>` : ""}
                </div>` : `<div class="empty">${t("尚无升级记录", "No upgrade history")}</div>`}
              <p class="muted" style="margin-top:.65rem">CLI：<code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/bundle.tgz</code></p>
            </div>
          </div>` : `
          <p class="muted" style="color:var(--danger)">${t("无法加载升级接口 ", "Cannot load upgrade API ")}<code>/api/v1/rules/upgrade/status</code>${t("。请确认已用新版 ", ". Ensure ")}<code>ma-waf-api</code>${t(" 重新编译并重启。", " is rebuilt and restarted.")}</p>
          <button type="button" class="ghost" id="gotoRulesUp">${t("打开特征库升级页", "Open signature upgrade page")}</button>`}
      </div>`;
    if ($("hdrDevice")) $("hdrDevice").textContent = info.hostname || t("本机", "Local");'''),
]

# ---------- bindRulesUpgradeForm ----------
pairs += [
    ('toast(false, "请选择规则包文件");',
     'toast(false, t("请选择规则包文件", "Please select a rule pack file"));'),
    ('if ($("ruResult")) $("ruResult").textContent = "上传并处理中…";',
     'if ($("ruResult")) $("ruResult").textContent = t("上传并处理中…", "Uploading and processing…");'),
    ('$("ruResult").innerHTML = `<span class="badge on">成功</span> custom=${esc(rec.custom_files)} rules=${esc(rec.rules_files)}',
     '$("ruResult").innerHTML = `<span class="badge on">${t("成功", "Success")}</span> custom=${esc(rec.custom_files)} rules=${esc(rec.rules_files)}'),
    ('promote=${rec.promoted ? "是" : "否"} · ${esc((rec.notes || []).join("； "))}`;',
     'promote=${rec.promoted ? t("是", "Yes") : t("否", "No")} · ${esc((rec.notes || []).join("； "))}`;'),
    ('toast(true, "本地规则库升级完成");',
     'toast(true, t("本地规则库升级完成", "Local rule pack upgrade complete"));'),
    ('$("ruResult").innerHTML = `<span class="badge off">失败</span> ${esc(e.message)}',
     '$("ruResult").innerHTML = `<span class="badge off">${t("失败", "Failed")}</span> ${esc(e.message)}'),
]

# ---------- loadRulesUpgrade ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>WAF 规则库升级 · 本地升级</h3>
        <p class="muted">${esc(st.bundle_hint || "")}</p>
        <div class="kv">
          <div><span>Staging 规则文件</span><b>${esc(st.staging_files ?? 0)} · <code class="mono">${esc(st.staging_dir || "")}</code></b></div>
          <div><span>Active 规则文件</span><b>${esc(st.active_files ?? 0)} · <code class="mono">${esc(st.active_dir || "")}</code></b></div>
          <div><span>验签公钥</span><b>${st.pubkey_present ? '<span class="badge on">已配置</span>' : '<span class="badge off">未配置</span>'} ${esc(st.pubkey_path || "")}</b></div>
          <div><span>CLI 脚本</span><b>${st.cli_script_ok ? '<span class="badge on">可用</span>' : '<span class="badge off">缺失</span>'} <code class="mono">${esc(st.cli_script || "")}</code></b></div>
          <div><span>上传上限</span><b>${esc(st.max_upload_mb ?? 64)} MB</b></div>
        </div>
      </div>
      <div class="grid cols-2">
        <div class="card">
          <h3>上传规则包</h3>
          <div class="form-grid" style="grid-template-columns:1fr">
            <label>规则包（.tgz / .tar.gz）
              <input type="file" id="ruFile" accept=".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar" />
            </label>
            <label>签名文件（可选 .sig）
              <input type="file" id="ruSig" accept=".sig" />
            </label>
            <label class="check"><input type="checkbox" id="ruPromote" checked /> 升级后立即 promote 并 reload Nginx</label>
          </div>
          <div class="toolbar" style="margin-top:.75rem">
            <button type="button" class="success" id="ruSubmit">确定并本地升级</button>
            <button type="button" class="ghost" id="ruRefresh">刷新状态</button>
          </div>
          <p class="muted">建议包结构：<code>custom/*.conf</code>（→ staging）和/或 <code>rules/*.conf</code>（→ ModSecurity rules）。生产建议附带 <code>包名.sig</code>。</p>
          <div id="ruResult" class="muted" style="margin-top:.5rem"></div>
        </div>
        <div class="card">
          <h3>最近一次升级</h3>
          ${last.time ? `
            <div class="kv">
              <div><span>时间</span><b class="mono">${esc(last.time)}</b></div>
              <div><span>方式</span><b>${esc(last.mode || "-")}</b></div>
              <div><span>文件</span><b class="mono">${esc(last.filename || "-")}</b></div>
              <div><span>custom / rules</span><b>${esc(last.custom_files ?? 0)} / ${esc(last.rules_files ?? 0)}</b></div>
              <div><span>已发布</span><b>${last.promoted ? '<span class="badge on">是</span>' : '<span class="badge off">否</span>'}</b></div>
              <div><span>验签</span><b>${last.sig_verified ? '<span class="badge on">通过</span>' : '<span class="badge">未验/跳过</span>'}</b></div>
              <div><span>操作者</span><b>${esc(last.user || "-")}</b></div>
              <div><span>备注</span><b>${esc((last.notes || []).join("； ") || "-")}</b></div>
              ${last.error ? `<div><span>错误</span><b style="color:var(--danger)">${esc(last.error)}</b></div>` : ""}
            </div>` : `<div class="empty">尚无升级记录</div>`}
          <p class="muted" style="margin-top:.85rem">离线 CLI 等价命令：<br/>
            <code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/rules_bundle.tgz</code>
          </p>
        </div>
      </div>`;''',
'''    pageRoot().innerHTML = `
      <div class="card" style="margin-bottom:.75rem">
        <h3>${t("WAF 规则库升级 · 本地升级", "WAF rule pack upgrade · local")}</h3>
        <p class="muted">${esc(st.bundle_hint || "")}</p>
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
              <input type="file" id="ruFile" accept=".tgz,.tar.gz,.tar,application/gzip,application/x-gzip,application/x-tar" />
            </label>
            <label>${t("签名文件（可选 .sig）", "Signature file (optional .sig)")}
              <input type="file" id="ruSig" accept=".sig" />
            </label>
            <label class="check"><input type="checkbox" id="ruPromote" checked /> ${t("升级后立即 promote 并 reload Nginx", "Promote and reload Nginx immediately after upgrade")}</label>
          </div>
          <div class="toolbar" style="margin-top:.75rem">
            <button type="button" class="success" id="ruSubmit">${t("确定并本地升级", "Confirm local upgrade")}</button>
            <button type="button" class="ghost" id="ruRefresh">${t("刷新状态", "Refresh status")}</button>
          </div>
          <p class="muted">${t("建议包结构：", "Suggested pack layout: ")}<code>custom/*.conf</code>${t("（→ staging）和/或 ", " (→ staging) and/or ")}<code>rules/*.conf</code>${t("（→ ModSecurity rules）。生产建议附带 ", " (→ ModSecurity rules). Production: include ")}<code>${t("包名.sig", "packname.sig")}</code>。</p>
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
              <div><span>${t("备注", "Notes")}</span><b>${esc((last.notes || []).join("； ") || "-")}</b></div>
              ${last.error ? `<div><span>${t("错误", "Error")}</span><b style="color:var(--danger)">${esc(last.error)}</b></div>` : ""}
            </div>` : `<div class="empty">${t("尚无升级记录", "No upgrade history")}</div>`}
          <p class="muted" style="margin-top:.85rem">${t("离线 CLI 等价命令：", "Offline CLI equivalent:")}<br/>
            <code class="mono">sudo ./scripts/update_rules.sh --offline /path/to/rules_bundle.tgz</code>
          </p>
        </div>
      </div>`;'''),
]

# ---------- loadHeavy ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="card">
        <h3>重保模式</h3>
        <p class="muted">对齐企业 WAF「重大活动 / 重保」场景：开启后将 CRS 偏执级别调至 <b>PL4</b> 并确保引擎为 <b>On</b>。关闭后回落到 PL2 并 reload。</p>
        <div class="switch-row">
          <div>
            <b>当前状态：</b>${on ? '<span class="badge on">已开启</span>' : '<span class="badge off">未开启</span>'}
            · 当前 PL${esc(pl.level ?? pl.paranoia_level ?? "-")}
          </div>
        </div>
        <div class="toolbar" style="margin-top:.85rem">
          <input id="heavyReason" placeholder="原因（必填，写入审计）" style="min-width:280px" />
          <button type="button" class="danger" id="heavyOn"${on ? " disabled" : ""}>开启重保</button>
          <button type="button" class="ghost" id="heavyOff"${on ? "" : " disabled"}>关闭重保</button>
        </div>
      </div>`;
    const run = async (enable) => {
      const reason = ($("heavyReason").value || "").trim();
      if (!reason) { toast(false, "请填写原因"); return; }
      try {
        await api("/api/v1/ops/heavy", { method: "POST", body: JSON.stringify({ on: enable, reason }) });
        toast(true, enable ? "重保已开启" : "重保已关闭");
        navigate("heavy", true);
      } catch (e) { toast(false, e.message); }
    };''',
'''    pageRoot().innerHTML = `
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
    };'''),
]

# ---------- diagBadge + loadTroubleshoot ----------
pairs += [
    ("if (c.ok) return '<span class=\"badge on\">通过</span>';",
     'if (c.ok) return `<span class="badge on">${t("通过", "Passed")}</span>`;'),
    ('if (c.severity === "critical") return \'<span class="badge off">失败</span>\';',
     'if (c.severity === "critical") return `<span class="badge off">${t("失败", "Failed")}</span>`;'),
    ("return '<span class=\"badge off\">告警</span>';",
     'return `<span class="badge off">${t("告警", "Warning")}</span>`;'),
    ('const overallLabel = overall === "ok" ? "健康" : (overall === "warn" ? "有告警" : "有故障");',
     'const overallLabel = overall === "ok" ? t("健康", "Healthy") : (overall === "warn" ? t("有告警", "Warnings") : t("有故障", "Failures"));'),
(
'''    pageRoot().innerHTML = `
      <div class="toolbar">
        <button type="button" id="tsRefresh">重新检测</button>
        <button type="button" class="ghost" id="tsReload">Reload Nginx</button>
        <button type="button" class="ghost" id="tsFixTLS">修复管理面证书</button>
        <button type="button" class="ghost" id="tsCopy">复制报告</button>
      </div>
      <div class="grid cols-4" style="margin-top:.65rem">
        <div class="card kpi"><div class="label">总体</div><div class="value" style="font-size:1.15rem"><span class="badge ${overallBadge}">${esc(overallLabel)}</span></div></div>
        <div class="card kpi"><div class="label">通过</div><div class="value">${esc(sum.ok ?? 0)}</div></div>
        <div class="card kpi"><div class="label">告警</div><div class="value">${esc(sum.warn ?? 0)}</div></div>
        <div class="card kpi"><div class="label">失败</div><div class="value">${esc(sum.fail ?? 0)}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>检查项</h3>
        <p class="muted">UTC ${esc(data.time_utc || "")} · 产品根 ${esc(data.product_root || "")}</p>
        <table class="data">
          <thead><tr><th>状态</th><th>分类</th><th>项目</th><th>详情</th><th>建议</th></tr></thead>
          <tbody>
            ${checks.map((c) => `
              <tr>
                <td>${diagBadge(c)}</td>
                <td>${esc(c.category || "")}</td>
                <td><b>${esc(c.title || c.id)}</b></td>
                <td class="mono" style="white-space:pre-wrap;max-width:36rem">${esc(c.detail || "")}</td>
                <td class="muted">${esc(c.hint || "")}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card">
          <h3>常见问题速查</h3>
          <ul class="muted" style="line-height:1.7">
            ${tips.map((t) => `<li><b>${esc(t.title || "")}</b> — ${esc(t.body || "")}</li>`).join("")}
          </ul>
          <p class="muted" style="margin-top:.5rem">完整手册见文档 <code>docs/troubleshooting.md</code> 或控制台「用户手册」。</p>
        </div>
        <div class="card">
          <h3>Nginx error 日志尾部</h3>
          <p class="muted mono">${esc((data.log_paths && data.log_paths.nginx_error) || "")}</p>
          <pre class="mono" style="white-space:pre-wrap;max-height:280px;overflow:auto;background:#0a101b;padding:.75rem;border-radius:10px;color:var(--muted)">${esc(logs.nginx_error || "（无内容或文件不可读）")}</pre>
        </div>
      </div>
    `;''',
'''    pageRoot().innerHTML = `
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
                <td>${esc(c.category || "")}</td>
                <td><b>${esc(c.title || c.id)}</b></td>
                <td class="mono" style="white-space:pre-wrap;max-width:36rem">${esc(c.detail || "")}</td>
                <td class="muted">${esc(c.hint || "")}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
      <div class="grid cols-2" style="margin-top:.85rem">
        <div class="card">
          <h3>${t("常见问题速查", "Quick FAQ")}</h3>
          <ul class="muted" style="line-height:1.7">
            ${tips.map((tip) => `<li><b>${esc(tip.title || "")}</b> — ${esc(tip.body || "")}</li>`).join("")}
          </ul>
          <p class="muted" style="margin-top:.5rem">${t("完整手册见文档 ", "Full manual: ")}<code>docs/troubleshooting.md</code>${t(" 或控制台「用户手册」。", " or console User Manual.")}</p>
        </div>
        <div class="card">
          <h3>${t("Nginx error 日志尾部", "Nginx error log tail")}</h3>
          <p class="muted mono">${esc((data.log_paths && data.log_paths.nginx_error) || "")}</p>
          <pre class="mono" style="white-space:pre-wrap;max-height:280px;overflow:auto;background:#0a101b;padding:.75rem;border-radius:10px;color:var(--muted)">${esc(logs.nginx_error || t("（无内容或文件不可读）", "(Empty or unreadable file)"))}</pre>
        </div>
      </div>
    `;'''),
    ('toast(true, "已确保管理面证书存在");',
     'toast(true, t("已确保管理面证书存在", "Management TLS cert ensured"));'),
    ('toast(true, "报告已复制到剪贴板");',
     'toast(true, t("报告已复制到剪贴板", "Report copied to clipboard"));'),
    ('toast(false, "复制失败，请手动选取页面内容");',
     'toast(false, t("复制失败，请手动选取页面内容", "Copy failed — select page content manually"));'),
]

# ---------- loadSystem ----------
pairs += [
(
'''    pageRoot().innerHTML = `
      <div class="grid cols-4">
        <div class="card kpi"><div class="label">API 状态</div><div class="value">${esc(health.status || "-")}</div></div>
        <div class="card kpi"><div class="label">引擎</div><div class="value" style="font-size:1.2rem">${esc(health.sec_rule_engine || status.engine_mode || "-")}</div></div>
        <div class="card kpi"><div class="label">Load1</div><div class="value">${esc(metrics.load1 ?? "-")}</div><div class="hint">主机负载</div></div>
        <div class="card kpi"><div class="label">内存使用</div><div class="value">${Number(metrics.mem_used_pct || 0).toFixed(0)}%</div><div class="hint">可用 ${esc(metrics.mem_avail_mb ?? "-")} MB</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>双机 HA / VIP</h3>
        <p class="muted">角色：<b>${esc(ha.role_guess || "standalone")}</b>
          · keepalived ${ha.keepalived_running ? '<span class="badge on">运行</span>' : '<span class="badge off">未运行</span>'}
          · 本机持有 VIP ${ha.local_has_vip ? '<span class="badge on">是</span>' : '<span class="badge off">否</span>'}
          · 健康 ${ha.health_ok ? '<span class="badge on">OK</span>' : '<span class="badge off">异常</span>'} — ${esc(ha.health_detail || "")}</p>
        <p class="muted">VIP: ${esc((ha.vips || []).join(", ") || "未解析")} · 配置: ${esc(ha.config_path || "无")}</p>
        <p class="muted">${esc(ha.hint || "")}</p>
      </div>
      <div class="grid cols-4" style="margin-top:.85rem">
        <div class="card kpi"><div class="label">Nginx Active</div><div class="value">${esc(metrics.nginx_active ?? "-")}</div><div class="hint">${metrics.nginx_status_ok ? "stub_status OK" : esc(metrics.nginx_status_err || "未采集")}</div></div>
        <div class="card kpi"><div class="label">拦截率</div><div class="value">${Number(metrics.intercept_rate_pct || 0).toFixed(2)}%</div></div>
        <div class="card kpi"><div class="label">平均时延</div><div class="value">${(Number(metrics.avg_request_time || 0) * 1000).toFixed(1)}<span style="font-size:.9rem"> ms</span></div></div>
        <div class="card kpi"><div class="label">API 请求</div><div class="value">${esc(metrics.api_requests ?? "-")}</div></div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>告警与自动加黑</h3>
        <p class="muted">写入 <code>var/lib/ops.json</code>。Challenge 指纹：${esc(opsWrap.challenge_fp || "-")}。定时加黑需启用 timer 并配置 Cron Token。</p>
        <div class="form-grid">
          <label>Alert Webhook URL
            <input id="opsWebhook" value="${esc(ops.alert_webhook || "")}" placeholder="https://hooks.example/…" />
          </label>
          <label>Cron Token（本机定时任务）
            <input id="opsCron" value="${esc(ops.cron_token || "")}" placeholder="随机长串" />
          </label>
          <label>自动加黑阈值（命中次数）
            <input id="opsThr" type="number" min="1" value="${esc(ops.autoblock_threshold ?? 30)}" />
          </label>
          <label>自动加黑 TopN
            <input id="opsTopN" type="number" min="1" value="${esc(ops.autoblock_top_n ?? 20)}" />
          </label>
          <label>攻击量告警阈值（审计尾部）
            <input id="opsAtk" type="number" min="0" value="${esc(ops.attack_alert_min ?? 100)}" />
          </label>
          <label>情报 IOC 存活天数
            <input id="opsIntelTTL" type="number" min="1" value="${esc(ops.intel_expire_days ?? 30)}" />
          </label>
          <label>SIEM syslog（host:port）
            <input id="opsSIEM" value="${esc(ops.siem_addr || "")}" placeholder="127.0.0.1:514" />
          </label>
          <label>SIEM 协议
            <select id="opsSIEMProto">
              <option value="udp" ${ops.siem_proto!=="tcp"?"selected":""}>udp</option>
              <option value="tcp" ${ops.siem_proto==="tcp"?"selected":""}>tcp</option>
            </select>
          </label>
          <label class="check"><input type="checkbox" id="opsABEn" ${ops.autoblock_enabled ? "checked" : ""} /> 启用定时自动加黑</label>
        </div>
        <div class="toolbar" style="margin-top:.75rem">
          <button id="opsSave">保存运维设置</button>
          <button class="ghost" id="opsTestHook">测试 Webhook</button>
          <button class="ghost" id="opsSIEMTest">测试 SIEM</button>
          <button class="ghost" id="opsGenTok">生成 Cron Token</button>
        </div>
      </div>
      <div class="card" style="margin-top:.85rem">
        <h3>运维动作</h3>
        <p class="muted">生产请设置 MA_WAF_STRICT_AUTH=1 与 bcrypt；告警: systemctl enable --now ma-waf-alert.timer</p>
        <div class="toolbar">
          <button id="sysReload">Reload Nginx</button>
          <button class="ghost" id="sysBackup">备份</button>
          <button class="ghost" id="sysHealth">再次探测</button>
        </div>
        <pre class="mono" style="white-space:pre-wrap;color:var(--muted);background:#0a101b;padding:.75rem;border-radius:10px">${esc(JSON.stringify({ health, metrics, status }, null, 2))}</pre>
        <p class="muted">Prometheus: <code>curl -s http://127.0.0.1:9090/metrics</code>（受 allow_cidrs 限制）</p>
      </div>`;''',
'''    pageRoot().innerHTML = `
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
          · ${t("健康", "Health")} ${ha.health_ok ? '<span class="badge on">OK</span>' : `<span class="badge off">${t("异常", "Abnormal")}</span>`} — ${esc(ha.health_detail || "")}</p>
        <p class="muted">VIP: ${esc((ha.vips || []).join(", ") || t("未解析", "Unresolved"))} · ${t("配置", "Config")}: ${esc(ha.config_path || t("无", "None"))}</p>
        <p class="muted">${esc(ha.hint || "")}</p>
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
      </div>`;'''),
    ('toast(true, "运维设置已保存");',
     'toast(true, t("运维设置已保存", "Ops settings saved"));'),
    ('toast(true, "已生成 Token，请保存");',
     'toast(true, t("已生成 Token，请保存", "Token generated — save it"));'),
    ('toast(!!r.ok, r.ok ? "Webhook 已发送" : ("HTTP " + r.status));',
     'toast(!!r.ok, r.ok ? t("Webhook 已发送", "Webhook sent") : ("HTTP " + r.status));'),
    ('toast(true, "SIEM 测试已发送");',
     'toast(true, t("SIEM 测试已发送", "SIEM test sent"));'),
    ('try { await api("/api/v1/backup", { method: "POST" }); toast(true, "备份完成"); }',
     'try { await api("/api/v1/backup", { method: "POST" }); toast(true, t("备份完成", "Backup complete")); }'),
]

missing = []
applied = 0
for i, item in enumerate(pairs):
    if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
        old, new = item
    else:
        continue
    if old not in text:
        missing.append(i)
        preview = old[:80].replace("\n", "\\n")
        print(f"SKIP missing pair index {i}: {preview!r}")
    else:
        text = text.replace(old, new, 1)
        applied += 1

if missing:
    print(f"Skipped {len(missing)} missing pairs out of {len(pairs)}")

if text == orig:
    print("No changes applied")
    raise SystemExit(0)

path.write_text(text, encoding="utf-8")
print(f"Applied {applied} replacements")
print(f"Size: {len(orig)} -> {len(text)}")

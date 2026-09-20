# Ma-WAF 全功能测试文档

| 项目 | 说明 |
|------|------|
| 产品 | Ma-WAF（Nginx 1.24 + ModSecurity 3 + OWASP CRS 4.x） |
| 文档版本 | 1.0 |
| 适用版本 | 与本仓库当前 `docs/capability-matrix.md` 对齐 |
| 测试目标 | 验证数据面防护、管理 API、Web 控制台、运维脚本及扩展能力均可交付使用 |
| 参考 | `docs/capability-matrix.md`、`scripts/test_waf_features.sh`、`scripts/verify_waf.sh` |

---

## 1. 测试说明

### 1.1 测试环境建议

| 角色 | 要求 |
|------|------|
| WAF 节点 | Rocky Linux 8.9/9.x 或 openEuler 22.03；已执行 `deploy.sh` + CRS |
| 受保护站点 | 可用上游（本机 mock、内网业务或经 Hosts 牵引的测试站） |
| 管理端 | 浏览器访问 `https://<WAF_IP>:8443/`；默认真机账号按现场配置 |
| 攻击/客户端 | Win10 / curl / 本机脚本；**仅对授权资产测试** |
| 网络 | 客户端能访问 WAF:80/443；WAF 能访问上游；管理口 8443 |

### 1.2 前置条件清单（全部通过后再测功能）

| # | 检查项 | 命令 / 操作 | 期望 |
|---|--------|-------------|------|
| P1 | 运行时 API 配置存在 | `ls /usr/local/Ma-waf/conf/api.yaml` | 存在（模板在 `configs/templates`，不在 conf） |
| P2 | 服务运行 | `systemctl is-active nginx ma-waf-api` | active |
| P3 | 配置语法 | `/usr/local/nginx/sbin/nginx -t` | successful |
| P4 | CRS 已安装 | `ls /usr/local/nginx/conf/modsecurity/rules/*.conf \| wc -l` | ≥20，且含 `REQUEST-901` |
| P5 | CRS setup 版本 | `grep crs_setup_version .../crs-setup.conf` | 含 `tx.crs_setup_version`（避免 901001→500） |
| P6 | 数据面健康 | `curl -s http://127.0.0.1/waf-health` | JSON ok |
| P7 | 管理面健康 | `curl -sk https://127.0.0.1:8443/api/v1/health` | 200 |
| P8 | 审计可写 | `ls -la /data/logs/nginx/modsec_audit.json` | nginx 可写 |
| P9 | 完整性基线（可选） | `python3 .../integrity_check.py --init` | 基线文件存在 |

缺失 `conf/api.yaml` 时：

```bash
sudo /usr/local/Ma-waf/scripts/init_api_config.sh
```

### 1.3 判定标准

| 结果 | 含义 |
|------|------|
| **通过** | 实际结果与期望一致 |
| **失败** | 功能不可用或结果错误 |
| **阻塞** | 因环境/依赖未满足无法测（如未装 GeoIP2） |
| **不适用** | 本环境明确不部署该项（如双机 HA） |

### 1.4 自动化冒烟（建议每次构建后先跑）

```bash
# 完整性
sudo /usr/local/Ma-waf/scripts/verify_waf.sh

# 功能可用性（只读 + 基础探针）
sudo /usr/local/Ma-waf/scripts/test_waf_features.sh

# 加强攻击探针 + 限流观察
sudo /usr/local/Ma-waf/scripts/test_waf_features.sh --attack

# 含可回滚写操作（备份/校验等）
sudo /usr/local/Ma-waf/scripts/test_waf_features.sh --write --json
```

日志：`/usr/local/Ma-waf/var/log/test_waf_features.log`

---

## 2. 测试用例总览

| 模块 | 用例编号范围 | 优先级 |
|------|--------------|--------|
| 安装部署与运维脚本 | T-DEP-xxx | P0 |
| 数据面基础与反向代理 | T-DP-xxx | P0 |
| OWASP CRS / 引擎模式 | T-CRS-xxx | P0 |
| 自定义防护包（上传/PII/Bot/虚补/会话/协议） | T-PACK-xxx | P0 |
| CC 限流与连接限制 | T-CC-xxx | P0 |
| Bot / JS Challenge / 善意 Bot | T-BOT-xxx | P1 |
| IP / Geo / 威胁情报 / 自动加黑 | T-IP-xxx | P1 |
| 站点 / 画像 / API 防护 / OpenAPI | T-SITE-xxx | P0 |
| 例外与误报 | T-EXC-xxx | P0 |
| 安全事件 / 审计 / 报表 / 洞察 | T-EVT-xxx | P0 |
| 规则管理 / 虚补 / 特征库升级 | T-RULE-xxx | P1 |
| 管理认证 / License / PKI | T-MGMT-xxx | P0 |
| 紧急旁路 / 重保 / 上线清单 | T-OPS-xxx | P1 |
| 告警 / SIEM / 指标 / HA | T-MON-xxx | P1 |
| 控制台与系统页 | T-UI-xxx | P1 |
| 自身安全与加固 | T-SEC-xxx | P1 |

---

## 3. 安装部署与运维脚本（T-DEP）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-DEP-001 | 一键部署 | `sudo ./scripts/deploy.sh` 或 `--skip-build` | 目录、systemd、nginx 配置就位；生成 `conf/api.yaml` |
| T-DEP-002 | CRS 安装 | `sudo scripts/install_crs.sh` | rules 目录规则数正常；无纯 placeholder |
| T-DEP-003 | API 配置初始化 | 删除后执行 `init_api_config.sh` | 重新生成 `conf/api.yaml`，API 可启动 |
| T-DEP-004 | 安装管理 API | `scripts/install_api.sh` | `/usr/local/Ma-waf/bin/ma-waf-api` 可执行；缺 api.yaml 时自动生成 |
| T-DEP-005 | 控制台同步 | `scripts/sync_console.sh` | `share/console` 更新；8443 可打开 |
| T-DEP-006 | waf_ctl 状态 | `waf_ctl.sh status` | 显示引擎模式、健康信息 |
| T-DEP-007 | 模式切换 | `waf_ctl.sh mode DetectionOnly` → `On` → `Off` → 恢复 | `SecRuleEngine` 与预期一致且 reload 成功 |
| T-DEP-008 | verify_waf | `verify_waf.sh` | 进程/CRS/权限等检查有明确 OK/FAIL |
| T-DEP-009 | fix_runtime | `fix_runtime.sh` | 证书/目录/控制台修复后服务可用 |
| T-DEP-010 | OS 加固（可选） | `harden_os.sh`（测试机） | sysctl/ssh 等按脚本执行；业务面仍可访问 |
| T-DEP-011 | logrotate | 检查 `/etc/logrotate.d/ma-waf` | 模板已安装 |
| T-DEP-012 | 更新不丢 conf | 同步代码时排除 `conf/` `var/` `backups/` | 更新后 `api.yaml` 仍在 |

---

## 4. 数据面基础与反向代理（T-DP）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-DP-001 | 健康检查 | `GET /waf-health` | 200 + JSON status ok（绕过重防护逻辑） |
| T-DP-002 | 正常业务转发 | 浏览器访问站点首页/静态资源 | 200/301/302；页面内容来自上游 |
| T-DP-003 | Host 匹配 | 配置 `server_name`，用正确 Host 访问 | 命中对应 `site-*.conf` |
| T-DP-004 | HTTPS 上游 | upstream=`https://...`，含 SNI（`proxy_ssl_server_name`） | 无 SSL handshake failure；非 502 |
| T-DP-005 | 上游故障页 | 停上游或错误 upstream | 502/503/504 → `waf-upstream.html` |
| T-DP-006 | 拦截页 | 触发 403 规则 | `waf-block.html`（中文「请求已被安全策略拦截」） |
| T-DP-007 | 限流页 | 触发 429 | `waf-ratelimit.html` |
| T-DP-008 | 英文拦截页 | 访问 `/waf-block.en.html` | 英文文案 |
| T-DP-009 | 安全响应头 | 站点启用 CSP | 响应含 CSP / X-Frame-Options 等 |
| T-DP-010 | X-Request-ID | 任意业务请求 | 响应头含 Request-ID；可与日志关联 |
| T-DP-011 | 静态资源旁路 | 请求 `.css/.js/.png` | ModSecurity off 路径生效，性能路径正确 |
| T-DP-012 | IPv4 优先（Cloudflare 等） | 上游解析含 AAAA 时 | 无 `No route to host`（gai.conf 或钉 IPv4） |

---

## 5. OWASP CRS 与引擎模式（T-CRS）

> **仅对授权测试目标发送探针。** 下列 payload 为常见检测样例，用于验证拦截与审计，禁止用于未授权扫描。

| ID | 功能点 | 步骤 | 期望结果（引擎 On） |
|----|--------|------|---------------------|
| T-CRS-001 | 引擎 On | 控制台或 `waf_ctl.sh mode On` | 恶意请求拦截；审计有记录 |
| T-CRS-002 | DetectionOnly | 切 DetectionOnly 后发 SQLi 样例 | **不拦截**（或非 403），但审计应有命中 |
| T-CRS-003 | 引擎 Off | mode Off | 探针放行；相当于旁路 |
| T-CRS-004 | SQLi | `GET /?id=1'%20OR%20'1'%3D'1` | 403/406；规则 ID 含 942xxx 等 |
| T-CRS-005 | XSS | `GET /?q=<script>alert(1)</script>` | 403；规则含 941xxx |
| T-CRS-006 | 路径穿越 | `GET /../../etc/passwd` | 403；规则含 930xxx 等 |
| T-CRS-007 | CRS setup | 确认无 901001 | 不再出现「CRS is deployed without configuration」→500 |
| T-CRS-008 | 偏执级 PL1–4 | 控制台/API `/crs/paranoia` 切换 | 配置生效；更高 PL 更严（误报可能增加） |
| T-CRS-009 | 规则热加载 | staging 改规则 → validate → 激活 → reload | 新规则生效；失败可回滚 |
| T-CRS-010 | 规则启停/优先级 | 控制台对规则 META 禁用某 ID | 对应攻击不再被该规则拦（或降级） |

样例 curl（Host 换成实际站点）：

```bash
curl -sS -o /dev/null -w "%{http_code}\n" -H "Host: www.example.com" \
  -A "Mozilla/5.0" "http://127.0.0.1/?id=1'%20OR%20'1'%3D'1"
```

---

## 6. 自定义防护包（T-PACK）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-PACK-001 | 防护包列表 | API/控制台 `/packs` | 列出 custom 规则包 |
| T-PACK-002 | 包启停 | 关闭某 pack 后重放对应攻击 | 行为随启停变化 |
| T-PACK-003 | 危险上传扩展名 | 上传 `.php` / 双扩展名 | 403；规则 110001/110002 |
| T-PACK-004 | 上传内容 | 上传含 `<?php` 的文件内容 | 403；110003 |
| T-PACK-005 | 上传大小 | 超过策略上限 | 403；110004 或 content-policy |
| T-PACK-006 | PII | 按 content-policy 配置审计/拦截样例 | 命中 PII 规则；控制台可配 |
| T-PACK-007 | 已知坏 Bot UA | UA=`sqlmap` / `nikto` | 403（规则或 nginx map） |
| T-PACK-008 | 虚拟补丁 JNDI | 请求含 `${jndi:ldap://...}` | 403；虚补规则 |
| T-PACK-009 | 会话/Cookie | 异常 Cookie（按 110300 策略） | 拦截或审计 |
| T-PACK-010 | ATO 登录限速 | 对 `/login` 短时间大量 POST | 429/403；洞察可见 ATO 标签 |
| T-PACK-011 | TRACE/TRACK | `TRACE /` | 405；协议规则 |
| T-PACK-012 | 自定义规则创建 | 控制台创建 140000 段规则 | reload 后命中 |

---

## 7. CC 限流与连接限制（T-CC）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-CC-001 | 全局限流 | 短时间高频请求同一 URI | 出现 429 |
| T-CC-002 | 站点 burst | 编辑站点 `burst_per_ip` 调低后压测 | 更容易触发 429 |
| T-CC-003 | 连接数限制 | 大量并发连接 | `limit_conn` 生效（429/503 类） |
| T-CC-004 | API 前缀更严限流 | 启用 API Protect 后压 `/api/` | API 路径更易限流 |

```bash
# 简单限流观察（次数可按站点 burst 调整）
for i in $(seq 1 40); do
  curl -sS -o /dev/null -w "%{http_code} " -H "Host: www.example.com" "http://127.0.0.1/?cc=$i"
done; echo
```

---

## 8. Bot / JS Challenge（T-BOT）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-BOT-001 | 软 Bot 挑战 | 站点开启 JS Challenge；`curl` 无 Cookie 访问 | 302 → `/waf-challenge.html` |
| T-BOT-002 | 挑战签发 | `POST /waf-challenge/issue` 或控制台相关 | 返回 Cookie / token |
| T-BOT-003 | 浏览器通过挑战 | 正常 Chrome 完成挑战 | 可继续访问业务 |
| T-BOT-004 | HMAC 硬校验 | 站点启用 challenge auth（需 auth_request 模块） | 无有效 Cookie → 401→挑战页 |
| T-BOT-005 | 善意 Bot | 配置 Googlebot 等 UA 到善意名单 | 不被挑战、不被坏 Bot 误杀 |
| T-BOT-006 | 坏 Bot 直接拦 | UA 含 sqlmap 等 | 403，可不进挑战流 |

---

## 9. IP / Geo / 威胁情报 / 自动加黑（T-IP）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-IP-001 | 黑名单 | 将测试客户端 IP 加入黑名单并 reload | 该 IP 访问 → 403；**可能无 ModSec 审计**（nginx 层） |
| T-IP-002 | 白名单 | 白名单 IP | 可配置绕过部分检测（按策略） |
| T-IP-003 | 地址簿 | 创建地址对象并应用到黑/白名单 | 引用生效；计数合理 |
| T-IP-004 | Geo 封锁列表 | `/geo/blocklist` 配置国家码 | 列表可读写 |
| T-IP-005 | Geo 执法 | 安装 MMDB + geoip2 后 `/geo/enforce`，站点开 Geo | 目标国家被拦；未装模块则阻塞/提示 |
| T-IP-006 | Geo 状态 | `/geo/status` | 显示模块/MMDB 就绪状态 |
| T-IP-007 | 威胁情报粘贴合并 | 控制台合并 IOC → 黑名单 | IP 进入黑名单 |
| T-IP-008 | 情报 URL 拉取 | `/threat-intel/fetch`（测试 URL） | 拉取成功或明确失败原因 |
| T-IP-009 | 情报 TTL 过期 | `/threat-intel/expire` 或 cron | 过期 IOC 清理 |
| T-IP-010 | 攻击源自动加黑 | `/autoblock` TopN + 可选 cron | 高频攻击 IP 进入黑名单 |
| T-IP-011 | update_threat_intel.sh | 执行脚本 | 名单更新成功 |

---

## 10. 站点 / 画像 / API 防护（T-SITE）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-SITE-001 | 站点列表 | 控制台「Web 站点」 | 列出 managed `site-*.conf` |
| T-SITE-002 | 创建站点 | server_name + listen + upstream + Enable WAF | 生成 conf 并 reload；健康检查按站点返回 |
| T-SITE-003 | 编辑站点 | 改 burst、CSP、JS Challenge、Geo、API 等 | 配置落盘且 reload 成功 |
| T-SITE-004 | 删除站点 | 删除测试站点 | conf 移除；不再匹配 |
| T-SITE-005 | 站点自发现 | 产生带 Host 的访问日志 → 「站点自发现」 | 解析出 Host；可审核创建 |
| T-SITE-006 | 策略画像 | 套用 均衡/API严格/仅检测/CMS/emergency 等 | 站点字段与 CRS PL 按画像变化 |
| T-SITE-007 | API 前缀防护 | Enable API + prefix `/api/` | `/api/` 走更严限流/方法限制 |
| T-SITE-008 | OpenAPI 生成 | 粘贴 OpenAPI JSON → generate | 生成规则包；可启停 |
| T-SITE-009 | OpenAPI 未知路径 | 访问未声明 path（策略为 deny 时） | 拦截或审计（按规则配置） |
| T-SITE-010 | SSL 站点 | 启用 SSL + 证书路径 | 443 可访问；证书错误有明确失败 |

**HTTPS 上游检查清单：**

- [ ] `proxy_ssl_server_name on`
- [ ] `proxy_ssl_name` / `Host` 为真实域名
- [ ] 避免上游 DNS 解析回 WAF 自身（死循环）

---

## 11. 例外与误报（T-EXC）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-EXC-001 | URI 绕过 | 对误报 URI 建 `uri_bypass` | 该路径不再被拦 |
| T-EXC-002 | URI+规则移除 | `uri_rule_remove` 去掉特定 rule id | 仅该规则对路径失效 |
| T-EXC-003 | 事件页一键放行 | 安全事件「放行」 | 自动创建例外并 reload |
| T-EXC-004 | 误报建议 | `/insights/fp` | 给出高频误报候选 |
| T-EXC-005 | 例外列表维护 | 增删改例外 | 文件存在；reload 后生效 |

---

## 12. 安全事件 / 审计 / 报表 / 洞察（T-EVT）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-EVT-001 | 审计落盘 | 引擎 On 下发拦截探针 | `/data/logs/nginx/modsec_audit.json` 行数增加 |
| T-EVT-002 | 安全事件列表 | 控制台「安全事件」刷新 | 可见 IP/URI/规则 ID/级别 |
| T-EVT-003 | 事件筛选 | 按级别、关键字筛选 | 过滤正确 |
| T-EVT-004 | 事件详情 | 点击行 | Drawer 显示完整 JSON 字段 |
| T-EVT-005 | 攻击摘要 | `/attacks/summary` | total、按规则/严重级统计 |
| T-EVT-006 | 攻击趋势 | `/attacks/trend` | 24h 趋势数据 |
| T-EVT-007 | 报表 CSV | `/reports/export?format=csv` | 可下载 |
| T-EVT-008 | 合规/打印 HTML | 报表页打印或另存 PDF | 页面可出 |
| T-EVT-009 | 攻击洞察 | `/insights` 仪表盘 | 家族/活动/ATO 等 |
| T-EVT-010 | 审计链 | `GET /audit/chain` | ok/count/校验结果 |
| T-EVT-011 | access JSON | 查看 `access.json` | 含 request_id、status、host |
| T-EVT-012 | api.yaml 审计路径 | `grep audit_log conf/api.yaml` | 指向实际审计文件 |

**说明：** Nginx 黑名单/Bot `return 403` **不会**写入 ModSec 审计，安全事件为空但拦截页仍可能出现——属预期，应用 `error.log` / `access.json` 交叉验证。

---

## 13. 规则管理 / 虚补 / 特征库（T-RULE）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-RULE-001 | 规则列表 | 控制台「防护规则」 | 列出规则与 META |
| T-RULE-002 | 规则校验 | `POST /rules/validate` | 语法错误可检出 |
| T-RULE-003 | 备份/回滚 | `POST /backup` → 改配置 → `/rollback` | 可恢复 |
| T-RULE-004 | reload 失败回滚 | 故意坏 conf 触发 reload | 自动回滚；服务不长期损坏 |
| T-RULE-005 | 虚补列表 | `/virtpatches` | 可查看 CVE/状态 |
| T-RULE-006 | 虚补创建 | 控制台创建虚补规则 | 生效 |
| T-RULE-007 | 过期虚补清理 | `POST /virtpatches/expire` | 过期项清理 |
| T-RULE-008 | 本地特征库升级 | 上传规则 .tgz（可选 .sig） | 升级成功；可 reload |
| T-RULE-009 | update_rules.sh | 在线/离线更新脚本 | 规则更新 + 可选验签 |
| T-RULE-010 | content-policy | 上传/PII 策略可配 | `/content-policy` 读写生效 |

---

## 14. 管理认证 / License / PKI（T-MGMT）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-MGMT-001 | 控制台登录 | `https://IP:8443/` 登录 | 进入总览 |
| T-MGMT-002 | API 登录 | `POST /api/v1/auth/login` | 返回 JWT |
| T-MGMT-003 | 未授权访问 | 无 Token 调鉴权接口 | 401 |
| T-MGMT-004 | 防暴破锁定 | 连续错误密码 | 触发 lockout（日志/接口提示） |
| T-MGMT-005 | TOTP 2FA | 配置 totp_secret 后登录 | 需动态码 |
| T-MGMT-006 | STRICT_AUTH | `MA_WAF_STRICT_AUTH=1` + bcrypt | 弱口令/空 hash 拒绝启动或登录 |
| T-MGMT-007 | 管理口 ACL | 非 allow_cidrs 源访问 8443 | 被 nginx deny |
| T-MGMT-008 | License 状态 | 控制台 License / fingerprint | 显示状态；宽限期可提示缺公钥 |
| T-MGMT-009 | License 门禁 | 无有效许可时变更类接口 | 按产品策略拒绝或告警 |
| T-MGMT-010 | PKI 列表 | `/pki/certs` | 列出证书 |
| T-MGMT-011 | 生成 admin 证 | `/pki/admin/ensure` | 生成/修复 `conf/tls/admin.crt` |

---

## 15. 紧急旁路 / 重保 / 上线（T-OPS）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-OPS-001 | 紧急 DetectionOnly | 仪表盘紧急降级（填原因） | 引擎 DetectionOnly；链审计记录原因 |
| T-OPS-002 | 紧急 Off | 一键 Off | 流量旁路 |
| T-OPS-003 | 紧急恢复 On | 恢复 | 引擎 On |
| T-OPS-004 | 重保模式 | `/ops/heavy` | PL4 + 引擎 On |
| T-OPS-005 | 上线清单 | `/ops/golive` | DetectionOnly→On 检查项提示 |
| T-OPS-006 | 故障排查页 | 系统→故障排查 | 一键体检 + 日志尾部 + 修复建议 |
| T-OPS-007 | ops.json | 写告警 webhook 等 | `alert_check.sh` 可读 |

---

## 16. 告警 / SIEM / 指标 / HA（T-MON）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-MON-001 | Prometheus 文本 | `GET http://127.0.0.1:9090/metrics` | 含 ma_waf/process 指标 |
| T-MON-002 | JSON 指标 | `/api/v1/metrics` | load/mem/stub_status 等 |
| T-MON-003 | nginx stub_status | 8081 本机 status | 活跃连接等 |
| T-MON-004 | alert timer | `systemctl status ma-waf-alert.timer` | enabled/active |
| T-MON-005 | alert_check | 手动跑 `alert_check.sh` | 阈值触发时 webhook 调用（可 mock） |
| T-MON-006 | SIEM CEF | 配置 `siem_addr` | syslog 收到 CEF |
| T-MON-007 | HA 状态 | `/ha/status` | 角色/VIP/keepalived 信息（单机可显示未启用） |
| T-MON-008 | keepalived 模板 | 双机环境套用 example | VIP 漂移；`ha_check.sh` 探测 |

---

## 17. 控制台页面走查（T-UI）

按菜单逐页打开，确认无白屏、主要按钮可点、接口 200：

| ID | 页面 | 检查要点 |
|----|------|----------|
| T-UI-001 | 总览 | 引擎模式、攻击摘要、紧急按钮、主机指标 |
| T-UI-002 | Web 站点 | CRUD、编辑字段保存 |
| T-UI-003 | 站点自发现 | 列表/审核创建 |
| T-UI-004 | 安全策略 | 画像套用、策略开关 |
| T-UI-005 | 防护规则 | 列表、启停、虚补入口 |
| T-UI-006 | 规则例外 | 列表与创建 |
| T-UI-007 | 重保模式 | 一键开启/恢复 |
| T-UI-008 | 安全事件 | 列表、筛选、详情、放行/拉黑 |
| T-UI-009 | 报表与分析 | 趋势、导出 |
| T-UI-010 | 地址簿 | CRUD、应用 |
| T-UI-011 | IP / Geo 名单 | 黑白名单、Geo |
| T-UI-012 | 系统与特征库 | CRS/Geo/情报/HA 概览 |
| T-UI-013 | 特征库升级 | 上传控件、状态 |
| T-UI-014 | PKI 证书 | 列表、生成 |
| T-UI-015 | 系统运维 | 备份、模式、告警配置 |
| T-UI-016 | 故障排查 | 体检结果可读 |
| T-UI-017 | 许可证 | fingerprint、状态 |

---

## 18. 自身安全与加固（T-SEC）

| ID | 功能点 | 步骤 | 期望结果 |
|----|--------|------|----------|
| T-SEC-001 | 完整性基线 | `integrity_check.py --verify` | 与基线一致 |
| T-SEC-002 | nginx 不可变属性 | `lsattr sbin/nginx` | 含 `i`（若 harden 已执行） |
| T-SEC-003 | worker 非 root | `ps -o user= -C nginx` | 存在非 root worker |
| T-SEC-004 | API 仅本机 | `ss -lntp \| grep 9090` | 127.0.0.1/::1 |
| T-SEC-005 | 配置权限 | `api.yaml` 640；密钥 600 | 权限收紧 |
| T-SEC-006 | 配置加密（可选） | `encrypt_config.sh` age/sops | 加解密流程可用 |
| T-SEC-007 | 更新包验签 | 带 .sig 的规则包 | 验签失败拒绝安装 |
| T-SEC-008 | 启动完整性（可选） | 启用 `integrity_prestart.sh` | 篡改后拒绝启动 |

---

## 19. 推荐测试顺序（一天可跑完的 P0）

```text
1. 前置 P1–P8
2. T-DEP 冒烟 + verify_waf + test_waf_features.sh --attack
3. T-DP 健康/转发/拦截页
4. T-CRS 三种模式 + SQLi/XSS
5. T-EVT 审计落盘 → 控制台安全事件可见（验证 api.yaml）
6. T-SITE 建站 / 编辑 / HTTPS 上游 SNI
7. T-CC 限流
8. T-EXC 例外放行
9. T-MGMT 登录 / ACL
10. T-OPS 紧急旁路恢复
11. T-UI 全页走查
12. 其余 P1 按需
```

---

## 20. 测试记录表（可复制）

| 用例 ID | 执行人 | 日期 | 环境 | 结果 | 实际现象 / 缺陷号 | 备注 |
|---------|--------|------|------|------|-------------------|------|
| T-CRS-004 | | | | ☐通过 ☐失败 ☐阻塞 ☐不适用 | | |
| T-EVT-002 | | | | ☐通过 ☐失败 ☐阻塞 ☐不适用 | | |
| … | | | | | | |

**缺陷记录建议字段：** 标题、用例 ID、严重级别（P0–P3）、复现步骤、期望/实际、日志摘录（`error.log` / `modsec_audit.json` / API 响应）。

---

## 21. 已知易混淆点（测试时注意）

1. **`configs/templates/api.yaml` ≠ 运行时配置**；安全事件依赖 `conf/api.yaml` 中 `audit_log`。
2. **901001** 未设 `tx.crs_setup_version` 时返回 **500**，不是拦截页。
3. **黑名单 403** 可能无安全事件；ModSec 拦截才进审计。
4. **浏览器 HSTS** 可能导致只测到 443；联调用 `http://` 或无痕窗口。
5. **DetectionOnly** 下攻击探针「不拦截」算通过，但应有审计。
6. **Geo / HA / auth_request HMAC** 依赖模块与数据文件，未就绪记「阻塞」而非「失败」。

---

## 22. 附录：快速对照命令

```bash
# 引擎与 CRS
grep SecRuleEngine /usr/local/nginx/conf/modsecurity/modsecurity.conf
grep crs_setup_version /usr/local/nginx/conf/modsecurity/crs-setup.conf

# 站点与上游
grep -Rsn "server_name\|proxy_pass\|proxy_ssl" /usr/local/nginx/conf/conf.d/

# 日志
tail -n 50 /data/logs/nginx/error.log
tail -n 5 /data/logs/nginx/modsec_audit.json
tail -n 5 /data/logs/nginx/access.json

# 服务
systemctl status nginx ma-waf-api ma-waf-alert.timer --no-pager
ss -lntp | grep -E ':80|:443|:8443|:9090'
```

---

## 23. 签字

| 角色 | 姓名 | 日期 | 结论 |
|------|------|------|------|
| 测试执行 | | | ☐建议发布 ☐有条件发布 ☐不通过 |
| 开发确认 | | | |
| 项目验收 | | | |

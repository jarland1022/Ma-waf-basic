# 功能完成度矩阵（对照最初企业级需求）

状态说明：
- **已实现**：代码/配置可交付使用
- **模板级**：规则或片段已提供，需按环境启用（模块/数据文件）
- **运维可配**：通过模式切换或脚本达成，非自动故障切换
- **未做**：本版本不交付（见 Wave 2）

| 需求项 | 状态 | 说明 |
|--------|------|------|
| 规则热加载 | 已实现 | staging/active + `nginx -s reload`（非零中断热补丁） |
| 规则启用/禁用/优先级 | 已实现 | META + API + 控制台 |
| 语法校验与回滚 | 已实现 | `rule_manager validate`；CLI/`POST /rollback`；API reload 失败自动回滚 |
| 规则命中统计 | 已实现 | 审计解析 + `/attacks/summary`；JSONL 增量索引（纯标准库，无需外部 sqlite 包） |
| GeoIP 访问控制 | 部分 | 控制台 Geo 就绪探测 `/geo/status`；MMDB+geoip2 后站点启用 `$geo_block`；报表国家热力用 Country.mmdb 按源 IP 补全 |
| CC 频率限制 | 已实现 | `limit_req` / `limit_conn`；站点模板已继承 |
| 文件上传 / PII / Bot / 虚补 | 已实现 | `custom/110000*` `120000*` |
| JSON 审计 / 分级 | 已实现 | ModSec JSON + 控制台筛选 |
| 链式哈希防篡改 | 已实现 | API 操作链 `audit.Chain`；核心文件 `integrity_check.py` |
| 日志轮转 | 已实现 | logrotate 模板 |
| Web 控制台 | 已实现 | `management/console`（vanilla）；React 前端为可选/归档 |
| REST API / 模式切换 / 健康检查 | 已实现 | Go Gin；`/healthz`；`/waf-health` |
| 站点 CRUD / 例外放行 / License | 已实现 | 控制台 + API；License 门禁变更接口 |
| API 安全（OpenAPI） | 已实现 | 控制台粘贴 JSON → `/openapi/generate`；规则包启停；`openapi_guard.py` 仍可用 |
| 威胁情报 | 已实现 | 粘贴合并 + URL 拉取 `/threat-intel/fetch`；脚本 `update_threat_intel.sh` |
| Geo 国家封锁管理 | 已实现 | API `/geo/blocklist` + 控制台 IP 页；需 GeoIP2 模块与 MMDB |
| 虚拟补丁控制台 | 已实现 | `/virtpatches` + 规则页 CVE/过期启停 |
| 会话保护 / CSP / 自定义拦截页 | 已实现 | 规则 + snippets + error_pages（Request-ID + 品牌 + 英文页） |
| 攻击趋势 / 报表导出 | 已实现 | `/attacks/trend`；`/reports/export?format=csv` |
| Prometheus 指标 | 已实现 | `GET /metrics`（文本）+ JSON `/api/v1/metrics` |
| 攻击地图 | 部分 | 国家热力格子 + 条形图；城市级地图需 City MMDB（未做） |
| 合规报表 | 已实现 | CSV + 可打印 HTML（浏览器另存 PDF）；无服务端定时 PDF |
| 防护能力包启停 | 已实现 | `/packs` 启停 custom 规则包；校验 `/rules/validate` |
| 威胁情报合并 | 已实现 | 控制台合并 IOC → 黑名单；脚本 `update_threat_intel.sh` |
| 审计链校验 | 已实现 | `GET /api/v1/audit/chain` |
| 过期虚补清理 | 已实现 | `POST /api/v1/virtpatches/expire` |
| HA 进程重启 | 已实现 | systemd `Restart=on-failure` |
| 双机 VIP / keepalived | 模板级 | `configs/ha/keepalived.conf.example` + `ha_check.sh` |
| fail-open | 运维可配 | `SecRuleEngine Off/DetectionOnly`；非引擎崩溃自动旁路 |
| 性能调优模板 | 已实现 | nginx.conf + modsecurity.conf |
| 主机指标 / 告警 | 已实现 | `/api/v1/metrics`（load/mem/stub_status）；`alert_check.sh` + timer |
| 一键部署 / 加固 / 校验 / ctl | 已实现 | `deploy.sh` `harden_os.sh` `verify_waf.sh` `waf_ctl.sh` |
| CRS 4.x 安装 | 已实现 | `install_crs.sh`；deploy 自动尝试；verify 拒绝纯占位 |
| OS 裁剪 / 内核 / SSH / auditd | 已实现 | `harden_os.sh` |
| 管理面 2FA / 防暴破 / STRICT_AUTH | 已实现 | TOTP + lockout；`MA_WAF_STRICT_AUTH=1` 强制 bcrypt/强 JWT |
| 启动完整性校验 | 已实现 | `integrity_prestart.sh`（默认关闭，可选启用） |
| 更新签名 / 配置加密 | 已实现 | `update_rules.sh` openssl；age/sops |
| SELinux/AppArmor 策略包 | 模板级 | `docs/selinux-notes.md` + `packaging/selinux/ma_waf.te` |
| L7 JS Challenge | 已实现 | soft-bot → 挑战页；`/waf-challenge/issue` HMAC Cookie（jwt_secret） |
| 行为式 Bot / 签名 Cookie | 部分 | HMAC 签发；站点可开 `auth_request` 硬校验（需模块）；无 Lua 行为指纹 |
| 告警 Webhook | 已实现 | 控制台写 `ops.json`；`alert_check.sh` 优先读 ops；含攻击量阈值 |
| 攻击源自动加黑 | 已实现 | `/autoblock` + TopN；可选 cron `/api/v1/cron/autoblock`（timer） |
| 站点编辑 / CC 限流 | 已实现 | 控制台编辑站点；burst/conn/JS/HMAC/Geo/API 字段 |
| 策略画像 Profiles | 已实现 | 命名画像（均衡/API严格/仅检测/CMS）套用到站点 |
| API 前缀防护 | 已实现 | 站点 Enable API + `api_protect` + OpenAPI path/method/CT |
| ATO / 凭证滥用 | 已实现 | 登录/重置路径限速；仪表盘 ATO 源；规则 tag `ma-waf/ato` |
| 善意 Bot 名单 | 已实现 | `/bots/good` → nginx map；不挑战/不误杀搜索引擎 |
| 攻击洞察 | 已实现 | `/insights` + 仪表盘家族/活动/ATO |
| 自定义规则创建 | 已实现 | 控制台创建 140000 段规则 / 虚补 |
| 误报建议 / 上线清单 | 已实现 | `/insights/fp`；`/ops/golive` DetectionOnly→On |
| CRS 偏执级 | 已实现 | `/crs/paranoia` PL1–4；画像可绑定 |
| 上传 / PII 策略 | 已实现 | 大小/扩展/PII 审计或拦截可配 |
| 情报 TTL | 已实现 | IOC 账本 + `/threat-intel/expire` |
| SIEM syslog | 已实现 | ops `siem_addr` CEF；alert_check 转发 |
| Geo 执法开关 | 已实现 | `/geo/enforce` 写入 `geo_block_map.conf`（需 MMDB+geoip2） |
| HA 状态可视 | 已实现 | `/ha/status` 角色/VIP/keepalived；系统页展示 |
| 紧急旁路 | 已实现 | `/ops/emergency` 必填原因；仪表盘一键降级/恢复 |
| 情报定时过期 | 已实现 | `cron/intel-expire` + alert_check timer |
| 山石风格控制台壳 | 已实现 | 顶栏模块 + 侧栏子菜单 + 面包屑（蓝白企业风） |
| 站点自发现 | 已实现 | `/sites/discover` 解析访问日志 Host；控制台审核新建 |
| 地址簿对象 | 已实现 | `/addrbook` + 引用计数近似 + 应用到黑/白名单 |
| PKI 管理面证书 | 已实现 | `/pki/certs` + `/pki/admin/ensure` 生成 admin.crt |
| 系统与特征库页 | 已实现 | `/sysinfo` CRS/Geo/情报/HA 概览 |
| 重保模式 | 已实现 | `/ops/heavy` → PL4 + 引擎 On；策略模板 policy_* |
| 本地规则库升级 | 已实现 | 控制台「特征库升级」上传 .tgz；`POST /rules/upgrade/local`；可选 .sig 验签 + promote/reload |
| 控制台故障排查 | 已实现 | 系统→故障排查；`GET /ops/troubleshoot` 一键体检 + 日志尾部 + 修复证书/Reload |
| 功能可用性测试脚本 | 已实现 | `scripts/test_waf_features.sh`（基建/数据面探针/API/可选写测） |
| 全功能测试文档 | 已实现 | [`docs/test-plan.md`](test-plan.md)（对照本矩阵的用例与验收表） |
| 运行时一键修复 | 已实现 | `scripts/fix_runtime.sh`（证书/目录/控制台/API 二进制） |

## 与 Imperva 类 WAAP 对照（公开能力，非逆向）

| Imperva 能力域 | Ma-WAF | 说明 |
|----------------|--------|------|
| WAF / OWASP Top10 | 已实现 | CRS 4.x + 自定义包 |
| API Security | 部分→增强 | OpenAPI path+method+CT；站点 API 前缀限流；无完整 schema/BOLA ML |
| Bot Management | 部分 | 坏/软/善 UA + JS/HMAC Challenge；无行为指纹/设备 SDK |
| DDoS（网络层） | 未做 | 需清洗中心；本产品侧重 L7 CC（limit_req/conn） |
| ATO | 部分→增强 | 登录/重置限速 + 洞察；无凭证情报云库 |
| Virtual Patching | 已实现 | CVE META + 控制台创建/过期清理 |
| Policy profiles | 已实现 | 命名画像一键套用 + CRS 偏执级；含 loose/normal/strict/debug/emergency |
| Threat Intel | 已实现 | IOC 合并/拉取 + TTL 过期 |
| Analytics / Insights | 部分→增强 | 家族/活动/ATO + 误报候选；无全球 SOC |
| Geo / IP Reputation | 已实现 | MMDB+geoip2 后 `/geo/enforce`；站点启用 `$geo_block` |
| SIEM | 已实现 | syslog CEF（非 Splunk 专用插件） |
| 站点自发现 / 地址簿 / PKI | 已实现 | 对标企业 WAF 运维对象与系统页子集（非完整网络域/L2/L3） |
| 本地规则库升级 | 已实现 | UI 上传 tgz；对齐 `update_rules.sh --offline` |

## 语言选型（摘要）

| 场景 | 选择 | 理由 |
|------|------|------|
| 数据平面 | Nginx + ModSecurity C/C++ | 不重写引擎，配置与模块扩展 |
| 管理 API | **Go** | 单二进制、并发、与 systemd 集成简单；本仓库已落地 |
| 控制台 | Vanilla JS（生产） | 免 Node 构建，交付快；React 可选增强 |
| 运维/规则工具 | Bash + Python 3.9+ | Rocky/openEuler 默认可用 |

若选 Python 做管理面长驻服务：需多进程/异步（uvicorn workers），注意与文件锁、reload 协作；本项目管理面已固定 Go。

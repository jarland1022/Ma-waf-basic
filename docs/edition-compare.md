# Ma-WAF 版本对照：Community / Professional / Enterprise

> 目标：**开源获客 + 专业版转化 + 企业档扩客单价**。  
> Community 解决「能装、能防、能看」；Professional 解决「能运维、能联动、能合规」；Enterprise 解决「能集群、能驻场、能签 SLA」。

相关入口：[README](../README.md) · [`community-vs-pro.md`](community-vs-pro.md)

> 本仓库仅开源 Community。Professional / Enterprise 的安装包与管理端源码不在此仓库。

---

## 1. 一句话定位

| 版本 | 定位 | 典型用户 |
|------|------|----------|
| **Community** | 自托管基础 WAF，永久免费 | 个人站、实验室、中小站试点、学生/运维学习 |
| **Professional** | 生产级单节点 / 小规模多站点 | 有安全合规要求的中小企业、独立站群、SaaS 单机房 |
| **Enterprise** | 多节点 HA、专属支持与定制 | 金融/政务/大型互联网、等保测评配套、重保窗口 |

---

## 2. 定价（人民币，含税另议）

| 版本 | 标价 | 计量 | 包含 |
|------|------|------|------|
| **Community** | **¥0（永久免费）** | 不限 | 本仓库全部开源能力；社区 Issue / Discussion；无 License、无到期 |
| **Professional** | **¥4,980 / 节点 / 年** | 按生产 WAF 节点 | 专业版功能 + 工作日 5×8 工单（邮件/企微）+ 规则/情报更新通道 |
| **Enterprise** | **¥15,800 起 / 年** | 按节点或按项目报价 | Professional 全部能力 + 多节点授权包 + HA 交付协助 + 专属客户经理 + 可选 SLA / 驻场 |

### 加购（提高客单价）

| 项 | 建议价 | 说明 |
|----|--------|------|
| 额外 Professional 节点 | ¥2,980 / 节点 / 年 | 同主体续期优惠可谈 |
| Professional → Enterprise 升级 | 补差价 | 当年剩余月份按比例 |
| 14～30 天全功能试用 License | 免费 | 需申请；到期回落 Community 能力边界 |
| 重保窗口值守 | ¥3,000～8,000 / 次 | 按窗口天数与站点规模 |
| 误报调优 / 上线陪跑 | ¥2,000 / 人天起 | 可抵扣首年订阅部分额度（商务约定） |
| 私有化签章规则源 / 私有情报源 | 单议 | Enterprise 常见需求 |

> 对外宣传可用「专业版约 **五千元/年/节点**」；合同与官网统一写 **¥4,980**，避免整数砍价。

---

## 3. 功能对照表

图例：✅ 包含 · 🔶 基础/受限 · ❌ 不含 · 🧩 模板或交付协助

### 3.1 数据平面与核心防护

| 能力 | Community | Professional | Enterprise |
|------|:---------:|:------------:|:----------:|
| Nginx + ModSecurity + OWASP CRS | ✅ | ✅ | ✅ |
| 引擎模式 On / DetectionOnly / Off | ✅ | ✅ | ✅ |
| 单站点反向代理 + TLS | ✅ | ✅ | ✅ |
| 多站点 CRUD / 站点自发现 | 🔶 建议 ≤1～2 站手工 | ✅ | ✅ |
| IP 黑白名单 | ✅ | ✅ | ✅ |
| 基础 CC 限流（limit_req / conn） | ✅ | ✅ | ✅ |
| CRS 偏执级 PL1～PL4 | 🔶 默认 PL1～2 | ✅ 含画像绑定 | ✅ |
| 自定义规则包（上传/协议等） | 🔶 文件级 | ✅ 控制台启停 | ✅ |
| 虚拟补丁（CVE）与签名规则升级 | ❌ | ✅ | ✅ |
| OpenAPI / API 前缀增强防护 | ❌ | ✅ | ✅ |
| GeoIP 国家封禁 | ❌ | ✅ | ✅ |
| Bot：坏 UA / JS Challenge / 善意 Bot | 🔶 基础 UA | ✅ | ✅ + 策略定制 |
| 会话 / ATO 登录路径防护包 | ❌ | ✅ | ✅ |
| L3/L4 DDoS 清洗 | ❌ | ❌ | 🧩 对接第三方清洗（方案） |

### 3.2 管理面与运维

| 能力 | Community | Professional | Enterprise |
|------|:---------:|:------------:|:----------:|
| Web 控制台（总览 / 事件 / 规则 / IP） | ✅ | ✅ | ✅ |
| 策略画像（宽松/正常/严格/应急） | ❌ | ✅ | ✅ |
| 威胁情报合并 / 拉取 / IOC TTL / 自动封禁 | ❌ | ✅ | ✅ + 私有源 |
| Webhook 告警 | 🔶 脚本级可选 | ✅ | ✅ |
| SIEM syslog CEF | ❌ | ✅ | ✅ + 对接协助 |
| 合规报表（等保/ISO/GDPR/SOX **映射**） | ❌ | ✅ | ✅ + 测评陪跑可选 |
| 审计链 / 配置备份回滚 | 🔶 基础备份 | ✅ | ✅ |
| 管理面 TOTP 2FA / STRICT_AUTH | 🔶 可选 | ✅ 推荐强制 | ✅ 强制基线 |
| HA（keepalived VIP）状态与交付 | ❌ | 🧩 模板自助 | ✅ 交付协助 + 多节点授权 |
| 重保模式 / 紧急旁路（审计原因） | ❌ | ✅ | ✅ + 值守 |
| 地址簿 / PKI 管理面证书 | ❌ | ✅ | ✅ |
| 故障排查一键体检 | 🔶 verify 脚本 | ✅ 控制台 | ✅ + 远程协助 |

### 3.3 授权、支持与商业

| 能力 | Community | Professional | Enterprise |
|------|:---------:|:------------:|:----------:|
| 开源许可 | Apache-2.0 | 商业许可 | 商业许可 |
| License 形态 | 无需付费激活（见下） | 硬件指纹节点 License | 多节点 / 集群包 |
| 商用支持 | 社区 Best-effort | 5×8 工单 | 专属通道；可购 7×24 |
| SLA | 无 | 响应时效约定（如 1 个工作日） | 合同 SLA（如 4h / 1h） |
| 发票与对公合同 | — | ✅ | ✅ |
| 源码 / 私有构建定制 | 社区贡献 | 不开放私有模块源码 | 可签 NDA 定制 |

---

## 4. Community 能力边界（产品承诺）

Community **永久免费**（Apache-2.0），并保证以下体验完整可用：

1. 一键或脚本部署到 Rocky / openEuler（后续补充 Docker）。
2. CRS 安装后可对常见 SQLi / XSS / 扫描器流量产生拦截或检测日志。
3. 控制台可登录，查看引擎状态与近期攻击事件，可切换模式并 Reload。
4. IP 名单与基础限流可配置。

Community **明确不承诺**：多站点规模化运维、情报订阅、SIEM、合规报表、商用 SLA、集群 HA 交付。

> 控制台中 Professional / Enterprise 能力以「可见但锁定 + 升级引导」呈现（转化优于完全隐藏）。

---

## 5. 推荐转化路径

```
GitHub / Gitee Star、Docker Pull
        ↓
  部署 Community（≤15 分钟成功）
        ↓
  控制台横幅 / 锁定菜单 → 申请 14～30 天试用
        ↓
  生产切 On + 调优陪跑（可选人天）
        ↓
  订阅 Professional（¥4,980/节点/年）
        ↓
  多机房 / 等保 / HA / SLA → 升级 Enterprise
```

**销售话术锚点**

- Community：「永久免费，先把站护起来；误报可 DetectionOnly 观察。」
- Professional：「站点一多、要对接安全设备和出合规材料时，年费通常低于一次外包评估。」
- Enterprise：「双机热备、重保、对公 SLA，按项目打包比按人天更可控。」

---

## 6. 工程实现约定（给后续开发）

| 约定 | 说明 |
|------|------|
| `EDITION` 文件 | 本仓库固定为 `community` |
| License Payload | 扩展 `tier`: `community` \| `professional` \| `enterprise` 与 `features[]` |
| API | 变更类接口按 feature flag 返回 402/403 + 升级 URL |
| 私钥 | **永不**进入本开源仓库；签发仅在商业签发机 |
| 商业模块 | 可同构代码库私有分支，或独立 `ma-waf-pro` 发行包 |

本对照表是对外承诺的「产品合同」草稿；实现 feature gate 时以本表为准迭代，避免 Community 过度阉割或 Professional 与 Enterprise 无差价感知。

# Ma-WAF Community

自托管 Web 应用防火墙的开源社区版。反向代理后面跑 **Nginx + ModSecurity + OWASP CRS**，用来拦截 SQL 注入、XSS、扫描器和其他常见 Web 攻击。

专业版在同一条产品线上，面向要多站点管控、威胁情报、SIEM 和商用支持的团队。参考价格 **¥4,980 / 节点 / 年**。对照与试用说明见社区控制台的「专业版」页，或 [`docs/community-vs-pro.md`](docs/community-vs-pro.md)。

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## 社区版能做什么

- 单站点反向代理，默认开启 OWASP CRS
- 拦截常见扫描器 User-Agent（sqlmap、nikto、acunetix 等）
- 按源 IP 限速（约 20 请求/秒，突发 40）
- 在规则文件里手工写 IP 黑名单
- 拦截页带专业版说明；控制台可申请试用

社区版不包含多站点控制台、地理封锁、威胁情报、虚拟补丁升级、SIEM、合规报表和商用许可。这些留在专业版，避免「整包开源、无人付费」。

## 5 分钟跑起来

需要 Docker 与 Docker Compose。

```bash
docker compose up -d
```

| 地址 | 作用 |
|------|------|
| http://127.0.0.1:8080/ | 演示业务（经过 WAF） |
| http://127.0.0.1:8090/ | 试用控制台登录（与专业版同款界面） |
| http://127.0.0.1:8090/home.html | 登录后的社区说明 |
| http://127.0.0.1:8090/trial.html | 专业版 14 天试用申请表单 |
| http://127.0.0.1:8090/pro.html | 价格与能力对照 |

登录账号：`admin` / `admin`（与专业版默认一致）。

自检：

```bash
# Linux / macOS
sh scripts/smoke-test.sh
# Windows PowerShell
powershell -File scripts/smoke-test.ps1
```

正常页面应返回 200；XSS、SQL 注入特征和 `User-Agent: sqlmap` 应返回 403。

接到真实业务时，修改 `docker-compose.yml` 中 `waf.environment.BACKEND`，例如 `http://your-app:80`。只观察、不拦截时，在 `.env` 里设置 `MODSEC_RULE_ENGINE=DetectionOnly`（先复制 `.env.example`）。

## 发布前改一处

把 `console/config.js` 里的 `salesEmail` 换成真实销售邮箱。试用申请页是 `trial.html`，不要再用会跳空白页的 `mailto:` 作为主按钮。

## 和专业版的关系

| | 社区版 | 专业版 |
|--|--------|--------|
| 获取 | 本仓库，Apache-2.0 | 商业许可，约 ¥4,980 / 节点 / 年 |
| 形态 | Docker 单站点 | 可安装的管理控制台（多站点、审计、情报、告警） |
| 支持 | GitHub Issues | 工作日商用支持，可签合同 |
| 试用 | — | 14 天。签发私钥不在本仓库 |

专业版报表只辅助合规材料，**不表示已经通过等保测评**。

## 目录

```text
docker-compose.yml          # waf + 演示站 + 控制台
rules/                      # CRS 之前的社区规则（扫描器、IP 黑名单示例）
nginx/                      # 限速、拦截页
console/                    # 社区说明与专业版引导
demo/                       # 被保护的演示页
docs/community-vs-pro.md
```

## 许可

本仓库中 Ma-WAF Community 的脚本、页面与规则示例采用 [Apache-2.0](LICENSE)。

运行时镜像 `owasp/modsecurity-crs` 以及 Nginx、ModSecurity、OWASP CRS 各自保留原许可证，见 [NOTICE](NOTICE)。

## English

Ma-WAF Community is a free, self-hosted reverse-proxy WAF (Nginx, ModSecurity, OWASP CRS) for a single site. Ma-WAF Professional is the paid edition for multi-site operations, threat intel, SIEM, and commercial support, priced around CNY 4,980 per node per year. See `docs/community-vs-pro.md`.

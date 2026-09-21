# Ma-WAF Community

自托管 Web 应用防火墙的**开源社区版**。用 Docker 自己安装后，流量经 **Nginx + ModSecurity + OWASP CRS** 再到达你的网站：能拦截攻击，也能在控制台看到效果。

专业版（多站点、威胁情报、SIEM、合规等）**不在本仓库**，试用期间可与版主沟通价格 / 节点 / 年**。对照：[`docs/community-vs-pro.md`](docs/community-vs-pro.md)。
wx:jarlandliu   jarland@mingansec.com

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## 社区版能做什么

| 能力 | 说明 |
|------|------|
| 自己安装 | `scripts/install.sh` / `install.ps1` 或 `docker compose up -d` |
| 真实防护 | 单站点反向代理 + OWASP CRS |
| 看到效果 | 控制台事件列表、Top 规则/IP；「一键验证防护效果」 |
| 扫描器拦截 | sqlmap / nikto / acunetix 等 UA |
| 基础限速 | 按源 IP 约 20 r/s |
| IP 黑名单 | 控制台维护后 `scripts/apply-blacklist.*` 或 `docker compose restart waf` |
| 接到业务 | `.env` 里改 `BACKEND=` 指向你的应用 |

**不含（专业版）：** 多站点管控台、威胁情报、地理封锁、Bot JS 挑战、虚拟补丁升级、SIEM、合规报表、商用支持。

## 一键安装

需要 [Docker](https://docs.docker.com/get-docker/)（Windows 用 Docker Desktop）。

```bash
# Linux / macOS
sh scripts/install.sh

# Windows PowerShell
powershell -File scripts/install.ps1
```

| 地址 | 作用 |
|------|------|
| http://127.0.0.1:8080/ | **防护入口**（默认后面是演示站；改 `BACKEND` 可护你的业务） |
| http://127.0.0.1:8090/ | **社区控制台**（界面与专业版一致；Pro 菜单可见但点击无反应） |

默认账号：`admin` / `admin`（在 `.env` 的 `DEMO_USER` / `DEMO_PASS` 修改）。

### 验证防护

```bash
# Linux / macOS
sh scripts/smoke-test.sh
# Windows（若改过端口： $env:WAF_URL="http://127.0.0.1:端口"）
powershell -File scripts/smoke-test.ps1
```

正常页 200；XSS / `sqlmap` UA 应为 403。也可在控制台点「一键验证防护效果」，事件表会自动刷新。

### 保护真实网站

1. 编辑 `.env`：`BACKEND=http://你的应用:端口`
2. 设置 `WAF_PUBLIC_URL=http://服务器IP或域名:8080`
3. `docker compose up -d`
4. 把公网流量指到 WAF 端口，不要直连应用  
5. 初期可用 `MODSEC_RULE_ENGINE=DetectionOnly`，确认后再改为 `On`

控制台内也有图文说明：登录后打开 [install.html](console/install.html)（部署后为 `/install.html`）。

## 目录

```text
docker-compose.yml     # waf + demo + api + console
community-api/         # 社区 API（事件 / 黑名单，标准库 Python）
rules/                 # CRS 前社区规则
nginx/                 # 限速模板、拦截页
console/               # 安装后控制台（总览 / 试用引导）
demo/                  # 内置演示站
scripts/install.*      # 一键安装
scripts/smoke-test.*   # 拦截自检
docs/                  # 社区 vs 专业版
```

## 许可

Apache-2.0（本仓库）。运行时镜像与 Nginx / ModSecurity / CRS 见 [NOTICE](NOTICE)。  
**Ma-WAF Professional 为商业软件，不在此开源。**

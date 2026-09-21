# Ma-WAF Community

自托管 Web 应用防火墙的**开源社区版**。用 Docker 自己安装后，流量经 **Nginx + ModSecurity + OWASP CRS** 再到达你的网站：能拦截攻击，也能在控制台看到效果。

专业版（多站点、威胁情报、SIEM、合规等）**不在本仓库**。联系：微信 `jarlandliu`，邮箱 `jarland@mingansec.com`。对照：[`docs/community-vs-pro.md`](docs/community-vs-pro.md)。

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
| 接到业务 | `.env` 里指定 HTTP 或 HTTPS 源站，见下文 |

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

## 防护 HTTP 站点与 HTTPS 站点

访问方连接的是 **WAF 入口**（默认 `http://<WAF地址>:8080`）。WAF 再按 `.env` 把放行的请求转到源站。源站可以是 HTTP，也可以是 HTTPS。社区版这一层入口本身是 HTTP；若要让访客用 HTTPS 访问 WAF，请在 WAF 前面再放证书终结（专业版提供站点证书管理）。

改完配置后执行：

```bash
docker compose up -d --force-recreate waf
```

### HTTP 源站

源站没有 TLS，例如内网 `192.168.1.10:80`。

```env
BACKEND=http://192.168.1.10:80
PROXY_HOST_HEADER=www.example.com
UPSTREAM_SSL_SNI=off
UPSTREAM_SSL_NAME=localhost
SERVER_NAME=www.example.com
WAF_PUBLIC_URL=http://127.0.0.1:8080
```

可直接复制 [`.env.http.example`](.env.http.example)。`PROXY_HOST_HEADER` 填站点域名；源站只认 IP、不看 Host 时，可写成 `$host`。

### HTTPS 源站

源站证书在源站上，WAF 用 HTTPS 去连它。必须打开 SNI，并把 Host 写成源站域名。

```env
BACKEND=https://www.example.com
PROXY_HOST_HEADER=www.example.com
UPSTREAM_SSL_SNI=on
UPSTREAM_SSL_NAME=www.example.com
SERVER_NAME=www.example.com
WAF_PUBLIC_URL=http://127.0.0.1:8080
```

可直接复制 [`.env.https.example`](.env.https.example)。

不要设置 `PROXY_SSL=on`。官方镜像里这个开关表示向上游出示客户端证书，不是「源站使用 HTTPS」。打开后 Nginx 会因缺少客户端证书无法启动，防护端口就没有监听。

### 对照

| 项目 | HTTP 源站 | HTTPS 源站 |
|------|-----------|------------|
| `BACKEND` | `http://主机:端口` | `https://域名` |
| `PROXY_HOST_HEADER` | 站点域名，或 `$host` | 必须是源站证书上的域名 |
| `UPSTREAM_SSL_SNI` | `off` | `on` |
| `UPSTREAM_SSL_NAME` | 可保持 `localhost` | 与 `PROXY_HOST_HEADER` 相同 |
| `PROXY_SSL` | 不要设置 | 不要设置 |

自检时只访问 WAF 入口。正常页面应为 200；XSS 与 `User-Agent: sqlmap` 应为 403。直接打开源站地址不会经过这台 WAF。

## 目录

```text
docker-compose.yml     # waf + demo + api + console
.env.example           # 默认演示站
.env.http.example      # 保护 HTTP 源站
.env.https.example     # 保护 HTTPS 源站
community-api/         # 社区 API（事件 / 黑名单，标准库 Python）
rules/                 # CRS 前社区规则
nginx/                 # 限速模板、拦截页、HTTPS 上游 SNI
console/               # 安装后控制台（总览 / 试用引导）
demo/                  # 内置演示站
scripts/install.*      # 一键安装
scripts/smoke-test.*   # 拦截自检
docs/                  # 社区 vs 专业版
```

## 许可

Apache-2.0（本仓库）。运行时镜像与 Nginx / ModSecurity / CRS 见 [NOTICE](NOTICE)。  
**Ma-WAF Professional 为商业软件，不在此开源。**

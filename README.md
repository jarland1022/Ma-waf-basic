# Ma-WAF Community

**English** | [中文](README.zh.md)

Self-hosted web application firewall. **Free forever** (Apache-2.0). Docker install puts **Nginx + ModSecurity + OWASP CRS** in front of your site: attacks are blocked, and you can see them in the console. No license file, no expiry, no per-node fee.

**Professional** (multi-site console, threat intel, SIEM, compliance reports, commercial support) is **not in this repo**. Typed consult (WhatsApp / email preferred): [WhatsApp](https://wa.me/8613717098262) · `jarland@mingansec.com` · [Mingansec](https://jarland1022.github.io/Ma-waf-basic/). Compare editions: [`docs/community-vs-pro.md`](docs/community-vs-pro.md).

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Edition](https://img.shields.io/badge/Community-free%20forever-brightgreen)](docs/community-vs-pro.md)

## What Community includes

| Capability | Notes |
|------------|--------|
| Price | **Free forever**, self-hosted, no subscription |
| Install | `scripts/install.sh` / `install.ps1` or `docker compose up -d` |
| Real protection | Single-site reverse proxy + OWASP CRS |
| Visibility | Console event list, top rules/IPs, one-click protection check |
| Scanner blocking | User-Agents such as sqlmap / nikto / acunetix |
| Basic rate limit | About 20 r/s per source IP |
| IP blacklist | Edit in console, then `scripts/apply-blacklist.*` or `docker compose restart waf` |
| Front your app | Set origin in `.env` (HTTP or HTTPS backend) |

**Not included (Professional / paid):** multi-site admin, threat intel, geo-blocking, bot JS challenge, virtual-patch upgrades, SIEM, compliance reports, commercial support, managed SOC ops.

Team behind Pro + managed ops: 7 senior engineers from Huawei and Tencent (10+ years each). Community stays free so you can evaluate the engine yourself.

## One-command install

Requires [Docker](https://docs.docker.com/get-docker/) (Docker Desktop on Windows).

```bash
# Linux / macOS
sh scripts/install.sh

# Windows PowerShell
powershell -File scripts/install.ps1
```

| URL | Role |
|-----|------|
| http://127.0.0.1:8080/ | **WAF entry** (demo origin by default; change `BACKEND` to protect your app) |
| http://127.0.0.1:8090/ | **Community console** (same UI family as Pro; Pro-only menus are visible but inactive) |

Default login: `admin` / `admin` (change `DEMO_USER` / `DEMO_PASS` in `.env`).

### Smoke test

```bash
# Linux / macOS
sh scripts/smoke-test.sh
# Windows (if you changed the port: $env:WAF_URL="http://127.0.0.1:PORT")
powershell -File scripts/smoke-test.ps1
```

Normal pages should be **200**. XSS / `sqlmap` User-Agent should be **403**. You can also click **one-click protection check** in the console; the event table refreshes automatically.

### Protect a real site

1. Edit `.env`: `BACKEND=http://your-app:port` (or `https://…`)
2. Set `WAF_PUBLIC_URL=http://YOUR_SERVER_IP_OR_HOST:8080`
3. `docker compose up -d`
4. Point public traffic at the WAF port, not directly at the app
5. Start with `MODSEC_RULE_ENGINE=DetectionOnly`, then switch to `On` when FPs are acceptable

Illustrated steps also live in [console/install.html](console/install.html) (`/install.html` after deploy).

## HTTP vs HTTPS origins

Clients hit the **WAF entry** (default `http://<waf-host>:8080`). The WAF forwards allowed requests to the origin. The origin may be HTTP or HTTPS. Community WAF listen port itself is HTTP; terminate TLS in front of the WAF if visitors need HTTPS (Professional includes site certificate management).

After changing `.env`:

```bash
docker compose up -d --force-recreate waf
```

### HTTP origin

```env
BACKEND=http://192.168.1.10:80
PROXY_HOST_HEADER=www.example.com
UPSTREAM_SSL_SNI=off
UPSTREAM_SSL_NAME=localhost
SERVER_NAME=www.example.com
WAF_PUBLIC_URL=http://127.0.0.1:8080
```

Copy [`.env.http.example`](.env.http.example). Use `$host` for `PROXY_HOST_HEADER` if the origin ignores Host and only binds an IP.

### HTTPS origin

The origin owns the certificate. The WAF connects to it with HTTPS. Enable SNI and set Host to the origin hostname.

```env
BACKEND=https://www.example.com
PROXY_HOST_HEADER=www.example.com
UPSTREAM_SSL_SNI=on
UPSTREAM_SSL_NAME=www.example.com
SERVER_NAME=www.example.com
WAF_PUBLIC_URL=http://127.0.0.1:8080
```

Copy [`.env.https.example`](.env.https.example).

Do **not** set `PROXY_SSL=on`. In the official image that flag means “present a client certificate to upstream”, not “origin uses HTTPS”. Enabling it without a client cert prevents Nginx from starting.

| Item | HTTP origin | HTTPS origin |
|------|-------------|--------------|
| `BACKEND` | `http://host:port` | `https://hostname` |
| `PROXY_HOST_HEADER` | Site name, or `$host` | Must match the origin certificate name |
| `UPSTREAM_SSL_SNI` | `off` | `on` |
| `UPSTREAM_SSL_NAME` | may stay `localhost` | same as `PROXY_HOST_HEADER` |
| `PROXY_SSL` | do not set | do not set |

Smoke-test only the WAF entry. Opening the origin URL bypasses this WAF.

## Layout

```text
docker-compose.yml     # waf + demo + api + console
.env.example           # default demo origin
.env.http.example      # protect an HTTP origin
.env.https.example     # protect an HTTPS origin
community-api/         # community API (events / blacklist, stdlib Python)
rules/                 # community rules before CRS
nginx/                 # rate-limit templates, block page, HTTPS upstream SNI
console/               # post-install console
demo/                  # built-in demo site
scripts/install.*      # one-command install
scripts/smoke-test.*   # block self-check
docs/                  # community vs professional
```

## Commercial options (not this repo)

| Tier | Starting USD | What you get |
|------|----------------|--------------|
| Community | $0 | This repository |
| Pro license | see sales | Commercial runtime, more ops features, support window |
| Managed ops | see sales | Pro + weekly tuning / alert triage by our team |

Landing / contact: https://jarland1022.github.io/Ma-waf-basic/ · WhatsApp · `jarland@mingansec.com`

## License

Apache-2.0 (this repository). Runtime images and Nginx / ModSecurity / CRS: [NOTICE](NOTICE).

**Ma-WAF Community is free forever.** Ma-WAF Professional is commercial software and is not open-sourced here.

Same text: [`README.en.md`](README.en.md).

# 在公开仓库发布落地页（Ma-waf-basic）

**正确仓库：** https://github.com/jarland1022/Ma-waf-basic（Public）  
**不要**在私有专业版仓库里开 Pages / 加 Variables（私有仓 Pages 常需付费，且会增加误公开风险）。

| 仓库 | 用途 |
|------|------|
| `Ma-waf-basic`（公开） | 社区版代码 + **英文落地页** + GitHub Pages |
| 私有 Ma-WAF Pro | 完整商业代码，保持 Private，勿挂营销站 |

落地页发布后地址一般为：

`https://jarland1022.github.io/Ma-waf-basic/`

---

## 1. 推送本仓库（含 workflow）

确保远程已有：

- `.github/workflows/pages-landing.yml`
- `docs/marketing/landing.html`

本地示例：

```powershell
cd D:\AI\Ma-waf-basic
git add .github/workflows/pages-landing.yml docs/marketing/
git status
git commit -m "Add public landing page and GitHub Pages workflow"
git push origin main
```

---

## 2. 添加 Variables（关键步骤）

打开：**https://github.com/jarland1022/Ma-waf-basic**（必须是这个公开仓）

1. 顶部点 **Settings**  
2. 左侧 **Secrets and variables** → **Actions**  
3. 上方点 **Variables**（不是 Secrets）  
4. **New repository variable**，添加 5 个：

| Name | Value |
|------|--------|
| `WHATSAPP_URL` | `https://wa.me/8613717098262` |
| `CALENDLY_URL` | `https://calendly.com/leonliu/ma-waf-consult` |
| `GITHUB_URL` | `https://github.com/jarland1022/Ma-waf-basic` |
| `EMAIL` | `jarland@mingansec.com` |
| `COMPANY` | `Mingansec` |

**不要**点 Actions 里的 *Create your own workflow*——工作流文件已经在仓库里了。

---

## 3. 打开 Pages

同一仓库：**Settings → Pages → Source → GitHub Actions**

---

## 4. 运行发布

1. 顶部 **Actions**  
2. 左侧 **Deploy landing (GitHub Pages)**  
3. **Run workflow** → **Run workflow**  
4. 变绿后打开：`https://jarland1022.github.io/Ma-waf-basic/`

自测：Chat on WhatsApp / Email / Try on GitHub 三个按钮。

---

## 和「Create your own」的关系

| 页面 | 要不要点 |
|------|----------|
| Actions → Get started / Create your own | **不要**（会建空 workflow） |
| Settings → Secrets and variables → Actions → **Variables** | **要**（加上面 5 个） |
| Actions → Deploy landing → Run workflow | **要**（发布） |

# Ma-WAF Community 一键安装（Docker / Windows PowerShell）
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "需要先安装 Docker Desktop: https://docs.docker.com/desktop/setup/install/windows-install/"
}

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "已创建 .env（可按需修改 BACKEND / 端口 / 密码）"
}

New-Item -ItemType Directory -Force -Path "logs","data" | Out-Null
$audit = "logs\modsec_audit.log"
if (-not (Test-Path $audit)) {
  New-Item -ItemType File -Path $audit | Out-Null
} elseif ((Get-Item $audit).PSIsContainer) {
  throw "logs\modsec_audit.log 目前是目录。请删掉后重新运行本脚本。"
}

Get-Content ".env" | ForEach-Object {
  if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
  $k,$v = $_.Split('=',2)
  Set-Item -Path "Env:$($k.Trim())" -Value $v.Trim()
}
$wafPort = if ($env:WAF_HTTP_PORT) { $env:WAF_HTTP_PORT } else { "8080" }
$consolePort = if ($env:CONSOLE_PORT) { $env:CONSOLE_PORT } else { "8090" }
if ($env:WAF_PUBLIC_URL) { } else {
  # 保持 .env 中的值；安装脚本不强制改写
}

docker compose pull
docker compose up -d

Write-Host ""
Write-Host "安装完成。"
Write-Host "  防护入口:   http://127.0.0.1:$wafPort/"
Write-Host "  社区控制台: http://127.0.0.1:$consolePort/   (默认 admin / admin)"
Write-Host "  自检:       powershell -File scripts\smoke-test.ps1"
Write-Host "接到真实业务: 编辑 .env 中 BACKEND=http://你的应用:端口 后执行 docker compose up -d"

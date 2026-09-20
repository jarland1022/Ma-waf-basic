# 应用 IP 黑名单：重启 waf 使 REQUEST-900 规则生效
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
docker compose restart waf
Write-Host "已重启 waf。黑名单规则应已生效。"

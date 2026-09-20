# 确认社区版会放行正常页面，并拦截 XSS 与扫描器 UA。
$ErrorActionPreference = "Stop"
$base = if ($env:WAF_URL) { $env:WAF_URL } else { "http://127.0.0.1:8080" }

function Get-Status([string[]]$CurlArgs) {
  $out = & curl.exe -s -o NUL -w "%{http_code}" @CurlArgs
  if ($LASTEXITCODE -ne 0 -and -not $out) { throw "curl failed: $($CurlArgs -join ' ')" }
  return [int]$out
}

$ok = Get-Status @($base + "/")
$xss = Get-Status @("-g", "--", ($base + "/?q=<script>alert(1)</script>"))
$scan = Get-Status @("-A", "sqlmap", ($base + "/"))
Write-Output "normal=$ok xss=$xss sqlmap=$scan"
if ($ok -ne 200 -or $xss -ne 403 -or $scan -ne 403) { throw "smoke failed" }
Write-Output "smoke ok"

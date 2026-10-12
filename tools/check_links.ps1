<#
.SYNOPSIS
  Checks that every download / info URL in data/runtimes.json is reachable.
.DESCRIPTION
  Sends HEAD (falling back to GET with "Range: bytes=0-0") and follows redirects.
  Prints one line per URL and exits 1 if any URL fails. Works on Windows PowerShell 5.1 and pwsh.
#>
[CmdletBinding()]
param(
  [string]$KbPath,
  [int]$TimeoutSec = 60,
  [int]$Retries = 2
)

$ErrorActionPreference = 'Stop'
if (-not $KbPath) { $KbPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '../data/runtimes.json' }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
$ProgressPreference = 'SilentlyContinue'

$kb = Get-Content -LiteralPath $KbPath -Raw -Encoding UTF8 | ConvertFrom-Json

# Collect url -> list of owners.
$urls = [ordered]@{}
function Add-Url([string]$url, [string]$owner) {
  if (-not $url) { return }
  if (-not $script:urls.Contains($url)) { $script:urls[$url] = New-Object System.Collections.Generic.List[string] }
  $script:urls[$url].Add($owner)
}
foreach ($pkg in $kb.packages.PSObject.Properties) {
  $p = $pkg.Value
  Add-Url $p.infoUrl "$($pkg.Name).infoUrl"
  if ($p.url) {
    foreach ($u in $p.url.PSObject.Properties) { Add-Url $u.Value "$($pkg.Name).url.$($u.Name)" }
  }
}

function Get-StatusCode([string]$url, [string]$method, [hashtable]$headers) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -UseBasicParsing `
      -MaximumRedirection 10 -TimeoutSec $TimeoutSec -UserAgent 'why-wont-it-open-link-check'
    return [int]$r.StatusCode
  } catch {
    $resp = $_.Exception.Response
    if ($resp) { return [int]$resp.StatusCode }
    return $_.Exception.Message
  }
}

function Test-Url([string]$url) {
  $result = ''
  for ($i = 0; $i -le $Retries; $i++) {
    $head = Get-StatusCode $url 'Head' @{}
    if ($head -is [int] -and $head -ge 200 -and $head -lt 400) { return @{ Ok = $true; Detail = "HEAD $head" } }
    $get = Get-StatusCode $url 'Get' @{ Range = 'bytes=0-0' }
    if ($get -is [int] -and $get -ge 200 -and $get -lt 400) { return @{ Ok = $true; Detail = "GET $get" } }
    $result = "HEAD $head, GET $get"
    if ($i -lt $Retries) { Start-Sleep -Seconds (2 * ($i + 1)) }
  }
  return @{ Ok = $false; Detail = $result }
}

$failed = 0
foreach ($url in $urls.Keys) {
  if (-not $url.StartsWith('https://')) {
    Write-Host "FAIL  $url  (not https)  [$($urls[$url] -join ', ')]"
    $failed++
    continue
  }
  $res = Test-Url $url
  if ($res.Ok) {
    Write-Host "ok    $url  ($($res.Detail))"
  } else {
    Write-Host "FAIL  $url  ($($res.Detail))  [$($urls[$url] -join ', ')]"
    $failed++
  }
}

Write-Host ''
Write-Host "$($urls.Count) URL(s) checked, $failed failed."
if ($failed -gt 0) { exit 1 }
exit 0

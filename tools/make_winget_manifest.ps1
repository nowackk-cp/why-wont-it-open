# Generates winget manifests for a published GitHub release.
#
#   ./tools/make_winget_manifest.ps1 -Version 0.2.0
#
# Downloads the release's WhyWontItOpen exe to compute its SHA256 and writes
# packaging/winget/<version>/*.yaml, ready to be submitted to
# https://github.com/microsoft/winget-pkgs (e.g. with `wingetcreate submit`).
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Repo = 'nowackk-cp/why-wont-it-open'
)

$ErrorActionPreference = 'Stop'
$id = 'nowackk-cp.WhyWontItOpen'
$manifestVersion = '1.12.0'
$tag = "v$Version"
$asset = "WhyWontItOpen-$tag-x86.exe"
$url = "https://github.com/$Repo/releases/download/$tag/$asset"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("wwio-" + [Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
  $file = Join-Path $tmp $asset
  Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
  $sha = (Get-FileHash $file -Algorithm SHA256).Hash.ToUpper()
} finally {
  Remove-Item -Recurse -Force $tmp
}

$out = Join-Path $PSScriptRoot "..\packaging\winget\$Version"
New-Item -ItemType Directory -Force $out | Out-Null
$header = "# yaml-language-server: `$schema=https://aka.ms/winget-manifest"

@"
$header.version.$manifestVersion.schema.json

PackageIdentifier: $id
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $manifestVersion
"@ | Set-Content -Encoding utf8 (Join-Path $out "$id.yaml")

@"
$header.installer.$manifestVersion.schema.json

PackageIdentifier: $id
PackageVersion: $Version
InstallerType: portable
Commands:
- whywontitopen
Installers:
- Architecture: x86
  InstallerUrl: $url
  InstallerSha256: $sha
ManifestType: installer
ManifestVersion: $manifestVersion
"@ | Set-Content -Encoding utf8 (Join-Path $out "$id.installer.yaml")

@"
$header.defaultLocale.$manifestVersion.schema.json

PackageIdentifier: $id
PackageVersion: $Version
PackageLocale: en-US
Publisher: nowackk-cp
PublisherUrl: https://github.com/nowackk-cp
PackageName: Why Won't It Open?
PackageUrl: https://github.com/$Repo
License: MIT
LicenseUrl: https://github.com/$Repo/blob/main/LICENSE
ShortDescription: Finds out why a Windows program won't start and shows the official fix.
Description: |-
  Drag a program that refuses to start onto the window. The tool finds missing or wrong components
  (Visual C++ runtimes, DirectX, .NET, 32/64-bit mix-ups, outdated DLLs, damaged files) and points to
  the official fix. It never runs the program it inspects and sends no data anywhere.
Tags:
- dll
- troubleshooting
- vcredist
- directx
- dotnet
- 0xc000007b
ReleaseNotesUrl: https://github.com/$Repo/releases/tag/$tag
ManifestType: defaultLocale
ManifestVersion: $manifestVersion
"@ | Set-Content -Encoding utf8 (Join-Path $out "$id.locale.en-US.yaml")

@"
$header.locale.$manifestVersion.schema.json

PackageIdentifier: $id
PackageVersion: $Version
PackageLocale: tr-TR
PackageName: Neden Açılmıyor?
ShortDescription: Bir Windows programının neden açılmadığını bulur ve resmi çözümü gösterir.
Description: |-
  Açılmayan programı pencereye sürükleyin. Araç eksik ya da yanlış bileşenleri (Visual C++ runtime'ları,
  DirectX, .NET, 32/64-bit karışıklığı, eski DLL'ler, bozuk dosyalar) bulur ve resmi çözümü gösterir.
  İncelediği programı asla çalıştırmaz ve hiçbir yere veri göndermez.
ManifestType: locale
ManifestVersion: $manifestVersion
"@ | Set-Content -Encoding utf8 (Join-Path $out "$id.locale.tr-TR.yaml")

Write-Host "Wrote manifests to $out (sha256 $sha)"
Write-Host "Validate with: winget validate --manifest `"$out`""

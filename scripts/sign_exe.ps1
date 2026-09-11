<#
.SYNOPSIS
  dist\InfraGuard\InfraGuard.exe 코드 서명 (Authenticode + RFC3161 타임스탬프).

.DESCRIPTION
  인증서는 조직이 발급받아 인증서 저장소(CurrentUser\My 또는 LocalMachine\My)에 넣어 둔 것을 지문(-Thumbprint)으로 고른다.
  -SelfSignedForTest 를 주면 테스트용 자체서명 인증서를 만들어 서명한다 — 반입 심사용이 아니라 서명 파이프라인 확인용.
  signtool.exe 는 Windows SDK 에 있다. 없으면 Set-AuthenticodeSignature(PowerShell 내장)로 폴백한다.

.EXAMPLE
  .\scripts\sign_exe.ps1 -Thumbprint 0123ABCD... -TimestampUrl http://timestamp.digicert.com
  .\scripts\sign_exe.ps1 -SelfSignedForTest
#>
param(
    [string]$Thumbprint,
    [switch]$SelfSignedForTest,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$Exe = "$PSScriptRoot\..\dist\InfraGuard\InfraGuard.exe"
)
$ErrorActionPreference = "Stop"
$Exe = (Resolve-Path $Exe).Path

if ($SelfSignedForTest) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=InfraGuard TEST (not for release)" `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(30)
    Write-Host "테스트 자체서명 인증서: $($cert.Thumbprint) (30일, 반입 심사에는 쓸 수 없음)"
} elseif ($Thumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    if (-not $cert) { throw "지문 $Thumbprint 인증서를 저장소에서 찾지 못함" }
} else {
    throw "-Thumbprint <지문> 또는 -SelfSignedForTest 중 하나 필요"
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($signtool) {
    & $signtool.FullName sign /sha1 $cert.Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Exe
    if ($LASTEXITCODE -ne 0) { throw "signtool 실패 ($LASTEXITCODE)" }
} else {
    Write-Host "signtool 없음 → Set-AuthenticodeSignature 폴백"
    $r = Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampUrl
    if ($r.Status -ne "Valid") { throw "서명 실패: $($r.Status) $($r.StatusMessage)" }
}
$sig = Get-AuthenticodeSignature $Exe
Write-Host ("서명 결과: {0}  서명자: {1}" -f $sig.Status, $sig.SignerCertificate.Subject)

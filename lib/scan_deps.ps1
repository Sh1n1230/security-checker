# osv-scanner による依存パッケージCVE検査 → reports/deps.json (正規化形式)
# 使い方: check.ps1 から $env:TARGET / $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$OUT = Join-Path $env:REPORT_DIR "deps.json"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

if (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue)) {
    Write-JsonUtf8 $OUT ([ordered]@{ category = "deps"; skipped = $true; findings = @() })
    Write-Output "スキップ (osv-scanner 未インストール)"
    exit 0
}

$RAW = Join-Path $env:REPORT_DIR "deps_raw.json"
& osv-scanner scan --recursive --format json "$env:TARGET" 2> $null | Out-File -FilePath $RAW -Encoding utf8

# 注: PowerShell の変数名は大文字小文字を区別しないため $RAW と別名にする
$data = $null
try {
    $data = Get-Content -Raw -Path $RAW | ConvertFrom-Json
} catch {
    $data = $null
}
if (-not $data -or -not ($data.PSObject.Properties.Name -contains "results")) {
    $data = [pscustomobject]@{ results = @() }
}
$resultsArr = @()
if ($data.results) { $resultsArr = @($data.results) }

$findings = @()
foreach ($res in $resultsArr) {
    $packages = @()
    if ($res.packages) { $packages = @($res.packages) }
    foreach ($p in $packages) {
        $vulns = @()
        if ($p.vulnerabilities) { $vulns = @($p.vulnerabilities) }
        foreach ($v in $vulns) {
            $sevRaw = $v.database_specific.severity
            if (-not $sevRaw) { $sevRaw = "MODERATE" }
            $s = $sevRaw.ToUpperInvariant()
            if ($s -eq "CRITICAL") { $mapped = "CRITICAL" }
            elseif ($s -eq "HIGH") { $mapped = "HIGH" }
            elseif ($s -eq "MODERATE" -or $s -eq "MEDIUM") { $mapped = "MEDIUM" }
            else { $mapped = "LOW" }

            $pkgName = $p.package.name
            if (-not $pkgName) { $pkgName = "?" }
            $pkgVersion = $p.package.version
            if (-not $pkgVersion) { $pkgVersion = "?" }

            $findings += [ordered]@{
                severity = $mapped
                message  = "$($pkgName): $($v.id)"
                location = "$pkgName@$pkgVersion"
            }
        }
    }
}

$result = [ordered]@{
    category = "deps"
    skipped  = $false
    findings = @($findings)
}
Write-JsonUtf8 $OUT $result

Write-Output "検出: $($findings.Count) 件"

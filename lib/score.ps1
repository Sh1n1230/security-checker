# 各スキャン結果を集計し100点満点のスコアを算出 → reports/summary.json
# 減点: CRITICAL -20 / HIGH -10 / MEDIUM -3 / LOW -1 (カテゴリ毎の減点上限 40)
# 使い方: check.ps1 から $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$SummaryPath = Join-Path $env:REPORT_DIR "summary.json"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

$penalty = @{ CRITICAL = 20; HIGH = 10; MEDIUM = 3; LOW = 1 }
$cap = 40

$order = @("secrets", "code", "deps", "config", "web")
$categories = @()

foreach ($name in $order) {
    $path = Join-Path $env:REPORT_DIR "$name.json"
    if (-not (Test-Path $path)) { continue }

    $c = Get-Content -Raw -Path $path | ConvertFrom-Json
    $findingsArr = @()
    if ($c.findings) { $findingsArr = @($c.findings) }

    # counts: severity ごとの件数。0件のseverityキーは含めない
    $counts = [ordered]@{}
    $grouped = $findingsArr | Group-Object -Property severity
    foreach ($g in $grouped) {
        $counts[$g.Name] = $g.Count
    }

    $deduction = 0
    if (-not $c.skipped) {
        $total = 0
        foreach ($f in $findingsArr) {
            if ($penalty.ContainsKey($f.severity)) {
                $total += $penalty[$f.severity]
            } else {
                $total += 1
            }
        }
        $deduction = if ($total -gt $cap) { $cap } else { $total }
    }

    $categories += [ordered]@{
        category  = $c.category
        skipped   = [bool]$c.skipped
        counts    = $counts
        findings  = @($findingsArr)
        deduction = $deduction
    }
}

$totalDeduction = 0
foreach ($cat in $categories) { $totalDeduction += $cat.deduction }
$raw = 100 - $totalDeduction
$score = if ($raw -lt 0) { 0 } else { $raw }

if ($score -ge 90) { $rank = "A" }
elseif ($score -ge 70) { $rank = "B" }
elseif ($score -ge 50) { $rank = "C" }
else { $rank = "D" }

$summary = [ordered]@{
    total_score = $score
    rank        = $rank
    categories  = $categories
}
Write-JsonUtf8 $SummaryPath $summary

# --- ターミナル表示 ---
function Get-NameJa($cat) {
    switch ($cat) {
        "secrets" { "シークレット" }
        "code"    { "コード解析  " }
        "deps"    { "依存CVE     " }
        "config"  { "設定ファイル" }
        "web"     { "Web検査     " }
        default   { $cat }
    }
}

Write-Output "==================== 結果 ===================="
Write-Output ("{0,-14} {1,5} {2,5} {3,5} {4,5}   {5}" -f "カテゴリ", "Crit", "High", "Med", "Low", "減点")
Write-Output "----------------------------------------------"
foreach ($cat in $categories) {
    if ($cat.skipped) {
        Write-Output ("{0,-14} {1}" -f (Get-NameJa $cat.category), "(スキップ)")
    } else {
        $critC = if ($cat.counts.Contains("CRITICAL")) { $cat.counts["CRITICAL"] } else { 0 }
        $highC = if ($cat.counts.Contains("HIGH")) { $cat.counts["HIGH"] } else { 0 }
        $medC  = if ($cat.counts.Contains("MEDIUM")) { $cat.counts["MEDIUM"] } else { 0 }
        $lowC  = if ($cat.counts.Contains("LOW")) { $cat.counts["LOW"] } else { 0 }
        Write-Output ("{0,-14} {1,5} {2,5} {3,5} {4,5}   -{5}" -f (Get-NameJa $cat.category), $critC, $highC, $medC, $lowC, $cat.deduction)
    }
}
Write-Output "----------------------------------------------"
Write-Output "総合スコア: $score / 100   ランク: $rank"
Write-Output "詳細: $SummaryPath"
Write-Output "=============================================="

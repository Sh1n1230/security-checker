<#
  危険なファイル権限(ACL)を検査する。読み取り専用。
  使い方: pwsh -File ./check_permissions.ps1 [対象ディレクトリ]  (省略時はホームの重要箇所のみ)
#>

param(
    [string]$Target = ""
)

$issues = 0

function Section([string]$name) {
    Write-Host ""
    Write-Host "--- $name ---"
}
function Report([string]$msg) {
    Write-Host "  ❌ $msg"
    $script:issues++
}

# 許可してよいアカウント(所有者・SYSTEM・Administrators・現在ユーザー)
$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$allowList = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    'CREATOR OWNER',
    $currentUser
)

function Test-DangerousAcl {
    param([string]$Path)
    $findings = @()
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $id = $ace.IdentityReference.Value
            if ($allowList -contains $id) { continue }
            $findings += $id
        }
    } catch {
        $findings += "(ACL取得エラー: $($_.Exception.Message))"
    }
    return $findings
}

Write-Host "=== ファイル権限(ACL)検査 ==="

# ~/.ssh
Section "~/.ssh"
$sshDir = Join-Path $HOME ".ssh"
if (Test-Path $sshDir) {
    $found = Test-DangerousAcl -Path $sshDir
    if ($found.Count -gt 0) {
        $names = $found -join ', '
        Report "~/.ssh に想定外のアカウントへの許可: $names → icacls `"$sshDir`" /inheritance:r /grant:r `"$env:USERNAME:F`" `"SYSTEM:F`""
        if ($names -match 'Everyone|Authenticated Users|BUILTIN\\Users') {
            Write-Host "     ⚠️  Everyone / Authenticated Users / BUILTIN\Users への許可は特に危険です"
        }
    }

    Get-ChildItem -Path $sshDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match '^(id_.*|.*\.pem|.*\.key)$' -and $_.Name -notmatch '\.pub$') {
            $keyFound = Test-DangerousAcl -Path $_.FullName
            if ($keyFound.Count -gt 0) {
                $names = $keyFound -join ', '
                Report "秘密鍵 $($_.FullName) に想定外のアカウントへの許可: $names → icacls `"$($_.FullName)`" /inheritance:r /grant:r `"$env:USERNAME:F`""
            }
        }
    }
    if ($issues -eq 0) { Write-Host "  ✅ 問題なし" }
} else {
    Write-Host "  (~/.ssh なし)"
}

# 認証情報系ファイル
Section "認証情報ファイル"
$credFiles = @(
    (Join-Path $HOME ".aws\credentials"),
    (Join-Path $HOME ".netrc"),
    (Join-Path $HOME ".npmrc"),
    (Join-Path $HOME ".pgpass"),
    (Join-Path $HOME ".docker\config.json")
)
$found = 0
foreach ($f in $credFiles) {
    if (-not (Test-Path $f -PathType Leaf)) { continue }
    $found = 1
    $danger = Test-DangerousAcl -Path $f
    if ($danger.Count -gt 0) {
        $names = $danger -join ', '
        Report "$f に想定外のアカウントへの許可: $names → icacls `"$f`" /inheritance:r /grant:r `"$env:USERNAME:F`""
    } else {
        Write-Host "  ✅ $f"
    }
}
if ($found -eq 0) { Write-Host "  (該当ファイルなし)" }

# 対象ディレクトリの検査
if ($Target -ne "") {
    Section "$Target 内の検査"
    if (Test-Path $Target) {
        # Everyone / Authenticated Users / BUILTIN\Users に書き込み許可があるファイルを検出
        $files = Get-ChildItem -Path $Target -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\\.git\\' } | Select-Object -First 500
        $checked = 0
        foreach ($f in $files) {
            if ($checked -ge 20) { break }
            try {
                $acl = Get-Acl -Path $f.FullName -ErrorAction Stop
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Allow' -and
                        $ace.IdentityReference.Value -match 'Everyone|Authenticated Users|BUILTIN\\Users' -and
                        $ace.FileSystemRights -match 'Write|FullControl|Modify') {
                        Report "誰でも書き込めるファイル: $($f.FullName) → icacls `"$($f.FullName)`" /remove `"$($ace.IdentityReference.Value)`""
                        $checked++
                        break
                    }
                }
            } catch { }
        }

        $secretFiles = Get-ChildItem -Path $Target -File -Recurse -ErrorAction SilentlyContinue | Where-Object {
            $_.FullName -notmatch '\\\.git\\' -and $_.Name -notmatch '\.example$' -and (
                $_.Name -eq '.env' -or $_.Name -like '.env.*' -or $_.Name -like '*.pem' -or $_.Name -like '*.key' -or $_.Name -like 'id_rsa*'
            )
        } | Select-Object -First 20
        foreach ($sf in $secretFiles) {
            Write-Host "  ⚠️  秘密情報の可能性: $($sf.FullName) (コミット対象になっていないか確認)"
        }
    } else {
        Write-Host "  (指定ディレクトリが存在しません: $Target)"
    }
}

Write-Host ""
if ($issues -gt 0) {
    Write-Host "結果: ❌ ${issues} 件の権限問題があります"
    exit 1
} else {
    Write-Host "結果: ✅ 権限の問題は見つかりませんでした"
    exit 0
}

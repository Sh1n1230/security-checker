<#
  Windows本体のセキュリティ設定を監査する。読み取り専用(設定は変更しない)。
  使い方: pwsh -File ./audit_windows.ps1
  管理者権限がない場合、一部セクションは「確認不可(要管理者権限)」と表示して続行する。
#>

$pass = 0
$fail = 0
$warn = 0

function Ok([string]$msg) {
    Write-Host "  ✅ $msg"
    $script:pass++
}
function Ng([string]$msg, [string]$advice) {
    Write-Host "  ❌ $msg"
    Write-Host "     → $advice"
    $script:fail++
}
function Warn([string]$msg, [string]$advice) {
    Write-Host "  ⚠️  $msg"
    Write-Host "     → $advice"
    $script:warn++
}
function Unknown([string]$msg) {
    Write-Host "  ⚠️  確認不可(要管理者権限): $msg"
    $script:warn++
}

Write-Host "=== Windows セキュリティ監査 ==="
Write-Host ""

# BitLocker
Write-Host "--- BitLocker(ディスク暗号化) ---"
try {
    $vols = Get-BitLockerVolume -ErrorAction Stop
    $osVol = $vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
    if (-not $osVol) { $osVol = $vols | Select-Object -First 1 }
    if ($osVol -and $osVol.ProtectionStatus -eq 'On') {
        Ok "BitLocker(ドライブ $($osVol.MountPoint))が有効"
    } elseif ($osVol) {
        Ng "BitLocker(ドライブ $($osVol.MountPoint))が無効" "設定 > プライバシーとセキュリティ > デバイスの暗号化 で有効化(盗難時のデータ保護)"
    } else {
        Warn "BitLocker対象ボリュームが見つかりません" "manage-bde -status で確認してください"
    }
} catch {
    try {
        $out = manage-bde -status 2>&1 | Out-String
        if ($out -match 'Protection Status:\s*Protection On') {
            Ok "BitLockerが有効(manage-bde -status で確認)"
        } elseif ($out -match 'Protection Status:\s*Protection Off') {
            Ng "BitLockerが無効(manage-bde -status で確認)" "manage-bde -on C: で有効化を検討(要管理者権限)"
        } else {
            Unknown "BitLocker状態(Get-BitLockerVolume / manage-bde とも失敗)"
        }
    } catch {
        Unknown "BitLocker状態"
    }
}

# Microsoft Defender
Write-Host ""
Write-Host "--- Microsoft Defender ---"
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.RealTimeProtectionEnabled) {
        Ok "リアルタイム保護が有効"
    } else {
        Ng "リアルタイム保護が無効" "設定 > プライバシーとセキュリティ > Windows セキュリティ > ウイルスと脅威の防止 で有効化"
    }
    $sigAge = $mp.AntivirusSignatureAge
    if ($null -ne $sigAge -and $sigAge -le 7) {
        Ok "ウイルス定義は最新(${sigAge}日前)"
    } elseif ($null -ne $sigAge) {
        Warn "ウイルス定義が古い(${sigAge}日前)" "Windows セキュリティ アプリから更新の確認を実行"
    } else {
        Unknown "ウイルス定義の鮮度"
    }
} catch {
    Unknown "Microsoft Defenderの状態(Get-MpComputerStatus 失敗。無効化されているか非対応環境の可能性)"
}

# ファイアウォール
Write-Host ""
Write-Host "--- ファイアウォール ---"
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $disabled = $profiles | Where-Object { -not $_.Enabled }
    if ($disabled.Count -eq 0) {
        Ok "ファイアウォールが全プロファイル(Domain/Private/Public)で有効"
    } else {
        $names = ($disabled | ForEach-Object { $_.Name }) -join ', '
        Ng "ファイアウォールが無効なプロファイルがあります: $names" "設定 > ネットワークとインターネット > ファイアウォールと保護 で有効化"
    }
} catch {
    Unknown "ファイアウォール状態"
}

# Windows Update
Write-Host ""
Write-Host "--- Windows Update ---"
try {
    $svc = Get-Service -Name wuauserv -ErrorAction Stop
    if ($svc.Status -eq 'Running') {
        Ok "Windows Update サービス(wuauserv)は稼働中"
    } else {
        Warn "Windows Update サービス(wuauserv)が停止中($($svc.Status))" "サービスを開始してください(要管理者権限の場合あり)"
    }
} catch {
    Unknown "Windows Update サービスの状態"
}
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $count = $result.Updates.Count
    if ($count -eq 0) {
        Ok "未適用の更新はありません"
    } else {
        Warn "未適用の更新が ${count} 件あります" "設定 > Windows Update から更新を適用してください"
    }
} catch {
    Write-Host "  ⚠️  未適用更新数の確認をスキップしました(COM検索に失敗、または時間がかかりすぎるため)"
}

# 画面ロック(スクリーンセーバー/自動ロック)
Write-Host ""
Write-Host "--- 画面ロック(自動ロックまでの時間) ---"
try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $val = Get-ItemProperty -Path $regPath -Name 'InactivityTimeoutSecs' -ErrorAction Stop
    $secs = $val.InactivityTimeoutSecs
    if ($secs -gt 0 -and $secs -le 900) {
        Ok "自動ロックまでの時間が ${secs} 秒に設定されています"
    } else {
        Warn "自動ロックまでの時間が長すぎます(${secs} 秒)" "15分(900秒)以内を推奨。グループポリシーまたはレジストリで設定"
    }
} catch {
    Warn "自動ロック(InactivityTimeoutSecs)が未設定です" "設定 > アカウント > サインイン オプション でスリープ/画面ロックの時間を設定してください"
}

# RDP
Write-Host ""
Write-Host "--- リモートデスクトップ(RDP) ---"
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 1) {
        Ok "リモートデスクトップ(RDP)は無効"
    } else {
        Warn "リモートデスクトップ(RDP)が有効です" "不要なら 設定 > システム > リモートデスクトップ で無効化"
    }
} catch {
    Unknown "リモートデスクトップの状態"
}

# WinRM
Write-Host ""
Write-Host "--- WinRM(リモート管理) ---"
try {
    $winrm = Get-Service -Name WinRM -ErrorAction Stop
    if ($winrm.Status -eq 'Running') {
        Warn "WinRM サービスが稼働中です" "不要ならリモート管理を無効化(Disable-PSRemoting -Force)"
    } else {
        Ok "WinRM サービスは停止中"
    }
} catch {
    Unknown "WinRM サービスの状態"
}

# SMB1
Write-Host ""
Write-Host "--- SMB1プロトコル ---"
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ($smb.EnableSMB1Protocol) {
        Ng "SMB1プロトコルが有効です" "脆弱な旧プロトコル。Set-SmbServerConfiguration -EnableSMB1Protocol `$false で無効化(要管理者権限)"
    } else {
        Ok "SMB1プロトコルは無効"
    }
} catch {
    Unknown "SMB1プロトコルの状態"
}

# スタートアップ項目(情報提供のみ)
Write-Host ""
Write-Host "--- スタートアップ項目 ---"
try {
    $items = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    $runCount = 0
    foreach ($k in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $k -ErrorAction Stop
            $runCount += ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count
        } catch { }
    }
    Write-Host "  ℹ️  Win32_StartupCommand: $($items.Count) 件 / Run キー: $runCount 件(情報提供。不審な項目がないか確認してください)"
} catch {
    Unknown "スタートアップ項目の列挙"
}

# UAC
Write-Host ""
Write-Host "--- UAC(ユーザーアカウント制御) ---"
try {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
    if ($uac.EnableLUA -eq 1) {
        Ok "UACが有効"
    } else {
        Ng "UACが無効です" "コントロールパネル > ユーザーアカウント > UAC設定 で有効化(要管理者権限)"
    }
} catch {
    Unknown "UACの状態"
}

# Guestアカウント
Write-Host ""
Write-Host "--- Guestアカウント ---"
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    if ($guest.Enabled) {
        Ng "Guestアカウントが有効です" "Disable-LocalUser -Name Guest で無効化(要管理者権限)"
    } else {
        Ok "Guestアカウントは無効"
    }
} catch {
    Unknown "Guestアカウントの状態"
}

Write-Host ""
Write-Host "結果: ✅ $pass  ❌ $fail  ⚠️ $warn"
if ($fail -gt 0) { exit 1 } else { exit 0 }

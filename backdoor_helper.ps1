# backdoor_helper.ps1 - IME SYSTEM backdoor block/unblock helper (elevated)
# usage: powershell -NoProfile -ExecutionPolicy Bypass -File backdoor_helper.ps1 -Action block|unblock
# called by backdoor.py via Start-Process -Verb RunAs (UAC), runs elevated.
param(
    [string]$Action = "block"
)
$ErrorActionPreference = "SilentlyContinue"

$HKLM_RUN = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

function Get-BackdoorServices {
    Get-CimInstance Win32_Service | Where-Object {
        $_.StartName -match "LocalSystem|SYSTEM" -and
        ($_.Name -match "Qianwen|qianwen" -or $_.PathName -match "QianwenIME")
    }
}

function Get-BackdoorRunValues {
    if (-not (Test-Path $HKLM_RUN)) { return @() }
    $p = Get-ItemProperty $HKLM_RUN
    $out = @()
    foreach ($prop in $p.PSObject.Properties) {
        if ($prop.Name -notlike "PS*" -and $prop.Name -match "Qianwen") {
            $out += [PSCustomObject]@{ Name = $prop.Name; Value = $prop.Value }
        }
    }
    return $out
}

function Get-BackdoorTasks {
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match "Qianwen" }
}

switch ($Action) {
    "block" {
        "=== 封堵服务 ==="
        foreach ($svc in Get-BackdoorServices) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled
            "  service: $($svc.Name) -> Disabled"
        }
        "=== 禁用开机自启 ==="
        foreach ($r in Get-BackdoorRunValues) {
            $newName = $r.Name + ".disabled_by_ime_manager"
            Set-ItemProperty $HKLM_RUN -Name $newName -Value $r.Value
            Remove-ItemProperty $HKLM_RUN -Name $r.Name -ErrorAction SilentlyContinue
            "  run: $($r.Name) -> disabled"
        }
        "=== 禁用计划任务 ==="
        foreach ($t in Get-BackdoorTasks) {
            Disable-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue | Out-Null
            "  task: $($t.TaskName) -> Disabled"
        }
        "BLOCK_DONE"
    }
    "unblock" {
        "=== 恢复服务自启 ==="
        foreach ($svc in Get-CimInstance Win32_Service | Where-Object {
            $_.Name -match "Qianwen|qianwen" -and $_.StartMode -eq "Disabled"
        }) {
            Set-Service -Name $svc.Name -StartupType Auto
            "  service: $($svc.Name) -> Auto"
        }
        "=== 恢复开机自启 ==="
        if (Test-Path $HKLM_RUN) {
            $p = Get-ItemProperty $HKLM_RUN
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -notlike "PS*" -and $prop.Name -like "*.disabled_by_ime_manager") {
                    $base = $prop.Name -replace "\.disabled_by_ime_manager$", ""
                    Set-ItemProperty $HKLM_RUN -Name $base -Value $prop.Value
                    Remove-ItemProperty $HKLM_RUN -Name $prop.Name -ErrorAction SilentlyContinue
                    "  run: $base -> restored"
                }
            }
        }
        "=== 启用计划任务 ==="
        foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match "Qianwen" -and $_.State -eq "Disabled"
        }) {
            Enable-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue | Out-Null
            "  task: $($t.TaskName) -> Enabled"
        }
        "UNBLOCK_DONE"
    }
    default {
        "usage: -Action block|unblock"
    }
}

# acl_helper.ps1 - IME order registry ACL helper
# usage: powershell -NoProfile -ExecutionPolicy Bypass -File acl_helper.ps1 -Action lock|unlock|status
# called silently by ime_core.py (CREATE_NO_WINDOW), no console flash.
param(
    [string]$Action = "status"
)
$ErrorActionPreference = "Stop"
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$ProfileRoot = "Registry::HKCU\Control Panel\International\User Profile"
$ProfilePath = "Registry::HKCU\Control Panel\International\User Profile\zh-Hans-CN"
$CtfPath = "Registry::HKCU\Software\Microsoft\CTF\SortOrder\AssemblyItem\0x00000804\{34745C63-B2F0-4784-8B67-5E12C8701A31}"

function Get-SubPath($Path) {
    return $Path -replace '^.*?Registry::HKCU\\', ''
}

function Open-KeyEx($Path) {
    $sub = Get-SubPath $Path
    $perm = [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions
    return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $perm)
}

function Get-DenyState($Path) {
    if (-not (Test-Path $Path)) { return @{ path = $Path; exists = $false; denies = @() } }
    $key = Open-KeyEx $Path
    try {
        $acl = $key.GetAccessControl()
        $denies = @($acl.Access | Where-Object {
            $_.AccessControlType -eq "Deny" -and $_.IdentityReference -eq $Identity
        } | ForEach-Object { $_.RegistryRights.ToString() })
        return @{ path = $Path; exists = $true; denies = $denies }
    } finally {
        $key.Close()
    }
}

function Add-Deny($Path, $Rights) {
    if (-not (Test-Path $Path)) { return }
    $key = Open-KeyEx $Path
    try {
        $acl = $key.GetAccessControl()
        $hit = @($acl.Access | Where-Object {
            $_.AccessControlType -eq "Deny" -and
            $_.IdentityReference -eq $Identity -and
            (($_.RegistryRights -band $Rights) -eq $Rights)
        })
        if ($hit.Count -eq 0) {
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($Identity, $Rights, "Deny")
            $acl.AddAccessRule($rule)
            $key.SetAccessControl($acl)
        }
    } finally {
        $key.Close()
    }
}

function Remove-Deny($Path, $Rights) {
    if (-not (Test-Path $Path)) { return }
    $key = Open-KeyEx $Path
    try {
        $acl = $key.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($Identity, $Rights, "Deny")
        $acl.RemoveAccessRule($rule) | Out-Null
        $key.SetAccessControl($acl)
    } finally {
        $key.Close()
    }
}

function Get-CtfSubkeys {
    if (-not (Test-Path $CtfPath)) { return @() }
    return @(Get-ChildItem $CtfPath | ForEach-Object { $_.PSPath })
}

switch ($Action) {
    "lock" {
        Add-Deny $ProfileRoot "SetValue,Delete"
        Add-Deny $ProfilePath "SetValue,Delete"
        Add-Deny $CtfPath "SetValue,Delete"
        foreach ($sub in Get-CtfSubkeys) { Add-Deny $sub "SetValue,Delete" }
        "LOCKED"
    }
    "unlock" {
        Remove-Deny $ProfileRoot "SetValue,Delete"
        Remove-Deny $ProfilePath "SetValue,Delete"
        Remove-Deny $CtfPath "SetValue,Delete"
        foreach ($sub in Get-CtfSubkeys) { Remove-Deny $sub "SetValue,Delete" }
        "UNLOCKED"
    }
    default {
        $root = Get-DenyState $ProfileRoot
        $profile = Get-DenyState $ProfilePath
        $ctf = Get-DenyState $CtfPath
        $subs = @(Get-CtfSubkeys | ForEach-Object { Get-DenyState $_ })
        $lockedSubs = @($subs | Where-Object { $_.denies -contains "SetValue, Delete" -or $_.denies -contains "Delete, SetValue" })
        $result = @{
            root_locked = ($root.denies -contains "SetValue, Delete" -or $root.denies -contains "Delete, SetValue")
            profile_locked = ($profile.denies -contains "SetValue, Delete" -or $profile.denies -contains "Delete, SetValue")
            ctf_locked = ($ctf.denies -contains "SetValue, Delete" -or $ctf.denies -contains "Delete, SetValue")
            subkeys_locked = ($subs.Count -gt 0) -and ($lockedSubs.Count -eq $subs.Count)
            keys = @($root) + @($profile) + @($ctf) + $subs
        }
        $result | ConvertTo-Json -Depth 4 -Compress
    }
}

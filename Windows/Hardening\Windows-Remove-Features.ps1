<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

https://github.com/microsoft/Intune-ACSC-Windows-Hardening-Guidelines/blob/main/scripts/UserApplicationHardening-RemoveFeatures.ps1
https://github.com/Azure/securedworkstation/blob/master/PAW/Scripts/PAW-DeviceConfig.ps1
#>

## Removing Powershell v 2.0
try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop

} catch {
    exit $LASTEXITCODE

}

## Removing .NET 3.5 (and below)
try {
    Disable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart

} catch {
    exit $LASTEXITCODE

}

## Removing Internet Explorer (for Windows 10)
if ((Get-WmiObject -class Win32_OperatingSystem).Caption -contains "Windows 10") {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart
    
    } catch {
    
        exit $LASTEXITCODE
    
    }

## Remove WorkFolders-Client
try {
    Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -ErrorAction Stop
} catch {
    exit $LASTEXITCODE
}

## Remove XPS Printing
try {
    Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -ErrorAction Stop
} catch {
    exit $LASTEXITCODE
}

## Remove Windows Media Player
try {
    Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -ErrorAction Stop
} catch {
    exit $LASTEXITCODE
}
}

# Require users to elevate when setting a network's location - prevent changing from Public to Private firewall profile
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation -Value 1 -PropertyType DWORD -Force

# Prevent saving of network credentials
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name DisableDomainCreds -Value 1 -PropertyType DWORD -Force

<#

.DESCRIPTION
Local Powershell Detection of currently configured and running Device Guard services.
Based on: https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#securityservicesconfigured

#>

# Verify pre-requisite winrm is running for the DeviceGuard cmdlet, then collect values.
$WinRM = (Get-Service -Name WinRM) 
if ($WinRM.Status -ne "Running") {Start-Service -Name WinRM}
$DGStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard)

# Security Services Configured
try {
    if ($DGStatus.SecurityServicesConfigured -contains 1){Write-Host "Credential Guard is configured."}
    if ($DGStatus.SecurityServicesConfigured -contains 2){Write-Host "Hypervisor Code Integrity is configured."}
    if ($DGStatus.SecurityServicesConfigured -contains 3){Write-Host "System Guard Secure Launch is configured."}
    if ($DGStatus.SecurityServicesConfigured -contains 4){Write-Host "SMM Firmware Measurement is configured."}
    }
catch [System.Exception] 
{
    Write-Warning "Failed to check status of Device Guard..."
    exit 1
}
catch {
Write-Error $_.Exception 
exit 1
}

# Security Services Running
    try {
    if ($DGStatus.SecurityServicesRunning -contains 1){Write-Host "Credential Guard is running."}
    if ($DGStatus.SecurityServicesRunning -contains 2){Write-Host "Hypervisor Code Integrity is running."}
    if ($DGStatus.SecurityServicesRunning -contains 3){Write-Host "System Guard Secure Launch is running."}
    if ($DGStatus.SecurityServicesRunning -contains 4){Write-Host "SMM Firmware Measurement is running."}
    }
catch [System.Exception] 
{
    Write-Warning "Failed to check status of Device Guard..."
    exit 1
}
catch {
Write-Error $_.Exception 
exit 1
}

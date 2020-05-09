if ($CredentialGuard) {
    $CredentialguardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    try {
        Write-LogEntry -Message "[Credential Guard]" 
        if ($CredentialGuardStatus.SecurityServicesRunning -like 1)
    {
        Write-Logentry -Message "Credential Guard Services are running."
    }
    else 
            {
                Write-LogEntry -Message "CredentialGuard Service are not running."
            }
            if ($CredentialGuardStatus.SecurityServicesConfigured -like 1)
            {
                Write-Logentry -Message "Credential Guard is configured."
            }
            else 
                    {
                        Write-LogEntry -Message "Credential Guard is not configured."
                    }
}
catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $CredentialGuard"
            }
        }

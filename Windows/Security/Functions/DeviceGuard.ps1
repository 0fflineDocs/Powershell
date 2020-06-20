Function Get-DeviceGuard(){
<#
.DESCRIPTION
Checks status of Device Guard
                
.EXAMPLE
Get-DeviceGuard
#>
        
#Variables
$DevGuardStatus = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$DevGuardInfo = Get-Computerinfo
        
        try {
            Write-LogEntry -Message "[Device Guard]" 
            if ($DevGuardStatus.CodeIntegrityPolicyEnforcementStatus -like 1)
        {
            Write-Logentry -Message "Device Guard Code Integrity Policy is activated and enforced."
        }
        else 
                {
                    Write-LogEntry -Message "Device Guard Code Integrity Policy is not activated."
                }
                if ($DevGuardStatus.SecurityServicesRunning -like 1)
                {
                    Write-Logentry -Message "Device Guard services are running."
                }
                else 
                        {
                            Write-LogEntry -Message "Device Guard services are not running."
                        }
                        if ($DevGuardInfo.DeviceGuardCodeIntegrityPolicyEnforcementStatus -eq "AuditMode")
                        {
                            Write-LogEntry -Message "Device Guard Code Integrity is currently in Audit Mode."
                        }
                        else
                                {
                                    
                                }
                        if ($DevGuardInfo.DeviceGuardSmartStatus -like 1)
                        {
                            Write-LogEntry -Message "Device Guard Smart Status is running."
                        }
                        else 
                                {
                                    Write-LogEntry -Message "Device Guard Smart Status is not running."
                                }        
                if ($DevGuardInfo.DeviceGuardSecurityServicesRunning -like "CredentialGuard")
                {
                    Write-LogEntry -Message "Credential Guard is running."
                }
                else
                        {
                            Write-LogEntry -Message "Credential Guard is not running."
                        }
                if ($DevGuardInfo.DeviceGuardSecurityServicesConfigured -like "CredentialGuard")
                {
                    Write-LogEntry -Message "Credential Guard is configured."
                }
                else
                        {
                            Write-LogEntry -Message "Credential Guard is not configured."
                        }
                 }
    catch [System.Exception] 
                {
                    Write-LogEntry -Message "Failed to check status of $DeviceGuard"
                }
            
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
}

if ($UEFISECBOOT) {
    $UEFISECBOOTStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    try {
        Write-LogEntry -Message "[SecureBoot & UEFI]"
        if ($UEFISECBOOTStatus -eq "True")
        {                
        Write-LogEntry -Message "UEFI & Secureboot enabled and configured correctly."
        }
            else  
            {
                Write-LogEntry -Message "UEFI and Secure Boot is not enabled correctly, please check the BIOS configuration."
            }
        }
        catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $UEFISECBOOT"
            }
        }

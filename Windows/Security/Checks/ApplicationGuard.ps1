if($ApplicationGuard){
    try {
    Write-LogEntry -Message "[Application Guard]"
    Write-LogEntry -Message "Checking if Windows Defender Application Guard is installed and enabled..." 
    $ApplicationGuardStatus = Get-WindowsOptionalFeature -Online -Featurename Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue
    if ($ApplicationGuardStatus.State = "Enabled") 
    {
    Write-Logentry -Message "Windows Defender Application Guard is installed and enabled."
    }
    else 
            {
                Write-LogEntry -Message "Windows Defender Application Guard is not enabled..."
            }
    }
            catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $ApplicationGuard"
            }
        }

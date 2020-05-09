if ($Defender) {
    Write-LogEntry -Message "[Defender]"
    $p = Get-MpPreference
    $c = Get-MpComputerStatus
    $p = @($p)
    $Defenderstatus = ($p += $c)
    try {
        $Service = get-service -DisplayName "Windows Defender Antivirus Service" -ErrorAction SilentlyContinue
        if ($Service.Status -eq "Running")
        {
        Write-LogEntry -Message "Windows Defender seems to be active and running in $PC" 
        }
        else 
        {
            Write-LogEntry -Message "Defender Service is not running..."
        }
        if ($Defenderstatus.AntivirusEnabled -eq "True") 
        {                
        Write-LogEntry -Message "Antivirus is Enabled"
        }
        else  
            {
                Write-LogEntry -Message "Antivirus is Disabled"
            }
        if ($Defenderstatus.AntispywareEnabled -eq "True") 
            {
                Write-LogEntry -Message "Antispyware is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "Antispyware is Disabled"
            }
        if ($Defenderstatus.RealTimeProtectionEnabled -eq "True") 
            {
                Write-LogEntry -Message "Real Time Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "Real Time Protection is Disabled"
            }    
        if ($Defenderstatus.IsTamperProtected -eq "True") 
            {
                Write-LogEntry -Message "Tamper Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "Tamper Protection is Disabled"
            }   
        if ($Defenderstatus.IoavProtectionEnabled -eq "True") 
            {
            Write-LogEntry -Message "IOAV Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "IOAV Protection is Disabled"
            }
        if ($Defenderstatus.EnableNetworkProtection -eq "1") 
            {
            Write-LogEntry -Message "Network Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "Network Protection is Disabled"
            }    
        }
        catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $Defender"
            }
        }

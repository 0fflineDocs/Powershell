if ($ATP) {
    $ATPStatus = get-service -displayname "Windows Defender Advanced Threat Protection Service" -ErrorAction SilentlyContinue
    try {
        Write-LogEntry -Message "[Defender ATP]"
    if ($ATPStatus.Status -eq "Running") 
    {
        Write-Logentry -Message "Defender ATP Service running."
    }
    else 
            {
                Write-LogEntry -Message "Defender ATP Service not running."
            }
}
catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $ATP"
            }
        }

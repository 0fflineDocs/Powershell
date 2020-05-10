Function Get-DefenderATP(){
<#
.DESCRIPTION
Checks Defender ATP service status.
    
.EXAMPLE
Get-DefenderATP
#>

#Variable
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
            
        catch {
            Write-Error $_.Exception 
            break
        }
}

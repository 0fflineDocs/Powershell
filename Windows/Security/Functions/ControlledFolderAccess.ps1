Function Get-ControlledFolderAccess(){
<#
.DESCRIPTION
Checks status of Controlled Folder Access
                        
.EXAMPLE
Get-ControlledFolderAccess
#>
                
#Variable
$p = Get-MpPreference -ErrorAction SilentlyContinue
$c = Get-MpComputerStatus -ErrorAction SilentlyContinue
$p = @($p)
$CFAstatus = ($p += $c)
    try {
        Write-LogEntry -Message "Checking status and configuration for Attack Surface Reduction..."
        if ($CFAstatus.EnableControlledFolderAccess -eq "2") 
    {
    Write-LogEntry -Message "Controlled Folder Access is enabled and in audit mode."
    }
    elseif ($CFAstatus.EnableControlledFolderAccess -eq "1") 
    {
        Write-LogEntry -Message "Controlled Folder Access is configured and enforced."
    }
        else 
        {
            Write-LogEntry -Message "Controlled Folder Access is not configured."
        }
}
catch [System.Exception] 
    {
        Write-LogEntry -Message "Failed to check status of $ControlledFolderAccess"
    }
catch {
Write-Error $_.Exception 
break
}
}

if($CredentialGuardPreReq){
try {
    Write-LogEntry -Message "[Credential Guard Pre-requisite]"
    $CGPrereq = Get-WindowsOptionalFeature -Online -Featurename Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($CGPrereq.state = "Enabled") 
    {
    Write-LogEntry -Message "Credential Guard prerequisite Hyper V is installed and enabled."
    }
    else 
    {
        Write-LogEntry -Message "Hyper-V All is not enabled/installed."
    }
}
    catch [System.Exception] 
    {
        Write-LogEntry -Message "Failed to check status of $CredentialGuardPreReq"
    }
}

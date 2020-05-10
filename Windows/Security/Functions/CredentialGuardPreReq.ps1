Function Get-CredentialGuardPreReq(){
        <#
        .DESCRIPTION
        Checks status of pre-requesits for Credential Guard
                
        .EXAMPLE
        Get-CredentialGuardPreReq
        #>
            #Variable
            $CGPrereq = Get-WindowsOptionalFeature -Online -Featurename Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
            
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
        
                        
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
}

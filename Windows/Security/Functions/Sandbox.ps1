Function Get-Sandbox(){
    <#
    .DESCRIPTION
    Checks if Sandbox is enabled and installed.
            
    .EXAMPLE
    Get-Sandbox
    #>
        #Variable
        $Sandboxstatus = Get-WindowsOptionalFeature -Online -Featurename Containers-DisposableClientVM -ErrorAction SilentlyContinue
        
        try {
            Write-LogEntry -Message "[Sandbox]"
            Write-LogEntry -Message "Checking if Windows Sandbox is installed and enabled..." 
          
            if ($Sandboxstatus.State = "Enabled") 
            {
            Write-Logentry -Message "Windows Sandbox is installed and enabled."
            }
            else 
                        {
                            Write-LogEntry -Message "Windows Sandbox is not enabled."
                        }
                }
                        catch [System.Exception] 
                        {
                            Write-LogEntry -Message "Failed to check status of $Sandbox"
                        }
                    
                catch {
                    Write-Error $_.Exception 
                    break
                }
}

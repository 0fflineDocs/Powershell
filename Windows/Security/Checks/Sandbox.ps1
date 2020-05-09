if($Sandbox){
        try {
        Write-LogEntry -Message "[Sandbox]"
        Write-LogEntry -Message "Checking if Windows Sandbox is installed and enabled..." 
        $Sandboxstatus = Get-WindowsOptionalFeature -Online -Featurename Containers-DisposableClientVM -ErrorAction SilentlyContinue
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
                }

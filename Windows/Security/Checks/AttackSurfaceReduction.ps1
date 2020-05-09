if ($AttackSurfaceReduction) {
            $p = Get-MpPreference -ErrorAction SilentlyContinue
            $c = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $p = @($p)
            $ASRstatus = ($p += $c)
            try {
                Write-LogEntry -Message "[Attack Surface Reduction]"
                if ($Defenderstatus.EnableNetworkProtection -eq "1") 
            {
            Write-LogEntry -Message "Network Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Message "Network Protection is Disabled"
            }    
                if ($ASRstatus.AttackSurfaceReductionRules_Actions -eq "2") 
                {
                    Write-LogEntry -Message "Attack Surface Reduction is configured and in audit mode."
                }
                elseif ($ASRstatus.AttackSurfaceReductionRules_Actions -eq "1")
                {
                    Write-LogEntry -Message "Attack Surface Reduction is configured and enforced."
                }
                else 
                {
                    Write-LogEntry -Message "Attack Surface Reduction is not configured."
                }
        }
        catch [System.Exception] 
            {
                Write-LogEntry -Message "Failed to check status of $AttackSurfaceReduction"
            }
        }

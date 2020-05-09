if ($Bitlocker) {
        Write-LogEntry -Message "[Bitlocker]" 
        $BitlockerStatus = Get-BitLockerVolume | select volumestatus,encryptionmethod,encryptionpercentage,mountpoint,VolumeType,ProtectionStatus,Keyprotector |? { $_.VolumeType -eq "OperatingSystem" -and $_.ProtectionStatus -eq "On" } -erroraction silentlycontinue
        switch ($BitlockerStatus.encryptionmethod) {
        Aes128 { $true }
        Aes256 { $true }
        Aes128Diffuser { $true }
        Aes256Diffuser { $true }
        XtsAes128 { $true }
        XtsAes256 { $true }
        Default { $false }
        }
            try {
                if ($BitlockerStatus.ProtectionStatus -eq "On")
                {                
                Write-LogEntry -Message "Bitlocker is enabled and configured correctly in $PC"
                Write-LogEntry -Message "Volumestatus: $($BitlockerStatus.Volumestatus)"
                Write-LogEntry -Message "Encryption Method: $($BitlockerStatus.Encryptionmethod)"
                Write-LogEntry -Message "Encryption Percentage: $($BitlockerStatus.EncryptionPercentage)"
                Write-LogEntry -Message "Mountpoint: $($BitlockerStatus.MountPoint)"
                Write-LogEntry -Message "Volumetype: $($BitlockerStatus.VolumeType)"
                Write-LogEntry -Message "Protectionstatus: $($BitlockerStatus.ProtectionStatus)"
                Write-LogEntry -Message "KeyProtector: $($BitlockerStatus.Keyprotector)"
                }
                    else  
                    {
                        Write-LogEntry -Message "Bitlocker is not enabled and not configured correctly in $PC"
                    }
                }
                catch [System.Exception] 
                    {
                        Write-LogEntry -Message "Failed to check status of $Bitlocker"
                    }
        }

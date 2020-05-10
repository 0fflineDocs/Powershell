Function Get-UefiSecureBoot(){
    <#
       .DESCRIPTION
       Checks if Secure Boot and UEFI is enabled and configured correctly in the device (based on powershell-command).
       
       .EXAMPLE
       Get-UefiSecureBoot
       #>
   
       #Variable
       $UEFISECBOOTStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
   
       try {
           Write-LogEntry -Message "[SecureBoot & UEFI]"
           if ($UEFISECBOOTStatus -eq "True")
           {                
           Write-LogEntry -Message "UEFI & Secureboot enabled and configured correctly."
           }
               else  
               {
                   Write-LogEntry -Message "UEFI and Secure Boot is not enabled correctly, please check the BIOS configuration."
               }
           }
           catch [System.Exception] 
               {
                   Write-LogEntry -Message "Failed to check status of $UEFISECBOOT"
               }
           
               
           catch {
               Write-Error $_.Exception 
               break
           }
}


<#PSScriptInfo

.VERSION 0.9

.GUID db087c94-c946-450f-81a6-568db251c536

.AUTHOR @0fflineDocs

.COMPANYNAME

.COPYRIGHT

.TAGS Endpoint Security, Endpoint Management

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
0.9 - Added Attack Surface Reduction Rules, AppLocker, Application Control.

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Security Posture is a powershell script for detecting status of different security related device features related to Microsoft 365 on Windows 10.
Currently the script detects the status of:

Operating System
TPM
Bitlocker
UEFI
SecureBoot
Defender
Cloud Protection Service (MAPS for Defender)
Block at first Sight
Defender for Endpoint
Application Guard
Windows Sandbox
Credential Guard
Device Guard
Attack Surface Reduction Rules
Controlled Folder Access
AppLocker
Application Control

Each area listed above can be called as individual functions or every function in the script can be called utilizing the -All switch.

The script will write entries to a log file residing at the client (C:\Windows\Temp\Client-SecurityPosture.log)
which preferably is read using CMTrace or OneTrace.

.EXAMPLE
Query using indvidual switches:
SecurityPosture -OS -TPMStatus -Bitlocker -UEFISECBOOT -Defender -DefenderforEndpoint -MAPS -ApplicationGuard -Sandbox -CredentialGuardPreReq -CredentialGuard -DeviceGuard -AttackSurfaceReduction -ControlledFolderAccess

Query every function using the -All switch:
SecurityPosture -All

Query using functions:
Get-BitLocker (returns information about Bitlocker in the PC)
Get-OperatingSystem (returns the current PCs OS-Edition, Architecture, Version, and Buildnumber) 

#> 

[cmdletbinding( DefaultParameterSetName = 'Security' )]
param(
[switch]$SecPos,
[switch]$Help,
[Switch]$All,
[switch]$OS,
[switch]$TPMStatus,
[switch]$Bitlocker,
[switch]$UEFISECBOOT,
[switch]$Defender,
[switch]$DefenderforEndpoint,
[switch]$MAPS,
[switch]$BAFS,
[switch]$ApplicationGuard,
[switch]$Sandbox,
[switch]$CredentialGuardPreReq,
[switch]$CredentialGuard,
[switch]$DeviceGuard,
[switch]$AttackSurfaceReduction,
[switch]$ControlledFolderAccess,
[switch]$AppLocker,
[switch]$ApplicationControl
)

#Global Variables
$ScriptVersion = "0.9"
$clientPath = "C:\Windows\Temp"
$PC = $env:computername 
$script:logfile = "$clientPath\Client-SecurityPosture.log"

#Check for Elevevation
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator"))
{
Write-Warning "This script needs to be run from an elevated PShell prompt.`nWould you kindly restart Powershell and launch it as Administrator before running the script again."
Write-Warning "Aborting Security Posture..."
Break
}

##############################################

<# FUNCTIONS #>

#Display descriptive information about the script and it's environment
Function SecPos {
    Clear-Host
    Write-Output "----------------------------------------------"
    Write-Output "           Script: Security Posture"
    Write-Output "----------------------------------------------"
    Write-Output "                 Version: $ScriptVersion"
    Write-Output "----------------------------------------------"
    Write-Output "      Logfiles will be genereated to:" 
    Write-Output "  $script:logfile"
    Write-Output "----------------------------------------------"
    Write-Output "        Help: 'Securityposture -Help'"
    Write-Output "----------------------------------------------"
    Write-Output "                 @0fflineDocs"
	Write-Output "----------------------------------------------"
}
    
Function Help {
Write-Host "[HELP]" -ForegroundColor Green
Write-Host "The script will write entries to a log file residing at the client at this location: (C:\Windows\Temp\Client-SecurityPosture.log)" `n -ForegroundColor White
Write-Host "You can query this script using indvidual switches and choose which ones you want to use:" -ForegroundColor Yellow 
Write-Host "SecurityPosture -OS -TPMStatus -Bitlocker -UEFISECBOOT -Defender -DefenderforEndpoint -MAPS -BAFS -ApplicationGuard -Sandbox -CredentialGuardPreReq -CredentialGuard -DeviceGuard -AttackSurfaceReduction -ControlledFolderAccess" `n -ForegroundColor White

Write-Host "You can also query every switch in this script using a global switch which includes all available options." -ForegroundColor Yellow
Write-Host "SecurityPosture -All" `n -ForegroundColor White
    
Write-Host "Each switch can also be queried separately as a function:" -ForegroundColor Yellow
Write-Host "Get-BitLocker (returns information about Bitlocker in the PC)" -ForegroundColor White
Write-Host "Get-OperatingSystem (returns the current PCs OS-Edition, Architecture, Version, and Buildnumber)" `n -ForegroundColor White
}    

function Write-LogEntry {
    [cmdletBinding()]
    param (
        [ValidateSet("Information", "Warning", "Error", "Success")]
        $Type = "Information",
        [parameter(Mandatory = $true)]
        $Message
    )
    switch ($Type) {
        'Error' {
            $severity = 1
            $fgColor = "Red"
            break;
        }
        'Warning' {
            $severity = 3
            $fgColor = "Yellow"
            break;
        }
        'Information' {
            $severity = 6
            $fgColor = "White"
            break;
        }
        'Success' {
            $severity = 6
            $fgColor = "Green"
            break;
        }
    }
    $dateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $dateTime.SetVarDate($(Get-Date))
    $utcValue = $dateTime.Value
    $utcOffset = $utcValue.Substring(21, $utcValue.Length - 21)
    $scriptName = (Get-PSCallStack)[1]
    $logLine = `
        "<![LOG[$message]LOG]!>" + `
        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($utcOffset)`" " + `
        "date=`"$(Get-Date -Format M-d-yyyy)`" " + `
        "component=`"$($scriptName.Command)`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$severity`" " + `
        "thread=`"$PID`" " + `
        "file=`"$($scriptName.ScriptName)`">";
        
    $logLine | Out-File -Append -Encoding utf8 -FilePath $logFile -Force
    Write-Host $Message -ForegroundColor $fgColor
}

Function Get-OperatingSystem(){
    <#
    .DESCRIPTION
    Checks the current PCs Operating System Edition, Architecture, Version, and Buildnumber.
    
    .EXAMPLE
    Get-OperatingSystem
    #>

    #Pre-Req for Get-CimInstance
    Get-Service -Name WinRM | Start-Service

    #Variable
    $win32os = Get-CimInstance Win32_OperatingSystem -computername $PC | Select-Object Caption, OSArchitecture, Version, Buildnumber, OperatingSystemSKU -ErrorAction silentlycontinue
    
    try {
            Write-LogEntry -Message "[Operating System]"
            $WindowsEdition = $win32os.Caption
            $OSArchitecture = $win32os.OSArchitecture 
            $WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"-ErrorAction silentlycontinue).ReleaseId 
            $BuildNumber = $win32os.Buildnumber
            Write-LogEntry -Message "OS-Edition is: $WindowsEdition"
            Write-LogEntry -Message "OS-Architecture is: $OSArchitecture"
            Write-LogEntry -Message "OS-Version is: $WindowsBuild"
            Write-LogEntry -Message "OS-Buildnumber is: $BuildNumber"
            }
        catch {
            Write-Error $_.Exception 
            break
        }
}

Function Get-TPMStatus(){
    <#
    .DESCRIPTION
    Checks if the TPM is enabled and configured correctly in the device.
    
    .EXAMPLE
    Get-TPMStatus
    #>

  #Variable
  $TPMStatus = (Get-TPM)

  try {
      Write-LogEntry -Message "[TPM]"
      if ($TPMStatus.TPMEnabled -contains "True")
      {                
      Write-LogEntry -Type Success -Message "TPM-chip is enabled in $PC"
      }
          else  
          {
              Write-LogEntry -Message "TPM is not enabled in $PC"
          }
          if ($TPMStatus.TPMActivated-contains "True")
          {                
          Write-LogEntry -Type Success -Message "TPM-chip is activated in $PC"
          }
          else  
          {
              Write-LogEntry -Message "TPM is not activated in $PC"
          }
    }
      catch [System.Exception] 
          {
              Write-LogEntry -Message "Failed to check status of $TPM"
          }
          catch {
              Write-Error $_.Exception 
              break
          }
}    

Function Get-Bitlocker(){
    <#
    .DESCRIPTION
    Get the BitlockerVolume and checks Volume status, Encryption method & percentage, mountpoint, the type of volume, the protection status of Bitlocker and it's Keyprotector.

    .EXAMPLE
    Get-Bitlocker
    #>

    $BitlockerStatus = Get-BitLockerVolume | Select-Object volumestatus,encryptionmethod,encryptionpercentage,mountpoint,VolumeType,ProtectionStatus,Keyprotector | Where-Object { $_.VolumeType -eq "OperatingSystem" -and $_.ProtectionStatus -eq "On" } -erroraction silentlycontinue
    try {
        Write-LogEntry -Message "[Bitlocker]" 
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
                Write-LogEntry -Type Success -Message "Bitlocker is enabled and configured correctly in $PC"
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
                        Write-LogEntry -Type Warning -Message "Bitlocker is not enabled and not configured correctly in $PC"
                    }
                }
                catch [System.Exception] 
                    {
                        Write-LogEntry -Type Error -Message "Failed to check status of $Bitlocker"
                    }
        }
        catch {
            Write-Error $_.Exception 
            break
        }
}

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
           Write-LogEntry -Message "[UEFI & SecureBoot]"
           if ($UEFISECBOOTStatus -eq "True")
           {                
           Write-LogEntry -Type Success -Message "UEFI & Secureboot enabled and configured correctly."
           }
               else  
               {
                   Write-LogEntry -Type Warning -Message "UEFI and Secure Boot is not enabled correctly, please check the BIOS configuration."
               }
           }
           catch [System.Exception] 
               {
                   Write-LogEntry -Type Error -Message "Failed to check status of $UEFISECBOOT"
               }
           
               
           catch {
               Write-Error $_.Exception 
               break
           }
}
   
Function Get-Defender(){
    <#
    .DESCRIPTION
    Resolves status of Windows Defender (Defender Service, Antivirus, Antispyware, Realtime Protection, Tamper Protection, IOAV Protection, Network Protection, PUAProtection).
    (IOAV = IE/EDGE Downloads and Outlook Express Attachments initiated)

    .EXAMPLE
    Get-Defender
    #>
   
    #Variable
    $Current = Get-Location
    $p = Get-MpPreference
    $c = Get-MpComputerStatus
    $p = @($p)
    $Defenderstatus = ($p += $c)
    Set-Location $Current
    try {
    Write-LogEntry -Message "[Defender]"
    $Service = get-service -DisplayName "Microsoft Defender Antivirus Service" -ErrorAction SilentlyContinue
    if ($Service.Status -eq "Running")
    {
    Write-LogEntry -Type Success -Message "Microsoft Defender Antivirus Service is active and running in $PC" 
    }
    else 
    {
        Write-LogEntry -Type Warning -Message "Defender Service is not running."
    }
    if ($Defenderstatus.AntivirusEnabled -eq "True") 
    {                
    Write-LogEntry -Type Success -Message "Antivirus is enabled."
    }
    else  
        {
            Write-LogEntry -Type Error -Message "Antivirus is disabled."
        }
        if ($Defenderstatus.AntispywareEnabled -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Antispyware is enabled."
        }
        else 
        {
            Write-LogEntry -Type Warning -Message "Antispyware is disabled."
        }
        if ($Defenderstatus.RealTimeProtectionEnabled -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Real Time Protection is enabled."
        }
            else 
            {
            Write-LogEntry -Type Warning -Message "Real Time Protection is disabled."
            }    
        if ($Defenderstatus.IsTamperProtected -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Tamper Protection is enabled."
        }
            else 
            {
            Write-LogEntry -Type Warning -Message "Tamper Protection is disabled."
            }   
        if ($Defenderstatus.IoavProtectionEnabled -eq "True") 
        {
        Write-LogEntry -Type Success -Message "IOAV Protection is enabled."
        }
            else 
            {
                Write-LogEntry -Type Warning -Message "IOAV Protection is disabled."
            }
        if ($Defenderstatus.EnableNetworkProtection -eq "1") 
            {
                Write-LogEntry -Type Success -Message "Network Protection is enabled."
            }
        else 
            {
                Write-LogEntry -Type Warning -Message "Network Protection is disabled."
            }    
        if ($Defenderstatus.PUAProtection -eq "2") 
            {
                Write-LogEntry -Type Warning -Message "Potentionally Unwanted Application Protection is in Audit mode."
            }
        elseif ($Defenderstatus.PUAProtection -eq "1") 
            {
                Write-LogEntry -Type Success -Message "Potentionally Unwanted Application Protection is enabled."
            }
        Else 
            {
                Write-LogEntry -Type Warning -Message "Potentionally Unwanted Application Protection is disabled."
            }
        }
        catch [System.Exception] 
            {
                Write-LogEntry -Type Error -Message "Failed to check status of $Defender"
            }
           catch {
               Write-Error $_.Exception 
               break
           }
}

Function Get-DefenderforEndpoint(){
<#
.DESCRIPTION
Checks Defender for Endpoint (formerly Defender ATP) service status.
    
.EXAMPLE
Get-DefenderforEndpoint
#>

#Variable
$ATPStatus = get-service -ServiceName "Sense" -ErrorAction SilentlyContinue
    try {
        Write-LogEntry -Message "[Defender for Endpoint]"
    if ($ATPStatus.Status -eq "Running") 
    {
        Write-Logentry -Type Success -Message "Defender for Endpoint Service is running."
    }
    else 
            {
                Write-LogEntry -Type Warning -Message "Defender for Endpoint Service is not running."
            }
}
catch [System.Exception] 
            {
                Write-LogEntry -Type Error -Message "Failed to check status of $ATP"
            }
            
        catch {
            Write-Error $_.Exception 
            break
        }
}

Function Get-MAPS(){
    <#
    .DESCRIPTION
    Checks MAPS for status of cloud-delivered protection
    URL: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/configure-network-connections-microsoft-defender-antivirus#validate-connections-between-your-network-and-the-cloud"
        
    .EXAMPLE
    Get-MAPS
    #>
    
    #Variable
    $Current = Get-Location
    $MAPS = Set-Location "C:\Program Files\Windows Defender\"
    $Test = (.\MpCmdRun.exe -validatemapsconnection)
    Set-Location $Current
  try {
    Write-LogEntry -Message "[MAPS - Cloud-delivered protection for Windows Defender]"  
    If ($Test -eq "ValidateMapsConnection successfully established a connection to MAPS")
{
Write-LogEntry -Type Success -Message "ValidateMapsConnection successfully established a connection to MAPS. 
Cloud-delivered protection is enabled."
}
else 
{
Write-LogEntry -Type Warning -Message "ValidateMapsConnection failed. Verify that you have enabled Cloud-delivered protection."
}
}
catch [System.Exception] 
            {
                Write-LogEntry -Type Error -Message "Failed to check status of $MAPS"
            }
            
        catch {
            Write-Error $_.Exception 
            break
        }
        
}

Function Get-BAFS(){
    <#
    .DESCRIPTION
    Checks if 'Block at first Sight' is configured for Windows Defender
    Source: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus?view=o365-worldwide

    .EXAMPLE
    Get-BAFS
    #>
    
    #Variable
    $Current = Get-Location
    $p = Get-MpPreference
    $c = Get-MpComputerStatus
    $p = @($p)
    $Defenderstatus = ($p += $c)
    Set-Location $Current

  try {
    Write-LogEntry -Message "[Block at first sight for Windows Defender]"  
    $p1 = ($Defenderstatus.DisableBlockAtFirstSeen -eq "0") 
    $p2 = ($Defenderstatus.CloudBlockLevel -eq "High") 
    $p3 = ($Defenderstatus.CloudExtendedTimeout  -eq "50") 
    $p4 = ($Defenderstatus.SubmitSamplesConsent  -eq "Always") 
    
    if ($p1 + $p2 + $p3 + $p4 -eq $True)
    {
        Write-LogEntry -Type Success -Message "Block at first sight is enabled and configured according to best practise."
    }
else 
    {
        Write-LogEntry -Type Warning -Message "Block at first sight is not configured for optimal security."
    }    
}
catch [System.Exception] 
            {
                Write-LogEntry -Type Error -Message "Failed to check status of $BAFS"
            }
            
        catch {
            Write-Error $_.Exception 
            break
        }
}

Function Get-ApplicationGuard(){
    <#
    .DESCRIPTION
    Checks Application Guard-status
        
    .EXAMPLE
    Get-ApplicationGuard
    #>
    
    #Variable
    $ApplicationGuardStatus = Get-WindowsOptionalFeature -Online -Featurename Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue

    try {
        Write-LogEntry -Message "[Application Guard]"
        if ($ApplicationGuardStatus.State = "Enabled") 
        {
        Write-Logentry -Type Success -Message "Windows Defender Application Guard is installed and enabled."
        }
        else 
                {
                    Write-LogEntry -Type Warning -Message "Windows Defender Application Guard is not enabled."
                }
        }
                catch [System.Exception] 
                {
                    Write-LogEntry -Type Error -Message "Failed to check status of $ApplicationGuard"
                }
            
            catch {
                Write-Error $_.Exception 
                break
            }
}

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
            if ($Sandboxstatus.State = "Enabled") 
            {
            Write-Logentry -Type Success -Message "Windows Sandbox is installed and enabled."
            }
            else 
                        {
                            Write-LogEntry -Type Warning -Message "Windows Sandbox is not enabled."
                        }
                }
                        catch [System.Exception] 
                        {
                            Write-LogEntry -Type Error -Message "Failed to check status of $Sandbox"
                        }
                    
                catch {
                    Write-Error $_.Exception 
                    break
                }
}

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
                Write-LogEntry -Type Success -Message "Credential Guard prerequisite Hyper V is installed and enabled."
                }
                else 
                {
                    Write-LogEntry -Type Warning -Message "Feature: Microsoft-Hyper-V-All is not installed/enabled."
                }
            }
                catch [System.Exception] 
                {
                    Write-LogEntry -Type Error -Message "Failed to check status of $CredentialGuardPreReq"
                }
        
                        
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
}
    
Function Get-CredentialGuard(){
        <#
        .DESCRIPTION
        Checks status of Credential Guard
                
        .EXAMPLE
        Get-CredentialGuard
        #>
        
        #Variable
        $CredentialguardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            try {
                Write-LogEntry -Message "[Credential Guard]" 
                if ($CredentialGuardStatus.SecurityServicesRunning -like 1)
            {
                Write-Logentry -Type Success -Message "Credential Guard Services are running."
            }
            else 
                    {
                        Write-LogEntry -Type Warning -Message "Credential Guard Services are not running."
                    }
                    if ($CredentialGuardStatus.SecurityServicesConfigured -like 1)
                    {
                        Write-Logentry -Type Success -Message "Credential Guard is configured."
                    }
                    else 
                            {
                                Write-LogEntry -Type Warning -Message "Credential Guard is not configured."
                            }
        }
        catch [System.Exception] 
                    {
                        Write-LogEntry -Type Error -Message "Failed to check status of $CredentialGuard"
                    }  
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
}

Function Get-DeviceGuard(){
<#
.DESCRIPTION
Checks status of Device Guard
                
.EXAMPLE
Get-DeviceGuard
#>
        
#Variables
$DevGuardStatus = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$DevGuardInfo = Get-Computerinfo | Select-Object -Property DeviceGuard*  
        try {
            Write-LogEntry -Message "[Device Guard]" 
            if ($DevGuardStatus.CodeIntegrityPolicyEnforcementStatus -like 1)
        {
            Write-Logentry -Type Success -Message "Device Guard Code Integrity Policy is activated and enforced."
        }
        else 
                {
                    Write-LogEntry -Type Warning -Message "Device Guard Code Integrity Policy is not activated."
                }
                if ($DevGuardStatus.SecurityServicesRunning -like 1)
                {
                    Write-Logentry -Type Success -Message "Device Guard services are running."
                }
                else 
                        {
                            Write-LogEntry -Type Warning -Message "Device Guard services are not running."
                        }
                        if ($DevGuardInfo.DeviceGuardCodeIntegrityPolicyEnforcementStatus -eq "AuditMode")
                        {
                            Write-LogEntry -Type Warning -Message "Device Guard Code Integrity is currently in Audit Mode."
                        }
                        else
                                {
                                    
                                }
                        if ($DevGuardInfo.DeviceGuardSmartStatus -like 1)
                        {
                            Write-LogEntry -Type Success -Message "Device Guard Smart Status is running."
                        }
                        else 
                                {
                                    Write-LogEntry -Type Warning -Message "Device Guard Smart Status is not running."
                                }        
                if ($DevGuardInfo.DeviceGuardSecurityServicesRunning -like "CredentialGuard")
                {
                    Write-LogEntry -Type Success -Message "Credential Guard is running."
                }
                else
                        {
                            Write-LogEntry -Type Warning -Message "Credential Guard is not running."
                        }
                if ($DevGuardInfo.DeviceGuardSecurityServicesConfigured -like "CredentialGuard")
                {
                    Write-LogEntry -Type Success -Message "Credential Guard is configured."
                }
                else
                        {
                            Write-LogEntry -Type Warning -Message "Credential Guard is not configured."
                        }
                 }
    catch [System.Exception] 
                {
                    Write-LogEntry -Type Error -Message "Failed to check status of $DeviceGuard"
                }
            
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
}
Function Get-AttackSurfaceReduction(){
<#
.DESCRIPTION
Checks status of AttackSurfaceReduction
                    
.EXAMPLE
Get-AttackSurfaceReduction
#>
            
#Variables
$Current = Get-Location
$RulesIds = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$RulesActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
$counter = 0
$RulesIdsArray = @()
$RulesIdsArray += $RulesIds
Set-Location $Current

    try { 
        Write-LogEntry -Message "[Attack Surface Reduction]"
        Write-Host "Attack Surface Reduction Rules are configured as follows:"
        ForEach ($j in $RulesIds)
        {
            ## Convert GUID into Rule Name
        If ($RulesIdsArray[$counter] -eq "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"){$RuleName = "Block all Office applications from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"){$RuleName = "Block execution of potentially obfuscated scripts"}
        ElseIf ($RulesIdsArray[$counter] -eq "56a863a9-875e-4185-98a7-b882c64b5ce5"){$RuleName = "Block abuse of exploited vulnerable signed drivers"}
        ElseIf ($RulesIdsArray[$counter] -eq "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"){$RuleName = "Block Win32 API calls from Office macro"}
        ElseIf ($RulesIdsArray[$counter] -eq "3B576869-A4EC-4529-8536-B80A7769E899"){$RuleName = "Block Office applications from creating executable content"}
        ElseIf ($RulesIdsArray[$counter] -eq "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"){$RuleName = "Block Office applications from injecting code into other processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "D3E037E1-3EB8-44C8-A917-57927947596D"){$RuleName = "Block JavaScript or VBScript from launching downloaded executable content"}
        ElseIf ($RulesIdsArray[$counter] -eq "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"){$RuleName = "Block executable content from email client and webmail"}
        ElseIf ($RulesIdsArray[$counter] -eq "01443614-cd74-433a-b99e-2ecdc07bfc25"){$RuleName = "Block executable files from running unless they meet a prevalence, age, or trusted list criteria"}
        ElseIf ($RulesIdsArray[$counter] -eq "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"){$RuleName = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"}
        ElseIf ($RulesIdsArray[$counter] -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c"){$RuleName = "Block process creations originating from PSExec and WMI commands"}
        ElseIf ($RulesIdsArray[$counter] -eq "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"){$RuleName = "Block untrusted and unsigned processes that run from USB"}
        ElseIf ($RulesIdsArray[$counter] -eq "26190899-1602-49e8-8b27-eb1d0a1ce869"){$RuleName = "Block Office communication applications from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"){$RuleName = "Block Adobe Reader from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "e6db77e5-3df2-4cf1-b95a-636979351e5b"){$RuleName = "Block persistence through WMI event subscription"}
        ElseIf ($RulesIdsArray[$counter] -eq "c1db55ab-c21a-4637-bb3f-a12568109d35"){$RuleName = "Use advanced protection against ransomware"}
       
        ## Check the Action type
        If ($RulesActions[$counter] -eq 0){$RuleAction = "Disabled"}
        ElseIf ($RulesActions[$counter] -eq 1){$RuleAction = "Block"}  
        ElseIf ($RulesActions[$counter] -eq 2){$RuleAction = "Audit"}
        
        ## Add Color to message based on Action type
        If ($RulesActions[$counter] -eq 1) {$FGColor = "Green"}
        ElseIf ($RulesActions[$counter] -eq 2) {$FGColor = "Yellow"}
        ElseIf ($RulesActions[$counter] -eq 0) {$FGColor = "Red"}
    
        ## Output Rule Id, Name and Action
        #Write-Host "Rule:" $RuleName
        Write-LogEntry -Message "Rule: $RuleName Action: $RuleAction"
        Write-Host "Action:" "[$RuleAction]" -ForegroundColor $FGColor
        $counter++
        
      
    }
}
catch [System.Exception] 
    {
        Write-LogEntry -Type Error -Message "Failed to check status of $AttackSurfaceReduction"
    }           
    catch {
            Write-Error $_.Exception 
            break
            }
}

Function Get-ControlledFolderAccess(){
<#
.DESCRIPTION
Checks status of Controlled Folder Access
                        
.EXAMPLE
Get-ControlledFolderAccess
#>
                
#Variable
$Current = Get-Location
$p = Get-MpPreference -ErrorAction SilentlyContinue
$c = Get-MpComputerStatus -ErrorAction SilentlyContinue
$p = @($p)
$CFAstatus = ($p += $c)
Set-Location $Current
    try {
        Write-LogEntry -Message "[Controlled Folder Access]"
        if ($CFAstatus.EnableControlledFolderAccess -eq "2") 
    {
    Write-LogEntry -Type Warning -Message "Controlled Folder Access is enabled and in audit mode."
    }
    elseif ($CFAstatus.EnableControlledFolderAccess -eq "1") 
    {
        Write-LogEntry -Type Success -Message "Controlled Folder Access is configured and enforced."
    }
        else 
        {
            Write-LogEntry -Type Warning -Message "Controlled Folder Access is not configured."
        }
}
catch [System.Exception] 
    {
        Write-LogEntry -Type Error -Message "Failed to check status of $ControlledFolderAccess"
    }
catch {
Write-Error $_.Exception 
break
}
}

Function Get-Applocker(){
<#
.DESCRIPTION
Counts and presents amount of AppLocker events in client, based on Get-AppLockerFileInformation
            
.EXAMPLE
Get-Applocker
#>

#Variable
$ApplockerAudited = (Get-AppLockerFileInformation -EventLog -EventType Audited).count
$ApplockerAllowed = (Get-AppLockerFileInformation -eventlog -EventType Allow).count
$ApplockerDenied = (Get-AppLockerFileInformation -eventlog -EventType Denied).count
    
            try {
                Write-LogEntry -Message "[AppLocker]"
                Write-LogEntry -Message "Audited AppLocker Events: $AppLockerAudited"
                Write-LogEntry -Message "Allowed AppLocker Events: $AppLockerAllowed"
                Write-LogEntry -Message "Denied AppLocker Events: $AppLockerDenied"
        }
        catch [System.Exception] 
                    {
                        Write-LogEntry -Type Error -Message "Failed to check status of AppLocker"
                    }
                    
                catch {
                    Write-Error $_.Exception 
                    break
                }
}

Function Get-ApplicationControl(){
<#
.DESCRIPTION
Checks status of Application Control based on events in Microsoft-Windows-CodeIntegrity/Operational

.EXAMPLE
Get-ApplicationControl
#>

#Variable
$ApplicationControlStatus = (Get-Winevent  Microsoft-Windows-CodeIntegrity/Operational)
        
                try {
                    Write-LogEntry -Message "[Application Control]"
                    if ($ApplicationControlStatus.id -eq "3076") 
                    {
                    Write-LogEntry -Type Warning -Message "Application Control is enabled and in audit mode."
                    }
                    elseif ($ApplicationControlStatus.id -eq "3077") 
                    {
                        Write-LogEntry -Type Success -Message "Application Control is configured and enforced."
                    }
                        else 
                        {
                            Write-LogEntry -Type Warning -Message "Application Control is not configured."
                        }
            }
            catch [System.Exception] 
                        {
                            Write-LogEntry -Type Error -Message "Failed to check status of Application Control"
                        }
                        
                    catch {
                        Write-Error $_.Exception 
                        break
                    }
    }

<################ SWITCHES #################>
if($SecPos){
SecPos
}

if($Help){
Help
}

if($OS){
Get-OperatingSystem
}

if ($TPM) {
Get-TPMStatus
}

if ($Bitlocker) {
Get-Bitlocker       
}

if ($UEFISECBOOT) {
Get-UefiSecureBoot
}

if ($Defender) {
Get-Defender
}

if ($DefenderforEndpoint) {
Get-DefenderforEndpoint
}

if ($MAPS) {
Get-MAPS
}

if ($BAFS) {
    Get-BAFS
}

if($ApplicationGuard){
Get-ApplicationGuard
}

if($Sandbox){
Get-Sandbox
}

if($CredentialGuardPreReq){
Get-CredentialGuardPreReq
}
    
if ($CredentialGuard) {
Get-CredentialGuard
}

if ($DeviceGuard) {
Get-DeviceGuard
}

if ($AttackSurfaceReduction) {
Get-AttackSurfaceReduction
}           
                 
if ($ControlledFolderAccess) {
Get-ControlledFolderAccess
}

if ($AppLocker) {
    Get-AppLocker
}

if ($ApplicationControl) {
    Get-ApplicationControl
}


if ($All) {
SecPos
Get-OperatingSystem
Get-TPMStatus
Get-Bitlocker       
Get-UefiSecureBoot
Get-Defender
Get-DefenderforEndpoint
Get-MAPS
Get-BAFS
Get-ApplicationGuard
Get-Sandbox
Get-CredentialGuardPreReq
Get-CredentialGuard
Get-DeviceGuard
Get-AttackSurfaceReduction
Get-ControlledFolderAccess
Get-AppLocker
Get-ApplicationControl
}

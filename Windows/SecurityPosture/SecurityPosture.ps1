<#PSScriptInfo

.VERSION 0.1

.GUID df2a92c8-29c5-4dc9-bb3e-2f934b536a9b

.AUTHOR @0fflineDocs

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
CloudProtectionService (MAPS for Defender)
DefenderATP
ApplicationGuard
Windows Sandbox
Credential Guard
Device Guard
Attack Surface Reduction
Controlled Folder Access

Each area listed above can be called as individual functions or every function in the script can be called utilizing the -All switch.

The script will write entries to a log file residing at the client (C:\Windows\Temp\Client-SecurityPosture.log)
which preferably is read using CMTrace or OneTrace.

.EXAMPLES
Query using indvidual switches:
.\SecurityPosture.ps1 -OS -TPM -Bitlocker -UEFISECBOOT -Defender -DefenderATP -MAPS -ApplicationGuard -Sandbox -CredentialGuardPreReq -CredentialGuard -DeviceGuard -AttackSurfaceReduction -ControlledFolderAccess

Query every function using the -All switch:
.\SecurityPosture.ps1 -All

Query using functions:
Get-BitLockerVolume (returns information about Bitlocker in the PC)
Get-OperatingSystem (returns the current PCs OS-Edition, Architecture, Version, and Buildnumber)

#>

[cmdletbinding( DefaultParameterSetName = 'Security' )]
param(
[switch]$SecPos,
[Switch]$All,
[switch]$OS,
[switch]$TPM,
[switch]$Bitlocker,
[switch]$UEFISECBOOT,
[switch]$Defender,
[switch]$DefenderATP,
[switch]$MAPS,
[switch]$ApplicationGuard,
[switch]$Sandbox,
[switch]$CredentialGuardPreReq,
[switch]$CredentialGuard,
[switch]$DeviceGuard,
[switch]$AttackSurfaceReduction,
[switch]$ControlledFolderAccess)

#Global Variables
$ScriptVersion = "0.1"
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
    Write-Output ">          Script: Security Posture"
    Write-Output "----------------------------------------------"
    Write-Output ">               Version: $ScriptVersion"
    Write-Output "----------------------------------------------"
    Write-Output ">      Logfiles will be genereated to:" 
    Write-Output ">    $script:logfile"
    Write-Output "----------------------------------------------"
    Write-Output "> Help: 'Get-Command -Module SecurityPosture'"
    Write-Output "----------------------------------------------"
    Write-Output ">               @0fflineDocs"
	Write-Output "----------------------------------------------"
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

Function Get-TPM(){
    <#
    .DESCRIPTION
    Checks if the TPM is enabled and configured correctly in the device.
    
    .EXAMPLE
    Get-TPM
    #>

    #Variable
    $TPMStatus = (Get-CIMClass -Namespace ROOT\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm -ErrorAction silentlycontinue)
        try {
           
            try {
                Write-LogEntry -Message "***[TPM]***"
                if ($TPMStatus.isenabled -eq "True")
                {                
                Write-LogEntry -Type Success -Message "TPM-chip is enabled and configured correctly in $PC"
                }
                    else  
                    {
                        Write-LogEntry -Type Warning -Message "TPM is not enabled and not configured correctly in $PC"
                    }
                }
                catch [System.Exception] 
                    {
                        Write-LogEntry -Type Error -Message "Failed to check status of $TPM"
                    }
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
    $p = Get-MpPreference
    $c = Get-MpComputerStatus
    $p = @($p)
    $Defenderstatus = ($p += $c)
   
    try {
    Write-LogEntry -Message "[Defender]"
    $Service = get-service -DisplayName "Windows Defender Antivirus Service" -ErrorAction SilentlyContinue
    if ($Service.Status -eq "Running")
    {
    Write-LogEntry -Type Success -Message "Windows Defender Antivirus Service is active and running in $PC" 
    }
    else 
    {
        Write-LogEntry -Type Warning -Message "Defender Service is not running..."
    }
    if ($Defenderstatus.AntivirusEnabled -eq "True") 
    {                
    Write-LogEntry -Type Success -Message "Antivirus is Enabled"
    }
    else  
        {
            Write-LogEntry -Type Error -Message "Antivirus is Disabled"
        }
        if ($Defenderstatus.AntispywareEnabled -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Antispyware is Enabled"
        }
        else 
        {
            Write-LogEntry -Type Warning -Message "Antispyware is Disabled"
        }
        if ($Defenderstatus.RealTimeProtectionEnabled -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Real Time Protection is Enabled"
        }
            else 
            {
            Write-LogEntry -Type Warning -Message "Real Time Protection is Disabled"
            }    
        if ($Defenderstatus.IsTamperProtected -eq "True") 
        {
            Write-LogEntry -Type Success -Message "Tamper Protection is Enabled"
        }
            else 
            {
            Write-LogEntry -Type Warning -Message "Tamper Protection is Disabled"
            }   
        if ($Defenderstatus.IoavProtectionEnabled -eq "True") 
        {
        Write-LogEntry -Type Success -Message "IOAV Protection is Enabled"
        }
            else 
            {
                Write-LogEntry -Type Warning -Message "IOAV Protection is Disabled"
            }
        if ($Defenderstatus.EnableNetworkProtection -eq "1") 
            {
                Write-LogEntry -Type Success -Message "Network Protection is Enabled"
            }
        else 
            {
                Write-LogEntry -Type Warning -Message "Network Protection is Disabled"
            }    
        if ($Defenderstatus.PUAProtection -eq "1") 
            {
                Write-LogEntry -Type Success -Message "Potentionally Unwanted Application-protection is enabled."
            }
        if ($Defenderstatus.PUAProtection -eq "2") 
            {
                Write-LogEntry -Type Warning -Message "Potentionally Unwanted Application-protection is in audit-mode."
            }
        Else 
            {
                Write-LogEntry -Type Warning -Message "Potentionally Unwanted Application-protection is disabled."
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
        Write-Logentry -Type Success -Message "Defender ATP Service is running."
    }
    else 
            {
                Write-LogEntry -Type Warning -Message "Defender ATP Service is not running."
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
    $MAPS = Set-Location "C:\Program Files\Windows Defender\"
    $Test = (.\MpCmdRun.exe -validatemapsconnection)
        
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
        Write-LogEntry -Message "Checking if Windows Defender Application Guard is installed and enabled..." 
        if ($ApplicationGuardStatus.State = "Enabled") 
        {
        Write-Logentry -Type Success -Message "Windows Defender Application Guard is installed and enabled."
        }
        else 
                {
                    Write-LogEntry -Type Warning -Message "Windows Defender Application Guard is not enabled..."
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
            Write-LogEntry -Message "Checking if Windows Sandbox is installed and enabled..." 
          
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
                    Write-LogEntry -Type Warning -Message "Hyper-V All is not enabled/installed."
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
            
#Variable
$p = Get-MpPreference -ErrorAction SilentlyContinue
$c = Get-MpComputerStatus -ErrorAction SilentlyContinue
$p = @($p)
$ASRstatus = ($p += $c)

    try {
        Write-LogEntry -Message "[Attack Surface Reduction]"
        if ($Defenderstatus.EnableNetworkProtection -eq "1") 
    {
    Write-LogEntry -Type Success -Message "Network Protection is Enabled"
    }
else 
    {
        Write-LogEntry -Type Warning -Message "Network Protection is Disabled"
    }    
        if ($ASRstatus.AttackSurfaceReductionRules_Actions -eq "2") 
        {
            Write-LogEntry -Type Warning -Message "Attack Surface Reduction is configured and in audit mode."
        }
        elseif ($ASRstatus.AttackSurfaceReductionRules_Actions -eq "1")
        {
            Write-LogEntry -Type Success -Message "Attack Surface Reduction is configured and enforced."
        }
        else 
        {
            Write-LogEntry -Type Warning -Message "Attack Surface Reduction is not configured."
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
$p = Get-MpPreference -ErrorAction SilentlyContinue
$c = Get-MpComputerStatus -ErrorAction SilentlyContinue
$p = @($p)
$CFAstatus = ($p += $c)
    try {
        Write-LogEntry -Message "Checking status and configuration for Attack Surface Reduction..."
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

<################ SWITCHES #################>
if($SecPos){
SecPos
}

if($OS){
Get-OperatingSystem
}

if ($TPM) {
Get-Tpm
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

if ($DefenderATP) {
Get-DefenderATP
}

if ($MAPS) {
Get-MAPS
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

if ($All) 
{
    SecPos
    Get-OperatingSystem
    Get-Tpm
    Get-Bitlocker       
    Get-UefiSecureBoot
    Get-Defender
    Get-DefenderATP
    Get-MAPS
    Get-ApplicationGuard
    Get-Sandbox
    Get-CredentialGuardPreReq
    Get-CredentialGuard
    Get-DeviceGuard
    Get-AttackSurfaceReduction
    Get-ControlledFolderAccess
}

$PC = $ENV:COMPUTERNAME
Write-Host "[Secured-Core PC - Local Assessment]" -ForegroundColor Yellow
Write-Host "Secured-Core PC: https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure"

# Pre-Requisite gor Get-CimInstance
Get-Service -Name WinRM | Start-Service

# Operating System Information
$Win32OS = Get-CimInstance Win32_OperatingSystem -computername $PC | Select-Object Caption, OSArchitecture, Version, Buildnumber, OperatingSystemSKU -ErrorAction silentlycontinue
try {
        Write-Host "[Operating System]" -ForegroundColor Yellow
        $WindowsEdition = $Win32OS.Caption 
        $OSArchitecture = $Win32OS.OSArchitecture 
        $WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"-ErrorAction silentlycontinue).ReleaseId 
        $BuildNumber = $Win32OS.Buildnumber
        Write-Host "OS-Edition is: $WindowsEdition" 
        Write-Host "OS-Architecture is: $OSArchitecture" 
        Write-Host "OS-Version is: $WindowsBuild" 
        Write-Host "OS-Buildnumber is: $BuildNumber" 
        Get-Service -Name WinRM | Stop-Service 
        }
    catch {
        Write-Error $_.Exception 
        break
    }

# Bitlocker Information
$BitlockerStatus = Get-BitLockerVolume | Select-Object volumestatus,encryptionmethod,encryptionpercentage,mountpoint,VolumeType,ProtectionStatus,Keyprotector | Where-Object { $_.VolumeType -eq "OperatingSystem" -and $_.ProtectionStatus -eq "On" } -erroraction silentlycontinue
try {
    Write-Host "[Bitlocker]" -ForegroundColor Yellow
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
            Write-Host "Bitlocker is enabled and configured correctly in $PC" -ForegroundColor Green
            Write-Host "Volumestatus: $($BitlockerStatus.Volumestatus)" 
            Write-Host "Encryption Method: $($BitlockerStatus.Encryptionmethod)"
            Write-Host "Encryption Percentage: $($BitlockerStatus.EncryptionPercentage)"
            Write-Host "Mountpoint: $($BitlockerStatus.MountPoint)" 
            Write-Host "Volumetype: $($BitlockerStatus.VolumeType)" 
            Write-Host "Protectionstatus: $($BitlockerStatus.ProtectionStatus)" 
            Write-Host "KeyProtector: $($BitlockerStatus.Keyprotector)" 
            }
                else  
                {
                    Write-Host "Bitlocker is not enabled and not configured correctly in $PC" -ForegroundColor Red
                }
            }
            catch [System.Exception] 
                {
                    Write-Host "Failed to check status of $Bitlocker" -ForegroundColor Red
                }
    }
    catch {
        Write-Error $_.Exception 
        break
    }

# Status of the TPM
$TPMStatus = (Get-TPM)
  try {
      Write-host "[TPM]" -ForegroundColor Yellow
      if ($TPMStatus.TPMEnabled -contains "True")
      {                
      Write-Host "TPM-chip is enabled in $PC" -ForegroundColor Green
      }
          else  
          {
              Write-Host "TPM is not enabled in $PC"
              Write-Host "https://support.microsoft.com/en-us/windows/enable-tpm-2-0-on-your-pc-1fd5a332-360d-4f46-a1e7-ae6b0c90645c"
          }
          if ($TPMStatus.TPMActivated-contains "True")
          {                
          Write-Host "TPM-chip is activated in $PC" -ForegroundColor Green
          }
          else  
          {
              Write-Host "TPM is not activated in $PC" -ForegroundColor Red
          }
    }
    catch [System.Exception] 
    {
        Write-Host "Failed to check status of $TPM"
    }
    catch {
        Write-Error $_.Exception 
        break
    }

# TPM Version
$TPMVersion = (Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm)
try {
    Write-Host "[TPM Version]" -ForegroundColor Yellow
    if ($TPMVersion.SpecVersion.StartsWith("2.0"))
    {                
    Write-Host "TPM version is 2.0" -ForegroundColor Green
    }
    else  
    {
        Write-Host "TPM version seems to be lower than 2.0, you need to turn on TPM 2.0 or this hardware might be outdated."
        Write-Host "https://support.microsoft.com/en-us/windows/enable-tpm-2-0-on-your-pc-1fd5a332-360d-4f46-a1e7-ae6b0c90645c"
    }
}
catch [System.Exception] 
{
  Write-Host "Failed to check status of $TPMVersion"
}
catch {
  Write-Error $_.Exception 
  break
}

# UEFI / Secure Boot
$UEFISECBOOTStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue 
   try {
        Write-Host "[UEFI & SecureBoot]" -ForegroundColor Yellow
        if ($UEFISECBOOTStatus -eq "True")
        {                
        Write-Host "UEFI & Secureboot is enabled and configured correctly." -ForegroundColor Green
        }
            else  
            {
                Write-Host "UEFI and Secure Boot is not enabled correctly, please check the BIOS configuration." -ForegroundColor Red
                Write-Host "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/disabling-secure-boot?view=windows-11#re-enable-secure-boot"
            }
        }
        catch [System.Exception] 
            {
                Write-Host "Failed to check status of $UEFISECBOOT"
            }
        catch {
            Write-Error $_.Exception 
            break
        }

# Kernel DMA Protection
$bootDMAProtectionCheck =
@"
  namespace SystemInfo
    {
      using System;
      using System.Runtime.InteropServices;

      public static class NativeMethods
      {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            /// </summary>
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
          SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
          IntPtr SystemInformation,
          Int32 SystemInformationLength,
          out Int32 ReturnLength);

        public static byte BootDmaCheck() {
          Int32 result;
          Int32 SystemInformationLength = 1;
          IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
          Int32 ReturnLength;

          result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

          if (result == 0) {
            byte info = Marshal.ReadByte(SystemInformation, 0);
            return info;
          }

          return 0;
        }
      }
    }
"@

Add-Type -TypeDefinition $bootDMAProtectionCheck

# returns true or false depending on whether Kernel DMA Protection is on or off
$KernelDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

try {
    Write-Host "[Kernel DMA Protection]" -ForegroundColor Yellow
    if ($KernelDMAProtection -eq "True")
    {                
    Write-Host "Kernel DMA Protection is enabled and configured correctly." -ForegroundColor Green
    }
        else  
        {
            Write-Host "UEFI and Secure Boot is not enabled correctly, please check the system configuration." -ForegroundColor Red
            Write-Host "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt"
        }
    }
    catch [System.Exception] 
        {
            Write-Host "Failed to check status of $KernelDMAProtection"
        }
    catch {
        Write-Error $_.Exception 
        break
    }

# System Guard Secure Launch   
Write-Host "[System Guard Secure Launch]" -ForegroundColor Yellow
Write-Host "(Requires Hypervisor Code Integrity, Credential Guard, and Virtualization Based Security)" 

$DevGuardStatus = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$DevGuardInfo = Get-Computerinfo | Select-Object -Property DeviceGuard*  
        try {
        Write-Host "[Hyper Visor Code Integrity]" -ForegroundColor Yellow
            if ($DevGuardStatus.CodeIntegrityPolicyEnforcementStatus -like 1)
        {
            Write-Host "Device Guard Code Integrity Policy is activated and enforced." -ForegroundColor Green
        }
        else 
                {
                    Write-Host "Device Guard Code Integrity Policy is not activated." -ForegroundColor Red
                    Write-Host "https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity"
                }
                if ($DevGuardStatus.SecurityServicesRunning -like 1)
                {
                    Write-Host "Device Guard services are running." -ForegroundColor Green
                }
                else 
                        {
                            Write-Host "Device Guard services are not running." -ForegroundColor Red
                        }
                        if ($DevGuardInfo.DeviceGuardCodeIntegrityPolicyEnforcementStatus -eq "AuditMode")
                        {
                            Write-Host "Device Guard Code Integrity is currently in Audit Mode." -ForegroundColor Green
                        }
                        else
                                {
                                    
                                }
                        if ($DevGuardInfo.DeviceGuardSmartStatus -like 1)
                        {
                            Write-Host "Device Guard Smart Status is running." -ForegroundColor Green
                        }
                        else 
                                {
                                    Write-Host "Device Guard Smart Status is not running." -ForegroundColor Red
                                }  
                Write-Host "[Credential Guard]" -ForegroundColor Yellow               
                if ($DevGuardInfo.DeviceGuardSecurityServicesRunning -like "CredentialGuard")
                {
                    Write-Host "Credential Guard is running." -ForegroundColor Green
                }
                else
                        {
                            Write-Host "Credential Guard is not running." -ForegroundColor Red
                            Write-Host "https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#enable-windows-defender-credential-guard"
                        }
                if ($DevGuardInfo.DeviceGuardSecurityServicesConfigured -like "CredentialGuard")
                {
                    Write-Host "Credential Guard is configured." -ForegroundColor Green
                }
                else
                        {
                            Write-Host "Credential Guard is not configured." -ForegroundColor Red
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

### Security Posture 

#### Install-Script -Name SecurityPosture

#### This is a powershell script for detecting status of different security-related features regarding Microsoft 365 on Windows 10. 
Currently the script detects the status of:   

- Operating System
- TPM
- Bitlocker
- UEFI
- SecureBoot 
- Defender
- CloudProtectionService (MAPS for Defender)
- DefenderATP
- ApplicationGuard
- Windows Sandbox
- Credential Guard
- Device Guard
- Attack Surface Reduction
- Controlled Folder Access  

The script will write entries to a log file residing at the client (*C:\Windows\Temp\Client-SecurityPosture.log*)   
which preferably is read using [CMTrace](https://www.microsoft.com/en-us/download/confirmation.aspx?id=50012) or [OneTrace](https://docs.microsoft.com/en-us/mem/configmgr/core/support/support-center-onetrace).

The script itself can be found and installed via [Powershell Gallery](https://www.powershellgallery.com/packages/SecurityPosture)  

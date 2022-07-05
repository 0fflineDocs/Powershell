Param(
[switch]$PreReq,
[switch]$Windows10VM,
[switch]$Windows11VM
)

# Global Variables
$HyperV = "C:\Hyper-V"
$VMs = "C:\Hyper-V\VMs"
$ISOFolder = "C:\ISO"
$Windows10 = "C:\ISO\W10-21H1-June-Business.ISO"
$Windows11 = "C:\ISO\W11-21H1-June-Business.ISO"

#Pre-Req
if ($PreReq) {
    # Check for elevation
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
    Write-Warning "You need to run this script from an elevated Powershell session!`nPlease run Powershell as an Administrator and try again."
    Write-Warning "Exiting script..."
    Break
    }
  
    if (!(Test-Path $HyperV)) {new-item -ItemType Directory -Force -Path $HyperV | Out-Null}
    if (!(Test-Path $VMs)) {new-item -ItemType Directory -Force -Path $VMs | Out-Null}
    if (!(Test-Path $ISOFolder)) {new-item -ItemType Directory -Force -Path $ISOFolder | Out-Null}

    Write-Host "##########################################" -ForegroundColor Green
    Write-Host "Hyper-V Location: $HyperV" -ForegroundColor White
    Write-Host "VMs Location: $VMs" -ForegroundColor White
    Write-Host "ISO Folder: $ISOFolder" -ForegroundColor White
    Write-Host "Windows 10: $Windows10" -ForegroundColor White
    Write-Host "Windows 11: $Windows11" -ForegroundColor White
    Write-Host "##########################################" -ForegroundColor Green
}

# Provision a Windows 10 Virtual Machine
if ($Windows10VM) {
    Write-Host "Provision a Windows 10 Virtual Machine..."
    Write-Host "Enter name of the VM, then press enter..."
    $VMNAME = Read-Host
    try {
                    Write-Host "Checking if VM $VMNAME already exist..."
                    $CheckVM = (Get-VM -Name $VMNAME -ErrorAction SilentlyContinue) 
                    if ($null -eq $CheckVM) {
                    Write-Host "Creating $VMNAME"
                    
                    #Create virtual machine
                    New-VHD -Dynamic -Path ($VHD = "C:\Hyper-V\VMs\$VMNAME.vhdx") -SizeBytes 90GB
                    New-VM -Generation 2 -Name $VMNAME -NoVHD -Version 10.0 -Verbose
                    Add-VMHardDiskDrive -VMNAME $VMNAME -Path $VHD -Verbose
                    Set-VMMemory -VMNAME $VMNAME -StartupBytes 3GB -DynamicMemoryEnabled $false
                    Set-VMProcessor -VMNAME $VMNAME -Count 2 -ExposeVirtualizationExtensions $true
                    
                    #Mount, Initialize and Dismount virtual hard disk
                    Mount-VHD -Path $VHD
                    Get-Disk | Where-Object partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle MBR -PassThru |
                    New-Partition -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel “OSDisk” -Confirm:$false
                    Dismount-VHD -Path $VHD 

                    # Security Settings + Integration services
                    $owner = Get-HgsGuardian UntrustedGuardian    
                    $kp = New-HgsKeyProtector -Owner $owner -AllowUntrustedRoot
                    Set-VMKeyProtector -VMNAME $VMNAME -KeyProtector $kp.RawData -Verbose
                    Enable-VMTPM -VMNAME $VMNAME -Verbose
                    Enable-VMIntegrationService -VMNAME $VMNAME -Name "Guest Service Interface"
                    Connect-VMNetworkAdapter -VMNAME $VMNAME -SwitchName "Default Switch"
                        
                    #Connect ISO
                    Add-VMDvdDrive -VMNAME $VMNAME -Verbose
                    Set-VMDvdDrive -VMNAME $VMNAME -Path $Windows10 -Verbose
                    Set-VM -Name $VMNAME -AutomaticCheckpointsEnabled $false

                    #Correct Boot Order
                    $DVD = Get-VMDVDDrive -VMNAME $VMNAME
                    Set-VMFirmware -VMNAME $VMNAME -FirstBootDevice $dvd

                }
                else  
                {
                    Write-Host "VM $VMNAME already created, moving on..."
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "Failed to check status of the VM..."
            }
}

# Provision a Windows 11 Virtual Machine
if ($Windows11VM) {
    Write-Host "Provision a Windows 11 Virtual Machine..."
    Write-Host "Enter name of the VM, then press enter..."
    $VMNAME = Read-Host
    try {
                    Write-Host "Checking if VM $VMNAME already exist..."
                    $CheckVM = (Get-VM -Name $VMNAME -ErrorAction SilentlyContinue) 
                    if ($null -eq $CheckVM) {
                    Write-Host "Creating $VMNAME"
                    
                    #Create virtual machine
                    New-VHD -Dynamic -Path ($VHD = "C:\Hyper-V\VMs\$VMNAME.vhdx") -SizeBytes 100GB
                    New-VM -Generation 2 -Name $VMNAME -NoVHD -Version 10.0 -Verbose
                    Add-VMHardDiskDrive -VMNAME $VMNAME -Path $VHD -Verbose
                    Set-VMMemory -VMNAME $VMNAME -StartupBytes 4GB -DynamicMemoryEnabled $false
                    Set-VMProcessor -VMNAME $VMNAME -Count 3 -ExposeVirtualizationExtensions $true
                    
                    #Mount, Initialize and Dismount virtual hard disk
                    Mount-VHD -Path $VHD
                    Get-Disk | Where-Object partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle MBR -PassThru |
                    New-Partition -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel “OSDisk” -Confirm:$false
                    Dismount-VHD -Path $VHD 
                    
                    # Security Settings + Integration services
                    $owner = Get-HgsGuardian UntrustedGuardian    
                    $kp = New-HgsKeyProtector -Owner $owner -AllowUntrustedRoot
                    Set-VMKeyProtector -VMNAME $VMNAME -KeyProtector $kp.RawData -Verbose
                    Enable-VMTPM -VMNAME $VMNAME -Verbose
                    Enable-VMIntegrationService -VMNAME $VMNAME -Name "Guest Service Interface"
                    Connect-VMNetworkAdapter -VMNAME $VMNAME -SwitchName "Default Switch"
                        
                    #Connect ISO
                    Add-VMDvdDrive -VMNAME $VMNAME -Verbose
                    Set-VMDvdDrive -VMNAME $VMNAME -Path $Windows11 -Verbose
                    Set-VM -Name $VMNAME -AutomaticCheckpointsEnabled $false

                    #Correct Boot Order
                    $DVD = Get-VMDVDDrive -VMNAME $VMNAME
                    Set-VMFirmware -VMNAME $VMNAME -FirstBootDevice $dvd

                }
                else  
                {
                    Write-Host "VM $VMNAME already created, moving on..."
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "Failed to check status of the VM..."
            }
}

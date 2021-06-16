#Update PowershellGet to latest
Set-ExecutionPolicy Bypass
Install-PackageProvider -Name NuGet -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PowerShellGet -Force
Update-Module -Name PowerShellGet

Install-Module -Name AzureAD -Force -Scope AllUsers
Install-Module -Name AzureADPreview -AllowClobber -Force -Scope AllUsers
Install-Module -Name DCToolBox -Force -Scope AllUsers
Install-Module -Name MSOnline -Force -Scope AllUsers
Install-Module -Name SharepointOnline -Force -Scope AllUsers
Install-Module -Name MicrosoftTeams -Force -Scope AllUsers
Install-module -Name ExchangeOnline -Force -Scope AllUsers 
Install-Module -Name PSReadline -force -Scope AllUsers
Install-Module -Name Microsoft.Graph.Intune -Force -Scope AllUsers
Install-Module -Name WindowsAutopilotIntune -Force -Scope AllUsers
Install-Module -Name Convert-WindowsImage -Force -Scope AllUsers 
Install-Module -Name IntuneWin32App -Force -Scope AllUsers
Install-Module -Name Terminal-Icons -Force -Scope AllUsers
Install-Module -Name Oh-my-posh -Force -Scope AllUsers
Set-ExecutionPolicy Restricted

#LEGACY
Install-Module ActiveDirectory -force
Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell (CLIENTOS)
Install-WindowsFeature RSAT-AD-PowerShell (SERVEROS)

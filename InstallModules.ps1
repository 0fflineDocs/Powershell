#Modules
Install-Module PowerShellGet -force
Set-ExecutionPolicy Bypass
Import-Module PowerShellGet

Install-Module ActiveDirectory -force
Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell (CLIENTOS)
Install-WindowsFeature RSAT-AD-PowerShell (SERVEROS)
Install-Module AzureAD -force
Install-Module AzureADPreview -AllowClobber -force
Install-Module Microsoft.Graph.Intune -force
Install-Module WindowsAutopilotIntune -force
Install-Module -Name IntuneWin32App
Install-module -Name Exchangeonline -Force
Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope AllUsers -MinimumVersion 0.3374.9 -AllowClobber -Confirm:$false -Force
Install-Module PSReadline -AllowPrerelease -force

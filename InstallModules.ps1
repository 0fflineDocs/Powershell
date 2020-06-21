#Modules
Install-Module PowerShellGet -force
Install-Module ActiveDirectory -force
Install-Module AzureAD -force
Install-Module Microsoft.Graph.Intune -force
Install-Module WindowsAutopilotIntune -force
Install-Module -Name IntuneWin32App
Install-module -Name Exchangeonline -Force
Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope AllUsers -MinimumVersion 0.3374.9 -AllowClobber -Confirm:$false -Force -AcceptLicense

#Scripts
Install-Script AutopilotDeviceSync
Install-Script -Name Get-LatestAdobeReaderInstaller

#Variables
$win32os = Get-CimInstance Win32_OperatingSystem -computername $PC | select Name, OSArchitecture, Version, Buildnumber, OperatingSystemSKU -ErrorAction silentlycontinue
$WindowsEdition = $win32os.Name
$OSArchitecture = $win32os.OSArchitecture 
$WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"-ErrorAction silentlycontinue).ReleaseId 
$BuildNumber = $win32os.Buildnumber

#Products
Clients OS-Edition is: $WindowsEdition
Clients OS-Architecture is: $OSArchitecture
Clients OS-Version is: $WindowsBuild
Clients OS-Buildnumber is: $BuildNumber

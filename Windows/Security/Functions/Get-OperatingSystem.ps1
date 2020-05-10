Function Get-OperatingSystem(){
    <#
    .DESCRIPTION
    Checks the current PCs Operating System Edition, Architecture, Version, and Build.
    
    .EXAMPLE
    Get-OperatingSystem
    #>

    #Variable
    $win32os = Get-CimInstance Win32_OperatingSystem -computername $PC | Select-Object Name, OSArchitecture, Version, Buildnumber, OperatingSystemSKU -ErrorAction silentlycontinue
        try {
            Write-LogEntry -Message "[Operating System]"
            $win32os = Get-CimInstance Win32_OperatingSystem -computername $PC | Select-Object Name, OSArchitecture, Version, Buildnumber, OperatingSystemSKU -ErrorAction silentlycontinue
            $WindowsEdition = $win32os.Name
            $OSArchitecture = $win32os.OSArchitecture 
            $WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"-ErrorAction silentlycontinue).ReleaseId 
            $BuildNumber = $win32os.Buildnumber
            Write-LogEntry -Message "Clients OS-Edition is: $WindowsEdition"
            Write-LogEntry -Message "Clients OS-Architecture is: $OSArchitecture"
            Write-LogEntry -Message "Clients OS-Version is: $WindowsBuild"
            Write-LogEntry -Message "Clients OS-Buildnumber is: $BuildNumber"
            }
        catch {
            Write-Error $_.Exception 
            break
        }
}

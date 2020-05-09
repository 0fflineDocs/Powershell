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

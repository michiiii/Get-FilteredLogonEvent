<#
.SYNOPSIS
Retrieves logon events from the Windows Security log, excluding LogonType 3 and the "SYSTEM" account.

This can be interesting if you want to know if service accounts connect regulary to your machine in an insecure manner.

.DESCRIPTION
This function queries the Windows Security log for logon events (EventID 4624) from the past number of specified days.
By default, it retrieves events from the last 2 days.
The function will exclude events with a LogonType of 3 and where the AccountName is "SYSTEM".

.PARAMETER days
Specifies the number of days back from which logon events should be retrieved. Default is 2 days.

.EXAMPLE
Get-LogonEventDetails

This command retrieves logon events from the last 2 days.

.EXAMPLE
Get-LogonEventDetails -days 5

This command retrieves logon events from the last 5 days. Excluding network logons as they don´t leave reusable credentials
#>

function Get-LogonEventDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, HelpMessage="Number of days back from which logon events should be retrieved.")]
        [int]$days = 2  # Default is 2 days (48 hours)
    )

    # Define the event ID
    $EventID = 4624
    $seconds = 86400000 * $days

    # Query the security log for the specified event ID within the time span
    $Events = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=$EventID) and TimeCreated[timediff(@SystemTime) <= ($seconds)]]]"

    # Parse the results and display the desired fields
    $Events | ForEach-Object {
        $XmlData = [xml]$_.ToXml()

        # Extract relevant data from the XML
        $Date = $_.TimeCreated
        $LogonType = ($XmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $AccountName = ($XmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'

        # Skip events with LogonType 3 or AccountName "SYSTEM"
        if ($LogonType -eq "3" -or $AccountName -eq "SYSTEM") { return }

        $AccountDomain = ($XmlData.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'

        # Return the extracted data as a custom object
        [PSCustomObject]@{
            'Date'         = $Date
            'LogonType'    = $LogonType
            'AccountName'  = $AccountName
            'AccountDomain'= $AccountDomain
        }
    } | Format-Table -AutoSize
}

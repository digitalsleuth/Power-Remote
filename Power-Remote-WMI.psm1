     <#

    .SYNOPSIS
        This powershell script has been designed to remotely connect to a machine (to which you have administrative access already), and
        retrieve several forensic artifacts including USBSTOR info from the registry, arpcache, dnscache, event logs etc.
        Currently the only thing required is the hostname (as indicated under Parameters) and the script will run all functions.
        When the module is imported, each function can be run separately, or altogether using the 'rra' alias or RemoteRunAll

        TODO:
            Add sqlite3.exe for csv import to db
            Add portable db viewer.
            Add choice of export (if var = csv, then $format = ....)

    .DESCRIPTION


    .NOTES
        Version        : 2.0
        Author         : Fetchered
        Prerequisite   : winpmem.exe binary in $location\bin folder
                       : Join-Object.ps1 (forked from github.com/ramblingcookiemonster/powershell)


    .PARAMETER ComputerName

            The host you want to run the remote acquisition against - either an IP address or Computer Name, in double quotes " "
            or a txt file (including path if not in current directory) containing the hostnames or IP's of the hosts you wish to run
            the function against.

    .PARAMETER Credential

            At a basic level, the username for which you will provide authorized credentials.
            Required when the current user credentials are unauthorized on the remote machine.
            If not provided, you will be prompted to enter them, if required.

    .PARAMETER HKCR, HKCU, HKLM, HKU, HKCC
            Specifically for the Get-RemoteRegistryKey function, will allow you to choose the Hive containing the
            registry key you wish to query

    .PARAMETER Subkey
            Specifically for the Get-RemoteRegistryKey function, is the full path, minus the actual key, you wish to query
            For example, if you want the SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation Key, the subkey will be:
            "SOFTWARE\Microsoft\Windows\CurrentVersion\", in quotes

    .PARAMETER Value
            Specifically for the Get-RemoteRegistry function, is the actual key for which you wish to attain the value
            For example, if you want the SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation key, the value will be:
            "OEMInformation", in quotes
    .Example

        Get-RemoteUSB
        Actual command:
        Get-RemoteUSB -ComputerName "IP/Hostname" -Credential "Username"
        Get-RemoteUSB -ComputerName "IP/Hostname"
        Get-RemoteUSB -ComputerName "hosts.txt" -Credential "Username"
        Get-RemoteUSB -ComputerName "hosts.txt"

        Get-RemoteRegistryKey
        Actual command:
        Get-RemoteRegistryKey -ComputerName "IP/Hostname" -Credential "Username" -HKLM -Subkey "SOFTWARE\Microsoft\Windows\CurrentVersion\" -Value "OEMInformation"
        Get-RemoteRegistryKey -ComputerName "hosts.txt" -HKLM -Subkey "SOFTWARE\Microsoft\Windows\CurrentVersion\" -Value "OEMInformation"


    #>
#Module Parameters
[CmdletBinding()]
param (
    [Parameter(ParameterSetName='ComputerName', Position=0)]
    $ComputerName = "127.0.0.1",
    [Parameter(ParameterSetName='Credential')]
    [ValidateNotNull()]
    [pscredential]
    [System.Management.Automation.Credential()]
    $Credential = [pscredential]::Empty
)
[System.String]$location = (get-location)
$TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
[System.String]$htmlHeader = @'
<!--mce:0-->
<style>BODY{font-family: Arial; font-size: 10pt;}
TABLE{border: 1px solid black; border-collapse: collapse;}
TH{border: 1px solid black; background: #dddddd; padding: 5px;}
TD{border: 1px solid black; padding: 5px;}</style>
'@

#Progress Bar
function Write-ProgressHelper {
#Borrowed from https://www.adamtheautomator.com/building-progress-bar-powershell-scripts/
param ([int]$StepNumber,[string]$StatusMessage)
Write-Progress -Activity 'Processing...' -Status $StatusMessage -PercentComplete (($StepNumber / $steps) * 100)
}
$script:steps = ([System.Management.Automation.PsParser]::Tokenize((Get-Content "$PSScriptRoot\$($MyInvocation.MyCommand.Name)"), [ref]$null) | Where-Object { $_.Type -eq 'Command' -and $_.Content -eq 'Write-ProgressHelper' }).Count
$stepCounter = 0

#Diagnostic Timer
function Get-RemoteTimer($ComputerName,$Credential){
#Diagnostics for timing the running of all functions against the host
$timer = [system.diagnostics.stopwatch]::StartNew()
Write-Output "Started at" ((Get-Date) -split " ")[1]
rra $ComputerName $Credential
$timer.Stop()
Write-Output "Finished at" ((Get-Date) -split " ")[1]
Write-Output "Total Elapsed Time:"$timer.Elapsed.Minutes "Minutes and"$Timer.Elapsed.Seconds "Seconds"
$timer.Reset()
}

#Set and Check Export Directory exists
function CheckExportDir() {
#Check to see if the directory we want to export to exists and, if not, create it.
#Create a log file in this directory as well to track forensic acquisition
    $location = (get-location)
    $export_directory = "$location\$ComputerName"
    $testFolder = (test-path $export_directory)
    $makeFolder = (New-Item -ItemType Directory -Force -Path $export_directory | Out-Null)
    if (!($testFolder)) {Write-ProgressHelper -StatusMessage "Export directory $export_directory does not exist - creating..." -StepNumber ($stepCounter++);
        $makeFolder
        }
}

#Run All
function RemoteRunAll($ComputerName,$Credential){
#Run all functions against the target
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        RemoteRunAll $ComputerName $Credential
        }
    }
    CheckExportDir
    $script:credname = $null
    if ($Credential -ne $null) {
        $script:credname = $Credential
        }
    Try {
        $script:credname = $Credential
        #$Credential = $script:Credential
        Write-ProgressHelper -StatusMessage "Running All Functions against $ComputerName"
        $functions = @('Get-RemotePCInfo','Get-RemoteApplication','Get-RemoteAuditStatus','Get-RemoteAccountLogoff','Get-RemoteTaskEvent','Get-RemoteAuditLog', 'Get-RemoteUserEvent', 'Get-RemoteUserChange','Get-RemotePasswordEvent','Get-RemoteGroupEvent','Get-RemoteGroupChange','Get-RemoteRunAs','Get-RemoteSpecialPriv','Get-RemoteSRPBlock','Get-RemotePowerEvent','Get-RemoteSvcStatusEvent','Get-RemoteSvcInstallEvent','Get-RemoteProcesses', 'Get-RemoteServicesActive','Get-RemoteArtifacts','Get-RemoteWirelessInfo','Get-RemoteAppCompat','Get-RemoteUSB', 'Get-RemoteRecentFiles','Get-RemoteMemoryDump')
        Get-RemoteNetCap $ComputerName $Credential -Timespan 30
        foreach ($func in $functions){
        Write-ProgressHelper -StatusMessage "Starting $func" -StepNumber ($stepCounter++)
        & $func $ComputerName $Credential
            }
        CleanUp
        Write-Output 'Remote Acquisition Complete'
        }
    Catch [System.UnauthorizedAccessException] {
        Write-ProgressHelper -StatusMessage "Username and Password Required"
        $Credential = Get-Credential -Message "Username and Password Required" -Username $credname
        $script:Credential = $Credential
        RemoteRunAll $ComputerName $Credential
        }
}

#Basic Info
function Get-RemotePCInfo($ComputerName,$Credential) {
#Grab numerous pieces of information about the host to establish basic details for reference
#Output to HTML file
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemotePCInfo $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    Else {$Credname = $script:credname}
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credsplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Gathering basic host information for $ComputerName" -StepNumber ($stepCounter++)
    $ReportTitle="Basic PC Information"
    $strPath = "$export_directory\$ComputerName-basicinfo.html"
    $pcsystemType = @{ 0="Unspecified"; 1="Desktop";2="Mobile";3="Workstation";4="Enterprise Server";5="Small Office and Home Office (SOHO) Server";6="Appliance PC";7="Performance Server";8="Maximum" }
    $drivetype = @{ [string]0 = 'Disk Drive'; [string]1 = 'Print Queue'; [string]2 = 'Device'; [string]3 = 'IPC'; [string]2147483648 = 'Disk Drive Admin'; [string]2147483649 = 'Print Queue Admin'; [string]2147483650 = 'Device Admin'; [string]2147483651 = 'IPC Admin'}
    $get_type = ([int](Get-WmiObject win32_computersystem -ComputerName $ComputerName @credsplat | Select-Object -ExpandProperty PCSystemType))
    $installDate = @{n="Install Date";e={$_.ConvertToDateTime($_.installdate)}}
    ConvertTo-Html -Head $htmlHeader -Title $ReportTitle -Body "<h1> Computer Name : $ComputerName </h1>" > "$strPath"
    Get-WmiObject win32_computersystem -ComputerName $ComputerName @credsplat  |Select-Object PSComputerName,Name,Manufacturer,Domain,Model,Systemtype,PrimaryOwnerName,@{n="PC System Type";e={$pcsystemType.$get_type}},PartOfDomain,CurrentTimeZone,BootupState,@{n="Memory(Gb)";e={$_.TotalPhysicalMemory /1Gb -as [int]}} | ConvertTo-Html  -Head $htmlHeader -Body "<h5>Created on: $(Get-Date)</h5><h2>ComputerSystem</h2>" >> "$strPath"
    Get-WmiObject win32_bios -ComputerName $ComputerName @credsplat| Select-Object Status,Version,PrimaryBIOS,Manufacturer,@{n="Release Date";e={$_.ConvertToDateTime($_.releasedate)}},SerialNumber | ConvertTo-Html -Head $htmlHeader -Body "<h2>BIOS Information</h2>" >> "$strPath"
    Get-WmiObject win32_Useraccount -ComputerName $ComputerName @credsplat | Where-Object {$_.localaccount -Match 'True'} | Select-Object Name,SID,Description,Fullname,Disabled | ConvertTo-html -Head $htmlHeader -Body "<h2>Local Users</h2>" >> "$strPath"
    ((Get-WmiObject win32_groupuser -ComputerName $ComputerName @credsplat |Where-Object {$_.groupcomponent -like '*"Administrators"'} | ForEach-Object {$_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $nul; $matches[1].trim('"') + "\" + $matches[2].trim('"') }) -split " " | Select-Object @{n="Administrators";e={$_.Trim()}} | ConvertTo-HTML -Head $htmlHeader -Body "<h2>Administrators</h2>") -replace "\*","Administrators" >> "$strPath"
    Get-WmiObject win32_DiskDrive -ComputerName $ComputerName @credsplat | Select-Object Index,Model,Caption,SerialNumber,Description,MediaType,FirmwareRevision,Partitions,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},PNPDeviceID | Sort-Object -Property Index | ConvertTo-Html -Head $htmlHeader -Body "<h2>Disk Drive Information</h1>" >> "$strPath"
    Get-WmiObject win32_share -ComputerName $ComputerName @credsplat | Select-Object Name,Path,Description,@{n="Type";e={$drivetype[[string]$_.Type]}}  | ConvertTo-html  -Head $htmlHeader -Body "<h2>Local Shares</h2>" >> "$strPath"
    Get-WmiObject win32_networkadapter -ComputerName $ComputerName @credsplat | Select-Object Name,Manufacturer,Description,AdapterType,Speed,MACAddress,NetConnectionID,PNPDeviceID | ConvertTo-Html -Head $htmlHeader -Body "<h2>Network Adapter Information</h2>" >> "$strPath"
    Get-WmiObject win32_NetworkAdapterConfiguration -ComputerName $ComputerName @credsplat | Select-Object @{n='IP Address';e={$_.ipaddress}},Description,@{n='MAC Address';e={$_.macaddress}},DHCPenabled,@{n="DHCPLeaseObtained";e={$_.ConvertToDateTime($_.DHCPLeaseObtained)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>Network Adapter Configuration</h2>" >> "$strPath"
    Get-WmiObject win32_startupCommand -ComputerName $ComputerName @credsplat | Select-Object Name,Location,Command,User,Caption  | ConvertTo-html  -Head $htmlHeader -Body "<h2>Startup  Software Information</h2>" >> "$strPath"
    Get-WmiObject win32_logicalDisk -ComputerName $ComputerName @credsplat | Select-Object DeviceID,VolumeName,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},@{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Size (GB)"},FileSystem, VolumeSerialNumber |  ConvertTo-html  -Head $htmlHeader -Body "<h2>Disk Information</h2>" >> "$strPath"
    Get-WmiObject win32_operatingsystem -ComputerName $ComputerName @credsplat | Select-Object Caption,OSArchitecture,Organization,$InstallDate,Version,SerialNumber,BootDevice,WindowsDirectory,CountryCode,@{n="Last Bootup";e={$_.ConvertToDateTime($_.lastbootup)}},@{n="Local Date/Time";e={$_.ConvertToDateTime($_.LocalDateTime)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>OS Information</h2>" >> "$strPath"

    $htmlHeader >> "$strPath"
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemotePCInfo $ComputerName $Credential
    }
}
#Applications
function Get-RemoteApplication($ComputerName,$Credential) {
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteApplication $ComputerName $Credential
        }
    }
#Use the Win32_Product Class to grab all software installed by standard methods
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credSplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
        }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $CredName)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Installed software for $ComputerName" -StepNumber ($stepCounter++)
    Get-WmiObject Win32_Product -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},Name,InstallDate,ProductID,Vendor,Version | Export-CSV -Path "$export_directory\$ComputerName-applications.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteApplication $ComputerName $Credential
    }
}

#Security Event Logs - 4624 and 4625
function Get-RemoteAuditStatus($ComputerName,$Credential){
#Check the Windows Security event log for 4624 and 4625 events
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteAuditStatus $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Successful/Failed Logon attempts on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $logontype4624 = @{n="LogonType";e={($_.InsertionStrings[8])}}
    $SID4624 = @{n="SID";e={$_.InsertionStrings[4]}}
    $accountname4624 = @{n="AccountName";e={$_.InsertionStrings[5]}}
    $loginid4624 = @{n="LoginID";e={$_.InsertionStrings[7]}}
    $sourcenetwork4624 = @{n="SourceNetworkAddress";e={$_.InsertionStrings[18]}}
    $filter4624 = "(logfile='Security' AND EventCode='4624')"

    $logontype4625 = @{n="LogonType";e={$_.InsertionStrings[10]}}
    $SID4625 = @{n="SID";e={$_.InsertionStrings[4]}}
    $accountname4625 = @{n="AccountName";e={$_.InsertionStrings[5]}}
    $failuretype4625 = @{n="FailureType";e={$_.InsertionStrings[7]}}
    $failuresubtype4625 = @{n="FailureSubType";e={$_.InsertionStrings[9]}}
    $workstationname4625 = @{n="WorkstationName";e={$_.InsertionStrings[13]}}
    $sourcenetwork4625 = @{n="SourceNetworkAddress";e={$_.InsertionStrings[19]}}
    $filter4625 = "(logfile='Security' AND EventCode='4625')"
    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName @credsplat -Filter $filter4624 | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventIdentifier, $logontype4624, $SID4624, $accountname4624, $loginid4624, $sourcenetwork4624 | Export-CSV -Path "$export_directory\$ComputerName-4624.csv" -NoTypeInformation
    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName @credsplat -Filter $filter4625 | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventIdentifier, $logontype4625, $SID4625, $accountname4625, $failuretype4625, $failuresubtype4625, $workstationname4625, $sourcenetwork4625 | Export-CSV -Path "$export_directory\$ComputerName-4625.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteAuditStatus $ComputerName $Credential
    }
}

#Security Event Log Info - 4634
function Get-RemoteAccountLogoff($ComputerName,$Credential){
#Check Windows Security event log for 4634 events, all types
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteAccountLogoff $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Logoffs on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $logofftype = @{n="LogonType";e={$_.InsertionStrings[4]}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $accountname = @{n="AccountName";e={$_.InsertionStrings[1]}}
    $loginid = @{n="LogonID";e={$_.InsertionStrings[3]}}
    $filter = "(logfile='Security' AND EventCode='4634')"
    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventIdentifier, Type, $logofftype, $SID, $accountname, $loginid | Export-CSV -Path "$export_directory\$ComputerName-4634.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteAccountLogoff $ComputerName $Credential
    }
}

#Security Event Logs - 4698 - 4702
function Get-RemoteTaskEvent($ComputerName,$Credential){
#Check the Windows Security event log for all new and modified scheduled tasks
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteTaskEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for New and Modified Scheduled Tasks on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $accountname = @{n="AccountName";e={$_.InsertionStrings[1]}}
    $loginid = @{n="LogonID";e={$_.InsertionStrings[3]}}
    $exec = @{n="Exec";e={$_.InsertionStrings[5] -replace "`r`n", "" -Match "<Exec>\s{0,}(.*)</Exec"}}
    $filter = "(logfile='Security' AND (EventCode='4698' OR EventCode='4699' OR EventCode='4700' OR EventCode='4701' OR EventCode='4702'))"
    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventIdentifier, $SID, $accountname, $loginid, $exec | Export-CSV -Path "$export_directory\$ComputerName-4698-4702.csv" -NoTypeInformation
    Get-WinEvent -ComputerName $ComputerName @credsplat @{LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106,140,141,200,201} -ErrorAction SilentlyContinue | Select-Object @{l="ComputerName";e={$ComputerName}},TimeCreated,Id,UserID,AccountName,LoginID,@{n="Exec";e={($_.Message -split ",")[0]}} | Export-CSV -Path "$export_directory\$ComputerName-TaskScheduler.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteTaskEvent $ComputerName $Credential
    }
}

#Event Logs - Security - 1102
function Get-RemoteAuditLog($ComputerName,$Credential) {
#Check Windows Security event log for event ID 1102, when the audit log is cleared
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteAuditLog $ComputerName $Credential
        }
    }
   if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Audit Clearing on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $user = @{n="User";e={$_.InsertionStrings[1]}}
    $CompName = @{n="Computer Name";e={$_.InsertionStrings[2]}}
    $logonID = @{n="Logon ID";e={$_.InsertionStrings[3]}}
    $filter = "(logfile='Security' AND EventCode='1102')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $User, $SID, $CompName, $logonID, Type | Export-CSV -Path "$export_directory\$ComputerName-1102.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteAuditLog $ComputerName $Credential
    }
}

#Event Logs - Security - 4720, 4722, 4725, 4726, 4738, 4741, 4743
function Get-RemoteUserEvent($ComputerName,$Credential) {
#Check Windows Security event log for any added or deleted, accounts or computers
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteUserEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Added/Deleted Accounts/Computers on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ModifiedAccount = @{n="Modified Account";e={$_.InsertionStrings[0]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[1]}}
    $ModifiedSID = @{n="Modified SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $OriginatorLogonID = @{n="Logon ID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND (EventCode='4720' OR EventCode='4722' OR EventCode='4725' OR EventCode='4726' OR EventCode='4738' OR EventCode='4741' OR EventCode='4743'))"
    Get-WmiObject win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-userevents.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteUserEvent $ComputerName $Credential
    }
}

#Event Logs - Security - 4738
function Get-RemoteUserChange($ComputerName,$Credential) {
#Check Windows Security event log for 4738, changed accounts or computers
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteUserChange $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Changed Accounts/Computers on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ModifiedAccount = @{n="Modified Account";e={$_.InsertionStrings[1]}}
    $ModifiedDomain = @{n="Modified Acct Domain";e={$_.InsertionStrings[2]}}
    $ModifiedSID = @{n="Modified SID";e={$_.InsertionStrings[3]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[4]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[5]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[6]}}
    $OriginatorLogonID = @{n="Logon ID";e={$_.InsertionStrings[7]}}
    #UAC Is a Bitwise Value which determines users permissions. REF: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
    $OldUAC =  @{n="Old UAC";e={$_.InsertionStrings[21]}}
    $NewUAC =  @{n="New UAC";e={$_.InsertionStrings[22]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND EventCode='4738')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $ModifiedDomain, $OldUAC, $NewUAC, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-userchanges.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteUserChange $ComputerName $Credential
    }
}

#Event Logs - Security - 4723, 4724
function Get-RemotePasswordEvent($ComputerName,$Credential) {
#Check Windows Security event log for password changes or resets
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemotePasswordEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Password Changes/Resets on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ModifiedAccount = @{n="Modified Account";e={$_.InsertionStrings[0]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[1]}}
    $ModifiedSID = @{n="Modified SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $OriginatorLogonID = @{n="Logon ID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND (EventCode='4723' OR EventCode='4724'))"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter  | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-passwordevents.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemotePasswordEvent $ComputerName $Credential
    }
}

#Event Logs - Security - 4727, 4730, 4731, 4734
function Get-RemoteGroupEvent($ComputerName,$Credential) {
#Check Windows Security event log for groups that have been created, deleted or modified
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteGroupEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Groups Created/Deleted/Modified on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $MemberAccount = @{n="Member Account";e={$_.InsertionStrings[0]}}
    $MemberSID = @{n="Member SID";e={$_.InsertionStrings[1]}}
    $MemberGroup = @{n="Member Group";e={$_.InsertionStrings[2]}}
    $GroupDomain = @{n="Group Domain";e={$_.InsertionStrings[3]}}
    $GroupSID = @{n="Group SID";e={$_.InsertionStrings[4]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[5]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[6]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[7]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[8]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND (EventCode='4727' OR EventCode='4730' OR EventCode='4731' OR EventCode='4734'))"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $MemberAccount, $MemberSID, $MemberGroup, $GroupSID, $GroupDomain, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-groupevents.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteGroupEvent $ComputerName $Credential
    }
}

#Event Logs - Security - 4728, 4729, 4732, 4733, 4735
function Get-RemoteGroupChange($ComputerName,$Credential) {
#Check Windows Security event log for additions to, deletions from, or changes to groups
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteGroupChange $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Add/Delete/Change to Groups on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $GroupName = @{n="Group Name";e={$_.InsertionStrings[0]}}
    $GroupDomain = @{n="Group Domain";e={$_.InsertionStrings[1]}}
    $GroupSID = @{n="Group SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[5]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND (EventCode='4728' OR EventCode='4729' OR EventCode='4732' OR EventCode='4733' OR EventCode='4735'))"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $GroupName, $GroupSID, $GroupDomain, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-groupchanges.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteGroupChange $ComputerName $Credential
    }
}

#Event Logs - Security - 4648
function Get-RemoteRunAs($ComputerName,$Credential) {
#Check Windows Security event log for any attempts to run applications as another user
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteRunAs $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for RunAs attempts on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[0]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[1]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[2]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[3]}}
    $OriginatingLogonGUID = @{n="Originating Logon GUID";e={$_.InsertionStrings[4]}}
    $TargetUser = @{n="Target Username";e={$_.InsertionStrings[5]}}
    $TargetDomain = @{n="Target Domain";e={$_.InsertionStrings[6]}}
    $TargetGUID = @{n="Target Logon GUID";e={$_.InsertionStrings[7]}}
    $TargetServer = @{n="Target Server Name";e={$_.InsertionStrings[8]}}
    $ProcessID = @{n="Process ID";e={[int64]$_.InsertionStrings[10]}}
    $ProcessName = @{n="Process Name";e={$_.InsertionStrings[11]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND EventCode='4648')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $OriginatingLogonGUID, $TargetUser, $TargetDomain, $TargetGUID, $TargetServer, $ProcessID, $ProcessName, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-runas.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteRunAs $ComputerName $Credential
    }
}

#Event Logs - Security - 4672
function Get-RemoteSpecialPriv($ComputerName,$Credential) {
#Check the Windows Security event log for any accounts using Special Privileges
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteSpecialPriv $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Security Event Logs for Special Privileges on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[0]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[1]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[2]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[3]}}
    $Privileges = @{n="Privileges";e={$_.InsertionStrings[4] -replace '\n','' -replace '\t\t\t',';'}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Security' AND EventCode='4672')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $Privileges, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-privevents.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteSpecialPriv $ComputerName $Credential
    }
}

#Event Logs - System - 866
function Get-RemoteSRPBlock($ComputerName,$Credential) {
#Check Windows Application event log for any software that was blocked by the Windows Software Restriction Policy
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteSRPBlock $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Application Event Logs for Software Restriction Policy on $ComputerName" -StepNumber ($stepCounter++)
    #$TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    #Need Sample of SRP event to determine format for output
    #$message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $filter = "(logfile='Application' AND EventCode='866')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},* | Export-CSV -Path "$export_directory\$ComputerName-srp.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteSRPBlock $ComputerName $Credential
    }
}

#Event Logs - System - 6005-6006, 6008
function Get-RemotePowerEvent($ComputerName,$Credential) {
#Check Windows System event log for any physical power events (off/on/reboot/dirty shutdown)
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemotePowerEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking System Event Logs for Startup/PowerOff/Reboot/Dirty Shutdown on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $filter = "(logfile='System' AND (EventCode='6005' OR EventCode='6006' OR EventCode='6008'))"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, Message | Export-CSV -Path "$export_directory\$ComputerName-power.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemotePowerEvent $ComputerName $Credential
    }
}

#Event Logs - System - 7036
function Get-RemoteSvcStatusEvent($ComputerName,$Credential) {
#Check Windows System log for service modifications (start/stop/restart/run)
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteSvcStatusEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking System Event Logs for Service Start/Stop/Restart/Running on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ServiceName = @{n="Service Name";e={$_.InsertionStrings[0]}}
    $ServiceStatus = @{n="Service Status";e={$_.InsertionStrings[1]}}
    $filter = "(logfile='System' AND EventCode='7036')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $ServiceName, $ServiceStatus, @{n="HostName";e={$_.ComputerName}} | Export-CSV -Path "$export_directory\$ComputerName-7036.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteSvcStatusEvent $ComputerName $Credential
    }
}

#Event Logs - System - 7045
function Get-RemoteSvcInstallEvent($ComputerName,$Credential) {
#Check Windows System event log for services that were installed
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteSvcInstallEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking System Event Logs for Service Installs on $ComputerName" -StepNumber ($stepCounter++)
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ServiceName = @{n="Service Name";e={$_.InsertionStrings[0]}}
    $ServiceFileName = @{n="Service File Name";e={$_.InsertionStrings[1]}}
    $ServiceType = @{n="Service Type";e={$_.InsertionStrings[2]}}
    $ServiceStartType = @{n="Service Start Type";e={$_.InsertionStrings[3]}}
    $user = @{n="User";e={($_.User -split '\\')[1]}}
    $filter = "(logfile='System' AND EventCode='7045')"
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName @credsplat -Filter $filter | Select-Object @{l="ComputerName";e={$ComputerName}},$TimeGenerated, EventCode, $ServiceName, $ServiceFileName, $ServiceType, $ServiceStartType, $User | Export-CSV -Path "$export_directory\$ComputerName-7045.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteSvcInstallEvent $ComputerName $Credential
    }
}

#RDP Events
function Get-RemoteRDPEvent($ComputerName,$Credential) {
#Check Microsoft-Windows-TerminalServices-LocalSessionManager/Operational for RDP Events
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteRDPEvent $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking for RDP Events on $ComputerName" -StepNumber ($stepCounter++)
    $domain = @{n="domain";e={((($_.Message -split '\n')[2] -replace "\r","" -split " ")[1] -split "\\")[0] }}
    $user = @{n="User";e={((($_.Message -split '\n')[2] -replace "\r","" -split " ")[1] -split "\\")[1] }}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $sessionID = @{n="Session ID";e={(($_.Message -split '\n')[3] -replace "\r","" -split " ")[2] }}
    $netAddress = @{n="Source Network Address";e={(($_.Message -split '\n')[4] -replace "\r","" -split " ")[3] }}
    Get-WinEvent -ComputerName $ComputerName @credsplat @{LogName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"} | Select-Object @{l="ComputerName";e={$ComputerName}},TimeCreated, id, $sessionID, $domain, $user, $netAddress, $message | Export-CSV -Path "$export_directory\$ComputerName-rdp.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteRDPEvent $ComputerName $Credential
    }
}

#Processes
function Get-RemoteProcesses($ComputerName,$Credential){
#Get the current running processes on the remote host
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteProcesses $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Running Processes on $ComputerName" -StepNumber ($stepCounter++)
    $CreationDate = @{n="CreationDate";e={$_.ConvertToDateTime($_.CreationDate)}}
    Get-WmiObject Win32_Process -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},Name,Description,$CreationDate,ProcessID,ParentProcessID,ThreadCount,ExecutablePath,CommandLine,@{n="Owner";e={$_.GetOwner().Domain + " " + $_.GetOwner().User}} | Export-CSV -Path "$export_directory\$ComputerName-processes.csv" -NoTypeInformation
    Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},@{n="Process Name";e={$_.Name}},@{n="PID";e={$_.IDProcess}},@{n="PPID";e={$_.CreatingProcessID}},@{n="CPU(%)";e={$_.PercentProcessorTime}},@{n="Memory_Usage(MB)";e={[Math]::Round(($_.workingSetPrivate /1mb),2)}},@{n="RunningTime(Min)";e={[Math]::Round(($_.ElapsedTime /60),0)}} | Sort-Object 'CPU(%)' -Descending | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-processorusage.csv"
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteProcesses $ComputerName $Credential
    }
}

#Services
function Get-RemoteServicesActive($ComputerName,$Credential){
#Get a list of active running services on the remote host
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteServicesActive $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Services on $ComputerName" -StepNumber ($stepCounter++)
    Get-WmiObject Win32_Service -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},Name,ProcessID,StartMode,State,Status,PathName | export-CSV -Path "$export_directory\$ComputerName-services.csv" -NoTypeInformation
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteServicesActive $ComputerName $Credential
    }
}

#Artifacts
function Get-RemoteArtifacts($ComputerName,$Credential){
#Get artifacts from the remote host using Invoke-WMI objects. Artifacts will be saved on the root of the OS Drive (determined by $driveLetter)
#Artifacts then will be copied from the target to the destination, then deleted from the target
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteArtifacts $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credsplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    CheckExportDir
    $driveLetter = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -Credential $Credential | Select-Object -expand SystemDrive) + "\"
    $shell = ("cmd /c " + $driveLetter + "windows\system32\")
    Write-ProgressHelper -StatusMessage "Retrieving specific host-based artifacts from $ComputerName" -StepNumber ($stepCounter++)
    $fileList = @('nets.csv','tasklists.csv','tasksvcs.csv','driverqueries.csv','dns.txt','arps.txt','scheds.csv')
    $outnet = ($driveLetter + ”nets.csv”)
    $outtasks = ($driveLetter + ”tasklists.csv")
    $outtasksvc = ($driveLetter + ”tasksvcs.csv")
    $outdns = ($driveLetter + ”dns.txt")
    $outdriver = ($driveLetter + ”driverqueries.csv")
    $outarp = ($driveLetter + ”arps.txt")
    $outsched = ($driveLetter + ”scheds.csv")

    $artifacts = @{tasklist = "tasklist.exe /v /FO csv >> $outtasks"; tasksvc = "tasklist.exe /svc /FO csv >> $outtasksvc"; dns = "ipconfig.exe /displaydns >> $outdns"; driverquery = "driverquery.exe /v /FO csv >> $outdriver"; arp = "arp.exe -a >> $outarp"; sched = "schtasks.exe /Query /FO CSV /V >> $outsched"}

    Try{
    foreach($key in $artifacts.Keys){
        Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($shell + $artifacts.$key) -ComputerName $ComputerName @credsplat -ErrorAction stop | Out-Null
        Write-ProgressHelper -StatusMessage " -$key" -StepNumber ($StepCounter++)
    }
    Invoke-WmiMethod Win32_process -name Create -ArgumentList ("cmd /c for /F `"tokens=1-5 delims= `" %A in ('netstat.exe -ano') do echo %A,%B,%C,%D,%E>>$outnet") -ComputerName $ComputerName @credsplat -ErrorAction stop | Out-Null
    Get-WmiObject win32_networkadapterconfiguration -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},PSComputerName,DNSHostName,Description,DNSDomain,MacAddress,@{n="IPv4";e={$_.IpAddress[0]}},@{n="IPv6";e={$_.IPAddress[1]}},@{n="IPv4Subnet";e={$_.IPSubnet[0]}},@{n="IPv6Subnet";e={$_.IPSubnet[1]}},DHCPServer,DHCPEnabled,@{n="DHCPLeaseObtained";e={$_.ConvertToDateTime($_.DHCPLeaseObtained)}},@{n="DHCPLeaseExpires";e={$_.ConvertToDateTime($_.DHCPLeaseExpires)}} | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-ipconfig.csv"
    Get-WmiObject win32_service -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},Name,DisplayName,PathName,ServiceType,State,Status,InstallDate,StartMode,DelayedAutoStart,AcceptPause,AcceptStop,ErrorControl,ExitCode,ServiceSpecificExitCode | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-scquery.csv"
    Get-WmiObject win32_ip4routeTable -ComputerName $ComputerName @credsplat | Select-Object @{l="ComputerName";e={$ComputerName}},PSComputerName,Name,Destination,Mask,NextHop,Metric1 | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-route.csv"
    }
    Catch{
        Throw $_
        Break
    }
    Write-ProgressHelper -StatusMessage "Copying artifacts to export directory" -StepNumber ($stepCounter++)
    $drivemount = (Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1) -replace ":",""
    New-PSDrive -Name $drivemount -PSProvider filesystem -Root $net_path @credsplat | Out-Null
    foreach($file in $fileList){
        Start-Sleep -s 3
        Copy-Item ($drivemount + ":\" + $file) "$export_directory\$ComputerName-$file" -Force
        Write-ProgressHelper -StatusMessage "Removing $file from host"
        Start-sleep -s 1
        Remove-Item ($drivemount + ":\" + $file) -Force
        }
    Remove-PSDrive $drivemount
    Import-CSV "$export_directory\$ComputerName-tasksvcs.csv" | Select-Object @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-tasksvc.csv"
    Import-CSV "$export_directory\$ComputerName-tasklists.csv" | Select-Object @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-tasklist.csv"
    Import-CSV "$export_directory\$ComputerName-driverqueries.csv" | Select-Object @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-driverquery.csv"
    $taskheader = (Get-Content "$export_directory\$ComputerName-scheds.csv" | Select -first 1)
    $schedcsv = ((Get-Content "$export_directory\$ComputerName-scheds.csv") -replace "$taskheader","" | Where {$_.trim() -ne ""})
    Add-Content -Path "$export_directory\$ComputerName-scheduledtask.csv" -Value ($taskheader)
    Add-Content -Path "$export_directory\$ComputerName-scheduledtask.csv" -value ($schedcsv)
    Import-CSV "$export_directory\$ComputerName-scheduledtask.csv" | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-scheduledtasks.csv"
    Remove-Item $export_directory\$ComputerName-scheduledtask.csv -Force
    Add-Content -Path "$export_directory\$ComputerName-netstats.csv" -Value ("Protocol,LocalAddress,ForeignAddress,State,PID")
    Add-Content -Path "$export_directory\$ComputerName-netstats.csv" -Value (Get-Content "$export_directory\$ComputerName-nets.csv" | Select -skip 2)
    Import-CSV "$export_directory\$ComputerName-netstats.csv" | Select @{l="ComputerName";e={$ComputerName}},Protocol,LocalAddress,ForeignAddress,@{n="State";e={if($_.Protocol -like 'UDP*'){'N/A'}else{$_.State}}},@{n="PID";e={if($_.Protocol -like 'UDP*'){$_.State}else{$_.PID}}}  | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-netstat.csv"
    Remove-Item "$export_directory\$ComputerName-nets.csv" -Force
    Remove-Item "$export_directory\$ComputerName-scheds.csv" -Force
    Remove-Item "$export_directory\$ComputerName-netstats.csv" -Force
    $arp_data = (Get-Content "$export_directory\$ComputerName-arps.txt")
    $arp_header = ("InternetAddress,PhysicalAddress,Type")
    Add-Content -Path "$export_directory\$ComputerName-arps.csv" -Value ($arp_header)
    Add-Content -Path "$export_directory\$ComputerName-arps.csv" -Value (($arp_data) -replace ' +',' ' -replace '^ ','' -replace ' $','' -replace ' ',',' -replace '\r','' | ? {$_.trim() -ne ""} | Select-String -pattern 'Internet' -NotMatch)
    Import-CSV "$export_directory\$ComputerName-arps.csv" | Select -skip 1 | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-arp.csv"
    Remove-Item "$export_directory\$ComputerName-arps.csv" -Force
    $dns_client_cache = @() #Shared on StackOverflow by Adam - https://stackoverflow.com/questions/49678217/export-list-array-to-csv-in-powershell
    $raw_dns_data = (Get-Content "$export_directory\$ComputerName-dns.txt")
    for ($element = 3; $element -le $raw_dns_data.length - 3; $element++) {
    if ( $raw_dns_data[$element].IndexOf('Record Name') -gt 0 ) {
        if ( $dns_entry ) { $dns_client_cache += $dns_entry }
        $dns_entry = New-Object -TypeName PSObject
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'RecordName' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    } elseif ( $raw_dns_data[$element].IndexOf('Record Type') -gt 0 ) {
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'RecordType' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    } elseif ( $raw_dns_data[$element].IndexOf('Time To Live') -gt 0 ) {
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'TimeToLive' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    } elseif ( $raw_dns_data[$element].IndexOf('Data Length') -gt 0 ) {
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'DataLength' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    } elseif ( $raw_dns_data[$element].IndexOf('Section') -gt 0 ) {
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'Section' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    } elseif ( $raw_dns_data[$element].IndexOf('CNAME Record') -gt 0 ) {
        Add-Member -InputObject $dns_entry -MemberType NoteProperty -Name 'CNAMERecord' -Value $raw_dns_data[$element].Split(':')[1].Trim()
    }
}
    $dns_client_cache | Select @{l="ComputerName";e={$ComputerName}}, * | Export-Csv "$export_directory\$ComputerName-dns.csv" -NoTypeInformation
    Write-ProgressHelper -StatusMessage "Host-based artifact acquisition complete" -StepNumber ($stepCounter++)
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteArtifacts $ComputerName $Credential
    }
}

#Wireless
function Get-RemoteWirelessInfo($ComputerName,$Credential){
#Use netsh on the host to retrieve Wireless Network profiles.
#Can be configured to retrieve the wireless key using the key=clear command, but is not enabled by default
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteWirelessInfo $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    CheckExportDir
    $driveLetter = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -Credential $Credential | Select-Object -expand SystemDrive) + "\"
    $shell = ("cmd /c " + $driveLetter + "windows\system32\")
    Write-ProgressHelper -StatusMessage "Checking Host Wireless Profiles" -StepNumber ($stepCounter++)
    $outWireless = ($driveLetter + "wireless.txt")
    $wireless = "netsh.exe wlan show profiles name='*' >> $outWireless"
    Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($shell + $wireless) -ComputerName $ComputerName @credsplat -ErrorAction stop | Out-Null
    Start-Sleep -s 10
    $drivemount = (Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1) -replace ":",""
    New-PSDrive -Name $drivemount -PSProvider filesystem -Root $net_path @credsplat | Out-Null
    Copy-Item ($drivemount + ":\wireless.txt") "$export_directory\$ComputerName-wireless.txt" -Force
    Write-ProgressHelper -StatusMessage "Removing $outWireless from host" -StepNumber ($stepCounter++)
    Remove-Item ($drivemount + ":\wireless.txt") -Force
    Remove-PSDrive $drivemount
    Write-ProgressHelper -StatusMessage "Wireless Profile acquisition complete" -StepNumber ($stepCounter++)
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteWirelessInfo $ComputerName $Credential
    }
}

#AppCompatCache
function Get-RemoteAppCompat{
param($ComputerName,$Credential)
# Adapted from https://github.com/davidhowell-tx/PS-WindowsForensics/blob/master/AppCompatCache/KansaModule/Get-AppCompatCache.ps1
# Modified for usage within WMI
# Added Win10-CreatorsUpdate partial support (0x34)
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteAppCompat $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "User/Password Required" -UserName $credname)
    }
    Elseif ($Credential -eq $null -and $script:Credential -ne [pscredential]::Empty) {
        $Credential = $script:Credential
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -eq $null -and $script:Credential -ne $null) {
        $credsplat['Credential'] = (Get-Credential -Message "Username and Password Required" -Username $credname)
    }
    $shimcachelocation = "SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\"
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking AppCompatCache on $ComputerName" -StepNumber ($stepCounter++)
    $reg = Get-WMIObject -List "StdRegProv" -NameSpace "root\default" -ComputerName $ComputerName @credsplat

#Get AppCompatCache from Registry

# Initialize Array to store our data
$EntryArray=@()
$AppCompatCache=$Null

$AppCompatCache = $reg.GetBinaryValue(2147483650, $SHIMCACHELOCATION, "AppCompatCache").uValue;

if ($AppCompatCache -ne $null) {
	# Initialize a Memory Stream and Binary Reader to scan through the Byte Array
	$MemoryStream = New-Object System.IO.MemoryStream(,$AppCompatCache)
	$BinReader = New-Object System.IO.BinaryReader $MemoryStream
	$UnicodeEncoding = New-Object System.Text.UnicodeEncoding

	# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
	$Header = ([System.BitConverter]::ToString($AppCompatCache[0..3])) -replace "-",""

	switch ($Header) {

		# 0x30 - Windows 10
		"30000000" {
            $MemoryStream.Position = 48

			# Complete loop to parse each entry
			while ($MemoryStream.Position -lt $MemoryStream.Length) {
				$Tag = [System.BitConverter]::ToString($BinReader.ReadBytes(4)) -replace "-",""
				################################
				# Add code to verify tag later #
				################################

				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}}, Name, Time, Data # Added Data
				$BinReader.ReadBytes(4) | Out-Null
				$SZ = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$NameLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
				$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
				$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$DataLength = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$TempObject.Data = $UnicodeEncoding.GetString($BinReader.ReadBytes($DataLength))
				$EntryArray += $TempObject
			}
		}
        # 0x34 - Windows 10
		"34000000" {
            $MemoryStream.Position = 52

			# Complete loop to parse each entry
			while ($MemoryStream.Position -lt $MemoryStream.Length) {
				$Tag = [System.BitConverter]::ToString($BinReader.ReadBytes(4)) -replace "-",""
				################################
				# Add code to verify tag later #
				################################

				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}}, Name, Time, Data # Added Data
				$BinReader.ReadBytes(4) | Out-Null
				$SZ = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$NameLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
				$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
				$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$DataLength = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
                $TempObject.Data = $UnicodeEncoding.GetString($BinReader.ReadBytes($DataLength))
				$EntryArray += $TempObject
			}
		}
		# 0x80 - Windows 8
		"80000000" {
			$Offset = [System.BitConverter]::ToUInt32($AppCompatCache[0..3],0)
			$Tag = [System.BitConverter]::ToString($AppCompatCache[$Offset..($Offset+3)],0) -replace "-",""

			if ($Tag -eq "30307473" -or $Tag -eq "31307473") {
				# 64-bit
				$MemoryStream.Position = ($Offset)

				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					# I've noticed some random gaps of space in Windows 8 AppCompatCache
					# We need to verify the tag for each entry
					# If the tag isn't correct, read through until the next correct tag is found

					# First 4 Bytes is the Tag
					$EntryTag = [System.BitConverter]::ToString($BinReader.ReadBytes(4),0) -replace "-",""

					if ($EntryTag -eq "30307473" -or $EntryTag -eq "31307473") {
						# Skip 4 Bytes
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Time
						$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ + 2))
						$BinReader.ReadBytes(8) | Out-Null
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject
					} else {
						# We've found a gap of space that isn't an AppCompatCache Entry
						# Perform a loop to read 1 byte at a time until we find the tag 30307473 or 31307473 again
						$Exit = $False

						while ($Exit -ne $true) {
							$Byte1 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
							if ($Byte1 -eq "30" -or $Byte1 -eq "31") {
								$Byte2 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
								if ($Byte2 -eq "30") {
									$Byte3 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
									if ($Byte3 -eq "74") {
										$Byte4 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
										if ($Byte4 -eq "73") {
											# Verified a correct tag for a new entry
											# Scroll back 4 bytes and exit the scan loop
											$MemoryStream.Position = ($MemoryStream.Position - 4)
											$Exit = $True
										} else {
											$MemoryStream.Position = ($MemoryStream.Position - 3)
										}
									} else {
										$MemoryStream.Position = ($MemoryStream.Position - 2)
									}
								} else {
									$MemoryStream.Position = ($MemoryStream.Position - 1)
								}
							}
						}
					}
				}

			} elseif ($Tag -eq "726F7473") {
				# 32-bit

				$MemoryStream.Position = ($Offset + 8)

				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					#Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Time

					$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ))
					$EntryArray += $TempObject
				}
			}
			$EntryArray | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Time | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
		}

		# BADC0FEE in Little Endian Hex - Windows 7 / Windows 2008 R2
		"EE0FDCBA" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)

			# Move BinReader to the Offset 128 where the Entries begin
			$MemoryStream.Position=128

			# Get some baseline info about the 1st entry to determine if we're on 32-bit or 64-bit OS
			$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)

			# Move Binary Reader back to the start of the entries
			$MemoryStream.Position=128

			if (($MaxLength - $Length) -eq 2) {
				if ($Padding -eq 0) {
					# 64-bit Operating System

					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
				} else {
					# 32-bit Operating System

					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Length, MaxLength, Offset, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}

				}
			}

			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			$EntryArray | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
		}

		# BADC0FFE in Little Endian Hex - Windows Server 2003 through Windows Vista and Windows Server 2008
		"FE0FDCBA" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)

			# Lets analyze the padding of the first entry to determine if we're on 32-bit or 64-bit OS
			$Padding = [System.BitConverter]::ToUInt32($AppCompatCache[12..15],0)

			# Move BinReader to the Offset 8 where the Entries begin
			$MemoryStream.Position=8

			if ($Padding -eq 0) {
				# 64-bit Operating System

				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
					$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)

					$EntryArray += $TempObject
				}

			} else {
				# 32-bit Operating System

				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Length, MaxLength, Offset, Time, Flag0, Flag1
					$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)

					$EntryArray += $TempObject
				}
			}

			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			$EntryArray | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
		}


		# DEADBEEF in Little Endian Hex - Windows XP
		"EFBEADDE" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)

			# Move to the Offset 400 where the Entries begin
			$MemoryStream.Position=400

			# Use the Number of Entries it says are available and iterate through this loop that many times
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, LastModifiedTime, Size, LastUpdatedTime
				$TempObject.Name = ($UnicodeEncoding.GetString($BinReader.ReadBytes(488))) -replace "\\\?\?\\",""
				# We read 488 bytes into the Entry, and the next attribute of note starts at 528. Lets read those 40 bytes of difference and skip them
				$Nothing = $BinReader.ReadBytes(40)
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				# I'm not fully confident in the Size value without having a Windows XP box to test. Mandiant Whitepaper only says Large_Integer, QWORD File Size. Harlan Carveys' script parses as 2 DWORDS.
				$TempObject.Size = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
				$TempObject.LastUpdatedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$EntryArray += $TempObject
			}

			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			$EntryArray | Select-Object -Property @{l="ComputerName";e={$ComputerName}},Name, Size, LastModifiedTime, LastUpdatedTime | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
		}
	}
}
}
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteAppCompat $ComputerName $Credential
    }
}

#Memory Dump
function Get-RemoteMemoryDump($ComputerName,$Credential){
#Copy the winpmem exec to the remote host, create a memory dump, copy to the originating source, and delete the results from the target
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteMemoryDump $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    CheckExportDir
    $driveLetter = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -Credential $Credential | Select-Object -expand SystemDrive) + "\"
    $drivemount = (Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1) -replace ":",""
    New-PSDrive -Name $drivemount -PSProvider filesystem -Root $net_path @credsplat | Out-Null
    Write-ProgressHelper -StatusMessage "Getting Memory Dump of $ComputerName" -StepNumber ($stepCounter++)
    Try {
        Copy-Item -Path "$location\bin\winpmem.exe" -Destination ($drivemount + ":\winpmem.exe") -Force
        $invokeMemDump = (Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($net_path + "\winpmem.exe --format raw -o " + $driveLetter + "memory.raw") -ComputerName $ComputerName @credsplat -ErrorAction stop)
        $memdumpPID = $invokeMemDump.processID
        $memdumpRunning = { Get-WmiObject -Class win32_process -Filter "ProcessID='$memdumpPID'" -ComputerName $ComputerName @credsplat -ErrorAction SilentlyContinue | Where-Object { ($_.ProcessName -eq 'winpmem.exe') } }
    }
    Catch{
        Throw $_
        Break
    }
    while ($null -ne (& $memdumpRunning)) {
    start-sleep -s 2
    }
    Write-ProgressHelper -StatusMessage "Removing winpmem executable from host"
    Remove-Item ($drivemount + ":\winpmem.exe") -Force
    Write-ProgressHelper -StatusMessage "Copying memory dump to export directory"
    Copy-Item ($drivemount + ":\memory.raw") "$export_directory\$ComputerName-memory.raw"
    Write-ProgressHelper -StatusMessage "Removing memory dump from host"
    Remove-Item ($drivemount + ":\memory.raw") -Force
    Write-ProgressHelper -StatusMessage "Memory acquisition complete" -StepNumber ($stepCounter++)
    Remove-PSDrive $drivemount
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteMemoryDump $ComputerName $Credential
    }
}

#USB Devices
function Get-RemoteUSB($ComputerName,$Credential){
#Gather USB Drive Letters, Serials, Usernames who inserted devices, First and Last Insert etc.
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteUSB $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)

    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Getting USB Details from $ComputerName" -StepNumber ($stepCounter++)
    $driveLetter = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName @credsplat | Select-Object -expand SystemDrive) + "\"
    $powershell = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -command "
    $drivemount = (Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1) -replace ":",""
    New-PSDrive -Name $drivemount -PSProvider filesystem -Root $net_path @credsplat | Out-Null
    . .\Join-Object.ps1

    Write-ProgressHelper -StatusMessage "Getting Volume information from HKLM:\System\MountedDevices"
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + '$Volumes = @(); Get-Item HKLM:\System\MountedDevices | Select-Object -ExpandProperty Property | where {$_ -like \"\??\Volume*\"} | ForEach-OBject {$volume = $_; $Volumes += New-Object -TypeName psobject -Property @{ Volume = $volume -replace \"\\\?\?\\Volume\",\"\"; KeyValue = ((Get-ItemProperty HKLM:\System\MountedDevices -Name $Volume).\"$volume\" | ForEach-Object{[convert]::ToString($_, 16)}) -join \"\" ; ASCII = ((Get-ItemProperty HKLM:\System\MountedDevices -Name $Volume).\"$volume\" | ForEach-Object{[convert]::ToChar($_)}) -join \"\" -replace \"\x00\",\"\" }}; $Volumes | Select-Object Volume,ASCII,KeyValue | Export-CSV -NoTypeInformation \"$driveletter\volumes.csv\"') -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
    while (!(Test-Path ($drivemount + ":\volumes.csv"))) {start-sleep -s 1}
    Write-ProgressHelper -StatusMessage "Getting Drive Letter information from HKLM:\System\MountedDevices"
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + '$Drives = @(); Get-Item HKLM:\System\MountedDevices | Select-Object -ExpandProperty Property | where {$_ -like \"\Dos*\"} | ForEach-OBject {$drive = $_; $Drives += New-Object -TypeName psobject -Property @{ Drive = $drive -replace \"\\DosDevices\\\\\",\"\"; KeyValue = ((Get-ItemProperty HKLM:\System\MountedDevices -Name $drive).\"$drive\" | ForEach-Object{[convert]::ToString($_, 16)}) -join \"\"; ASCII = ((Get-ItemProperty HKLM:\System\MountedDevices -Name $drive).\"$drive\" | ForEach-Object{[convert]::ToChar($_)}) -join \"\" -replace \"\x00\",\"\"}}; $Drives | Select-Object Drive,ASCII,KeyValue | Export-CSV -NoTypeInformation \"$driveLetter\drives.csv\"') -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
    while (!(Test-Path ($drivemount + ":\drives.csv"))) {start-sleep -s 1}

    Write-ProgressHelper -StatusMessage "Copying generated artifacts from $ComputerName\$driveLetter"
    Copy-Item ($drivemount + ":\volumes.csv") "$export_directory\$ComputerName-volume.csv"
    Copy-Item ($drivemount + ":\drives.csv") "$export_directory\$ComputerName-drive.csv"

    Write-ProgressHelper -StatusMessage "Removing artifacts from $ComputerName\$driveLetter"
    while (!(Test-Path ("$export_directory\$ComputerName-volume.csv"))) {start-sleep -s 1}
    Remove-Item ($drivemount + ":\volumes.csv") -Force
     while (!(Test-Path ("$export_directory\$ComputerName-drive.csv"))) {start-sleep -s 1}
    Remove-Item ($drivemount + ":\drives.csv") -Force

    Write-ProgressHelper -StatusMessage "Generating table of Drive Letters and Volumes from $ComputerName"
    Import-CSV $export_directory\$ComputerName-drive.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-drives.csv
    Import-CSV $export_directory\$ComputerName-volume.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-volumes.csv
    Remove-Item $export_directory\$ComputerName-drive.csv -Force
    Remove-Item $export_directory\$ComputerName-volume.csv -Force
    $Drives = (Import-CSV $export_directory\$ComputerName-drives.csv)
    $Volumes = (Import-CSV $export_directory\$ComputerName-volumes.csv)
    Join-Object -Left $Drives -Right $Volumes -LeftJoinProperty KeyValue -RightJoinProperty KeyValue -Type AllInBoth | Select-Object ComputerName,Drive,Volume,ASCII,KeyValue | Sort-object Device | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-volumes_and_drives.csv"

    Write-ProgressHelper -StatusMessage "Getting User Mountpoints from each users NTUSER.DAT registry key on $ComputerName"
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + '(Get-ItemProperty \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*\" | Where {$_.ProfileImagePath -notlike \"C:\windows*\"}| Select-Object @{n=\"UserName\";e={($_.ProfileImagePath -split \"\\\\\")[2]}}, @{n=\"SID\";e={$_.PSChildName}} | ForEach-Object {$SID = $_.SID; $UserName = $_.UserName; (Get-Item Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2).GetSubKeyNames() -like \"{*\" } | Select-Object @{n=\"GUID\";e={$_}},@{l=\"UserName\";e={$UserName}}) | Export-CSV -NoTypeInformation \"$driveLetter\UserMountPoints.csv\"') -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
    Start-sleep -s 5

    Write-ProgressHelper -StatusMessage "Copying User Mountpoints artifacts from $ComputerName"
    Copy-Item ($drivemount + ":\UserMountPoints.csv") "$export_directory\$ComputerName-usermount.csv"

    Write-ProgressHelper -StatusMessage "Removing artifact from $ComputerName"
    Remove-Item ($drivemount + ":\usermountpoints.csv") -Force

    Write-ProgressHelper -StatusMessage "Generating table of Drive Letters, Volumes, and Usernames who mounted them"
    $DriveVols = (Import-CSV "$export_directory\$ComputerName-volumes_and_drives.csv")
    Import-CSV $export_directory\$ComputerName-usermount.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-usermounts.csv
    Remove-Item $export_directory\$ComputerName-usermount.csv -Force
    $UserMounts = (Import-CSV "$export_directory\$ComputerName-usermounts.csv")
    Join-Object -Left $DriveVols -Right $UserMounts -LeftJoinProperty Volume -RightJoinProperty GUID -Type AllInBoth | Select-Object ComputerName,Drive,GUID,Volume,UserName,ASCII,KeyValue | Sort-object Device | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-alldrives.csv"

    Write-ProgressHelper -StatusMessage "Retrieving USBSTOR and WpdBusEnum information from $ComputerName to get volume names"
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + ('Get-ItemProperty HKLM:\System\CurrentControlSet\Enum\USBSTOR\*\* | Select-Object @{n=\"Serial\";e={($_.PSChildName -replace \"&[0-9]$\",\"\")}},@{n=\"Device\";e={$_.FriendlyName}},ContainerID,@{n=\"HardwareID\";e={($_.HardwareID)[0]}},@{n=\"Vendor_Product\";e={($_.PSParentPath -split \"\\\\\")[6]}} | Export-CSV -NoTypeInformation \"$driveLetter\usbstor.csv\"')) -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
    while (!(Test-Path ($drivemount + ":\usbstor.csv"))) {start-sleep -s 1}
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + ('Get-ItemProperty HKLM:\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\* | Select-Object DeviceDesc,FriendlyName,ContainerID | Export-CSV -NoTypeInformation \"$driveLetter\wpdenum.csv\"')) -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
    while (!(Test-Path ($drivemount + ":\wpdenum.csv"))) {start-sleep -s 1}

    Write-ProgressHelper -StatusMessage "Retrieving artifacts from $ComputerName"
    Copy-Item ($drivemount + ":\usbstor.csv") ("$export_directory\$ComputerName-usbstors.csv")
    Copy-Item ($drivemount + ":\wpdenum.csv") ("$export_directory\$ComputerName-wpdenums.csv")
    Start-Sleep -s 5

    Write-ProgressHelper -StatusMessage "Removing generated artifacts from $ComputerName"
    while (!(Test-Path ("$export_directory\$ComputerName-usbstors.csv"))) {start-sleep -s 1}
    Remove-Item ($drivemount + ":\usbstor.csv") -Force
    while (!(Test-Path ("$export_directory\$ComputerName-wpdenums.csv"))) {start-sleep -s 1}
    Remove-Item ($drivemount + ":\wpdenum.csv") -Force

    Write-ProgressHelper -StatusMessage "Generating table containing all USB drive information from registry from $ComputerName"
    Import-CSV $export_directory\$ComputerName-usbstors.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-usbstor.csv
    Import-CSV $export_directory\$ComputerName-wpdenums.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-wpdenum.csv
    Remove-Item $export_directory\$ComputerName-usbstors.csv -Force
    Remove-Item $export_directory\$ComputerName-wpdenums.csv -Force
    $usbtable = (Import-CSV $export_directory\$ComputerName-usbstor.csv)
    $wpdtable = (Import-CSV $export_directory\$ComputerName-wpdenum.csv)
    Join-Object -Left $wpdtable -Right $usbtable -LeftJoinProperty ContainerID -RightJoinProperty ContainerID -Type AllInBoth  | Select-Object ComputerName,Device,FriendlyName,Serial,HardwareID,Vendor_Product,ContainerID | Sort-Object Device | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-driveinfo.csv"

    Write-ProgressHelper -StatusMessage "Retrieving setupapi.dev.log from $ComputerName"
    Copy-Item ($drivemount + ":\Windows\inf\setupapi.dev.log") ("$export_directory\$ComputerName-setupapi.dev.log")
    Start-sleep -s 2

    Write-ProgressHelper -StatusMessage "Grabbing First and Last Insert Dates for all USB devices discovered using setupapi.dev.log and Windows Event Logs from $ComputerName"
    Get-WinEvent -ComputerName $ComputerName @credsplat @{LogName = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"} | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-driverframeworks.csv"
    $driveinfo = Import-CSV $export_directory\$ComputerName-driveinfo.csv
    $driver = Import-CSV $export_directory\$ComputerName-driverframeworks.csv
    $driveinfo | Select-Object Serial | ForEach-Object {$Serial = $_.Serial ; $lastremoved = ($driver | Where {$_.Id -eq '2100' -and $_.message -like "*(27, 2)*" -and $_.message -match "$Serial"}).TimeCreated; $driver | Where-Object {$_.message -match "$Serial" -and $_.Id -eq '2003'} | Select-Object ComputerName,@{n="LastInsert";e={$_.TimeCreated}}, @{n="LastRemoved";e={$lastremoved}},ID, OpCodeDisplayName, UserID, Message, @{n="Serial";e={$Serial}}  | Sort-Object Serial -desc} | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-usblastinsert.csv"
    $driveinfo | Select-Object Serial | ForEach-object {$Serial = $_.Serial; Get-Content "$export_directory\$ComputerName-setupapi.dev.log" | Select-string $serial -SimpleMatch -Context 0,1 | Select @{l="ComputerName";e={$ComputerName}},@{n="FirstInsert";e={[datetime](($_.Context.PostContext[0]) -replace ">>>  Section Start ","")}}, @{n="Device";e={($_.Line) -replace ">>>  \[Device\ Install\ \(Hardware\ initiated\)\ -\ ","" -replace "\]",""}}, @{n="Serial";e={$serial}}} | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-usbfirstinsert.csv"
    $lastInsert = Import-CSV $export_directory\$ComputerName-usblastinsert.csv
    $firstInsert = Import-CSV $export_directory\$ComputerName-usbfirstinsert.csv
    Join-Object -left $firstInsert -right $lastInsert -LeftJoinProperty Serial -RightJoinProperty Serial -Type AllInLeft | select ComputerName, Device, FirstInsert, LastInsert, LastRemoved, Serial, OpCodeDisplayName,UserID,Message,ID | Sort-Object Device -desc -Unique | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-usbinserttimes.csv"

    <# No longer necessary, retrieve from USB via LastWrite
    Write-ProgressHelper -StatusMessage "Grabbing VID/PID of USB devices from $ComputerName"
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + 'Get-ItemProperty HKLM:\System\CurrentControlSet\Enum\USB\*\*\  | Select-Object @{n=\"Serial\";e={$_.PSChildName}}, @{n=\"VID_PID\";e={($_.HardWareID -split \"\\\\\")[1]}}, ContainerID | Export-CSV -NoTypeInformation \"$driveLetter\usbvidpid.csv\"') -ComputerName $ComputerName @credsplat -ErrorAction stop | Out-Null
    while (!(Test-Path ($drivemount + ":\usbvidpid.csv"))) {start-sleep -s 1}
    Copy-Item ($drivemount + ":\usbvidpid.csv") ("$export_directory\$ComputerName-usbvidpid.csv")
    Start-sleep -s 1
    while (!(Test-Path ("$export_directory\$ComputerName-usbvidpid.csv"))) {start-sleep -s 1}
    Remove-Item ($drivemount + ":\usbvidpid.csv") -Force
    $usbvidpid = Import-CSV $export_directory\$ComputerName-usbvidpid.csv
    #>
    
    Write-ProgressHelper -StatusMessage "Getting USB First Insert and USBSTOR Key Last Write Times"
    Get-RemoteUSBLastWrite $ComputerName @credsplat
    Start-sleep -s 3
    Copy-Item ($drivemount + ":\usblastwrite.csv") ("$export_directory\$ComputerName-usblastwrites.csv")
    Import-CSV $export_directory\$ComputerName-usblastwrites.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-usblastwrite.csv
    Remove-Item $export_directory\$ComputerName-usblastwrites.csv -Force
    $lastwrite = (Import-CSV $export_directory\$ComputerName-usblastwrite.csv)
    Copy-Item ($drivemount + ":\usbfirstsincereboot.csv") ("$export_directory\$ComputerName-usbfirstsincereboots.csv")
    Import-CSV $export_directory\$ComputerName-usbfirstsincereboots.csv | Select @{l="ComputerName";e={$ComputerName}},* | Export-CSV -NoTypeInformation $export_directory\$ComputerName-usbfirstsincereboot.csv
    Remove-Item $export_directory\$ComputerName-usbfirstsincereboots.csv -Force
    $firstsince = (Import-CSV $export_directory\$ComputerName-usbfirstsincereboot.csv)
    Join-Object -Left $lastwrite -right $firstsince -LeftJoinProperty Serial -RightJoinProperty Serial -Type AllInBoth | Select ComputerName,VID_PID,Serial,FirstInsertSinceReboot,LastWrite | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-usbwritetimes.csv"
    $writetimes = (Import-CSV $export_directory\$ComputerName-usbwritetimes.csv)
    Join-Object -Left $driveinfo -Right $writetimes -LeftJoinProperty Serial -RightJoinProperty Serial -Type AllInLeft | Select ComputerName,Device, FriendlyName, Serial, HardwareID, Vendor_Product,ContainerID,FirstInsertSinceReboot,LastWrite | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-alldriveinfo.csv"
    Remove-Item ($drivemount + ":\usblastwrite.csv") -Force
    Remove-Item ($drivemount + ":\usbfirstsincereboot.csv") -Force
    <#$alldriveinfo = Import-CSV $export_directory\$ComputerName-alldriveinfo.csv
    Join-Object -Left $alldriveinfo -Right $usbvidpid -LeftJoinProperty ContainerID -RightJoinProperty ContainerID -Type AllInLeft | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-alldriveinfo.csv" #>
    $usbinsert = Import-CSV $export_directory\$ComputerName-usbinserttimes.csv
    $alldriveinfo = Import-CSV $export_directory\$ComputerName-alldriveinfo.csv
    Join-Object -left $alldriveinfo -right $usbinsert -LeftJoinProperty Serial -RightJoinProperty Serial -Type AllInBoth | Select ComputerName, Device, FriendlyName,Serial,HardWareID,Vendor_Product,VID_PID,ContainerID,FirstInsert,@{n="FirstInsertSinceReboot";e={[datetime]$_.FirstInsertSinceReboot}},LastInsert,@{n="LastWrite";e={[datetime]$_.LastWrite}},LastRemoved | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-finaldriveinfo.csv"

    Write-ProgressHelper -StatusMessage "Combining all USB Registry Information together"
    $alldrives = (Import-CSV $export_directory\$ComputerName-alldrives.csv | Select-Object ComputerName,Drive,GUID,Volume,UserName,@{n="DeviceSerial";e={((($_.ASCII) -split "\#")[2]) -replace "&[0-9]$",""}},ASCII,@{n="DeviceType";e={(($_.ASCII) -split "\#")[1]}},KeyValue)
    $finaldriveinfo = (Import-CSV $export_directory\$ComputerName-finaldriveinfo.csv)
    Join-Object -Left $finaldriveinfo -right $alldrives -LeftJoinProperty Serial -RightJoinProperty DeviceSerial -Type AllInBoth | Select-Object ComputerName,Drive,Device,FriendlyName,DeviceType,Serial,DeviceSerial,UserName,GUID,Volume,HardwareID,Vendor_Product,VID_PID,KeyValue,ASCII,FirstInsert,FirstInsertSinceReboot,LastInsert,LastWrite,LastRemoved | Sort-Object Drive -Descending | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-device_info.csv"
    #Grab the USB information from the host and put it in the Basic Info HTML file for quick reference

    Import-CSV $export_directory\$ComputerName-device_info.csv | Select-Object Drive,Device,FriendlyName,DeviceType,Serial,DeviceSerial,UserName,Guid,Volume,FirstInsert,FirstInsertSinceReboot,LastInsert,LastWrite,LastRemoved | ConvertTo-HTML -Head $htmlHeader -Body "<h2>USB Registry Information</h2>"  >> $export_directory\$ComputerName-basicinfo.html
    Write-ProgressHelper -StatusMessage "Remote USB Device Information retrieval complete." -StepNumber ($stepCounter++)
    Remove-PSDrive $drivemount
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteUSB $ComputerName $Credential
    }
}

#Specific Registry Key
function Get-RemoteRegistryKey{
#Grab details about a specific registry on a host or a group of hosts
param($ComputerName,[ValidateNotNullOrEmpty()]$Credential,[switch]$HKCR,[switch]$HKCU,[switch]$HKLM,[switch]$HKU,[switch]$HKCC,$Subkey,$Value)
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteRegistryKey $ComputerName $Credential
        }
    }
    if ($HKCR) {$Hive = 2147483648; $HiveName = "HKEY_CLASSES_ROOT"; $Choice = $HKCR}
    if ($HKCU) {$Hive = 2147483649; $HiveName = "HKEY_CURRENT_USER"; $Choice = $HKCU}
    if ($HKLM) {$Hive = 2147483650; $HiveName = "HKEY_LOCAL_MACHINE"; $Choice = $HKLM}
    if ($HKU) {$Hive = 2147483651; $HiveName = "HKEY_USERS"; $Choice = $HKU}
    if ($HKCC) {$Hive = 2147483653; $HiveName = "HKEY_CURRENT_CONFIG"; $Choice = $HKCC}
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    #$Credential = $script:Credential
    Try {
        $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Elseif ($Credential -eq $null -and $script:Credential -ne [pscredential]::Empty) {
        $Credential = $script:Credential
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -eq $null -and $script:Credential -ne $null) {
        $credsplat['Credential'] = (Get-Credential -Message "Username and Password Required" -Username $credname)
    }
    $REG_SZ = 1
    $REG_EXPAND_SZ = 2
    $REG_BINARY = 3
    $REG_DWORD = 4
    $REG_MULTI_SZ = 7
    $REG_QWORD = 11
    if ($subkey[-1] -ne "\") {
        $subkey = ($subkey + "\")
    }
    $RegProvider = Get-WmiObject -list "StdRegProv" -namespace root\default -ComputerName $ComputerName @credsplat
    $sNames = $RegProvider.EnumValues($hive, $subkey).sNames
    $Types = $RegProvider.EnumValues($hive, $subkey).Types
    $Index = [array]::IndexOf($sNames, $value)
    $Type = $Types[$Index]
    switch ($Type) {
          $REG_SZ
          {
            $KeyType = 'REG_SZ'
            $ReturnKeyValue = $RegProvider.GetStringValue($hive, $subkey, $value).sValue
            Break
          }
          $REG_EXPAND_SZ
          {
            $KeyType = 'REG_EXPAND_SZ'
            $ReturnKeyValue = $RegProvider.GetExpandedStringValue($hive, $subkey, $value).sValue
            Break
          }
          $REG_BINARY
          {
            $KeyType = 'REG_BINARY'
            $ReturnKeyValue =  $RegProvider.GetBinaryValue($hive, $subkey, $value).uValue
            Break
          }
          $REG_DWORD
          {
            $KeyType = 'REG_DWORD'
            $ReturnKeyValue = $RegProvider.GetDWORDValue($hive, $subkey, $value).uValue
            Break
          }
          $REG_MULTI_SZ
          {
            $KeyType = 'REG_MULTI_SZ'
            $ReturnKeyValue = $RegProvider.GetMultiStringValue($hive, $subkey, $value).sValue
            Break
          }
          $REG_QWORD
          {
            $KeyType = 'REG_QWORD'
            $ReturnKeyValue = $RegProvider.GetQWORDValue($hive, $subkey, $value).sValue
            Break
          }
        }
    Write-Output "\\$ComputerName\$HiveName\$subkey$value is a $KeyType key with a value of $ReturnKeyValue"
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteRegistryKey $ComputerName $Credential $Choice $subkey $value
    }
}
function Get-RemoteRecentFiles($ComputerName,$Credential){
#Get the Users directories and list all recent files for each user
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteRecentFiles $ComputerName $Credential
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-ProgressHelper -StatusMessage "Checking Remote Users Recent Files" -StepNumber ($stepCounter++)
    $RemoteUsers = (Get-WmiObject win32_userprofile -ComputerName $ComputerName @credsplat | Select-Object LocalPath | Where-Object {$_.LocalPath -like "*Users*"})
        ForEach ($UserFolder in $RemoteUsers){$UserFolder = ($RemoteUsers.LocalPath -split "\\")[-1]; Get-WmiObject cim_datafile -ComputerName $ComputerName @credsplat -Filter ('drive="c:" AND path="\\Users\\' + $UserFolder + '\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"') | Select-Object @{l="ComputerName";e={$ComputerName}},@{l="UserName";e={$UserFolder}},@{n="FileName";e={($_.Name -split "\\")[-1]}},@{n="CreationDate";e={$_.ConvertToDateTime($_.CreationDate)}},@{n="InstallDate";e={$_.ConvertToDateTime($_.InstallDate)}},@{n="LastAccessed";e={$_.ConvertToDateTime($_.LastAccessed)}},@{n="LastModified";e={$_.ConvertToDateTime($_.LastModified)}}| Export-CSV -NoTypeInformation -Append "$export_directory\$ComputerName-RecentFiles.csv"
        }
    }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output ($PSItem -split "\.")[0] "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteRecentFiles $ComputerName $Credential
    }
}

function Get-RemoteUSBLastWrite($ComputerName,$Credential){
    Try {
    $powershell = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -command "
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    $scriptblock = {$Domain = [AppDomain]::CurrentDomain;
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly');
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run);
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False);
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class');
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey',
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', 
                [IntPtr], 
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle],
                    [System.Text.StringBuilder],
                    [UInt32 ].MakeByRefType(),
                    [UInt32],
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [UInt32 ].MakeByRefType(),
                    [long].MakeByRefType()
                )
            );
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]));
            $FieldArray = [Reflection.FieldInfo[]] @(       
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            );
            $FieldValueArray = [Object[]] @('RegQueryInfoKey',$True);
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,@('advapi32.dll'),$FieldArray,$FieldValueArray);
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute);
            [void]$TypeBuilder.CreateType();
            $ClassLength = 255;
        [long]$TimeStamp = $null;
        $RegistryKeyLastWrite = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'default').OpenSubKey('SYSTEM\CurrentControlSet\Enum\USB');
        Add-Content -Path 'C:\usblastwrite.csv' -Value ('VID_PID,LastWrite,Serial')
        foreach ($value in $RegistryKeyLastWrite.GetSubKeyNames()){
        $serial = (($RegistryKeyLastWrite.OpenSubKey($value)).GetSubKeyNames());
        $ClassName = New-Object System.Text.StringBuilder (($RegistryKeyLastWrite.OpenSubKey($value)).OpenSubKey($serial)).Name;
        $RegistryHandle = (($RegistryKeyLastWrite.OpenSubKey($value)).OpenSubKey($serial)).Handle;
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        );
        [string]$lastwrite = [datetime]::FromFileTime($TimeStamp);
        $lastwrite = $lastwrite.Trim();
        Add-Content -Path 'C:\usblastwrite.csv' -Value ($value + ',' + $lastwrite + ',' + ($serial -replace '&[0-9]$',''))
            }
        $RegistryKeyReboot = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'default').OpenSubKey('SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}');
        [long]$TimeStamp = $null;
        Add-Content -Path 'C:\usbfirstsincereboot.csv' -Value ('DeviceName,FirstInsertSinceReboot,Serial');
        foreach ($value in $RegistryKeyReboot.GetSubKeyNames()){
        $serial = ((($RegistryKeyReboot.OpenSubKey($value)) -split '#')[5]) -replace '&[0-9]$','';
        $ClassName2 = New-Object System.Text.StringBuilder ($RegistryKeyReboot.OpenSubKey($value)).Name;
        $RegistryHandle2 = ($RegistryKeyReboot.OpenSubKey($value)).Handle;
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle2,
            $ClassName2,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        );
        [string]$firstSinceReboot = [datetime]::FromFileTime($TimeStamp);
        $firstSinceReboot = $firstSinceReboot.Trim();
        Add-Content -Path 'C:\usbfirstsincereboot.csv' -Value ($value + ',' + $firstSinceReboot + ',' + $serial)
            }
        }
        Invoke-WmiMethod win32_process -Name Create -ArgumentList ($powershell + $scriptblock) -ComputerName $ComputerName @credsplat -ErrorAction Stop | Out-Null
        }
        Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteUSBLastWrite $ComputerName $Credential
    }
}

function Get-RemoteNetCap{
param($ComputerName,[ValidateNotNullOrEmpty()]$Credential,[Parameter(Mandatory=$True)][int]$Timespan)
    if ($ComputerName -like '*.txt') {
        ForEach ($Computer in Get-Content $ComputerName) {
        $ComputerName = $Computer
        Get-RemoteNetCap $ComputerName $Credential $Timespan
        }
    }
    if ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credname = $Credential
        }
    Elseif ($Credential -is [pscredential]) {
        $credname = $Credential.UserName
        }
    $Credential = $script:Credential
    Try {
    $credsplat = @{}
    if ($Credential -is [pscredential]){
        $credsplat['Credential'] = $Credential
    }
    Elseif ($Credential -ne $null -and $Credential -isnot [pscredential]) {
        $credSplat['Credential'] = (Get-Credential -Message "Username and Password Required" -UserName $credname)
    }
    Else {
        $credsplat['Credential'] = $Credential
    }
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$"
    $driveLetter = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName @credsplat | Select-Object -expand SystemDrive) + "\"
    CheckExportDir
    $drivemount = (Get-ChildItem function:[d-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1) -replace ":",""
    New-PSDrive -Name $drivemount -PSProvider filesystem -Root $net_path @credsplat | Out-Null
    Write-ProgressHelper -StatusMessage "Getting $Timespan second traffic capture from $ComputerName" -StepNumber ($stepCounter++)
    $netstart = "cmd /c netsh trace start capture=yes report=yes provider=Microsoft-Windows-TCPIP provider=Microsoft-Windows-Security-Netlogon tracefile="
    $netstop = "cmd /c netsh trace stop"
    $stamp = [int](Get-Date -UFormat %s)
    $filename = ($ComputerName + '-' + [string]$stamp + '-capture.etl')
    $cabfile = ($ComputerName + '-' + [string]$stamp + '-capture.cab')
    Invoke-WmiMethod win32_process -Name Create -ArgumentList ($netstart + $driveLetter + $filename) -ComputerName $ComputerName @credsplat -ErrorAction SilentlyContinue | Out-Null
    $Message = "Capture set for $Timespan seconds"
    Write-ProgressHelper -StatusMessage "Capture started - will complete in $Timespan seconds" -StepNumber ($stepCounter++) 
    foreach ($second in (1..$Timespan)){$Multiplier = (100 / $Timespan); Write-Progress -Id 1 -Activity $Message -Status "$($Timespan - $second) seconds remaining" -PercentComplete (($Timespan - $second) * $Multiplier) ; start-sleep -s 1 }
    Write-Progress -Activity 'Completed' -Completed -Id 1
    Write-Output "Capture time met - stopping capture"
    Write-ProgressHelper -StatusMessage "Capture time met - stopping capture" -StepNumber ($stepCounter++)
    Invoke-WmiMethod win32_process -name Create -ArgumentList ($netstop) -ComputerName $ComputerName @credsplat -ErrorAction SilentlyContinue | Out-Null
    while (!(Test-Path ("$drivemount`:\$cabfile"))){start-sleep -s 1}
    Write-ProgressHelper -StatusMessage "Copying Files" -StepNumber ($stepCounter++)
    Write-Output "Copying Files"
    Copy-Item ("$drivemount`:\$filename") ("$export_directory\$filename")
    Copy-Item ("$drivemount`:\$cabfile") ("$export_directory\$cabfile")
    while (!(Test-Path ("$export_directory\$cabfile"))){Start-Sleep -s 1}
    Remove-Item ("$drivemount`:\$filename") -Force
    Remove-Item ("$drivemount`:\$cabfile") -Force
    Write-ProgressHelper -StatusMessage "Copy Complete" -StepNumber ($stepCounter++)
    Write-Output "Copy Complete"
    Remove-PSDrive $drivemount | Out-Null
    Write-ProgressHelper -StatusMessage "Converting trace to CSV" -StepNumber ($stepCounter++)
    Write-Output "Converting trace to CSV"
    & netsh trace convert input="$export_directory\$filename" output="$export_directory\$filename.csv" dump=CSV| Out-Null
    Get-WinEvent -Path "$export_directory\$filename" -oldest | Select @{l="ComputerName";e={$ComputerName}},TimeCreated, @{n='PID';e={$udppid = $_.Message -match '.*PID = (\d+).*'; $ipv6pid = $_.Message -match '.*PID=(\d+).*'; if($_.Message -like 'TCP*' -and $_.Message -like '*PID =*'){$_.Properties[6].Value}elseif($_.Message -like 'TCP*' -and $ipv6pid){($ipv6pid = $matches[1])}elseif($_.Message -like 'UDP*' -and $udppid){($udppid = $matches[1])}else {'N/A'}}}, @{n="State";e={if($_.Message -like '*State =*'){($_.Message -split ' ')[8] -replace '\.',''}else{'N/A'}}}, @{n='Local IP and PORT';e={if ($_.Message -like 'TCP*' -and $_.Message -like '*local=*'){($_.Message -split ' ')[3] -replace '\(local=',''}elseif($_.Message -like 'UDP*' -and $_.Message -like '*LocalAddress =*'){($_.message -split ' ')[5] -replace ',',''}else{'N/A'}}}, @{n='Remote IP and Port';e={if ($_.Message -like 'TCP*' -and $_.Message -like '*remote=*'){($_.Message -split ' ')[4] -replace '\)','' -replace 'remote=',''}elseif($_.Message -like 'UDP*' -and $_.Message -like '*RemoteAddress*'){($_.Message -split ' ')[8] -replace '\)',''}else{'N/A'}}}, @{n='NDIS: IPv4';e={if ($_.Message -like '*IP Address =*'){($_.Message -split ' ')[16]}else{'N/A'}}},@{n='NDIS: IPv6';e={if ($_.Message -like '*IPv6 address =*'){($_.Message -split ' ')[23] -replace '\.',''}else{'N/A'}}}, Message | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-netinfo.csv"
    Write-Output "Conversion complete"
    Write-ProgressHelper -StatusMessage "Conversion complete" -StepNumber ($stepCounter++)
        }
    Catch [System.UnauthorizedAccessException] {
    Write-ProgressHelper -StatusMessage "Username and Password Required"
    Write-Output "Credentials Required"
    $Credential = Get-Credential -Message "Username and Password Required" -UserName $credname
    $script:Credential = $Credential
    Get-RemoteNetCap $ComputerName $Credential $Timespan
    }
}
#Cleanup
function Cleanup {
#Ensure the Credential and Credname variables do not stick in the current environment
Clear-Variable -Name Credential
Clear-Variable -Name Credname
Remove-Variable -Name Credential
Remove-Variable -Name credname
}
Set-Alias rra RemoteRunAll
Export-ModuleMember -Function RemoteRunAll -alias rra
Export-ModuleMember -function Get-Remote*



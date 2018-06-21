     <#

    .SYNOPSIS
        This powershell script has been designed to remotely connect to a machine (to which you have administrative access already), and
        retrieve several forensic artifacts including USBSTOR info from the registry, arpcache, dnscache, event logs etc.
        Currently the only thing required is the hostname (as indicated under Parameters) and the script will run all functions.

        TODO:
            Add redundancies for failures
            Add sqlite3.exe for csv import to db
            Add portable db viewer.
            Add Functions for individual launch
            Add choice of export (if var = csv, then $format = ....)
    .DESCRIPTION
        

    .NOTES
        Version        : 0.1
        Author         : Fetchered
        Prerequisite   : winpmem.exe binary in $location\bin folder

       

    .PARAMETER hostname


        The host you want to run the remote acquisition against - default is 127.0.0.1
    .Example
    
        
        Get-
        Actual command:
        Get-

    #>
[CmdletBinding()]
param (
    [Parameter(ParameterSetName='ComputerName', Position=0)]
    [Alias("Cn","hostname","comp","host")]
    $ComputerName = "127.0.0.1",
    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,
<#  [Parameter(Position=1)]
    [System.String]$creds = $null, #To be added soon
    [Parameter(Position=2)]
    [System.String]$format = "csv", #To be added soon #>
    [System.String]$location = (get-location),
    [System.String]$export_directory = "$location\$ComputerName",
    [System.String]$net_path = "\\$ComputerName\C$\",
    [System.String]$driveLetter = (gwmi win32_operatingsystem -ComputerName $ComputerName -Credential $Credential | select -expand SystemDrive) + "\",
    [System.String]$powershell = ($driveLetter + "windows\system32\WindowsPowerShell\v1.0\powershell.exe"),
    [System.String]$shell = ("cmd /c " + $driveLetter + "windows\system32\"),
    [System.String]$shimcachelocation = "SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\",
    [System.String]$htmlHeader = @'
<!--mce:0-->
<style>BODY{font-family: Arial; font-size: 10pt;}
TABLE{border: 1px solid black; border-collapse: collapse;}
TH{border: 1px solid black; background: #dddddd; padding: 5px;}
TD{border: 1px solid black; padding: 5px;}</style>
'@,
    $regkey = @{ "HKEY_CLASSES_ROOT" = 2147483648; "HKEY_CURRENT_USER" = 2147483649; "HKEY_LOCAL_MACHINE" = 2147483650; "HKEY_USERS" = 2147483651; "HKEY_CURRENT_CONFIG" = 2147483653 },
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}},
    $TimeWritten = @{n="TimeWritten";e={$_.ConvertToDateTime($_.TimeWritten)}},
    $reg = (Get-WMIObject -List -NameSpace "root\default" -ComputerName $ComputerName -Credential $Credential | Where-Object {$_.Name -eq "StdRegProv"})
    <#
    If($format = csv{
        $outputFormat = (Export-CSV -NoTypeInformation $export_directory\$ComputerName-<>+ "." + $format)
        }
    Elseif($format = db{ 
        $outputFormat = ""
        }
    Elseif($format = html{
        $outputFormat = ""
        }
    #>
    )

function CheckExportDir() {
#Check to see if the directory we want to export to exists and, if not, create it.
    $location = (get-location)
    $export_directory = "$location\$ComputerName"
    $testFolder = (test-path $export_directory)
    $makeFolder = (New-Item -ItemType Directory -Force -Path $export_directory | Out-Null)
    if (!($testFolder)) {Write-Progress -Activity "Export directory $export_directory does not exist" -Status "Creating export directory...";
        $makeFolder
        }
}

function RemoteRunAll($ComputerName){
#Run all functions against the target 
    $location = (get-location)
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Host ""
    Write-Host "Running All Functions against $ComputerName"
    $functions = @('Get-RemotePCInfo','Get-RemoteApplications','Get-RemoteAuditStatus','Get-RemoteAccountLogoff','Get-RemoteTaskEvents','Get-RemoteAuditLog', 'Get-RemoteUserEvents', 'Get-RemoteUserChanges','Get-RemotePasswordEvents','Get-RemoteGroupEvents','Get-RemoteGroupChanges','Get-RemoteRunAs','Get-RemoteSpecialPriv','Get-RemoteSRPBlock','Get-RemotePowerEvents','Get-RemoteSvcStatusEvents','Get-RemoteSvcInstallsEvents','Get-RemoteProcesses', 'Get-RemoteServicesActive','Get-RemoteArtifacts','Get-RemoteMemoryDump','Get-RemoteWirelessInfo','Get-RemoteAppCompat')
    foreach ($func in $functions){ 
    Write-Progress -Activity "Starting function" -Status "Running $func"
    & $func $ComputerName
    }
}

#Basic Info
function Get-RemotePCInfo($ComputerName) {
#Grab numerous pieces of information about the host to establish basic details for reference
#Output to HTML file
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Gathering basic host information for $ComputerName"
    $ReportTitle="Basic PC Information"
    $strPath = "$export_directory\$ComputerName-basicinfo.html"
    $pcsystemType = @{ 0="Unspecified"; 1="Desktop";2="Mobile";3="Workstation";4="Enterprise Server";5="Small Office and Home Office (SOHO) Server";6="Appliance PC";7="Performance Server";8="Maximum" }
    $get_type = ([int](gwmi win32_computersystem -ComputerName $ComputerName -Credential $Credential | select -ExpandProperty PCSystemType))
    $installDate = @{n="Install Date";e={$_.ConvertToDateTime($_.installdate)}}
    $oemkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
    $regnames = $reg.EnumValues($regkey.HKEY_LOCAL_MACHINE, $oemkey).sNames
    ConvertTo-Html -Head $htmlHeader -Title $ReportTitle -Body "<h1> Computer Name : $ComputerName </h1>" > "$strPath"  
    Get-WmiObject win32_computersystem -ComputerName $ComputerName -Credential $Credential|select PSComputerName,Name,Manufacturer,Domain,Model,Systemtype,PrimaryOwnerName,@{n="PC System Type";e={$pcsystemType.$get_type}},PartOfDomain,CurrentTimeZone,BootupState | ConvertTo-Html  -Head $htmlHeader -Body "<h5>Created on: $(Get-Date)</h5><h2>ComputerSystem</h2>" >> "$strPath" 
    Get-WmiObject win32_bios -ComputerName $ComputerName -Credential $Credential| select Status,Version,PrimaryBIOS,Manufacturer,@{n="Release Date";e={$_.ConvertToDateTime($_.releasedate)}},SerialNumber | ConvertTo-Html -Head $htmlHeader -Body "<h2>BIOS Information</h2>" >> "$strPath" 
    Get-WmiObject win32_Useraccount -ComputerName $ComputerName -Credential $Credential | where {$_.localaccount -Match 'True'} | select Name,SID,Description,Fullname,Disabled | ConvertTo-html -Head $htmlHeader -Body "<h2>Local Users</h2>" >> "$strPath" 
    ((Get-WmiObject win32_groupuser -ComputerName $ComputerName -Credential $Credential |? {$_.groupcomponent -like '*"Administrators"'} |% {$_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $nul; $matches[1].trim('"') + "\" + $matches[2].trim('"') }) -split " " | Select @{n="Administrators";e={$_.Trim()}} | ConvertTo-HTML -Head $htmlHeader -Body "<h2>Administrators</h2>") -replace "\*","Administrators" >> "$strPath"
    Get-WmiObject win32_DiskDrive -ComputerName $ComputerName -Credential $Credential | Select Index,Model,Caption,SerialNumber,Description,MediaType,FirmwareRevision,Partitions,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},PNPDeviceID | Sort-Object -Property Index | ConvertTo-Html -Head $htmlHeader -Body "<h2>Disk Drive Information</h1>" >> "$strPath" 
    Get-WmiObject win32_networkadapter -ComputerName $ComputerName -Credential $Credential | Select Name,Manufacturer,Description,AdapterType,Speed,MACAddress,NetConnectionID,PNPDeviceID | ConvertTo-Html -Head $htmlHeader -Body "<h2>Network Adapter Information</h2>" >> "$strPath" 
    Get-WmiObject win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Credential $Credential | select @{n='IP Address';e={$_.ipaddress}},Description,@{n='MAC Address';e={$_.macaddress}},DHCPenabled,@{n="DHCPLeaseObtained";e={$_.ConvertToDateTime($_.DHCPLeaseObtained)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>Network Adapter Configuration</h2>" >> "$strPath" 
    Get-WmiObject win32_startupCommand -ComputerName $ComputerName -Credential $Credential | select Name,Location,Command,User,Caption  | ConvertTo-html  -Head $htmlHeader -Body "<h2>Startup  Software Information</h2>" >> "$strPath" 
    Get-WmiObject win32_logicalDisk -ComputerName $ComputerName -Credential $Credential | select DeviceID,VolumeName,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},@{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Size (GB)"},FileSystem, VolumeSerialNumber |  ConvertTo-html  -Head $htmlHeader -Body "<h2>Disk Information</h2>" >> "$strPath" 
    Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -Credential $Credential | select Caption,OSArchitecture,Organization,$InstallDate,Version,SerialNumber,BootDevice,WindowsDirectory,CountryCode,@{n="Last Bootup";e={$_.ConvertToDateTime($_.lastbootup)}},@{n="Local Date/Time";e={$_.ConvertToDateTime($_.LocalDateTime)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>OS Information</h2>" >> "$strPath" 

    $htmlHeader >> "$strPath"
    echo "<br/><h2>OEM Information</h2>" >> "$strPath"
    echo "<table>" >> "$strPath"
    echo "<colgroup><col/></colgroup>" >> "$strPath"
    foreach($name in $regnames){
        $values = $reg.GetStringValue($regkey.HKEY_LOCAL_MACHINE, $oemkey, $name); 
        ("<tr><th>" + $name + "</th></tr><tr><td>"+ $values.sValue + "</td></tr>") >> "$strPath"
        }
        echo "</table></body></html>" >> "$strPath"
        }
Get-RemotePCInfo $ComputerName

#Applications
function Get-RemoteApplications($ComputerName) {
#Use the Win32_Product Class to grab all software installed by standard methods
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Installed software for $ComputerName"
    Get-WmiObject Win32_Product -ComputerName $ComputerName -Credential $Credential | select Name,InstallDate,ProductID,Vendor,Version | Export-CSV -Path "$export_directory\$ComputerName-applications.csv" -NoTypeInformation
}
Get-RemoteApplications $ComputerName

#Security Event Logs - 4624 and 4625
function Get-RemoteAuditStatus($ComputerName){
#Check the Windows Security event log for 4624 and 4625 events
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Successful/Failed Logon attempts on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $logontype4624 = @{n="LogonType";e={($_.InsertionStrings[8])}}
    $SID4624 = @{n="SID";e={$_.InsertionStrings[4]}}
    $accountname4624 = @{n="AccountName";e={$_.InsertionStrings[5]}}
    $loginid4624 = @{n="LoginID";e={$_.InsertionStrings[7]}}
    $sourcenetwork4624 = @{n="SourceNetworkAddress";e={$_.InsertionStrings[18]}}

    $logontype4625 = @{n="LogonType";e={$_.InsertionStrings[10]}}
    $SID4625 = @{n="SID";e={$_.InsertionStrings[4]}}
    $accountname4625 = @{n="AccountName";e={$_.InsertionStrings[5]}}
    $failuretype4625 = @{n="FailureType";e={$_.InsertionStrings[7]}}
    $failuresubtype4625 = @{n="FailureSubType";e={$_.InsertionStrings[9]}}
    $workstationname4625 = @{n="WorkstationName";e={$_.InsertionStrings[13]}}
    $sourcenetwork4625 = @{n="SourceNetworkAddress";e={$_.InsertionStrings[19]}}

    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4624'} | select $TimeGenerated, EventIdentifier, $logontype4624, $SID4624, $accountname4624, $loginid4624, $sourcenetwork4624 | Export-CSV -Path "$export_directory\$ComputerName-4624.csv" -NoTypeInformation
    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4625'} | select $TimeGenerated, EventIdentifier, $logontype4625, $SID4625, $accountname4625, $failuretype4625, $failuresubtype4625, $workstationname4625, $sourcenetwork4625 | Export-CSV -Path "$export_directory\$ComputerName-4625.csv" -NoTypeInformation
}
Get-RemoteAuditStatus $ComputerName

#Security Event Log Info - 4634
function Get-RemoteAccountLogoff($ComputerName){
#Check Windows Security event log for 4634 events, all types
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Logoffs on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $logofftype = @{n="LogonType";e={$_.InsertionStrings[4]}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $accountname = @{n="AccountName";e={$_.InsertionStrings[1]}}
    $loginid = @{n="LogonID";e={$_.InsertionStrings[3]}}

    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4634'} | select $TimeGenerated, EventIdentifier, Type, $logofftype, $SID, $accountname, $loginid | Export-CSV -Path "$export_directory\$ComputerName-4634.csv" -NoTypeInformation
}
Get-RemoteAccountLogoff $ComputerName

#Security Event Logs - 4698 - 4702
function Get-RemoteTaskEvents($ComputerName){
#Check the Windows Security event log for all new and modified scheduled tasks 
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for New and Modified Scheduled Tasks on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $logofftype = @{n="LogonType";e={$_.InsertionStrings[4]}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $accountname = @{n="AccountName";e={$_.InsertionStrings[1]}}
    $loginid = @{n="LogonID";e={$_.InsertionStrings[3]}}
    $exec = @{n="Exec";e={$_.InsertionStrings[5] -replace "`r`n", "" -Match "<Exec>\s{0,}(.*)</Exec"}}

    Get-WmiObject Win32_NtLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4698' -or $_.EventCode -eq '4699' -or $_.EventCode -eq '4700' -or $_.EventCode -eq '4701' -or $_.EventCode -eq '4702'} | select $TimeGenerated, EventIdentifier, $SID, $accountname, $loginid, $exec | Export-CSV -Path "$export_directory\$ComputerName-4698-4702.csv" -NoTypeInformation
}
Get-RemoteTaskEvents $ComputerName

#Event Logs - Security - 1102
function Get-RemoteAuditLog($ComputerName) {
#Check Windows Security event log for event ID 1102, when the audit log is cleared
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Audit Clearing on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $SID = @{n="SID";e={$_.InsertionStrings[0]}}
    $user = @{n="User";e={$_.InsertionStrings[1]}}
    $CompName = @{n="Computer Name";e={$_.InsertionStrings[2]}}
    $logonID = @{n="Logon ID";e={$_.InsertionStrings[3]}}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '1102'} | select $TimeGenerated, EventCode, $User, $SID, $CompName, $logonID, Type | Export-CSV -Path "$export_directory\$ComputerName-1102.csv" -NoTypeInformation
}
Get-RemoteAuditLog $ComputerName

#Event Logs - Security - 4720, 4722, 4725, 4726, 4738, 4741, 4743
function Get-RemoteUserEvents($ComputerName) {
#Check Windows Security event log for any added or deleted, accounts or computers
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Added/Deleted Accounts/Computers on $ComputerName"
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ModifiedAccount = @{n="Modified Account";e={$_.InsertionStrings[0]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[1]}}
    $ModifiedSID = @{n="Modified SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $OriginatorLogonID = @{n="Logon ID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4720' -or $_.EventCode -eq '4722' -or $_.EventCode -eq '4725' -or $_.EventCode -eq '4726' -or $_.EventCode -eq '4738' -or $_.EventCode -eq '4741' -or $_.EventCode -eq '4743'} | select $TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-userevents.csv" -NoTypeInformation
}
Get-RemoteUserEvents $ComputerName

#Event Logs - Security - 4738
function Get-RemoteUserChanges($ComputerName) {
#Check Windows Security event log for 4738, changed accounts or computers
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Changed Accounts/Computers on $ComputerName"
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
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4738'} | select $TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $ModifiedDomain, $OldUAC, $NewUAC, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-userchanges.csv" -NoTypeInformation
}
Get-RemoteUserChanges $ComputerName

#Event Logs - Security - 4723, 4724
function Get-RemotePasswordEvents($ComputerName) {
#Check Windows Security event log for password changes or resets
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Password Changes/Resets on $ComputerName"
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ModifiedAccount = @{n="Modified Account";e={$_.InsertionStrings[0]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[1]}}
    $ModifiedSID = @{n="Modified SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $OriginatorLogonID = @{n="Logon ID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4723' -or $_.EventCode -eq '4724'} | select $TimeGenerated, EventCode, $ModifiedAccount, $ModifiedSID, $OriginatingUser, $OriginatingSID, $OriginatorLogonID, $AcctDomain, Type, $message | Export-CSV -Path "$export_directory\$ComputerName-passwordevents.csv" -NoTypeInformation
}
Get-RemotePasswordEvents $ComputerName

#Event Logs - Security - 4727, 4730, 4731, 4734
function Get-RemoteGroupEvents($ComputerName) {
#Check Windows Security event log for groups that have been created, deleted or modified
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Groups Created/Deleted/Modified on $ComputerName"
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
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4727' -or $_.EventCode -eq '4730' -or $_.EventCode -eq '4731' -or $_.EventCode -eq '4734'} | select $TimeGenerated, EventCode, $MemberAccount, $MemberSID, $MemberGroup, $GroupSID, $GroupDomain, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-groupevents.csv" -NoTypeInformation
}
Get-RemoteGroupEvents $ComputerName

#Event Logs - Security - 4728, 4729, 4732, 4733, 4735
function Get-RemoteGroupChanges($ComputerName) {
#Check Windows Security event log for additions to, deletions from, or changes to groups
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Add/Delete/Change to Groups on $ComputerName"
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $GroupName = @{n="Group Name";e={$_.InsertionStrings[0]}}
    $GroupDomain = @{n="Group Domain";e={$_.InsertionStrings[1]}}
    $GroupSID = @{n="Group SID";e={$_.InsertionStrings[2]}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[3]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[4]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[5]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[6]}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4728' -or $_.EventCode -eq '4729' -or $_.EventCode -eq '4732' -or $_.EventCode -eq '4733' -or $_.EventCode -eq '4735'} | select $TimeGenerated, EventCode, $GroupName, $GroupSID, $GroupDomain, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-groupchanges.csv" -NoTypeInformation
}
Get-RemoteGroupChanges $ComputerName

#Event Logs - Security - 4648
function Get-RemoteRunAs($ComputerName) {
#Check Windows Security event log for any attempts to run applications as another user
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for RunAs attempts on $ComputerName"
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
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4648'}| select $TimeGenerated, EventCode, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $OriginatingLogonGUID, $TargetUser, $TargetDomain, $TargetGUID, $TargetServer, $ProcessID, $ProcessName, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-runas.csv" -NoTypeInformation
}
Get-RemoteRunAs $ComputerName

#Event Logs - Security - 4672
function Get-RemoteSpecialPriv($ComputerName) {
#Check the Windows Security event log for any accounts using Special Privileges
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Security Event Logs for Special Privileges on $ComputerName"
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $OriginatingSID = @{n="Originating SID";e={$_.InsertionStrings[0]}}
    $OriginatingUser = @{n="Originating User";e={$_.InsertionStrings[1]}}
    $AcctDomain = @{n="Account Domain";e={$_.InsertionStrings[2]}}
    $OriginatingLogonID = @{n="Originating LogonID";e={$_.InsertionStrings[3]}}
    $Privileges = @{n="Privileges";e={$_.InsertionStrings[4] -replace '\n','' -replace '\t\t\t',';'}}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4672'}| select $TimeGenerated, EventCode, $OriginatingUser, $OriginatingSID, $OriginatingLogonID, $Privileges, $AcctDomain, $message, Type | Export-CSV -Path "$export_directory\$ComputerName-privevents.csv" -NoTypeInformation
}
Get-RemoteSpecialPriv $ComputerName

#Event Logs - System - 866
function Get-RemoteSRPBlock($ComputerName) {
#Check Windows Application event log for any software that was blocked by the Windows Software Restriction Policy
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Application Event Logs for Software Restriction Policy on $ComputerName"
    $TimeGenerated = @{n="Time Generated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    #Need Sample of SRP event to determine format for output
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "Application"} | Where-Object {$_.EventCode -eq '866'} | select * | Export-CSV -Path "$export_directory\$ComputerName-srp.csv" -NoTypeInformation
}
Get-RemoteSRPBlock $ComputerName

#Event Logs - System - 6005-6006, 6008
function Get-RemotePowerEvents($ComputerName) {
#Check Windows System event log for any physical power events (off/on/reboot/dirty shutdown)
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking System Event Logs for Startup/PowerOff/Reboot/Dirty Shutdown on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "System"} | Where-Object {$_.EventCode -eq '6005' -or $_.EventCode -eq '6006' -or $_.EventCode -eq '6008'} | select $TimeGenerated, EventCode, Message | Export-CSV -Path "$export_directory\$ComputerName-power.csv" -NoTypeInformation
}
Get-RemotePowerEvents $ComputerName

#Event Logs - System - 7036
function Get-RemoteSvcStatusEvents($ComputerName) {
#Check Windows System log for service modifications (start/stop/restart/run)
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking System Event Logs for Service Start/Stop/Restart/Running on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $TimeWritten = @{n="TimeWritten";e={$_.ConvertToDateTime($_.TimeWritten)}}
    $ServiceName = @{n="Service Name";e={$_.InsertionStrings[0]}}
    $ServiceStatus = @{n="Service Status";e={$_.InsertionStrings[1]}}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "System"} | Where-Object {$_.EventCode -eq '7036'} | select $TimeGenerated, EventCode, $ServiceName, $ServiceStatus, ComputerName | Export-CSV -Path "$export_directory\$ComputerName-7036.csv" -NoTypeInformation
}
Get-RemoteSvcStatusEvents $ComputerName

#Event Logs - System - 7045
function Get-RemoteSvcInstallsEvents($ComputerName) {
#Check Windows System event log for services that were installed
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking System Event Logs for Service Installs on $ComputerName"
    $TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
    $ServiceName = @{n="Service Name";e={$_.InsertionStrings[0]}}
    $ServiceFileName = @{n="Service File Name";e={$_.InsertionStrings[1]}}
    $ServiceType = @{n="Service Type";e={$_.InsertionStrings[2]}}
    $ServiceStartType = @{n="Service Start Type";e={$_.InsertionStrings[3]}}
    $user = @{n="User";e={($_.User -split '\\')[1]}}
    Get-WmiObject Win32_NTLogEvent -ComputerName $ComputerName -Credential $Credential | Where {$_.logfile -Match "System"} | Where-Object {$_.EventCode -eq '7045'} | select $TimeGenerated, EventCode, $ServiceName, $ServiceFileName, $ServiceType, $ServiceStartType, $User | Export-CSV -Path "$export_directory\$ComputerName-7045.csv" -NoTypeInformation
}
Get-RemoteSvcInstallsEvents $ComputerName

#RDP Events
function Get-RemoteRDPEvents($ComputerName) {
#Check Microsoft-Windows-TerminalServices-LocalSessionManager/Operational for RDP Events
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking for RDP Events on $ComputerName"
    $domain = @{n="domain";e={((($_.Message -split '\n')[2] -replace "\r","" -split " ")[1] -split "\\")[0] }}
    $user = @{n="User";e={((($_.Message -split '\n')[2] -replace "\r","" -split " ")[1] -split "\\")[1] }}
    $message = @{n="Message";e={($_.Message -split '\n')[0] -replace "\r","" }}
    $sessionID = @{n="Session ID";e={(($_.Message -split '\n')[3] -replace "\r","" -split " ")[2] }}
    $netAddress = @{n="Source Network Address";e={(($_.Message -split '\n')[4] -replace "\r","" -split " ")[3] }}
    Get-WinEvent -ComputerName $ComputerName -Credential $Credential @{LogName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"} | select TimeCreated, id, $sessionID, $domain, $user, $netAddress, $message | Export-CSV -Path "$export_directory\$ComputerName-rdp.csv" -NoTypeInformation 
}
Get-RemoteRDPEvents $ComputerName

#Processes
function Get-RemoteProcesses($ComputerName){
#Get the current running processes on the remote host
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Running Processes on $ComputerName"
    $CreationDate = @{n="CreationDate";e={$_.ConvertToDateTime($_.CreationDate)}}
    Get-WmiObject Win32_Process -ComputerName $ComputerName -Credential $Credential | select Name,Description,ProcessID,ParentProcessID,ThreadCount,ExecutablePath,CommandLine,@{n="Owner";e={$_.GetOwner().Domain + " " + $_.GetOwner().User}} | Export-CSV -Path "$export_directory\$ComputerName-processes.csv" -NoTypeInformation
}
Get-RemoteProcesses $ComputerName

#Services
function Get-RemoteServicesActive($ComputerName){
#Get a list of active running services on the remote host
    $export_directory = "$location\$ComputerName"
    CheckExportDir
    Write-Progress "Checking Services on $ComputerName"
    Get-WmiObject Win32_Service -ComputerName $ComputerName -Credential $Credential | select Name,ProcessID,StartMode,State,Status,PathName | export-CSV -Path "$export_directory\$ComputerName-services.csv" -NoTypeInformation
}
Get-RemoteServicesActive $ComputerName

function Get-RemoteArtifacts($ComputerName){
#Get artifacts from the remote host using Invoke-WMI objects. Artifacts will be saved on the root of the OS Drive (determined by $driveLetter)
#Artifacts then will be copied from the target to the destination, then deleted from the target
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$\"
    CheckExportDir
    Write-Progress "Retrieving specific host-based artifacts from $ComputerName"
    $fileList = @('netstat.txt','tasklist.txt','tasksvc.txt','scquery.txt','ipconfig.txt','dns.txt','route.txt','arp.txt','sched.txt','usb.csv')
    $outnet = ($driveLetter + ”netstat.txt”)
    $outtasks = ($driveLetter + ”tasklist.txt")
    $outtasksvc = ($driveLetter + ”tasksvc.txt")
    $outscquery = ($driveLetter + ”scquery.txt")
    $outipconfig = ($driveLetter + ”ipconfig.txt")
    $outdns = ($driveLetter + ”dns.txt")
    $outroute = ($driveLetter + ”route.txt")
    $outarp = ($driveLetter + ”arp.txt")
    $outsched = ($driveLetter + ”sched.txt")
    $outusb = ($driveLetter + ”usb.csv")

    
    $artifacts = @{ netstat = ("netstat.exe -ano >> $outnet"); tasklist = "tasklist.exe /v >> $outtasks"; tasksvc = "tasklist.exe /svc >> $outtasksvc"; scquery = "sc.exe query state= all >> $outscquery"; ipconfig = "ipconfig.exe /all >> $outipconfig"; dns = "ipconfig.exe /displaydns >> $outdns"; route = "route.exe PRINT >> $outroute"; arp = "arp.exe -a >> $outarp"; sched = "schtasks.exe /Query /FO CSV /V >> $outsched"; usb = ("$powershell -command Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | select FriendlyName,PSChildName | ConvertTo-CSV -NoTypeInformation >> $outusb") }

    Try{
    foreach($key in $artifacts.Keys){
        Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($shell + $artifacts.$key) -ComputerName $ComputerName -Credential $Credential -ErrorAction stop | Out-Null
        Write-Progress " -$key"
    }
    Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($artifacts.usb) -ComputerName $ComputerName -Credential $Credential -ErrorAction stop | Out-Null
    }
    Catch{
        Throw $_
        Break
    }
    Write-Progress "Copying artifacts to export directory"
    foreach($file in $fileList){
        Start-Sleep -s 2
        Copy-Item ($net_path + $file) "$export_directory\$ComputerName-$file" -Force
        Write-Progress "Removing $file from host"
        Remove-Item ($net_path + $file) -Force
        }
    #Grab the USB information from the host and put it in the Basic Info HTML file for quick reference
    $usbcsv = (Import-CSV -Path ”$export_directory\$ComputerName-usb.csv” | ConvertTo-HTML -Head $htmlHeader -Body "<h2>USB Registry Information</h2>" )
    $usbcsv -replace "PSChildName","Serial Number" >> "$export_directory\$ComputerName-basicinfo.html"
    Write-Progress "Host-based artifact acquisition complete"
}
Get-RemoteArtifacts $ComputerName

function Get-RemoteWirelessInfo($ComputerName){
#Use netsh on the host to retrieve Wireless Network profiles. 
#Can be configured to retrieve the wireless key using the key=clear command, but is not enabled by default
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$\"
    CheckExportDir
    Write-Progress "Checking Host Wireless Profiles"
    $outWireless = ($driveLetter + "wireless.txt")
    $wireless = "netsh.exe wlan show profiles name='*' >> $outWireless"
    Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($shell + $wireless) -ComputerName $ComputerName -Credential $Credential -ErrorAction stop | Out-Null
    Start-Sleep -s 5
    Copy-Item ($net_path + "wireless.txt") "$export_directory\$ComputerName-wireless.txt" -Force
    Write-Progress "Removing $outWireless from host"
    Remove-Item ($net_path + "wireless.txt") -Force
    Write-Host "Wireless Profile acquisition complete"
}
Get-RemoteWirelessInfo $ComputerName

function Get-RemoteAppCompat($ComputerName){
# Adapted from https://github.com/davidhowell-tx/PS-WindowsForensics/blob/master/AppCompatCache/KansaModule/Get-AppCompatCache.ps1
# Modified for usage within WMI
# Added Win10-CreatorsUpdate partial support (0x34)
$export_directory = "$location\$ComputerName"
CheckExportDir
Write-Progress "Checking AppCompatCache on $ComputerName"
$reg = (Get-WMIObject -List -NameSpace "root\default" -ComputerName $ComputerName -Credential $Credential | Where-Object {$_.Name -eq "StdRegProv"})

#Get AppCompatCache from Registry

# Initialize Array to store our data
$EntryArray=@()
$AppCompatCache=$Null

$AppCompatCache = $reg.GetBinaryValue($regkey.HKEY_LOCAL_MACHINE, $SHIMCACHELOCATION, "AppCompatCache").uValue;

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
            Write-Progress "Getting AppCompatCache"
			$MemoryStream.Position = 48
			
			# Complete loop to parse each entry
			while ($MemoryStream.Position -lt $MemoryStream.Length) {
				$Tag = [System.BitConverter]::ToString($BinReader.ReadBytes(4)) -replace "-",""
				################################
				# Add code to verify tag later # 
				################################
				
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property Name, Time, Data # Added Data
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
            Write-Progress "Checking AppCompatCache"
			$MemoryStream.Position = 52
			
			# Complete loop to parse each entry
			while ($MemoryStream.Position -lt $MemoryStream.Length) {
				$Tag = [System.BitConverter]::ToString($BinReader.ReadBytes(4)) -replace "-",""
				################################
				# Add code to verify tag later # 
				################################
				
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property Name, Time, Data # Added Data
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
						$TempObject = "" | Select-Object -Property Name, Time
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
					$TempObject = "" | Select-Object -Property Name, Time
					
					$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ))
					$EntryArray += $TempObject
				}
			}
			$EntryArray | Select-Object -Property Name, Time | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
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
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
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
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Offset, Time, Flag0, Flag1
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
			$EntryArray | Select-Object -Property Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
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
					$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
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
					$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Offset, Time, Flag0, Flag1
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
			$EntryArray | Select-Object -Property Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
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
				$TempObject = "" | Select-Object -Property Name, LastModifiedTime, Size, LastUpdatedTime
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
			$EntryArray | Select-Object -Property Name, Size, LastModifiedTime, LastUpdatedTime | Export-CSV -NoTypeInformation "$export_directory\$ComputerName-appcompat.csv"
		}
	}
}
}
Get-RemoteAppCompat $ComputerName

function Get-RemoteMemoryDump($ComputerName){
#Copy the winpmem exec to the remote host, create a memory dump, copy to the originating source, and delete the results from the target
    $export_directory = "$location\$ComputerName"
    $net_path = "\\$ComputerName\C$\"
    CheckExportDir
    Write-Progress "Getting Memory Dump of $ComputerName"
    Try {
        Copy-Item -Path "$location\bin\winpmem.exe" -Destination ($net_path + "winpmem.exe") -Force
        $invokeMemDump = (Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($net_path + "winpmem.exe --format raw -o " + $driveLetter + "memory.raw") -ComputerName $ComputerName -Credential $Credential -ErrorAction stop)
        $memdumpPID = $invokeMemDump.processID
        $memdumpRunning = { Get-WmiObject -Class win32_process -Filter "ProcessID='$memdumpPID'" -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue | ? { ($_.ProcessName -eq 'winpmem.exe') } }
    }
    Catch{
        Throw $_
        Break
    }
    while ($null -ne (& $memdumpRunning)) {
    start-sleep -s 2
    }
    Write-Progress "Removing winpmem executable from host"
    Remove-Item ($net_path + "winpmem.exe") -Force
    Write-Progress "Copying memory dump to export directory"
    Copy-Item ($net_path + "memory.raw") "$export_directory\$ComputerName-memory.raw"
    Write-Progress "Removing memory dump from host"
    Remove-Item ($net_path + "memory.raw") -Force
    Write-Progress "Memory acquisition complete"
}

Get-RemoteMemoryDump $ComputerName
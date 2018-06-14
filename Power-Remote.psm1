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
        Version        : 
        Author         : 
        Prerequisite   : winpmem.exe binary in $location\bin folder

       

    .PARAMETER 
        -hostname: The host you want to run the remote acquisition against - default is 127.0.0.1
    .Example
    
        
        Get-
        Actual command:
        Get-

    #>
[CmdletBinding()]
param (
    [Parameter(Position=0)]
    [System.String]$hostname = "127.0.0.1",
    [Parameter(Position=1)]
    [System.String]$func = "$Null",
    [Parameter(Position=2)]
    [System.String]$format = "csv",
    [System.String]$location = (get-location),
    [System.String]$export_directory = "$location\$hostname",
    [System.String]$net_path = "\\$hostname\C$\",
    [System.String]$driveLetter = (gwmi win32_operatingsystem -ComputerName $hostname | select -expand SystemDrive) + "\",
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
    $reg = (Get-WMIObject -List -NameSpace "root\default" -ComputerName $hostname | Where-Object {$_.Name -eq "StdRegProv"})
    <#
    If($format = csv{
        $outputFormat = ""
        }
    Elseif($format = db{ 
        $outputFormat = ""
        }
    Elseif($format = html{
        $outputFormat = ""
        }
    #>
    )

If(!(test-path $export_directory)) {
    Write-Host ""
    Write-Host "Export directory does not exist - creating"
    New-Item -ItemType Directory -Force -Path $export_directory | Out-Null
    }

#Basic Info
function GetBasicInfo($hostname) {
Write-Host ""
Write-Host "Gathering basic host information for $hostname"
$ReportTitle="Basic Information"
$strPath = "$export_directory\$hostname-basicinfo.html"
$pcsystemType = @{ 0="Unspecified"; 1="Desktop";2="Mobile";3="Workstation";4="Enterprise Server";5="Small Office and Home Office (SOHO) Server";6="Appliance PC";7="Performance Server";8="Maximum" }
$get_type = ([int](gwmi win32_computersystem -ComputerName $hostname | select -ExpandProperty PCSystemType))
$installDate = @{n="Install Date";e={$_.ConvertToDateTime($_.installdate)}}
$oemkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
$regnames = $reg.EnumValues($regkey.HKEY_LOCAL_MACHINE, $oemkey).sNames
ConvertTo-Html -Head $htmlHeader -Title $ReportTitle -Body "<h1> Computer Name : $hostname </h1>" > "$strPath"  
Get-WmiObject win32_computersystem -ComputerName $hostname|select PSComputerName,Name,Manufacturer,Domain,Model,Systemtype,PrimaryOwnerName,@{n="PC System Type";e={$pcsystemType.$get_type}},PartOfDomain,CurrentTimeZone,BootupState | ConvertTo-Html  -Head $htmlHeader -Body "<h5>Created on: $(Get-Date)</h5><h2>ComputerSystem</h2>" >> "$strPath" 
Get-WmiObject win32_bios -ComputerName $hostname| select Status,Version,PrimaryBIOS,Manufacturer,@{n="Release Date";e={$_.ConvertToDateTime($_.releasedate)}},SerialNumber | ConvertTo-Html -Head $htmlHeader -Body "<h2>BIOS Information</h2>" >> "$strPath" 
Get-WmiObject win32_Useraccount -ComputerName $hostname | where {$_.localaccount -Match 'True'} | select Name,SID,Description,Fullname,Disabled | ConvertTo-html -Head $htmlHeader -Body "<h2>Local Users</h2>" >> "$strPath" 
((Get-WmiObject win32_groupuser -ComputerName $hostname |? {$_.groupcomponent -like '*"Administrators"'} |% {$_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $nul; $matches[1].trim('"') + "\" + $matches[2].trim('"') }) -split " " | Select @{n="Administrators";e={$_.Trim()}} | ConvertTo-HTML -Head $htmlHeader -Body "<h2>Administrators</h2>") -replace "\*","Administrators" >> "$strPath"
Get-WmiObject win32_DiskDrive -ComputerName $hostname | Select Index,Model,Caption,SerialNumber,Description,MediaType,FirmwareRevision,Partitions,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},PNPDeviceID | Sort-Object -Property Index | ConvertTo-Html -Head $htmlHeader -Body "<h2>Disk Drive Information</h1>" >> "$strPath" 
Get-WmiObject win32_networkadapter -ComputerName $hostname | Select Name,Manufacturer,Description,AdapterType,Speed,MACAddress,NetConnectionID,PNPDeviceID | ConvertTo-Html -Head $htmlHeader -Body "<h2>Network Adapter Information</h2>" >> "$strPath" 
Get-WmiObject win32_NetworkAdapterConfiguration -ComputerName $hostname | select @{n='IP Address';e={$_.ipaddress}},Description,@{n='MAC Address';e={$_.macaddress}},DHCPenabled,@{n="DHCPLeaseObtained";e={$_.ConvertToDateTime($_.DHCPLeaseObtained)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>Network Adapter Configuration</h2>" >> "$strPath" 
Get-WmiObject win32_startupCommand -ComputerName $hostname | select Name,Location,Command,User,Caption  | ConvertTo-html  -Head $htmlHeader -Body "<h2>Startup  Software Information</h2>" >> "$strPath" 
Get-WmiObject win32_logicalDisk -ComputerName $hostname | select DeviceID,VolumeName,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},@{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Size (GB)"},FileSystem, VolumeSerialNumber |  ConvertTo-html  -Head $htmlHeader -Body "<h2>Disk Information</h2>" >> "$strPath" 
Get-WmiObject win32_operatingsystem -ComputerName $hostname | select Caption,OSArchitecture,Organization,$InstallDate,Version,SerialNumber,BootDevice,WindowsDirectory,CountryCode,@{n="Last Bootup";e={$_.ConvertToDateTime($_.lastbootup)}},@{n="Local Date/Time";e={$_.ConvertToDateTime($_.LocalDateTime)}} | ConvertTo-html  -Head $htmlHeader -Body "<h2>OS Information</h2>" >> "$strPath" 

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
GetBasicInfo $hostname

#Applications
function GetApplications($hostname) {
Write-Host ""
Write-Host "Getting Installed software for $hostname"
Get-WmiObject -Class Win32_Product -ComputerName $hostname | select Name,InstallDate,ProductID,Vendor,Version | Export-CSV -Path "$export_directory\$hostname-applications.csv" -NoTypeInformation
    }
GetApplications $hostname

#Event Log Info - 4624, 4625, 4634, 4698, 4699, 4700, 4701, 4702
function GetSecurityLogs($hostname){
Write-Host ""
Write-Host "Getting Event Logs for Logons/Logoffs"
$TimeGenerated = @{n="TimeGenerated";e={$_.ConvertToDateTime($_.TimeGenerated)}}
$TimeWritten = @{n="TimeWritten";e={$_.ConvertToDateTime($_.TimeWritten)}}
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

$logontype4634 = @{n="LogonType";e={$_.InsertionStrings[4]}}
$SID4634 = @{n="SID";e={$_.InsertionStrings[0]}}
$accountname4634 = @{n="AccountName";e={$_.InsertionStrings[1]}}
$loginid4634 = @{n="LogonID";e={$_.InsertionStrings[3]}}

$SID98_02 = @{n="SID";e={$_.InsertionStrings[0]}}
$accountname98_02 = @{n="AccountName";e={$_.InsertionStrings[1]}}
$loginid98_02 = @{n="LogonID";e={$_.InsertionStrings[3]}}
$exec98_02 = @{n="Exec";e={$_.InsertionStrings[5] -replace "`r`n", "" -Match "<Exec>\s{0,}(.*)</Exec"}}

$get4624 = (Get-WmiObject Win32_NtLogEvent -ComputerName $hostname | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4624'} | select $TimeGenerated, EventIdentifier, $logontype4624, $SID4624, $accountname4624, $loginid4624, $sourcenetwork4624 | Export-CSV -Path "$export_directory\$hostname-4624.csv" -NoTypeInformation)
$get4625 = (Get-WmiObject Win32_NtLogEvent -ComputerName $hostname | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4625'} | select $TimeGenerated, EventIdentifier, $logontype4625, $SID4625, $accountname4625, $failuretype4625, $failuresubtype4625, $workstationname4625, $sourcenetwork4625 | Export-CSV -Path "$export_directory\$hostname-4625.csv" -NoTypeInformation)
$get4634 = (Get-WmiObject Win32_NtLogEvent -ComputerName $hostname | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4634'} | select $TimeGenerated, EventIdentifier, $logontype4634, $SID4634, $accountname4634, $loginid4634 | Export-CSV -Path "$export_directory\$hostname-4634.csv" -NoTypeInformation)
$get4698_4702 = (Get-WmiObject Win32_NtLogEvent -ComputerName $hostname | Where {$_.logfile -Match "Security"} | Where-Object {$_.EventCode -eq '4698' -or $_.EventCode -eq '4699' -or $_.EventCode -eq '4700' -or $_.EventCode -eq '4701' -or $_.EventCode -eq '4702'} | select $TimeGenerated, EventIdentifier, $SID98_02, $accountname98_02, $loginid98_02, $exec98_02 | Export-CSV -Path "$export_directory\$hostname-4698-4702.csv" -NoTypeInformation)
$get4624, $get4625, $get4634, $get4698_4702
    }
GetSecurityLogs $hostname

#Event Logs - System - 6005 and 6006
function GetSystemLogs($hostname) {
Write-Host ""
Write-Host "Gathering System Event Logs for ID 6005 and 6005"
$get6005_6006 = (Get-WmiObject Win32_NTLogEvent -ComputerName $hostname | Where {$_.logfile -Match "System"} | Where-Object {$_.EventCode -eq '6005' -or $_.EventCode -eq '6006'} | select $TimeGenerated, EventCode | Export-CSV -Path "$export_directory\$hostname-6005-6006.csv" -NoTypeInformation)
$get6005_6006
    }
GetSystemLogs $hostname

#Processes
function GetProcesses($hostname){
Write-Host ""
Write-Host "Gathering Running Processes on $hostname"
$CreationDate = @{n="CreationDate";e={$_.ConvertToDateTime($_.CreationDate)}}
Get-WmiObject Win32_Process -ComputerName $hostname | select Name,Description,ProcessID,ParentProcessID,ThreadCount,ExecutablePath,CommandLine,@{n="Owner";e={$_.GetOwner().Domain + " " + $_.GetOwner().User}} | Export-CSV -Path "$export_directory\$hostname-processes.csv" -NoTypeInformation
    }
GetProcesses $hostname

#Services
function GetServices($hostname){
Write-Host ""
Write-Host "Gathering Services on $hostname"
Get-WmiObject Win32_Service -ComputerName $hostname | select Name,ProcessID,StartMode,State,Status,PathName | export-CSV -Path "$export_directory\$hostname-services.csv" -NoTypeInformation
    }
GetServices $hostname

function GetHostArtifacts($hostname){
Write-Host ""
Write-Host "Gathering specific host-based artifacts from $hostname"
$fileList = @('netstat.txt','tasklist.txt','tasksvc.txt','scquery.txt','ipconfig.txt','dns.txt','route.txt','arp.txt','sched.txt','usb.csv')
$outnet = ("$export_directory\$hostname-netstat.txt")
$outtasks = ("$export_directory\$hostname-tasklist.txt")
$outtasksvc = ("$export_directory\$hostname-tasksvc.txt")
$outscquery = ("$export_directory\$hostname-scquery.txt")
$outipconfig = ("$export_directory\$hostname-ipconfig.txt")
$outdns = ("$export_directory\$hostname-dns.txt")
$outroute = ("$export_directory\$hostname-route.txt")
$outarp = ("$export_directory\$hostname-arp.txt")
$outsched = ("$export_directory\$hostname-sched.txt")
$outusb = ("$export_directory\$hostname-usb.csv")

    
$artifacts = @{ netstat = ("netstat.exe -ano >> $outnet"); tasklist = "tasklist.exe /v >> $outtasks"; tasksvc = "tasklist.exe /svc >> $outtasksvc"; scquery = "sc.exe query state= all >> $outscquery"; ipconfig = "ipconfig.exe /all >> $outipconfig"; dns = "ipconfig.exe /displaydns >> $outdns"; route = "route.exe PRINT >> $outroute"; arp = "arp.exe -a >> $outarp"; sched = "schtasks.exe /Query /FO CSV /V >> $outsched"; usb = ("$powershell -command Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | select FriendlyName,PSChildName | ConvertTo-CSV -NoTypeInformation >> $outusb") }

Try{
    foreach($key in $artifacts.Keys){
    $invokeArtifacts = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($shell + $artifacts.$key) -ComputerName $hostname -ErrorAction stop)
    Write-Host " -$key"
    }
    $invokeUSB = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($artifacts.usb) -ComputerName $hostname -ErrorAction stop)
    }
Catch{
#
    Throw $_
    Break
    }
start-sleep -s 5
    Write-Host "Saving artifacts to export directory"
    $usbcsv = (Import-CSV -Path ("$export_directory\$hostname-usb.csv") | ConvertTo-HTML -Head $htmlHeader -Body "<h2>USB Registry Information</h2>" )
    $usbcsv -replace "PSChildName","Serial Number" >> "$export_directory\$hostname-basicinfo.html"
    Write-Host "Host-based artifact acquisition complete"
    }
GetHostArtifacts $hostname

function GetMemoryDump($hostname){
Write-Host "Getting Memory Dump of $hostname"
Try {
    Copy-Item -Path "$location\bin\winpmem.exe" -Destination ($net_path + "winpmem.exe") -Force
    $invokeMemDump = (Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($net_path + "winpmem.exe --format raw -o " + $driveLetter + "memory.raw") -ComputerName $hostname -ErrorAction stop)
    $memdumpPID = $invokeMemDump.processID
    $memdumpRunning = { Get-WmiObject -Class win32_process -Filter "ProcessID='$memdumpPID'" -ComputerName $hostname -ErrorAction SilentlyContinue | ? { ($_.ProcessName -eq 'winpmem.exe') } }
    }
Catch{
    Throw $_
    Break
    }
while ($null -ne (& $memdumpRunning)) {
 start-sleep -s 2
    }
Write-Host "Removing winpmem executable from host"
Remove-Item ($net_path + "winpmem.exe") -Force
Write-Host "Copying memory dump to export directory"
$copyMem = (Copy-Item ($net_path + "memory.raw") "$export_directory\$hostname-memory.raw")
Write-Host "Removing memory dump from host"
Remove-Item ($net_path + "memory.raw") -Force
Write-Host "Memory acquisition complete"
    }
GetMemoryDump $hostname

function GetWirelessInfo($hostname){
Write-Host ""
Write-Host "Gathering Host Wireless Profiles"
$outWireless = ("$export_directory\$hostname-wireless.txt")
$wireless = "netsh.exe wlan show profiles name='*' >> $outWireless"
$invokeNetsh = (Invoke-WmiMethod -Class win32_process -name Create -ArgumentList ($shell + $wireless) -ComputerName $hostname -ErrorAction stop)
<#start-sleep -s 5
Write-Host "Copying to export directory"
Copy-Item ($net_path + "wireless.txt") "$export_directory\$hostname-wireless.txt"
Remove-Item ($net_path + "wireless.txt") #>
Write-Host "Wireless Profile acquisition complete"
    }
GetWirelessInfo $hostname

function GetAppCompat($hostname){
Write-Host ""
Write-Host "Gathering AppCompatCache from host"
# Adapted from https://github.com/davidhowell-tx/PS-WindowsForensics/blob/master/AppCompatCache/KansaModule/Get-AppCompatCache.ps1
# Modified for usage within WMI
# Added Win10-CreatorsUpdate partial support (0x34)

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
            Write-Output "!!!!!!!!!!"
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
            Write-Output "!!!!!!!!!!"
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
			$EntryArray | Select-Object -Property Name, Time | Export-CSV -NoTypeInformation "$export_directory\$hostname-appcompat.csv"
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
			$EntryArray | Select-Object -Property Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$hostname-appcompat.csv"
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
			$EntryArray | Select-Object -Property Name, Time, Flag0, Flag1 | Export-CSV -NoTypeInformation "$export_directory\$hostname-appcompat.csv"
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
			$EntryArray | Select-Object -Property Name, Size, LastModifiedTime, LastUpdatedTime | Export-CSV -NoTypeInformation "$export_directory\$hostname-appcompat.csv"
		}
	}
}
}
#GetAppCompat $hostname 

function RemoteRunAll($hostname){
    $functions = @('GetBasicInfo','GetApplications','GetSecurityLogs','GetSystemLogs','GetProcesses','GetServices','GetHostArtifacts','GetMemoryDump','GetWirelessInfo','GetStormShield','GetAppCompat')
    foreach ($func in $function){ 
    & $func $hostname
    }
}

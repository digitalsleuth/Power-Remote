# Power-Remote
A PowerShell based remote acquisition tool for Administrators/DFIR personnel.
This tool is initially designed to enable those with network administrator/OU-level credentials to be able to get artifacts from machines exhibiting suspicious behaviour on the network.
It assumes you already have credentials which will give you full system access on other machines within your OU or on your network.

The tool is currently in Beta, with updates being pushed regularly.
It will grab the following if run start-to-finish:

- Basic Host Information
- USBSTOR/USB/WpdBusEnum/Volume/GUID/VID_PID/MountedDevices/User MountPoints2 artifacts from the registry
- First and Last USB Insert Times from setupapi.dev.log, Windows Event Logs, and Registry Key LastWriteTimes
- Running processes for all users
- All services and states
- IPConfig
- DNS Cache
- Arp Cache
- Wireless LAN (WLAN) profiles (can be configured to include keys)
- AppCompatCache (Win XP - Win10 - thanks to Dave Howell)
- Memory Dump (requires winpmem executable in a folder 'bin' in the same directory as the script is run
- Current Routes
- Scheduled Tasks (not just via at.exe)
- Netstat Information
- Event Logs (Security - 4624,4625,4634,4698-4702; System - 6005,6005)
- Installed Applications

A folder will be created automatically in the current directory and given the name of the ComputerName 
# Requirements
This tool will require you have the winpmem executable from Rekall renamed to winpmem.exe, and stored in a folder named 'bin' in the directory the module is run from.
It also requires the Join-Object.ps1 script, located in this repo, borrowed from Warren Frame (github.com/RamblingCookieMonster)
Place the Join-Object.ps1 file in the directory where you will run the module.
- Also requires that you change the Execution Policy to allow the scripts to run and run from either PowerShell or PowerShellISE as Local Administrator:
`Set-ExecutionPolicy Bypass -Force` or `Set-ExecutionPolicy Unrestricted -Force`

Script and functions can be executed in one of two ways:

Functions:
```
Import-Module <path_to>Power-Remote-<WMI or CIM>.psm1
<function> -ComputerName <computername/IP/txt file>
<function> -ComputerName <computername/IP/txt file> -Credential <username>
RemoteRunAll -ComputerName <computername/IP/txt file> (this will run all functions against the hosts)
```
Txt file should contain computernames/IP's each on a single line
  
Example Hosts Txt file:
```
10.10.10.1
10.10.10.2
10.10.10.97
```
 
More features to follow, as you will see in the code.

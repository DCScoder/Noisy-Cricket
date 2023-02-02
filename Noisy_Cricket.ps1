###################################################################################
#
#    Script:    Noisy_Cricket.ps1
#    Version:   1.2
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Windows malware persistence mechanism removal
#    Usage:     .\Noisy_Cricket.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$Script = "Noisy_Cricket_"
$Version = "v1.2"

########## Admin ##########

# Destination
$Destination = $PSScriptRoot
# System Date/Time
$Timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$Endpoint = $env:ComputerName
# Out
$Name = $Script+$Endpoint+$Timestamp
# Log
Start-Transcript $Destination\$Name.log -Append | Out-Null

########## Startup ##########

Write-Host "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Script: Noisy_Cricket.ps1 - $Version - Author: Dan Saunders dcscoder@gmail.com

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Check Run As Administrator
$Admin=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $False)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator priveleges."
    Write-Host "`n"
    exit
}

########## Input ##########

# Target
$Filename = Read-Host -Prompt "
Insert Filename + Extension, i.e. evil123.exe ->"
$RevisedFilename = [IO.Path]::GetFileNameWithoutExtension($Filename)

# Confirm
Write-Host "`nWARNING: This script will make permanent changes to the Windows registry and file system`n
for the supported persistence mechanisms. This includes specific registry keys,`n
including values where '$RevisedFilename' is referenced and also all live files in`n
volume 'C:\' called '$Filename'.

Are you sure you want to continue?" -ForegroundColor yellow -BackgroundColor black
$Confirm = Read-Host "`n'yes' or 'no'"
if ($Confirm -eq 'yes') {

}
else
{
    exit
}

########## Registry SIDs ##########

# HKU Users
$Users = Get-ChildItem Registry::HKEY_USERS\ | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-[\d\-]+$'}

########## Memory Process ##########

Write-Host "`nTask (1 / 22)    |  Removing any associated active Memory Processes.`n" -ForegroundColor yellow -BackgroundColor black

# Active Process
if((Get-Process "$RevisedFilename" -ea SilentlyContinue) -eq $Null){
    Write-Host "No process called"$RevisedFilename" running."
}

else {
    Stop-Process -processname "$RevisedFilename" -Force
    Write-Host "Process called "$RevisedFilename" found and killed."
}

########## Autorun / Startup ##########

Write-Host "`nTask (2 / 22)    |  Removing any associated Autorun keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.001] Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" -ForegroundColor red -BackgroundColor black

# HKLM Run
$HKLMRun6432 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path "$HKLMRun6432" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRun6432" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM WOW6432Node Run key."
}
    else
{
    Write-Host "No hits found in HKLM WOW6432Node Run key."
}
# HKLM Run
$HKLMRun = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path "$HKLMRun" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRun" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM Run key."
}
    else
{
    Write-Host "No hits found in HKLM Run key."
}
# HKLM RunOnce
$HKLMRunOnce = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
if (Get-ItemProperty -Path "$HKLMRunOnce" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRunOnce" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM RunOnce key."
}
    else
{
    Write-Host "No hits found in HKLM RunOnce key."
}
# HKLM RunOnceEx
$HKLMRunOnceEx = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
if (Get-ItemProperty -Path "$HKLMRunOnceEx" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRunOnceEx" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM RunOnceEx key."
}
    else
{
    Write-Host "No hits found in HKLM RunOnceEx key."
}
# HKLM Shell Folders
$HKLMsh = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
if (Get-ItemProperty -Path "$HKLMsh" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMsh" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM Shell Folders key."
}
    else
{
    Write-Host "No hits found in HKLM Shell Folders key."
}
# HKLM User Shell Folders
$HKLMush = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
if (Get-ItemProperty -Path "$HKLMush" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMush" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM User Shell Folders key."
}
    else
{
    Write-Host "No hits found in HKLM User Shell Folders key."
}
# HKLM Run Services
$HKLMrs = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
if (Get-ItemProperty -Path "$HKLMrs" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMrs" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM Run Services key."
}
    else
{
    Write-Host "No hits found in HKLM Run Services key."
}
# HKLM Run Services Once
$HKLMrso = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
if (Get-ItemProperty -Path "$HKLMrso" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMrso" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM Run Services Once key."
}
    else
{
    Write-Host "No hits found in HKLM Run Services Once key."
}
# HKLM Explorer Run
$HKLMer = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
if (Get-ItemProperty -Path "$HKLMer" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMer" -Name "$RevisedFilename"
    Write-Host "Hit found in HKLM Explorer Run key."
}
    else
{
    Write-Host "No hits found in HKLM Explorer Run key."
}
# HKU Run
foreach($User in $Users)
{
    $HKURun = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\Run"
    if($Item = Get-ItemProperty -Path "$HKURun" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURun" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' Run key."
    }
    else
    {
        Write-Host "No hits found in '$User' Run key."
    }
}
# HKU RunOnce
foreach($User in $Users)
{
    $HKURunOnce = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    if($Item = Get-ItemProperty -Path "$HKURunOnce" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURunOnce" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' RunOnce key."
    }
    else
    {
        Write-Host "No hits found in '$User' RunOnce Run key."
    }
}
# HKU RunOnceEx
foreach($User in $Users)
{
    $HKURunOnceEx = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
    if($Item = Get-ItemProperty -Path "$HKURunOnceEx" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURunOnceEx" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' RunOnceEx key."
    }
    else
    {
        Write-Host "No hits found in '$User' RunOnceEx key."
    }
}
# HKU Shell Folders
foreach($User in $Users)
{
    $HKUsf = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    if($Item = Get-ItemProperty -Path "$HKUsf" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUsf" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' Shell Folders key."
    }
    else
    {
        Write-Host "No hits found in '$User' Shell Folders key."
    }
}
# HKU User Shell Folders
foreach($User in $Users)
{
    $HKUusf = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    if($Item = Get-ItemProperty -Path "$HKUusf" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUusf" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' User Shell Folders key."
    }
    else
    {
        Write-Host "No hits found in '$User' User Shell Folders key."
    }
}
# HKU Run Services
foreach($User in $Users)
{
    $HKUrso = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunServices"
    if($Item = Get-ItemProperty -Path "$HKUrso" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUrso" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' Run Services key."
    }
    else
    {
        Write-Host "No hits found in '$User' Run Services key."
    }
}
# HKU Run Services Once
foreach($User in $Users)
{
    $HKUrso = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    if($Item = Get-ItemProperty -Path "$HKUrso" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUrso" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' Run Services Once key."
    }
    else
    {
        Write-Host "No hits found in '$User' Run Services Once key."
    }
}
# HKU Explorer Run
foreach($User in $Users)
{
    $HKUer = Join-Path $User.PSPath "\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    if($Item = Get-ItemProperty -Path "$HKUer" -Name "$RevisedFilename" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUer" -Name "$RevisedFilename"
        Write-Host "Hit found in '$User' Explorer Run key."
    }
    else
    {
        Write-Host "No hits found in '$User' Explorer Run key."
    }
}
# System Startup Folder
$SystemStartupFolder = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Include $Filename -Force -Recurse -ea SilentlyContinue
$SSCount = $SystemStartupFolder.Count
Write-Host "$SSCount hit(s) found for '$Filename' in System Startup folder."
$SystemStartupFolder | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$SystemStartupFolder | Remove-Item -Force -ea SilentlyContinue
# User Startup Folder
$UserStartupFolder = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" -Include $Filename -Force -Recurse -ea SilentlyContinue
$USCount = $UserStartupFolder.Count
Write-Host "$USCount hit(s) found for '$Filename' in User Startup folder."
$UserStartupFolder | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$UserStartupFolder | Remove-Item -Force -ea SilentlyContinue

########## Logon Script ##########

Write-Host "`nTask (3 / 22)    |  Removing any associated Logon Script keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1037.001] Boot or Logon Initialization Scripts: Logon Script (Windows)" -ForegroundColor red -BackgroundColor black

# Logon Script
foreach($User in $Users)
{
    $Env = Join-Path $User.PSPath "\Environment"
    if (reg query "$User\Environment" /v "UserInitMprLogonScript" | findstr /ri "$RevisedFilename")
    {
        Write-Host "Hit found in '$User' Logon Scripts key."
        reg delete "$User\Environment" /v "UserInitMprLogonScript" /f
    }
    else
    {
        Write-Host "No hits found in '$User' Logon Scripts key."
    }
}

########## Screensaver ##########

Write-Host "`nTask (4 / 22)    |  Removing any associated Screensaver keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.002] Event Triggered Execution: Screensaver" -ForegroundColor red -BackgroundColor black

# Screensaver
foreach($User in $Users)
{
    $Env = Join-Path $User.PSPath "\Control Panel\Desktop"
    if (reg query "$User\Control Panel\Desktop" /v "WallPaper" | findstr /ri "$RevisedFilename")
    {
        Write-Host "Hit found in '$User' Screensaver key."
        reg delete "$User\Control Panel\Desktop" /v "WallPaper" /f
    }
    else
    {
        Write-Host "No hits found in '$User' Screensaver key."
    }
}

########## Netsh Helper DLL ##########

Write-Host "`nTask (5 / 22)    |  Removing any associated Autorun keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.007] Event Triggered Execution: Netsh Helper DLL" -ForegroundColor red -BackgroundColor black

# Netsh
$Netsh = "HKLM:\Software\Microsoft\Netsh"
if (Get-ItemProperty -Path "$Netsh" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$Netsh" -Name "$RevisedFilename"
    Write-Host "Hit found in Netsh Helper DLL key."
}
    else
{
    Write-Host "No hits found in Netsh Helper DLL key."
}

########## Winlogon Helper DLL ##########

Write-Host "`nTask (6 / 22)    |  Removing any associated Winlogon Helper DLL keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.004] Boot or Logon Autostart Execution: Winlogon Helper DLL" -ForegroundColor red -BackgroundColor black

# HKLM Winlogon Notify
$HKLMwlno = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwlno" /v "Notify" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Notify key."
        reg delete "$HKLMwlno" /v "Notify" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Notify key."
    }
# HKLM Winlogon Userinit
$HKLMwlui = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwlui" /v "Userinit" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Userinit key."
        reg delete "$HKLMwlui" /v "Userinit" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Userinit key."
    }
# HKLM Winlogon Shell
$HKLMwlsh = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwlsh" /v "Shell" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Shell key."
        reg delete "$HKLMwlsh" /v "Shell" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Shell key."
    }
# HKLM Winlogon6432 Notify
$HKLMwl6432no = "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwl6432no" /v "Notify" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Wow6432Node Notify key."
        reg delete "$HKLMwl6432no" /v "Notify" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Wow6432Node Notify key."
    }
# HKLM Winlogon6432 Userinit
$HKLMwl6432ui = "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwl6432ui" /v "Userinit" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Wow6432Node Userinit key."
        reg delete "$HKLMwl6432ui" /v "Userinit" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Wow6432Node Userinit key."
    }
# HKLM Winlogon6432 Shell
$HKLMwl6432sh = "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (reg query "$HKLMwl6432sh" /v "Shell" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Wow6432Node Shell key."
        reg delete "$HKLMwl6432sh" /v "Shell" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Wow6432Node Shell key."
    }
# HKU Winlogon Shell
foreach($User in $Users)
{
    $Env = Join-Path $User.PSPath "\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (reg query "$User\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" | findstr /ri "$RevisedFilename")
    {
        Write-Host "Hit found in '$User' Winlogon Helper Shell key."
        reg delete "$User\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
    }
    else
    {
        Write-Host "No hits found in '$User' Winlogon Helper Shell key."
    }
}

########## Windows Services ##########

Write-Host "`nTask (7 / 22)    |  Removing any associated Windows Services." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1543.003] Create or Modify System Process: Windows Service" -ForegroundColor red -BackgroundColor black

# Services
$Services = "HKLM:\System\CurrentControlSet\Services"
if (Get-Item -Path "$Services\$RevisedFilename" -ea SilentlyContinue) {
    Remove-Item -Path "$Services\$RevisedFilename"
    Write-Host "Hit found in HKLM Windows Services key."
}
    else
{
    Write-Host "No hits found in HKLM Windows Services key."
}

########### AppInit DLL ##########

Write-Host "`nTask (8 / 22)    |  Removing any associated AppInit DLL." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.010] Event Triggered Execution: AppInit DLLs" -ForegroundColor red -BackgroundColor black

# AppInit
$AppInit = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
if (reg query "$AppInit" /v "AppInit_DLLs" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM AppInit key."
        reg delete "$AppInit" /v "AppInit_DLLs" /f
    }
    else
    {
        Write-Host "No hits found in HKLM AppInit key."
    }

# AppInit Wow6432Node
$AppInit6432 = "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
if (reg query "$AppInit6432" /v "AppInit_DLLs" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM AppInit Wow6432Node key."
        reg delete "$AppInit6432" /v "AppInit_DLLs" /f
    }
    else
    {
        Write-Host "No hits found in HKLM AppInit Wow6432Node key."
    }

########## Port Monitors ##########

Write-Host "`nTask (9 / 22)    |  Removing any associated Port Monitor keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.010] Boot or Logon Autostart Execution: Port Monitors" -ForegroundColor red -BackgroundColor black

# Port Monitors
$Port = "HKLM:\System\CurrentControlSet\Control\Print\Monitors\$RevisedFilename"
if (Get-ItemProperty -Path "$Port" -ea SilentlyContinue) {
    Remove-Item -Path "$Port"
    Write-Host "Hit found in HKLM Port Monitors key."
}
    else
{
    Write-Host "No hits found in HKLM Port Monitors key."
}

########## Security Support Providers (SSP) ##########

Write-Host "`nTask (10 / 22)   |  Removing any associated Security Support Providers DLLs." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.005] Boot or Logon Autostart Execution: Security Support Provider" -ForegroundColor red -BackgroundColor black

# SSP
$Lsa = "HKLM\System\CurrentControlSet\Control\Lsa"
if (reg query "$Lsa" /v "Security Packages" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Lsa SSP key."
        reg delete "$Lsa" /v "Security Packages" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Lsa SSP key."
    }
# SSP OSC
$Lsaosc = "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig"
if (reg query "$Lsaosc" /v "Security Packages" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Lsa OSConfig SSP key."
        reg delete "$Lsaosc" /v "Security Packages" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Lsa OSConfig SSP key."
    }

########## Application Shims ##########

Write-Host "`nTask (11 / 22)   |  Removing any associated Application Shims." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.011] Event Triggered Execution: Application Shimming" -ForegroundColor red -BackgroundColor black

# Shim Custom
$shimcustom = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\$Filename"
if (Get-Item -Path "$shimcustom" -ea SilentlyContinue) {
    Remove-Item -Path "$shimcustom"
    Write-Host "Hit found in Application Shim Custom key."
}
    else
{
    Write-Host "No hits found in Application Shim Custom key."
}

########## Winsock ##########

Write-Host "`nTask (12 / 22)   |  Removing any associated Winsock keys." -ForegroundColor yellow -BackgroundColor black

# HKLM Winsock
$HKLMws = "HKLM\System\CurrentControlSet\Services\WinSock2\Parameters"
if (reg query "$HKLMws" /v "AutodialDLL" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Winsock key."
        reg delete "$HKLMws" /v "AutodialDLL" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winsock key."
    }

########## AutoProxyTypes ##########

Write-Host "`nTask (13 / 22)   |  Removing any associated AutoProxyTypes keys." -ForegroundColor yellow -BackgroundColor black

# HKCR AutoProxyTypes
$HKCRapt = "HKCR\AutoProxyTypes\Application/$RevisedFilename"
if (reg query "$HKCRapt" /v "DllFile" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKCR AutoProxyTypes key."
        reg delete "$HKCRapt" /v "DllFile" /f
    }
    else
    {
        Write-Host "No hits found in HKCR AutoProxyTypes key."
    }

########## Command Processor ##########

Write-Host "`nTask (14 / 22)   |  Removing any associated Command Processor keys." -ForegroundColor yellow -BackgroundColor black

# HKLM Command Processor
$HKLMcp = "HKLM\Software\Microsoft\Command Processor"
if (reg query "$HKLMcp" /v "AutoRun" | findstr /ri '$RevisedFilename')
    {
        Write-Host "Hit found in HKLM Command Processor key."
        reg delete "$HKLMcp" /v "AutoRun" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Command Processor key."
    }
# HKU Command Processor
foreach($User in $Users)
{
    $Env = Join-Path $User.PSPath "\Software\Microsoft\Command Processor"
    if (reg query "$User\Software\Microsoft\Command Processor" /v "AutoRun" | findstr /ri "$RevisedFilename")
    {
        Write-Host "Hit found in '$User' Command Processor key."
        reg delete "$User\Software\Microsoft\Command Processor" /v "AutoRun" /f
    }
    else
    {
        Write-Host "No hits found in '$User' Command Processor key."
    }
}

########## Known DLL ##########

Write-Host "`nTask (15 / 22)   |  Removing any associated Known DLL keys." -ForegroundColor yellow -BackgroundColor black

$HKLMkd = "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
if (Get-ItemProperty -Path "$HKLMkd" -Name "$RevisedFilename" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMkd" -Name "$RevisedFilename"
    Write-Host "Hit found in Known DLL key."
}
    else
{
    Write-Host "No hits found in Known DLL key."
}

########## Scheduled Tasks ##########

Write-Host "`nTask (16 / 22)   |  Removing any associated Scheduled Tasks." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1053.005] Scheduled Task/Job: Scheduled Task" -ForegroundColor red -BackgroundColor black

# Tasks
$Tasks = @()

$Schedule = New-Object -ComObject "Schedule.Service"
$Schedule.Connect()
$out = @()

    # Get Root Tasks
$Schedule.GetFolder($Path).GetTasks(0) | % {
    $Xml = [xml]$_.xml
    $Out += New-Object psobject -Property @{
        "Name" = $_.Name
        "Path" = $_.Path
        "LastRunTime" = $_.LastRunTime
        "NextRunTime" = $_.NextRunTime
        "Actions" = ($Xml.Task.Actions.Exec | % { "$($_.Command) $($_.Arguments)" }) -join "`n"
        }
    }

    # Iterate Tasks
    foreach ($Op in $Out) {

	if ($Op.Actions -match $Filename) {
        schtasks /delete /tn $Op.Name /f}

	else {Write-Host "No hit found in Scheduled Task entry."}
	}

########## Background Intelligent Transfer Service (BITS) ##########

Write-Host "`nTask (17 / 22)   |  Removing any associated Windows Background Intelligent Transfer Service (BITS) jobs." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1197] BITS Jobs" -ForegroundColor red -BackgroundColor black

# Jobs
if ($Job = Get-BitsTransfer -AllUsers -Name "$RevisedFilename" -ea SilentlyContinue) {
    $Job | Remove-BitsTransfer -Confirm:$False -ea SilentlyContinue
    Write-Host "Hit found in BITS jobs."
}
else
{
    Write-Host "No hits found in BITS jobs."
}

########## Windows Management Instrumentation (WMI) ##########

Write-Host "`nTask (18 / 22)   |  Removing any associated Windows Management Instrumentation (WMI) entries." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.003] Event Triggered Execution: Windows Management Instrumentation Event Subscription" -ForegroundColor red -BackgroundColor black

# Event Filters
if((Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$RevisedFilename'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event filter called '$RevisedFilename'."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$RevisedFilename'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event filter called "$RevisedFilename" found and removed."
}
# Consumers
if((Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$RevisedFilename'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event consumer called "$RevisedFilename"."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$RevisedFilename'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event consumer called "$RevisedFilename" found and removed."
}
# Bindings
if((Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$RevisedFilename%'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event binding called '$RevisedFilename'."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$RevisedFilename%'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event binding called '$RevisedFilename' found and removed."
}

########## Shortcuts (LNK) ##########

Write-Host "`nTask (19 / 22)   |  Removing any associated LNK (.lnk) files." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.009] Boot or Logon Autostart Execution: Shortcut Modification" -ForegroundColor red -BackgroundColor black

# LNK
$LinkFile = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*" -Include "$Filename.lnk" -Force -Recurse -ea SilentlyContinue
$LCount = $LinkFile.Count
Write-Host "$LCount hit(s) found for $Filename in LNK files."
$LinkFile | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$LinkFile | Remove-Item -Force -ea SilentlyContinue

########## Alternate Data Streams (ADS) ##########

Write-Host "`nTask (20 / 22)   |  Removing any associated Alternate Data Stream (ADS) entries." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1564.004] Hide Artifacts: NTFS File Attributes" -ForegroundColor red -BackgroundColor black

# ADS
if((Get-ChildItem "C:\" | ForEach-Object {Get-Item $_.FullName -stream "$Filename" -ea 'SilentlyContinue'} | Where-Object stream -ne ':$DATA' -ea SilentlyContinue) -eq $Null){
    Write-Host "No Alternate Data Stream called '$Filename'."
}

else {
    try
{
    Get-ChildItem "C:\" -Recurse | ForEach-Object {Get-Item $_.FullName -stream "$Filename" -Force -ea SilentlyContinue} | Where-Object stream -ne ':$DATA' | Remove-Item -Force -ea SilentlyContinue
}
catch
{

}
    Write-Host "Alternate Data Stream called '$Filename' found and removed."
}

########## Temporary Files ##########

Write-Host "`nTask (21 / 22)   |  Removing any unused Temporary files." -ForegroundColor yellow -BackgroundColor black

# Temp File Paths
$Temps = @("C:\Windows\Temp\*", "C:\Temp\*", "C:\Users\*\Appdata\Local\Temp\*")
foreach ($Folder in $Temps) {Remove-Item $Folder -Force -Recurse -ea SilentlyContinue}
Write-Host "Unused Temporary Files Cleaned."

########## New Technology File System (NTFS) ##########

Write-Host "`nTask (22 / 22)   |  Removing any malware binaries from NTFS file system." -ForegroundColor yellow -BackgroundColor black

# File Trace
$BadFile = Get-ChildItem -Path "C:\*" -Include $Filename -Force -Recurse -ea SilentlyContinue
$BCount= $BadFile.Count
Write-Host "$BCount hit(s) found for $Filename in NTFS."
$BadFile | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$BadFile | Remove-Item -Force -ea SilentlyContinue

Write-Host "`nEradication completed!" -ForegroundColor green -BackgroundColor black
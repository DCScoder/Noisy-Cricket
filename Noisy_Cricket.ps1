###################################################################################
#
#    Script:    Noisy_Cricket.ps1
#    Version:   1.0
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

$script = "Noisy_Cricket_"
$version = "v1.0"

########## Admin ##########

# Destination
$dst = $PSScriptRoot
# System Date/Time
$ts = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$edp = $env:ComputerName
# Out
$name = $script+$edp+$ts
# Log
Start-Transcript $dst\$name.log -Append | Out-Null

########## Startup ##########

Write-Host "`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Script: Noisy_Cricket.ps1 - $version - Author: Dan Saunders dcscoder@gmail.com

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Check Run As Administrator
$admin=[Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
  Write-Warning "You have insufficient permissions. Run this script with local Administrator priveleges."
  exit
}

########## Input ##########

# Target
$fn = Read-Host -Prompt "
Insert Filename + Extension, i.e. evil123.exe ->"
$revfn = [IO.Path]::GetFileNameWithoutExtension($fn)

# Confirm
Write-Host "`nWARNING: This script will make permanent changes to the Windows registry and file system`n
for the supported persistence mechanisms. This includes specific registry keys,`n
including values where '$revfn' is referenced and also all live files in`n
volume 'C:\' called '$fn'.

Are you sure you want to continue?" -ForegroundColor yellow -BackgroundColor black
$confirm = Read-Host "`n'yes' or 'no'"
if ($confirm -eq 'yes') {

}
else
{
    exit
}

########## Registry SIDs ##########

# HKU Users
$users = Get-ChildItem Registry::HKEY_USERS\ | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-[\d\-]+$'}

########## Memory Process ##########

Write-Host "`nTask (1 / 22)    |  Removing any associated active Memory Processes.`n" -ForegroundColor yellow -BackgroundColor black

# Active Process
if((Get-Process "$revfn" -ea SilentlyContinue) -eq $Null){
    Write-Host "No process called"$revfn" running."
}

else {
    Stop-Process -processname "$revfn" -Force
    Write-Host "Process called "$revfn" found and killed."
}

########## Autorun / Startup ##########

Write-Host "`nTask (2 / 22)    |  Removing any associated Autorun keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.001] Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" -ForegroundColor red -BackgroundColor black

# HKLM Run
$HKLMRun6432 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path "$HKLMRun6432" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRun6432" -Name "$revfn"
    Write-Host "Hit found in HKLM WOW6432Node Run key."
}
    else
{
    Write-Host "No hits found in HKLM WOW6432Node Run key."
}
# HKLM Run
$HKLMRun = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path "$HKLMRun" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRun" -Name "$revfn"
    Write-Host "Hit found in HKLM Run key."
}
    else
{
    Write-Host "No hits found in HKLM Run key."
}
# HKLM RunOnce
$HKLMRunOnce = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
if (Get-ItemProperty -Path "$HKLMRunOnce" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRunOnce" -Name "$revfn"
    Write-Host "Hit found in HKLM RunOnce key."
}
    else
{
    Write-Host "No hits found in HKLM RunOnce key."
}
# HKLM RunOnceEx
$HKLMRunOnceEx = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
if (Get-ItemProperty -Path "$HKLMRunOnceEx" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMRunOnceEx" -Name "$revfn"
    Write-Host "Hit found in HKLM RunOnceEx key."
}
    else
{
    Write-Host "No hits found in HKLM RunOnceEx key."
}
# HKLM Shell Folders
$HKLMsh = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
if (Get-ItemProperty -Path "$HKLMsh" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMsh" -Name "$revfn"
    Write-Host "Hit found in HKLM Shell Folders key."
}
    else
{
    Write-Host "No hits found in HKLM Shell Folders key."
}
# HKLM User Shell Folders
$HKLMush = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
if (Get-ItemProperty -Path "$HKLMush" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMush" -Name "$revfn"
    Write-Host "Hit found in HKLM User Shell Folders key."
}
    else
{
    Write-Host "No hits found in HKLM User Shell Folders key."
}
# HKLM Run Services
$HKLMrs = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
if (Get-ItemProperty -Path "$HKLMrs" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMrs" -Name "$revfn"
    Write-Host "Hit found in HKLM Run Services key."
}
    else
{
    Write-Host "No hits found in HKLM Run Services key."
}
# HKLM Run Services Once
$HKLMrso = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
if (Get-ItemProperty -Path "$HKLMrso" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMrso" -Name "$revfn"
    Write-Host "Hit found in HKLM Run Services Once key."
}
    else
{
    Write-Host "No hits found in HKLM Run Services Once key."
}
# HKLM Explorer Run
$HKLMer = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
if (Get-ItemProperty -Path "$HKLMer" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMer" -Name "$revfn"
    Write-Host "Hit found in HKLM Explorer Run key."
}
    else
{
    Write-Host "No hits found in HKLM Explorer Run key."
}
# HKU Run
foreach($user in $users)
{
    $HKURun = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\Run"
    if($Item = Get-ItemProperty -Path "$HKURun" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURun" -Name "$revfn"
        Write-Host "Hit found in '$user' Run key."
    }
    else
    {
        Write-Host "No hits found in '$user' Run key."
    }
}
# HKU RunOnce
foreach($user in $users)
{
    $HKURunOnce = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    if($Item = Get-ItemProperty -Path "$HKURunOnce" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURunOnce" -Name "$revfn"
        Write-Host "Hit found in '$user' RunOnce key."
    }
    else
    {
        Write-Host "No hits found in '$user' RunOnce Run key."
    }
}
# HKU RunOnceEx
foreach($user in $users)
{
    $HKURunOnceEx = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
    if($Item = Get-ItemProperty -Path "$HKURunOnceEx" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKURunOnceEx" -Name "$revfn"
        Write-Host "Hit found in '$user' RunOnceEx key."
    }
    else
    {
        Write-Host "No hits found in '$user' RunOnceEx key."
    }
}
# HKU Shell Folders
foreach($user in $users)
{
    $HKUsf = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    if($Item = Get-ItemProperty -Path "$HKUsf" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUsf" -Name "$revfn"
        Write-Host "Hit found in '$user' Shell Folders key."
    }
    else
    {
        Write-Host "No hits found in '$user' Shell Folders key."
    }
}
# HKU User Shell Folders
foreach($user in $users)
{
    $HKUusf = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    if($Item = Get-ItemProperty -Path "$HKUusf" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUusf" -Name "$revfn"
        Write-Host "Hit found in '$user' User Shell Folders key."
    }
    else
    {
        Write-Host "No hits found in '$user' User Shell Folders key."
    }
}
# HKU Run Services
foreach($user in $users)
{
    $HKUrso = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunServices"
    if($Item = Get-ItemProperty -Path "$HKUrso" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUrso" -Name "$revfn"
        Write-Host "Hit found in '$user' Run Services key."
    }
    else
    {
        Write-Host "No hits found in '$user' Run Services key."
    }
}
# HKU Run Services Once
foreach($user in $users)
{
    $HKUrso = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    if($Item = Get-ItemProperty -Path "$HKUrso" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUrso" -Name "$revfn"
        Write-Host "Hit found in '$user' Run Services Once key."
    }
    else
    {
        Write-Host "No hits found in '$user' Run Services Once key."
    }
}
# HKU Explorer Run
foreach($user in $users)
{
    $HKUer = Join-Path $user.PSPath "\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    if($Item = Get-ItemProperty -Path "$HKUer" -Name "$revfn" -ea SilentlyContinue)
    {
        Remove-ItemProperty -Path "$HKUer" -Name "$revfn"
        Write-Host "Hit found in '$user' Explorer Run key."
    }
    else
    {
        Write-Host "No hits found in '$user' Explorer Run key."
    }
}
# System Startup Folder
$ssf = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*" -Include $fn -Force -Recurse -ea SilentlyContinue
$scount = $ssf.Count
Write-Host "$scount hit(s) found for '$fn' in System Startup folder."
$ssf | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$ssf | Remove-Item -Force -ea SilentlyContinue
# User Startup Folder
$usf = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" -Include $fn -Force -Recurse -ea SilentlyContinue
$ucount = $usf.Count
Write-Host "$ucount hit(s) found for '$fn' in User Startup folder."
$usf | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$usf | Remove-Item -Force -ea SilentlyContinue

########## Logon Script ##########

Write-Host "`nTask (3 / 22)    |  Removing any associated Logon Script keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1037.001] Boot or Logon Initialization Scripts: Logon Script (Windows)" -ForegroundColor red -BackgroundColor black

# Logon Script
foreach($user in $users)
{
    $env = Join-Path $user.PSPath "\Environment"
    if (reg query "$user\Environment" /v "UserInitMprLogonScript" | findstr /ri "$revfn")
    {
        Write-Host "Hit found in '$user' Logon Scripts key."
        reg delete "$user\Environment" /v "UserInitMprLogonScript" /f
    }
    else
    {
        Write-Host "No hits found in '$user' Logon Scripts key."
    }
}

########## Screensaver ##########

Write-Host "`nTask (4 / 22)    |  Removing any associated Screensaver keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.002] Event Triggered Execution: Screensaver" -ForegroundColor red -BackgroundColor black

# Screensaver
foreach($user in $users)
{
    $env = Join-Path $user.PSPath "\Control Panel\Desktop"
    if (reg query "$user\Control Panel\Desktop" /v "WallPaper" | findstr /ri "$revfn")
    {
        Write-Host "Hit found in '$user' Screensaver key."
        reg delete "$user\Control Panel\Desktop" /v "WallPaper" /f
    }
    else
    {
        Write-Host "No hits found in '$user' Screensaver key."
    }
}

########## Netsh Helper DLL ##########

Write-Host "`nTask (5 / 22)    |  Removing any associated Autorun keys." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.007] Event Triggered Execution: Netsh Helper DLL" -ForegroundColor red -BackgroundColor black

# Netsh
$netsh = "HKLM:\Software\Microsoft\Netsh"
if (Get-ItemProperty -Path "$netsh" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$netsh" -Name "$revfn"
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
if (reg query "$HKLMwlno" /v "Notify" | findstr /ri '$revfn')
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
if (reg query "$HKLMwlui" /v "Userinit" | findstr /ri '$revfn')
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
if (reg query "$HKLMwlsh" /v "Shell" | findstr /ri '$revfn')
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
if (reg query "$HKLMwl6432no" /v "Notify" | findstr /ri '$revfn')
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
if (reg query "$HKLMwl6432ui" /v "Userinit" | findstr /ri '$revfn')
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
if (reg query "$HKLMwl6432sh" /v "Shell" | findstr /ri '$revfn')
    {
        Write-Host "Hit found in HKLM Winlogon Helper Wow6432Node Shell key."
        reg delete "$HKLMwl6432sh" /v "Shell" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Winlogon Helper Wow6432Node Shell key."
    }
# HKU Winlogon Shell
foreach($user in $users)
{
    $env = Join-Path $user.PSPath "\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (reg query "$user\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" | findstr /ri "$revfn")
    {
        Write-Host "Hit found in '$user' Winlogon Helper Shell key."
        reg delete "$user\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
    }
    else
    {
        Write-Host "No hits found in '$user' Winlogon Helper Shell key."
    }
}

########## Windows Services ##########

Write-Host "`nTask (7 / 22)    |  Removing any associated Windows Services." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1543.003] Create or Modify System Process: Windows Service" -ForegroundColor red -BackgroundColor black

# Services
$Services = "HKLM:\System\CurrentControlSet\Services"
if (Get-Item -Path "$Services\$revfn" -ea SilentlyContinue) {
    Remove-Item -Path "$Services\$revfn"
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
if (reg query "$AppInit" /v "AppInit_DLLs" | findstr /ri '$revfn')
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
if (reg query "$AppInit6432" /v "AppInit_DLLs" | findstr /ri '$revfn')
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
$Port = "HKLM:\System\CurrentControlSet\Control\Print\Monitors\$revfn"
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
$lsa = "HKLM\System\CurrentControlSet\Control\Lsa"
if (reg query "$lsa" /v "Security Packages" | findstr /ri '$revfn')
    {
        Write-Host "Hit found in HKLM Lsa SSP key."
        reg delete "$lsa" /v "Security Packages" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Lsa SSP key."
    }
# SSP OSC
$lsaosc = "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig"
if (reg query "$lsaosc" /v "Security Packages" | findstr /ri '$revfn')
    {
        Write-Host "Hit found in HKLM Lsa OSConfig SSP key."
        reg delete "$lsaosc" /v "Security Packages" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Lsa OSConfig SSP key."
    }

########## Application Shims ##########

Write-Host "`nTask (11 / 22)   |  Removing any associated Application Shims." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1546.011] Event Triggered Execution: Application Shimming" -ForegroundColor red -BackgroundColor black

# Shim Custom
$shimcustom = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\$fn"
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
if (reg query "$HKLMws" /v "AutodialDLL" | findstr /ri '$revfn')
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
$HKCRapt = "HKCR\AutoProxyTypes\Application/$revfn"
if (reg query "$HKCRapt" /v "DllFile" | findstr /ri '$revfn')
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
if (reg query "$HKLMcp" /v "AutoRun" | findstr /ri '$revfn')
    {
        Write-Host "Hit found in HKLM Command Processor key."
        reg delete "$HKLMcp" /v "AutoRun" /f
    }
    else
    {
        Write-Host "No hits found in HKLM Command Processor key."
    }
# HKU Command Processor
foreach($user in $users)
{
    $env = Join-Path $user.PSPath "\Software\Microsoft\Command Processor"
    if (reg query "$user\Software\Microsoft\Command Processor" /v "AutoRun" | findstr /ri "$revfn")
    {
        Write-Host "Hit found in '$user' Command Processor key."
        reg delete "$user\Software\Microsoft\Command Processor" /v "AutoRun" /f
    }
    else
    {
        Write-Host "No hits found in '$user' Command Processor key."
    }
}

########## Known DLL ##########

Write-Host "`nTask (15 / 22)   |  Removing any associated Known DLL keys." -ForegroundColor yellow -BackgroundColor black

$HKLMkd = "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
if (Get-ItemProperty -Path "$HKLMkd" -Name "$revfn" -ea SilentlyContinue) {
    Remove-ItemProperty -Path "$HKLMkd" -Name "$revfn"
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
schtasks /delete /tn "$revfn" /f

########## Background Intelligent Transfer Service (BITS) ##########

Write-Host "`nTask (17 / 22)   |  Removing any associated Windows Background Intelligent Transfer Service (BITS) jobs." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1197] BITS Jobs" -ForegroundColor red -BackgroundColor black

# Jobs
if ($job = Get-BitsTransfer -AllUsers -Name "$revfn" -ea SilentlyContinue) {
    $job | Remove-BitsTransfer -Confirm:$False -ea SilentlyContinue
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
if((Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$revfn'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event filter called '$revfn'."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='$revfn'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event filter called "$revfn" found and removed."
}
# Consumers
if((Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$revfn'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event consumer called "$revfn"."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='$revfn'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event consumer called "$revfn" found and removed."
}
# Bindings
if((Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$revfn%'" -ea SilentlyContinue) -eq $Null){
    Write-Host "No event binding called '$revfn'."
}

else {
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$revfn%'" -ea SilentlyContinue | Remove-WmiObject -Verbose
    Write-Host "Event binding called '$revfn' found and removed."
}

########## Shortcuts (LNK) ##########

Write-Host "`nTask (19 / 22)   |  Removing any associated LNK (.lnk) files." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1547.009] Boot or Logon Autostart Execution: Shortcut Modification" -ForegroundColor red -BackgroundColor black

# LNK
$lf = Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*" -Include "$fn.lnk" -Force -Recurse -ea SilentlyContinue
$lcount = $lf.Count
Write-Host "$lcount hit(s) found for $fn in LNK files."
$lf | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$lf | Remove-Item -Force -ea SilentlyContinue

########## Alternate Data Streams (ADS) ##########

Write-Host "`nTask (20 / 22)   |  Removing any associated Alternate Data Stream (ADS) entries." -ForegroundColor yellow -BackgroundColor black
Write-Host "`nMITRE ATT&CK [T1564.004] Hide Artifacts: NTFS File Attributes" -ForegroundColor red -BackgroundColor black

# ADS
if((Get-ChildItem "C:\" | ForEach-Object {Get-Item $_.FullName -stream "$fn" -ea 'SilentlyContinue'} | Where-Object stream -ne ':$DATA' -ea SilentlyContinue) -eq $Null){
    Write-Host "No Alternate Data Stream called '$fn'."
}

else {
    try
{
    Get-ChildItem "C:\" -Recurse | ForEach-Object {Get-Item $_.FullName -stream "$fn" -Force -ea SilentlyContinue} | Where-Object stream -ne ':$DATA' | Remove-Item -Force -ea SilentlyContinue
}
catch
{

}
    Write-Host "Alternate Data Stream called '$fn' found and removed."
}

########## Temporary Files ##########

Write-Host "`nTask (21 / 22)   |  Removing any unused Temporary files." -ForegroundColor yellow -BackgroundColor black

# Temp File Paths
$temps = @("C:\Windows\Temp\*", "C:\Temp\*", "C:\Users\*\Appdata\Local\Temp\*")
ForEach ($folder in $temps) {Remove-Item $folder -Force -Recurse -ea SilentlyContinue}
Write-Host "Unused Temporary Files Cleaned."

########## New Technology File System (NTFS) ##########

Write-Host "`nTask (22 / 22)   |  Removing any malware binaries from NTFS file system." -ForegroundColor yellow -BackgroundColor black

# File Trace
$bf = Get-ChildItem -Path "C:\*" -Include $fn -Force -Recurse -ea SilentlyContinue
$tcount = $bf.Count
Write-Host "$tcount hit(s) found for $fn in NTFS."
$bf | Get-FileHash -ea 0 -Algorithm MD5 | Format-List
$bf | Remove-Item -Force -ea SilentlyContinue

Write-Host "`nEradication completed!" -ForegroundColor green -BackgroundColor black
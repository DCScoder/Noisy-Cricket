# Noisy Cricket
Windows malware persistence mechanism removal.

#### Description:

The Noisy Cricket is primarily utilised for the removal of persistence mechanisms utilised by the malware, as well as traces of the malicious binary file from Windows operating systems.

The script focusses on using living-off-the-land binaries (LOLbins) to carry out a series of functions including but not limited to, searching registry hives for keys and values depicting the target file name, assess hidden alternate data streams executing the malware, active associated memory processes, traces of the malicious file in the NTFS volume and much more.
Once hits are encountered, the persistence mechanisms and files are removed from the host.
Results are returned into terminal and a log file of all findings is produced for audit purposes.
The script should only be used post-root cause analysis, as artefacts of interest for forensics analysis are deleted.
You should also ensure any malware samples required for reverse-engineering have been collected, prior to execution of this script.

**_CAUTION:_ There are limitations with the identification of malware and persistence, as this script focuses on the file naming convention provided. Ensure only _unique_ target filenames are used, i.e. _evil123.exe_ and NOT _svchost.exe_.**

#### Persistence Mechanisms Supported:

Common malware persistence mechanisms targetted include those mapped to MITRE ATT&CK:

- MITRE ATT&CK [T1547.001] Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- MITRE ATT&CK [T1037.001] Boot or Logon Initialization Scripts: Logon Script (Windows)
- MITRE ATT&CK [T1546.002] Event Triggered Execution: Screensaver
- MITRE ATT&CK [T1546.007] Event Triggered Execution: Netsh Helper DLL
- MITRE ATT&CK [T1547.004] Boot or Logon Autostart Execution: Winlogon Helper DLL
- MITRE ATT&CK [T1543.003] Create or Modify System Process: Windows Service
- MITRE ATT&CK [T1546.010] Event Triggered Execution: AppInit DLLs
- MITRE ATT&CK [T1547.010] Boot or Logon Autostart Execution: Port Monitors
- MITRE ATT&CK [T1547.005] Boot or Logon Autostart Execution: Security Support Provider
- MITRE ATT&CK [T1546.011] Event Triggered Execution: Application Shimming
- MITRE ATT&CK [T1053.005] Scheduled Task/Job: Scheduled Task
- MITRE ATT&CK [T1197] BITS Jobs
- MITRE ATT&CK [T1546.003] Event Triggered Execution: Windows Management Instrumentation Event Subscription
- MITRE ATT&CK [T1547.009] Boot or Logon Autostart Execution: Shortcut Modification
- MITRE ATT&CK [T1564.004] Hide Artifacts: NTFS File Attributes
- Winsock
- AutoProxyTypes
- Command Processor
- Known DLL

#### Cleanup Operations Supported:

General cleanup operations are also carried out, as depicted below:

- Active volatile associated memory processes
- Removal of target binary from NTFS volume C:\
- Removal of unused temporary files from NTFS volume C:\

#### Usage:

```
.\Noisy_Cricket.ps1
```

#### Requirements:

- Script must be run with local Administrator priveleges.
- Ensure local PowerShell policies permit execution.

#### Demonstration:

Malware PE binary in NTFS volume;

![alt text](https://github.com/DCScoder/Noisy-Cricket/blob/main/Screenshots/File%20System%20binary.png)

Persistence via HKLM Run key;

![alt text](https://github.com/DCScoder/Noisy-Cricket/blob/main/Screenshots/Reg%20persistence.png)

Hit found in HKLM Run key & removed from registry;

![alt text](https://github.com/DCScoder/Noisy-Cricket/blob/main/Screenshots/Run%20key%20hit.png)

Hit found in NTFS volume & removed from file system;

![alt text](https://github.com/DCScoder/Noisy-Cricket/blob/main/Screenshots/NTFS%20hit.png)

**Noisy Cricket**

> The Noisy Cricket is a tiny, palm-sized firearm of astonishing power. Despite its small size, it launches a large orb of energy.

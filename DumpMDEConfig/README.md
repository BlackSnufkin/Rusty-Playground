# DumpMDEConfig :shield:

## Description
This tool enumerates Microsoft Defender, it identifying exclusion paths, allowed threats, protection history and ASR (Attack Surface Reduction) rules enabled on the system. No admin privileges required.

## Usage
Run the executable to list the Microsoft Defender Configuration.

## Example
```txt

PS C:\Users\L.Ackerman\Desktop\Development\Rusty-Playground\DumpMDEConfig> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

PS C:\Users\L.Ackerman\Desktop\Development\Rusty-Playground\DumpMDEConfig> .\target\x86_64-pc-windows-msvc\release\DumpMDEConfig.exe

[+] Exclusion Path: C:\Users\L.Ackerman\AppData\Local\Temp\vmware-L.Ackerman\VMwareDnD
[!] Time Created: 2024-06-03 08:53:30.527790700 UTC

[+] ASR Rule Triggered: 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c - (Prevent Adobe Reader from creating child processes)
[!] Time Created: 2024-06-07 08:57:42.596451100 UTC

[+] ASR Rule Triggered: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 - (Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem)
[!] Time Created: 2024-06-09 14:19:27.197803 UTC

[+] Allowed Threats of the system:
ThreatID: 2147729891
Tool Name: HackTool:Win32/Mimikatz.D
Path: file:_C:\Users\L.Ackerman\Documents\mimikatz.exe
Time Created: 2024-06-07 11:49:04.508103200 UTC

ThreatID: 2147756241
Tool Name: VirTool:Win32/Kekeo.A!MTB
Path: file:_C:\Users\L.Ackerman\Documents\Rubeus.exe
Time Created: 2024-06-07 12:21:26.140346600 UTC


[+] Defender Protection History
Threat Name: Ransom:Win32/ContiCrypt.PL!MTB
Severity: Severe
Category: Ransomware
Path: amsi:_\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Action Taken: Quarantine
Time Created: 2024-04-21 09:41:21.140124800 UTC

Threat Name: HackTool:Win32/Mimikatz.D
Severity: High
Category: Tool
Path: file:_C:\Users\L.Ackerman\Documents\mimikatz.exe
Action Taken: Quarantine
Time Created: 2024-06-07 11:48:50.899367300 UTC

Threat Name: HackTool:Win32/Mimikatz.D
Severity: High
Category: Tool
Path: file:_C:\Users\L.Ackerman\Documents\mimikatz.exe
Action Taken: Quarantine
Time Created: 2024-06-07 11:49:06.658568400 UTC


Threat Name: VirTool:MSIL/Kekeo!atmn
Severity: Severe
Category: Tool
Path: file:_C:\Users\L.Ackerman\Documents\Rubeus.exe; process:_pid:5480,ProcessStart:133622364887807555
Action Taken: Quarantine
Time Created: 2024-06-07 12:21:46.903276400 UTC

Threat Name: VirTool:MSIL/Kekeo.C
Severity: Severe
Category: Tool
Path: file:_C:\Users\L.Ackerman\Documents\Rubeus.exe; process:_pid:5480,ProcessStart:133622364887807555
Action Taken: Allow
Time Created: 2024-06-07 12:21:46.916400 UTC


[+] Exploit Guard Protection History
Rule ID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Description: Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem
Detection Time: 2024-06-09 14:19:55.290 UTC
User: DARKGATE-RT\L.Ackerman
Path: C:\Users\L.Ackerman\Desktop\mimikatz.exe
Process Name: C:\Windows\System32\lsass.exe
Target Commandline: "C:\Users\L.Ackerman\Desktop\mimikatz.exe"
 

Rule ID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
Description: Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem
Detection Time: 2024-06-09 14:38:27.007 UTC
User: DARKGATE-RT\L.Ackerman
Path: C:\Users\L.Ackerman\Desktop\Tools\safetydump\target\x86_64-pc-windows-msvc\release\safetydump.exe
Process Name: C:\Windows\System32\lsass.exe
Target Commandline: "C:\Users\L.Ackerman\Desktop\Tools\safetydump\target\x86_64-pc-windows-msvc\release\safetydump.exe"

```
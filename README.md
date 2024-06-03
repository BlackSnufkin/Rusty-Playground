# Rusty-Playground :crab:
> Some Rust program I wrote while learning Malware Development 

# ClipboradMon :pushpin:
  - Simpale Program to monitor clipborad for changes and log them or copy the file depenads on the situastion
---
# DefExclusions :pushpin:
  - Simpale Program to enum Defender Exclusions from normal user (no admin)
---
# ElevateToken :pushpin:
  - Impersonates user tokens, and creates processes with elevated system privileges
  - Refernce:
    - [Token::elevate](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_token.c)
---
# HeapEnc :pushpin:
  - Simple exmaple of heap encryption
  - Refernce:
    - [nimHeapEnc](https://github.com/nbaertsch/nimHeapEnc)
---
# HideDll :pushpin:
  - Simpale Program that will Hide the dll in the current process + anti-analysis method so the dll cant be dumped with memory scanner (test against pe-sieve)
---
# HookFinder :pushpin:
  - Rust code that attempts to detect userland API hooks in place by AV/EDR
---
# IoDllProxyLoad :pushpin:
  - Using windows thread pool API to proxy the loading and unloading of a DLL through an I/O completion callback function utilizing named pipes
  - Refernce:
    - [IoDllProxyLoad](https://github.com/fin3ss3g0d/IoDllProxyLoad)
    - [weaponizing-windows-thread-pool-apis-proxying-dll-loads](https://fin3ss3g0d.net/index.php/2024/03/18/weaponizing-windows-thread-pool-apis-proxying-dll-loads/)
---
# NtCreateUserProcess :pushpin:
  - Spawn Process with NtCreateUserProcess and Block Dlls and PPID Spoofing
  - Refernce:
    - [ntcreateuserprocess_1](https://offensivedefence.co.uk/posts/ntcreateuserprocess/)
    - [ntcreateuserprocess_2](https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html)   
---
# PatchlessAmsiBypass 📌
  - Amsi Bypass with HWBP So no hooks in memory
  - Reference:
    - [patchless_amsi](https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf)
---
# PatchlessBypass 📌
  - Improved Version of the PatchlessAmsiBypass Patch ETW + AMSI on all threads
  - Reference:
    - [PatchlessHook](https://github.com/ScriptIdiot/sleepmask_PatchlessHook/)
---
# SelfErase 📌
  - Delete a currently running file from disk
  - Reference:
    - [self_remove](https://github.com/Enelg52/OffensiveGo/tree/main/self_remove)
    - [delete-self-poc](https://github.com/LloydLabs/delete-self-poc)
---
# SilentFart :pushpin:
  - Leveraging NTAPI to grab NTDLL for unhooking without triggering "PspCreateProcessNotifyRoutine"
  - Refernce:
    - [GhostFart](https://github.com/mansk1es/GhostFart)
---
# StackEncrypt :pushpin:
  - Shuffele & encrpyt the Stack and sleep with indirect syscalls to NtDelayExecution
  - Refernce:
    - [StackMask](https://github.com/WKL-Sec/StackMask) 
---
# UnhookNtdll :pushpin:
  - Rust implementation of the Perun's Fart thechnique
  - Using NtCreateUserProcess Both local and remote can be done with this program
  - Refernce:
    - [arsenal-rs](https://github.com/memN0ps/arsenal-rs)
---
# USB_mon :pushpin:
  - USB monitoring for new devices and display info about the devices
---
# VEH-ProxyDll :pushpin:
  - leverage the VEH (Vectored Exception Handler) to modify the context, especially RIP register to take us to the LoadLibraryA, and the RCX to hold the function's argument (module name) of LoadLibraryA. 
  - To trigger our exception, VirtualProtect is used to set the page to PAGE_GUARD, thus triggering the STATUS_GUARD_PAGE_VIOLATIO
  - Refernce:
    - [VEH-DLL-proxy-load.c](https://github.com/kleiton0x00/Proxy-DLL-Loads/blob/main/VEH-DLL-proxy-load.c)
---
# Whoami_alt :pushpin:
  - Alternatives to the command whoami by leveraging uncommon winapi (this is not presnt on [WhoIsWho](https://github.com/MzHmO/WhoIsWho) and on [WhoamiAlternatives](https://twitter.com/vxunderground/status/1720265558501794288))



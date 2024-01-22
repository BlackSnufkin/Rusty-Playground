# Rusty-Playground :crab:
> Some Rust program I wrote while learning Malware Development 

# ElevateToken :pushpin:
  - Impersonates user tokens, and creates processes with elevated system privileges
  - Refernce:
    - [Token::elevate](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_token.c)
---
# Gabimaru :pushpin:
  - Module Stomping with Threadless Injection x2 (1. load dll 2. Shellcode Injection )
  - Refernce:
    - [ThreadlessInjection](https://github.com/0prrr/Malwear-Sweet/tree/main/ThreadlessInjection)
    - [Defcon31](https://github.com/OtterHacker/Conferences/tree/main/Defcon31)
---
# JumpThreadHijack :pushpin:
  - Shellcode Injection with ThreadHijacking without the usage of SetThreadContext
  - Refernce:
    - [TheLostThread](https://github.com/0prrr/Malwear-Sweet/tree/main/TheLostThread)
---
# ModuleStomping :pushpin:
  - This is like the base program for everything and it all build upong this
  - Module Stomping with indirect syscalls and injection in .text section of the targeted dll
  - Refernce:
    - [module_stomping-rs](https://github.com/memN0ps/arsenal-rs/tree/main/module_stomping-rs)
    - [D1rkInject](https://github.com/TheD1rkMtr/D1rkInject)
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

# Rusty-Playground :toolbox:
> Some Rust program I wrote while learning Malware Development 

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

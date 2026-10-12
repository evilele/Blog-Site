# Protections of MsMpEng

*(blog post in progress)*<br><br>

The following post explains the encountered protections of MsMpEng, the main process of MDE.

## Why do I care?

TL:DR; see [EDR-Introspection](https://github.com/evilele/EDR-Introspection)<br>
Summarized: To analyse all actions that MsMpEng is doing at any point in time, some kind of monitor process needs full access to MsMpEng's process.

## Use-Cases & Protections

### Debuging MsMpEng

### Introspection via Hooking DLL

I.e. loading a hooking DLL into MsMpEng, to track relevant syscalls via ntdll. 

1. MsMpEng is PPL-AM -> strip PPL or elevate Injector to PPL-AM
2. `OpenProcess(MsMpEng_pid, PROCESS_ALL_ACCESS)` returns stripped rights -> disable (handle) kernel callbacks or patch handle access in kernel mode again
3. `CreateRemoteThread(hMsMpEng, any_addr)` is denied, even with full access -> disable kernel callbacks or use thread hijacking
  1. OpenThread is also protected by kernel callbacks -> disable kernel callbacks or patch thread handle access in kernel mode
4. `LoadLibrary(hMsMpEng, unsigned.dll)` does not load because of CodeIntegrity -> use reflective injection

### Introspection via Patching MsMpEng Code

1. MsMpEng is PPL-AM -> strip PPL or elevate Injector to PPL-AM
2. `OpenProcess(MsMpEng_pid, PROCESS_ALL_ACCESS)` returns stripped rights -> disable (handle) kernel callbacks or patch handle access in kernel mode again
3. Skill Issue: How can I log syscalls of MsMpEng, only with patching (not loading a new dll and hooking) ntdll.dll inside MsMpEng? SOS send help

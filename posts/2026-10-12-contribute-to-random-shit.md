# How to Learn about and Contribute to interesting Repos

> *This is a small write-up about how I get interested about reading and maybe even contributing to random projects, as an example I'll take [KDU](https://github.com/hfiref0x/KDU) and [ThreadlessInject](https://github.com/CCob/ThreadlessInject)*

# 1. Look up Tools similar to yours

I was refining my [InjectLoader](https://github.com/evilele/EDR-Introspection) to move away from EdrSandblast (eww, kernel callbacks), and only depend on [KDU](https://github.com/hfiref0x/KDU) and it's `-pho` mode. 
This required to again expand KDU's user-mode code base, which I was kind of familiar at this point. Nevertheless, I had to learn how the kernel handles handles (hehe), how to find and patch them.
<br><br>
Following this I had process and thread handles to protected processes, but still no generic way to execute code. Also, only being able to load DLLs with reflective loading limits the DLLs to be custom ones (with a custom reflective loader entrypoint).
3 interesting techniques popped up in my search for similar tools:

1. Host (manual) mapped DLL injection from [DLLium](https://github.com/Paxai/DLLium)
2. Generic thread hijacking, i.e. clean function prologue, shellcode calling and epilogue from [GuidedHacking](https://github.com/guidedhacking/GuidedHacking-Injector)
3. Executing shellcode without* an executor, NANI?! [ThreadlessInject](https://github.com/CCob/ThreadlessInject)

# 2. Plan and implement your Improvements

> *For me the best way to understand a new concept is to play around and incorporate it into something I (partially) know, therefore trying to contribute to random, interesting projects seems like a nice way.*

## Host-mapped and Generic Thread Hijacking

I just read up the source-code (I mostly understood the techniques in isolation), copied it to my [InjectLoader](https://github.com/evilele/EDR-Introspection/tree/master/InjectLoader), renamed some variables for clarity and made the code compatible with my architecture and *separation of duties*.

## Threadless Injection

This was very cool to learn, shoutout to Ceri's [talk about it](https://www.youtube.com/watch?v=z8GIjk0rfbI).
While I knew the individual components, the idea behind temporarily hooking code as an executor was new to me. After watching the talk and having a look at the codebase I had kind of an understanding of it.
To better understand it, and maybe to even be helpful I wanted to try my luck first on the "Avoid RWX on hooked function". So I had a look at the relevant code and came up with a plan:

### Check current Code Flow
* Increase the injectors timeout to 60min in Main()
* Execute the target (e.g. Notepad) and attach a debugger
* Set a breakpoint on the target function (e.g. `bp kernelbase!MapViewOfFileEx`)
* Print the start of the original (unhooked) function with `u kernelbase!MapViewOfFileEx L1`
* Print the mem protection with `!vprot kernelbase!MapViewOfFileEx`, should be RX
* Execute the injector `.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx`
* Print the mem protection again with `!vprot kernelbase!MapViewOfFileEx`, should be RWX <- **this is the problem stated**
* Continue the debugged process and let the breakpoint hit (e.g. press save in Notepad)
* Note the new call instruction at the start of the now hooked function
* Set a second breakpoint in the code cave (where the loader shellcode is injected e.g. `bp 00007ffcfb520000`)
* Continue again and the loader shellcode should be hit
* Continue again and calc should pop

### Update the Code Logic
* Reset the hooked function memory protection to RX again right after the hook is written
* Update the restore section in the shellcode loader itself
    * Right be before the movabs,mov instructions a VirtualProctect must set RWX to the hooked function
    * The hooked function is restored with movabs,mov
    * Immidiately after mov a VirtualProctect must reset to RX

### Update the Loader Shellcode
```asm
sub rsp, 30h          ; Allocate shadow space (20h) + extra space for oldProtect variable (8h)
mov rcx, hookedFunc   ; Arg 1: The Address of the hooked function
mov rdx, 8            ; Arg 2: Size (only the first 8 bytes must be overwritten)
mov r8, 40h           ; Arg 3: New protect (PAGE_EXECUTE_READWRITE)
lea r9, [rsp + 20h]   ; Arg 4: Point out variable r9 to a temporary stack
mov rax, VirtProt     ; addr of VirtualProtect, must be calculated and written by injector
call rax
add rsp, 30h          ; Clean up stack
```

### Verify the new Code Flow
* Execute the target (e.g. Notepad) and attach a debugger
* Set a breakpoint on the target function (e.g. `bp kernelbase!MapViewOfFileEx`)
* Print the start of the original (unhooked) function with `u kernelbase!MapViewOfFileEx L1`
* Print the mem protection with `!vprot kernelbase!MapViewOfFileEx`, should be RX
* Execute the injector `.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx`
* Print the mem protection again with `!vprot kernelbase!MapViewOfFileEx`, **should STILL be RX**
* Continue the debugged process and let the breakpoint hit (e.g. press save in Notepad)
* Note the new call instruction at the start of the now hooked function
* Set a second breakpoint in the code cave (where the loader shellcode is injected e.g. `bp 00007ffcfb520000`)
* Continue again and the loader shellcode should be hit
* Single step to debug the new restore logic
* Continue again and calc should pop
* ?
* Profit

# 3. Conclusion
> *Do stuff that is interests you, break things, hack the world*

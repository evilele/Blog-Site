# The Injected Shellcode Code-Flow Dilemmas

> *This is a short write-up on a shellcode flow dilemma, when your shellcode loader stub has to call something like `LoadLibraryA` and cleanly return to "normal" code.*

How I got here? See **Appendix**. This is my attempt to summarise my findings.

# Jump, Enter, Exit

A process has different methonds to control the flow of execution.
In "normal" land the compiler handles stack, registers, cleanup, etc.
In injected shellcode land, the malware writer has to handle each aspect correclty.
Below is a short overview of the 3 possibilities to control the code flow:

* `call` takes execution somewhere else and pushes the return address (the one right after the call address) on the stack, so the called location can just `ret` to this previous location (given the stack is balanced, i.e. the ret address is at the current `rsp` position)
* `jmp` takes you in and out of code without touching the stack, but you have to handle correct returns manually
* `push X`-`ret` is a hand-rolled "call" that lands on `X` and allows the called location to again `ret` to the shellcode. Notice the two `ret` yet no `call`? In the bizz this is called foreshadowing.

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

# The <s>Shellcode</s> Dilemmas appear

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
*Also, see my struggles with ThreadlessInject in the follow-up post*.
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
pop rax          ; get ret addr (OpenFile+0x0C, after the call)
sub rax, 0x0C    ; size of movabs and call instructions
```

After this setup the shellcode has to restore the original bytes of `OpenFile` (exercise of the reader), do its malicious stuff and go back to `OpenFile`.
We chose `rax` (or `r10` or `r11`) because the non-volatile registers as well as function argument registers must be the same when re-entering the hooked function, else we change the behaviour or crash it.
However, any called function like `LoadLibraryA` usually changes these volatile, non-function-argument registers, meaning before calling any other function we must push and then pop into `rax` again

```asm
push rax                  ; safe OpenFile addr

; cleanup OpenFile
movabs rcx, originalIntructions_0_8
mov qword ptr [rax], rcx
movabs rcx, originalInstruction_8_C
mov dword ptr [rax+8], rcx

; call LoadLibrary
sub rsp, 28h              ; each function requires shadow space (20h) + maybe 16byte alignment (+8h or +0h)
movabs rax, LoadLibraryA
movabs rcx, dllPath
call rax                  ; actual call to LoadLibraryA, will ret to line below
add rsp, 28h              ; rebalance the stack (delete shadow space again)

ret                       ; the OpenFile addr should now be at the top of the stack again
```

The stack should be balanced anyhow as mentioned above, unless this thread should crash and burn (mhh, yes).

# The Problems arise

The `ret` above would now return to the top of the `OpenFile` function, **not** at `OpenFile+0x0C` where it originally would have.
If CET were active it would see the mismatch and kill the process.
*If `OpenFile` would be a legit target to return to (i.e. there is a call instruction right before the `OpenFile` function bytes, and this call was triggered some time before) CET would be okay with this ultra-special case.*
<br><br>
As an unexpected bonus (for me at least); Remember the `call rax` from function hooking? 
If you do not "clear" this `call` with a `ret`, then the next `ret` will fail, i.e. the legit `ret` in `OpenFile`, as CET would still expect to `ret` to `OpenFile+0x0C`.
To recall, `CET` expects calls and returns to be "balanced", but the `call shellcode` was not balanced out with a `ret` to right after the shellcode.

# How to solve it?

In my limited experience I guess it would be easiest to use `call` and `ret` whenever the return address should not be changed.
Then it's just about keeping the stack balanced, as you should always do if the thread must no crash.
For special cases like ThreadlessInject (and I guess many more), using `jmp`s allows to mess with the returns even with CET active.
As my favourite west-taiwanese philosopher liked to say:

> *2 jmps are as strong as a call and ret combined* 
<br>
> - Sun Tsu, probably

# Appendix

This <del>nighmare into</del> shellcode writing started 6 months ago with Sektor7's proposal 
> "Why do you need kernel callbacks disabled, when you could already get a process handle?"

Being naive enough, I tried it instead of counting a win as a win (I already achieved DLL loading in protected procs):

- Firstly, I expanded KDU to also give process and thread handles.
- I noticed I still cannot use `CreateRemoteThread` in EDR procs.
- Thread Hijacking and `QueueUserAPC2` was added to my inject loader, giving me a first taste of how to **inject shellcode**.
- Finally, [ThreadlessInject](https://github.com/CCob/ThreadlessInject) challenged my puny understanding of injected shellcode even more.


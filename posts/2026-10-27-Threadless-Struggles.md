# Struggles with Threadless Injection

Turns out I did not fully understand CCobs [ThreadlessInject](https://github.com/CCob/ThreadlessInject) when trying to implement it into my stitty [InjectLoader](https://github.com/evilele/EDR-Introspection/tree/master/InjectLoader).
A quick overview of CCob's ThreadlessInject:

```
                                                                     
  original caller                                                    
 ┌────────────────┐                                                  
 │                │        hooked function                           
 │                │       ┌────────────────┐       injected          
 │ call ──────────┼───────► mov rax, lpInj◄┼───┐  ┌────────────────┐ 
 │                │       │ jmp rax ───────┼───┼──► mov rax, hooked│ 
 │                │       │                │   │  │ push rax       │ 
 │                │       │                │   │  │                │ 
 │                │       │                │   │  │ ;do stuff      │ 
 │                │       │                │   │  │ ;call shellcode│ 
 │                │       │                │   │  │ ;restore hooked│ 
 │                │       │                │   │  │                │ 
 │                │       │                │   │  │ pop rax; hooked│ 
 │                │       │                │   └──┼ jmp rax        │ 
 │                │       │                │      └────────────────┘ 
 │                │       │                │                         
 │                │       └────────────────┘                         
 │                │                                                  
 └────────────────┘                                                  
                                                                     
```

The `mov rax, lpInj` and `jmp rax` instructions are inserted by a remote injector, the "injected" code gets executed the next time this process calls the hooked function.
The injected code does your malware stuff, restores the hooked function and returns to it. 
From the POV of the injected process everything should stay the same, just that it *also* executed the injected code.

## What are volatile registers anyway?

I wrongly assumed volatile registers can be freely changed.
Or I just read [Microsoft's documentaion](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170) wrong.

> ... are considered volatile, or potentially changed by a callee on return.

> Consider volatile registers destroyed on function calls ...

What I understood was that I could **freely change volatile registers in injected code**, and continue with the original function as if nothing happened.
Obviously I cannot, not without risking a crash. This is because the volatile registers `rcx`,`rdx`,`r8`,`r9` are used in x64_86 for function arguments.
Meaning that at the start of the hooked function, the caller of the hooked function placed specific values into these 4 regs.
Changing these 4 regs in the shellcode and returning back to the hooked function changes behaviour (or a crash).

Also, even if my injected shellcode would not change these 4, `rcx`,`rdx`,`r8`,`r9`, any function called by the injected shellcode may change them (as well as the 3 other volatile regs).
Below is a depiction of my self-inflicted-not-reading-the-fucking-manual struggles:

```
                                                                                              
  original caller                                                                             
 ┌────────────────┐                                                                           
 │                │        hooked                                                             
 │                │       ┌────────────────┐       injected                                   
 │ call ──────────┼───────► mov rax, lpInj◄┼───┐  ┌────────────────┐                          
 │                │       │ jmp rax ───────┼───┼──► mov rax, hooked│                          
 │                │       │                │   │  │ push rax       │                          
 │                │       │                │   │  │                │        any syscall       
 │                │       │                │   │  │                │       ┌────────────────┐ 
 │                │       │                │   │  │ syscall ───────┼───────► ;changes regs  │ 
 │                │       │                │   │  │ ; other stuff ◄┼───────┬ ret; lol       │ 
 │                │       │                │   │  │                │       └────────────────┘ 
 │                │       │                │   │  │ pop rax; hooked│                          
 │                │       │                │   └──┼ jmp rax        │                          
 │                │       │                │      └────────────────┘                          
 │                │       │                │                                                  
 │                │       └────────────────┘                                                  
 │                │                                                                           
 └────────────────┘                                                                           
                                                                                              
```

So I cannot have the non-volatile regs changed when re-entering the hooked function.
I can also not have the function argument regs changed when re-entering the hooked function (unless I only use functions with <4 args, but I want it to stay universal).
*And as a bonus, I also have to keep the stack balanced when re-entering, unless I want to crash the proc as soon as hooked returns.*

## A solution?

With all the above in mind, there is only `rax`,`r10`,`r11` that my injected code can freely change and re-enter hooked. 
Also, any syscall in injected might change these 3 regs, placing further restrictions how I can handle my registers during the injected shellcode.
Nevertheless, I may have found a working generic prototype, see below:

```
                           must be restored                                                    
                           when returned to        injected may only change                    
  original caller          from inj.               rax,r10,r11 when returning                  
 ┌────────────────┐                                to hooked                                   
 │                │        hooked                                                              
 │                │       ┌────────────────┐       injected                                    
 │ call ──────────┼───────► mov rax, lpInj◄┼───┐  ┌────────────────┐                           
 │                │       │ jmp rax ───────┼───┼──► mov rax, hooked│                           
 │                │       │                │   │  │ push rax       │                           
 │                │       │                │   │  │ ; other stuff  │        any syscall        
 │                │       │                │   │  │                │       ┌────────────────┐  
 │                │       │                │   │  │ syscall ───────┼───────►                │  
 │                │       │                │   │  │ ; other stuff ◄┼───────┬─               │  
 │                │       │                │   │  │                │       └────────────────┘  
 │                │       │                │   │  │ pop rax; hooked│        volatile regs:     
 │                │       │                │   └──┼ jmp rax        │         injected code must
 │                │       │                │      └────────────────┘         assume they change
 │                │       │                │                                                   
 │                │       └────────────────┘       volatile regs:           non-volatile regs: 
 │                │                                 expected to change       not changed       
 └────────────────┘        x64 call regs:           by the syscalls                            
                            set by og caller,                                                  
  volatile regs:            expected to have       non-volatile regs:                          
   expect hooked func       a certain value         preserved at syscall                       
   to change them           at hooked entry                                                    
                            -> rcx,rdx,r8,r9                                                   
  non-volatile regs:           (ignoring xmm)                                                  
   expect hooked func       -> injected must                                                   
   to preserve them            preserve them                                                   
                                                                                               
                           other vol. regs:                                                    
                            can be changed by                                                  
                            injected code                                                      
                            -> rax,r10,r11                                                     
                                                                                               
                           non-volatile regs:                                                  
                            must be preserved for                                              
                            original caller                                                    
```

## Bonus

When you wouldn't even dare to overwrite `rax`, this might be a solution to preserve **all registers**:

```asm
; hooked function
push rax
mov rax, lpInj
jmp rax
; ...
```

```asm
; injector
; old rax is on top of stack
mov rax, hooked
push rax       ; safe return addr -> stack: retAddr,oldRax

; safe all other regs
; restore hooked function
; do other stuff

pop rax        ; dummy pop, this was the retAddr
pop rax        ; real rax restored
jmp [rsp-10h]  ; return to hooked
```

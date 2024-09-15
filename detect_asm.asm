.code

 __read_tr proc
    str rax
    ret
 __read_tr endp


 _cli proc
    cli 
    ret
 _cli endp

 _sti proc
    sti 
    ret
 _sti endp

  __read_cs proc
    mov rax, cs
    ret
 __read_cs endp

 __lock_sidt proc
   db 0F0h  ; lock prefix
   sidt qword ptr [rcx]
   ret
 __lock_sidt endp

 __ss_fault_sidt proc
    mov rax, rsp ; Safe rsp into rax

    mov rsp, 4AAAAAAAA555A555h ; Mov some non canonical value into rsp
    sidt qword ptr [rsp] ; #SS should be thrown here
    mov rsp, rax

    ret
 __ss_fault_sidt endp


__gp_fault_sidt proc
    mov rax, 4AAAAAAAA555A555h ; Mov some non canonical value into rax
    sidt qword ptr [rax] ; #GP should be thrown here

    ret
__gp_fault_sidt endp


; Args:
; cx <- Cs selector  
switch_segment proc
   pop rax                  ; Stores the ret address in rax
   push cx                  ; Push the segment selector onto the stack

   push rax                 ; Push the returning rip onto the stack

   retf                     ; Far return to switch to a different segment selector
switch_segment endp

get_proc_number proc
    push rbx
    push rcx
    push rdx

    xor  eax, eax            ; Clear eax
    mov  eax, 0Bh            ; Set eax to leaf 0x0B
    xor  ecx, ecx            ; Set ecx to 0 (subleaf 0)
    cpuid

    mov  eax, edx ; Save apic id

    pop  rdx
    pop  rcx
    pop  rbx

    ret
get_proc_number endp

end
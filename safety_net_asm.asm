.data

; Error codes
dummy_error_code dq 0 

; Exception vectors
invalid_opcode_vector dq 6h
page_fault_vector dq 0Eh
general_protection_vector dq 0Dh
stack_segment_fault_vector dq 0Ch

extern seh_handler_ecode:proc

.code

save_general_regs macro
    push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
endm

restore_general_regs macro
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
endm

; Just mock nmis
asm_nmi_handler proc
	iretq
asm_nmi_handler endp

; No Ecode handlers
asm_ud_handler proc
    push qword ptr [dummy_error_code]
    push qword ptr [invalid_opcode_vector]
	jmp asm_core_exception_handler
asm_ud_handler endp

; Ecode handlers
asm_pf_handler proc
	push qword ptr [page_fault_vector]
	jmp asm_core_exception_handler
asm_pf_handler endp

asm_gp_handler proc
	push qword ptr [general_protection_vector]
	jmp asm_core_exception_handler
asm_gp_handler endp

asm_ss_handler proc
	push qword ptr [stack_segment_fault_vector]
	jmp asm_core_exception_handler
asm_ss_handler endp

; Core handler
; Expects the error code and the exception vector on the stack
asm_core_exception_handler proc
	save_general_regs

	mov rcx, rsp
	sub rsp, 20h
	call seh_handler_ecode
	add rsp, 20h

	restore_general_regs
	add rsp, 8	; remove exception vector
	add rsp, 8  ; remove error code

	iretq
asm_core_exception_handler endp

end
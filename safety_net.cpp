#include "includes.h"
#include "func_defs.hpp"
#include "structs.hpp"

#include <ntimage.h>

extern "C" void seh_handler_ecode(idt_regs_ecode_t* regs);

namespace safety_net {
	bool inited = false;

	uint64_t g_image_base;
	uint64_t g_image_size;

	segment_descriptor_interrupt_gate_64* my_idt = 0;
	segment_descriptor_register_64 my_idtr = { 0 };

	idt_regs_ecode_t* context_storage = 0;

	/*
		Utility
	*/

	segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler) {
		segment_descriptor_interrupt_gate_64 gate = { 0 };

		gate.interrupt_stack_table = 1; // Doesn't really matter which one we point it to as all point to the same; Just has to be non 0
		gate.segment_selector = __read_cs().flags;
		gate.must_be_zero_0 = 0;
		gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
		gate.must_be_zero_1 = 0;
		gate.descriptor_privilege_level = 0;
		gate.present = 1;
		gate.reserved = 0;

		uint64_t offset = (uint64_t)assembly_handler;
		gate.offset_low = (offset >> 0) & 0xFFFF;
		gate.offset_middle = (offset >> 16) & 0xFFFF;
		gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

		return gate;
	}

	/*
		Core
	*/
	extern "C" void seh_handler_ecode(idt_regs_ecode_t* regs) {
		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)g_image_base;
		IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(g_image_base + dos_header->e_lfanew);
		IMAGE_DATA_DIRECTORY* exception = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		RUNTIME_FUNCTION* rt_functions = (RUNTIME_FUNCTION*)(g_image_base + exception->VirtualAddress);

		// stack_segment_fault faults require the real rsp in rax (;
		// Look into detect_asm.asm:__ss_fault_sidt for more details
		if (regs->exception_vector == stack_segment_fault) {
			regs->rsp = regs->rax;
		}

		uint64_t rip_rva = regs->rip - g_image_base;
		// Try to resolve the exception directly with rip
		for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx) {
			RUNTIME_FUNCTION* function = &rt_functions[idx];
			if (!(rip_rva >= function->BeginAddress && rip_rva < function->EndAddress))
				continue;

			UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
			if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
				continue;

			SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
			for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
				SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
				if (rip_rva >= scope_record->BeginAddress && rip_rva < scope_record->EndAddress) {
					memcpy(&context_storage[get_proc_number()], regs, sizeof(idt_regs_ecode_t));

					regs->rip = g_image_base + scope_record->JumpTarget;

					return;
				}
			}
		}

		// If we reached here this means that the exception couldn't get
		// resolved with rip, so we have to stack trace to find the __except
		// block (Just walk rsp chain by 8 bytes at a time)
		uint64_t* stack_ptr = (uint64_t*)regs->rsp;
		while (stack_ptr) {
			uint64_t potential_caller_rip = *stack_ptr;
			uint64_t potential_caller_rva = potential_caller_rip - g_image_base;

			// Check whether the current stack address can even be a function in our driver
			if (potential_caller_rva > g_image_size) {
				stack_ptr++;
				continue;
			}

			// Check whether the potential_caller_rva corresponds to an __except block
			for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx) {
				RUNTIME_FUNCTION* function = &rt_functions[idx];
				if (!(potential_caller_rva >= function->BeginAddress && potential_caller_rva < function->EndAddress))
					continue;

				UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
				if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
					continue;

				SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
				for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
					SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
					if (potential_caller_rva >= scope_record->BeginAddress && potential_caller_rva < scope_record->EndAddress) {
						memcpy(&context_storage[get_proc_number()], regs, sizeof(idt_regs_ecode_t));

						regs->rip = g_image_base + scope_record->JumpTarget;
						regs->rsp = (uint64_t)(stack_ptr + 1); // Point rsp to below the return address (*mostly* is the state of the stack of the caller function)

						return;
					}
				}
			}

			stack_ptr++;
		}
	}

	/*
		Exposed API's
	*/

	bool init_safety_net(uint64_t image_base, uint64_t image_size) {
		if (!image_base || !image_size)
			return false;

		g_image_base = image_base;
		g_image_size = image_size;

		PHYSICAL_ADDRESS max_addr = { 0 };
		max_addr.QuadPart = MAXULONG64;
		my_idt = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(0x1000, max_addr);
		if (!my_idt)
			return false;

		memset(my_idt, 0, 0x1000);

		segment_descriptor_register_64 win_idtr;
		__sidt(&win_idtr);

		memcpy(my_idt, (void*)win_idtr.base_address, win_idtr.limit);

		my_idt[nmi] = create_interrupt_gate(asm_nmi_handler);

		my_idt[invalid_opcode] = create_interrupt_gate(asm_ud_handler);

		my_idt[general_protection] = create_interrupt_gate(asm_gp_handler);
		my_idt[page_fault] = create_interrupt_gate(asm_pf_handler);
		my_idt[stack_segment_fault] = create_interrupt_gate(asm_ss_handler);

		my_idtr.base_address = (uint64_t)my_idt;
		my_idtr.limit = win_idtr.limit;

		context_storage = (idt_regs_ecode_t*)MmAllocateContiguousMemory(KeQueryActiveProcessorCount(0) * sizeof(idt_regs_ecode_t), max_addr);
		if (!context_storage)
			return false;

		memset(context_storage, 0 , KeQueryActiveProcessorCount(0) * sizeof(idt_regs_ecode_t));

		inited = true;

		return true;
	}

	bool start_safety_net(segment_descriptor_register_64* curr_descriptor_storage) {

		// Init first and for gods sake gimme a valid parameter
		if (!inited || !curr_descriptor_storage)
			return false;

		_cli();

		// Store the old idtr
		__sidt(curr_descriptor_storage);

		// Load the new idtr
		__lidt(&my_idtr);

		return true;
	}

	void stop_safety_net(segment_descriptor_register_64* overwritten_descriptor_storage) {
		__lidt(overwritten_descriptor_storage);

		_sti();
	}

	idt_regs_ecode_t* get_core_last_interrupt_record(void) {
		if (!inited)
			return 0;

		return &context_storage[get_proc_number()];
	}
}
#pragma once
#include "includes.h"
#include "structs.hpp"

/*
	Assembly
*/
extern "C" void _cli(void);
extern "C" void _sti(void);
extern "C" void _sgdt(void* gdtr);
extern "C" void _lgdt(void* gdtr);
extern "C" uint16_t __read_tr(void);
extern "C" void __write_tr(uint16_t selector);
extern "C" segment_selector __read_cs(void);

// Util
extern "C" uint32_t get_proc_number(void);

// Detection specific assembly routines
extern "C" void __lock_sidt(void* idtr_storage);
extern "C" void __ss_fault_sidt(void);
extern "C" void __gp_fault_sidt(void);

// Idt handlers
extern "C" void asm_nmi_handler(void);

extern "C" void asm_ud_handler(void);

extern "C" void asm_pf_handler(void);
extern "C" void asm_gp_handler(void);
extern "C" void asm_ss_handler(void);


/*
	High level detections
*/

namespace idt {
	void execute_idt_detections(void);
};

namespace gdt {
	void execute_gdt_detections(void);
};

namespace tr {
	void execute_tr_detections(void);
};

namespace safety_net {
	bool init_safety_net(uint64_t image_base, uint64_t image_size);

	bool start_safety_net(segment_descriptor_register_64* curr_descriptor_storage);
	void stop_safety_net(segment_descriptor_register_64* overwritten_descriptor_storage);
	idt_regs_ecode_t* get_core_last_interrupt_record(void);
}
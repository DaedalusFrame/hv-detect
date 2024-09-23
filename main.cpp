#include "includes.h"
#include "func_defs.hpp"
#include "physmem/physmem.hpp"

void execute_detections(uint64_t driver_base, uint64_t driver_size) {
	if (!physmem::init_physmem())
		return;
	
	log_new_line();
	log_info("Physmem inited");

	if (!safety_net::init_safety_net(driver_base, driver_size))
		return;

	log_info("Safety net inited\n");

	safety_net_t storage;
	if (!safety_net::start_safety_net(storage))
		return;

	/*
	__try {
		__debugbreak();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	*/

	cr4 curr_cr4;
	cr4 new_cr4;
	curr_cr4.flags = __readcr4();
	new_cr4.flags = curr_cr4.flags;

	new_cr4.smap_enable = 0;
	new_cr4.smep_enable = 0;
	__writecr4(new_cr4.flags);

	//safety_net::cpl::switch_to_cpl_3();
	//safety_net::cpl::switch_to_cpl_0();

	__writecr4(curr_cr4.flags);

	safety_net::stop_safety_net(storage);

	safety_net::idt::log_all_interrupts();
}

NTSTATUS driver_entry(uint64_t driver_base, uint64_t driver_size) {

	log_info("Driver loaded at %p with size %p", driver_base, driver_size);

	execute_detections(driver_base, driver_size);

	return STATUS_SUCCESS;
}
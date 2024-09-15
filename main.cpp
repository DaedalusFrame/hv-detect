#include "includes.h"
#include "func_defs.hpp"

void execute_detections(uint64_t driver_base, uint64_t driver_size) {
	safety_net::init_safety_net(driver_base, driver_size);

	log_info("IDT:");
	idt::execute_idt_detections();
	log_new_line();

	log_info("GDT:");
	gdt::execute_gdt_detections();
	log_new_line();

	log_info("TR:");
	tr::execute_tr_detections();
	log_new_line();
}

NTSTATUS driver_entry(uint64_t driver_base, uint64_t driver_size) {

	execute_detections(driver_base, driver_size);

	return STATUS_SUCCESS;
}
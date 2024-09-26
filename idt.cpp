#include "includes.h"
#include "func_defs.hpp"
#include "physmem/physmem.hpp"

namespace idt {
    char allocated_memory_page[0x1000];

    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> SIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing (TO DO!)
        detection_6 -> Non canonical address passed as memory operand
        detection_7 -> Non canonical address passed as memory operand in SS segment -> #SS
        detection_8 -> Executing sidt with cpl = 3 but with cr4.umip = 0 && eflags.ac = 0
        detection_9 -> Executing sidt with cpl = 3 but with cr4.umip = 1 -> #GP(0) should be caused
    */
    namespace storing {
        bool detection_1(void) {
            bool hypervisor_detected = false;

            // Lock prefix should cause an exception
            segment_descriptor_register_64 idtr;
            __try {
                __lock_sidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_2(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #PF and not #GP as 0xdead is canonical (;
                __sidt((void*)0xdead); // If there actually is a va 0xdead then you honestly deserve that dub
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_3(void) {

            volatile segment_descriptor_register_64* idtr_in_tlb = (volatile segment_descriptor_register_64*)allocated_memory_page;
            // Put the part of the memory page we will use into the tlb
            // so that the cpu will be able to access it when executing sidt
            for (uint32_t i = 0; i < sizeof(segment_descriptor_register_64); i++) {
                volatile uint8_t dummy = *(uint8_t*)((uint64_t)allocated_memory_page + i);
                UNREFERENCED_PARAMETER(dummy);
            }

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_memory_page, stored_flags)) {
                return false;
            }

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_memory_page)) {
                return false;
            }

            // The instruction should go through as the idtr page is still in the tlb (but not mapped in cr3!)
            bool hypervisor_detected = false;
            __try {
                __sidt((void*)idtr_in_tlb);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true; // Should not happen on bare metal
            }

            if (!physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_memory_page, stored_flags)) {
                return hypervisor_detected;
            }

            return hypervisor_detected;
        }

        bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __sidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;

                // Account for hypervisors over adjusting the tsc
                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        bool detection_5(void) {
            // Compatibility mode IDTR storing (TO DO)

            return false;
        }

        bool detection_6(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #GP as we pass a non canonical address as an operand
                __gp_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_7(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #SS as we pass a non canonical address and we do so in rsp (-> stack segment)
                __ss_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_8(void) {
            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 0;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            rflags curr_flags;
            rflags new_flags;
            curr_flags.flags = __readeflags();
            new_flags.flags = curr_flags.flags;

            new_flags.alignment_check_flag = 0;
            __writeeflags(new_flags.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            bool hypervisor_detected = false;
            segment_descriptor_register_64 idtr;

            __try {
                // This should not cause an exception since we disable cr4.usermode_instruction_prevention
                __sidt(&idtr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            __writeeflags(curr_flags.flags);

            return hypervisor_detected;
        }

        bool detection_9(void) {
            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 1;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            rflags curr_flags;
            rflags new_flags;
            curr_flags.flags = __readeflags();
            new_flags.flags = curr_flags.flags;

            new_flags.alignment_check_flag = 0;
            __writeeflags(new_flags.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            bool hypervisor_detected = false;
            segment_descriptor_register_64 idtr;

            __try {
                // This should cause an exception since we set cr4.usermode_instruction_prevention
                __sidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                idt_regs_ecode_t* record = safety_net::idt::get_core_last_interrupt_record();
                if (record->exception_vector != general_protection || record->error_code != 0)
                    hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            __writeeflags(curr_flags.flags);

            return hypervisor_detected;
        }

        void execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return;

            bool detection_1_result = detection_1();
            bool detection_2_result = detection_2();
            bool detection_3_result = detection_3();
            bool detection_4_result = detection_4();
            bool detection_5_result = detection_5();
            bool detection_6_result = detection_6();
            bool detection_7_result = detection_7();
            bool detection_8_result = detection_8();
            bool detection_9_result = detection_9();

            safety_net::stop_safety_net(storage);

            if (detection_1_result) {
                log_error_indent(2, "Failed detection 1");
            }
            else {
                log_success_indent(2, "Passed detection 1");
            }

            if (detection_2_result) {
                log_error_indent(2, "Failed detection 2");
            }
            else {
                log_success_indent(2, "Passed detection 2");
            }

            if (detection_3_result) {
                log_error_indent(2, "Failed detection 3");
            }
            else {
                log_success_indent(2, "Passed detection 3");
            }

            if (detection_4_result) {
                log_error_indent(2, "Failed detection 4");
            }
            else {
                log_success_indent(2, "Passed detection 4");
            }

            if (detection_5_result) {
                log_error_indent(2, "Failed detection 5");
            }
            else {
                log_success_indent(2, "Passed detection 5");
            }

            if (detection_6_result) {
                log_error_indent(2, "Failed detection 6");
            }
            else {
                log_success_indent(2, "Passed detection 6");
            }

            if (detection_7_result) {
                log_error_indent(2, "Failed detection 7");
            }
            else {
                log_success_indent(2, "Passed detection 7");
            }

            if (detection_8_result) {
                log_error_indent(2, "Failed detection 8");
            }
            else {
                log_success_indent(2, "Passed detection 8");
            }

            if (detection_9_result) {
                log_error_indent(2, "Failed detection 9");
            }
            else {
                log_success_indent(2, "Passed detection 9");
            }
        }
    };

    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> LIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing (TO DO!)
        detection_6 -> Non canonical address passed as memory operand
        detection_7 -> Non canonical address passed as memory operand in SS segment -> #SS
    */
    namespace loading {

        bool detection_1(void) {
            bool hypervisor_detected = false;

            // Lock prefix should cause an exception
            segment_descriptor_register_64 idtr;
            __sidt(&idtr); // Just in case the hv actually loads the idtr

            __try {
                __lock_lidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_2(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause a page fault
            __try {
                // This should cause #PF since 0xdead is canonical but not mapped
                __lidt((void*)0xdead);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_3(void) {
            memset(allocated_memory_page, 0, 0x1000);

            segment_descriptor_register_64 idtr;
            __sidt(&idtr);

            // This memcpy also maps the va into the tlb
            memcpy(allocated_memory_page, &idtr, sizeof(idtr));

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_memory_page, stored_flags)) {
                return false;
            }

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_memory_page)) {
                return false;
            }

            // The instruction should go through as the idtr page is still in the tlb (but not mapped in cr3!)
            bool hypervisor_detected = false;
            __try {
                __lidt(allocated_memory_page);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;  // Should not happen on bare metal
            }

            physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_memory_page, stored_flags);
            return hypervisor_detected;
        }

        bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;

            // Copy the current idtr into idtr to ensure we load valid idtrs via lidt during timing
            __sidt(&idtr);

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __lidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;

                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        bool detection_5(void) {
            // Compatibility mode IDTR storing (TO DO)
            return false;
        }

        bool detection_6(void) {
            bool hypervisor_detected = false;

            // Non-canonical address should cause a general protection fault
            __try {
                __gp_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_7(void) {
            bool hypervisor_detected = false;

            // Non-canonical address in SS segment should cause a stack segment fault
            __try {
                __ss_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_8(void) {
            segment_descriptor_register_64 idtr;
            __sidt(&idtr);

            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 0;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            bool hypervisor_detected = false;
            __try {
                // This should cause an exception since it is not affected by cr4.usermode_instruction_prevention
                __lidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                idt_regs_ecode_t* record = safety_net::idt::get_core_last_interrupt_record();
                if (record->exception_vector != general_protection || record->error_code != 0)
                    hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            return hypervisor_detected;
        }

        void execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return;

            bool detection_1_result = detection_1();
            bool detection_2_result = detection_2();
            bool detection_3_result = detection_3();
            bool detection_4_result = detection_4();
            bool detection_5_result = detection_5();
            bool detection_6_result = detection_6();
            bool detection_7_result = detection_7();
            bool detection_8_result = detection_8();

            safety_net::stop_safety_net(storage);

            if (detection_1_result) {
                log_error_indent(2, "Failed detection 1");
            }
            else {
                log_success_indent(2, "Passed detection 1");
            }

            if (detection_2_result) {
                log_error_indent(2, "Failed detection 2");
            }
            else {
                log_success_indent(2, "Passed detection 2");
            }

            if (detection_3_result) {
                log_error_indent(2, "Failed detection 3");
            }
            else {
                log_success_indent(2, "Passed detection 3");
            }

            if (detection_4_result) {
                log_error_indent(2, "Failed detection 4");
            }
            else {
                log_success_indent(2, "Passed detection 4");
            }

            if (detection_5_result) {
                log_error_indent(2, "Failed detection 5");
            }
            else {
                log_success_indent(2, "Passed detection 5");
            }

            if (detection_6_result) {
                log_error_indent(2, "Failed detection 6");
            }
            else {
                log_success_indent(2, "Passed detection 6");
            }

            if (detection_7_result) {
                log_error_indent(2, "Failed detection 7");
            }
            else {
                log_success_indent(2, "Passed detection 7");
            }

            if (detection_8_result) {
                log_error_indent(2, "Failed detection 8");
            }
            else {
                log_success_indent(2, "Passed detection 8");
            }
        }
    };

    void execute_idt_detections(void) {
        memset(allocated_memory_page, 0, 0x1000);

        safety_net_t storage;
        if (!safety_net::start_safety_net(storage))
            return;

        safety_net::stop_safety_net(storage);

        log_new_line();
        log_info_indent(1, "SIDT");
        storing::execute_detections();
        log_new_line();

        log_info_indent(1, "LIDT");
        loading::execute_detections();
        log_new_line();


        if (!safety_net::start_safety_net(storage))
            return;

        if (!physmem::paging_manipulation::win_set_memory_range_supervisor(allocated_memory_page, 0x1000, __readcr3(), 0)) {
            safety_net::stop_safety_net(storage);
            return;
        }

        safety_net::stop_safety_net(storage);
    }
};
#include "includes.h"
#include "func_defs.hpp"

namespace idt {
    namespace win {
        uint64_t win_get_virtual_address(uint64_t physical_address) {
            PHYSICAL_ADDRESS phys_addr = { 0 };
            phys_addr.QuadPart = physical_address;

            return (uint64_t)(MmGetVirtualForPhysical(phys_addr));
        }

        uint64_t win_get_physical_address(void* virtual_address) {
            return MmGetPhysicalAddress(virtual_address).QuadPart;
        }

        bool win_destroy_memory_page_mapping(void* memory, uint64_t& stored_flags) {
            va_64_t mem_va;
            mem_va.flags = (uint64_t)memory;

            pml4e_64* pml4_table = 0;
            pdpte_64* pdpt_table = 0;
            pde_64* pde_table = 0;
            pte_64* pte_table = 0;

            pml4_table = (pml4e_64*)win_get_virtual_address(__readcr3());
            if (!pml4_table)
                return false;

            pdpt_table = (pdpte_64*)win_get_virtual_address(pml4_table[mem_va.pml4e_idx].page_frame_number << 12);
            if (!pdpt_table) {
                return false;
            }

            pde_table = (pde_64*)win_get_virtual_address(pdpt_table[mem_va.pdpte_idx].page_frame_number << 12);
            if (!pde_table) {
                return false;
            }

            pte_table = (pte_64*)win_get_virtual_address(pde_table[mem_va.pde_idx].page_frame_number << 12);
            if (!pte_table)
                return false;

            stored_flags = pte_table[mem_va.pte_idx].flags;
            pte_table[mem_va.pte_idx].flags = 0;

            __invlpg(pte_table);

            return true;
        }

        bool win_restore_memory_page_mapping(void* memory, uint64_t stored_flags) {
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;

            va_64_t mem_va;
            mem_va.flags = (uint64_t)memory;

            pml4e_64* pml4_table = 0;
            pdpte_64* pdpt_table = 0;
            pde_64* pde_table = 0;
            pte_64* pte_table = 0;

            pml4_table = (pml4e_64*)win_get_virtual_address(__readcr3());
            if (!pml4_table)
                return false;

            pdpt_table = (pdpte_64*)win_get_virtual_address(pml4_table[mem_va.pml4e_idx].page_frame_number << 12);
            if (!pdpt_table) {
                return false;
            }

            pde_table = (pde_64*)win_get_virtual_address(pdpt_table[mem_va.pdpte_idx].page_frame_number << 12);
            if (!pde_table) {
                return false;
            }

            pte_table = (pte_64*)win_get_virtual_address(pde_table[mem_va.pde_idx].page_frame_number << 12);
            if (!pte_table)
                return false;

            pte_table[mem_va.pte_idx].flags = stored_flags;
            __invlpg(pte_table);

            return true;
        }

        bool is_memory_page_mapped(void* memory) {
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;

            va_64_t mem_va;
            mem_va.flags = (uint64_t)memory;

            pml4e_64* pml4_table = 0;
            pdpte_64* pdpt_table = 0;
            pde_64* pde_table = 0;
            pte_64* pte_table = 0;

            pml4_table = (pml4e_64*)win_get_virtual_address(__readcr3());
            if (!pml4_table)
                return false;

            pdpt_table = (pdpte_64*)win_get_virtual_address(pml4_table[mem_va.pml4e_idx].page_frame_number << 12);
            if (!pdpt_table) {
                return false;
            }

            pde_table = (pde_64*)win_get_virtual_address(pdpt_table[mem_va.pdpte_idx].page_frame_number << 12);
            if (!pde_table) {
                return false;
            }

            pte_table = (pte_64*)win_get_virtual_address(pde_table[mem_va.pde_idx].page_frame_number << 12);
            if (!pte_table)
                return false;

            return pte_table[mem_va.pte_idx].present;
        }

    };

    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> SIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing (TO DO!)
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
                if(safety_net::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
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
                if (safety_net::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_3(void) {
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;
            void* allocated_page = MmAllocateContiguousMemory(0x1000, max_addr);
            if (!allocated_page)
                return false;

            memset(allocated_page, 0, 0x1000);

            volatile segment_descriptor_register_64* idtr_in_tlb = (volatile segment_descriptor_register_64*)allocated_page;
            // Put the part of the memory page we will use into the tlb
            // so that the cpu will be able to access it when executing sidt
                for (uint32_t i = 0; i < sizeof(segment_descriptor_register_64); i++) {
                    volatile uint8_t dummy = *(uint8_t*)((uint64_t)allocated_page + i);
                    UNREFERENCED_PARAMETER(dummy);
                }

            uint64_t stored_flags;
            if (!win::win_destroy_memory_page_mapping(allocated_page, stored_flags)) {
                return false;
            }

            if (win::is_memory_page_mapped(allocated_page)) {
                return false;
            }

            // The instruction should go through as the idtr page is still in the tlb (but not mapped in cr3!)
            // If this instruction causes a bsod you know you don't handle sidt properly
            bool hypervisor_detected = false;
            __try {
                __sidt((void*)idtr_in_tlb);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true; // Should not happen on bare metal
            }

            if (!win::win_restore_memory_page_mapping(allocated_page, stored_flags)) {
                return hypervisor_detected;
            }

            return hypervisor_detected;
        }

        bool detection_4(void) {
            _disable();

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
                    _enable();
                    return true;
                }
            }

            _enable();
            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        bool detection_5(void) {
            // TO DO!

            return false;
        }

        bool detection_6(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #GP as we pass a non canonical address
                __gp_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::get_core_last_interrupt_record()->exception_vector != general_protection)
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
                if (safety_net::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

		bool execute_detections(void) {
            segment_descriptor_register_64 curr;
            if (!safety_net::start_safety_net(&curr))
                return false;

            if (detection_1()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 1");
                return true;
            }
            log_success_indent(2, "Passed detection 1");

            if (detection_2()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 2");
                return true;
            }
            log_success_indent(2, "Passed detection 2");

            if (detection_3()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 3");
                return true;
            }
            log_success_indent(2, "Passed detection 3");

            if (detection_4()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 4");
                return true;
            }
            log_success_indent(2, "Passed detection 4");

            if (detection_5()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 5");
                return true;
            }
            log_success_indent(2, "Passed detection 5");

            if (detection_6()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 6");
                return true;
            }
            log_success_indent(2, "Passed detection 6");

            if (detection_7()) {
                safety_net::stop_safety_net(&curr);
                log_error_indent(2, "Failed detection 7");
                return true;
            }
            log_success_indent(2, "Passed detection 7");
            safety_net::stop_safety_net(&curr);

            return false;
		}
	};

	namespace loading {
		bool execute_detections(void) {

            return false;
		}
	};

	void execute_idt_detections(void) {
        log_info_indent(1, "SIDT");
        storing::execute_detections();

        log_info_indent(1, "LIDT");
        loading::execute_detections();
	}
};
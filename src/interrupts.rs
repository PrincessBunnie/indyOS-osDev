use lazy_static::lazy_static;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;
use crate::memory::page::{map_single_page_alloc, page_table_from_addr, PAGE_FAULT_STATS};
use crate::proc::virtual_memory::user_layout::*;
use crate::proc::process::SCHEDULER;
use crate::{serial_println};
use crate::errors::OSError;
use crate::memory::segmentation::DOUBLE_FAULT_IST_INDEX;
use crate::proc::virtual_memory::{VmFlags, KERNEL_HEAP_SIZE, KERNEL_HEAP_START};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler).set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt
    };
}

pub fn init_idt() {
    serial_println!("Loading IDT...");
    IDT.load();
    serial_println!("IDT loaded successfully!");
}

/*
Exception types by handler signature

// Type 1: No error code
extern "x86-interrupt" fn handler(stack_frame: InterruptStackFrame) { }

// Type 2: With error code
extern "x86-interrupt" fn handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) { }

// Type 3: Diverging (doesn't return - for double fault)
extern "x86-interrupt" fn handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    panic!("...");
}

// Type 4: Page fault (special error code type)
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,  // ← Special type
) { }
 */

// fn my_general_handler(
//     stack_frame: InterruptStackFrame,
//     index: u8,
//     error_code: Option<u64>,
// ) {
//     let error_code = error_code.unwrap_or(0xFFFF_FFFF);
//     serial_println!("EXCEPTION: {} ERROR CODE: {}\nFRAME:\n{:#?}", index, error_code, stack_frame);
// }
// 
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    // record the fault
    PAGE_FAULT_STATS.record_fault();

    let fault_addr = match Cr2::read() {
        Ok(virt_addr) => {
            virt_addr
        },
        Err(e) => {
            panic!("Virtual Address is not valid {:#?}", e)
        }
    };

    if fault_addr.as_u64() < NULL_GUARD_END {
        PAGE_FAULT_STATS.record_null_pointer();
        panic!(
            "NULL POINTER DEREFERENCE at {:?}\n\
             Error code: {:?}\n\
             Stack frame: {:#?}",
            fault_addr, error_code, stack_frame
        );
    }

    // parse specific fault error code to better understand the nature of the fault
    let was_present = error_code.contains(
        PageFaultErrorCode::PROTECTION_VIOLATION
    );
    let was_write = error_code.contains(
        PageFaultErrorCode::CAUSED_BY_WRITE
    );
    // use this to determine CPL
    let was_user = error_code.contains(
        PageFaultErrorCode::USER_MODE
    );
    let was_instruction_fetch = error_code.contains(
        PageFaultErrorCode::INSTRUCTION_FETCH
    );

    // only map if page is not present (karen paging ( "I demand to see a new page" >:o ) )
    if was_present {
        PAGE_FAULT_STATS.record_permission_fault();
        panic!(
            "Permission violation at {:?} (page already mapped)\n{:#?}",
            fault_addr, stack_frame
        );
    }

    // another check to help determine cpl, this and the interrupt stack frame information should ALWAYS align
    let interrupted_cs = stack_frame.code_segment.0;
    let interrupted_privilege = interrupted_cs & 0x3;

    // Record access type and mode
    PAGE_FAULT_STATS.record_access_type(was_write, was_instruction_fetch);
    PAGE_FAULT_STATS.record_mode(was_user);

    // Check if we're in kernel space or user space
    // let is_kernel_addr = fault_addr.as_u64() >= 0xFFFF_8000_0000_0000;

    // this aligns the address to a page boundary by using bit arithmetic to zero out the lower 12 bits
    // bit arithmetic is harder to read but faster than the corresponding integer division
    // let aligned_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);
    //
    // let page = Page::<Size4KiB>::from_start_address(aligned_addr).expect("Address should be aligned");

    // user
    if was_user && interrupted_privilege == 3 {
        handle_user_page_fault(fault_addr, stack_frame, error_code, was_instruction_fetch, was_user, was_write)
    } else if !was_user && interrupted_privilege == 0 {
        handle_kernel_page_fault(fault_addr, stack_frame, error_code)
    } else {
        panic!(
            "PAGE FAULT: Inconsistent privilege state!\n\
            was_user flag: {}, CS privilege: {}\n\
            This indicates CPU bug or corrupted state",
            was_user, interrupted_privilege
        );
    }
}

fn handle_kernel_page_fault(
    fault_addr: VirtAddr,
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode
) {
    const KERNEL_HEAP_END: usize = KERNEL_HEAP_START + KERNEL_HEAP_SIZE;
    if fault_addr.as_u64() < KERNEL_HEAP_START as u64 || fault_addr.as_u64() > KERNEL_HEAP_END as u64 {
        panic!(
            "PAGE FAULT: Kernel Fault beyond heap range {:?}\n\
                     {:#?}\n\
                     {}",
            fault_addr, stack_frame,
            PAGE_FAULT_STATS.summary()
        );
    }
    let page = Page::<Size4KiB>::containing_address(fault_addr);

    // get the CURRENTLY ACTIVE page table (from CR3)
    let (current_pml4_frame, _cr_flags): (PhysFrame<Size4KiB>, Cr3Flags) = Cr3::read();
    let current_pml4_phys = current_pml4_frame.start_address();

    // create an OffsetPageTable for the active page table
    let mut page_table = unsafe {
        page_table_from_addr(current_pml4_phys)
    };

    // double check page is not already mapped
    match page_table.translate_page(page) {
        Ok(_frame) => {
            // page IS already mapped
            panic!("Page fault on already-mapped page {:?}\nError: {:?}", page, error_code);
        }
        Err(_) => {
            // page not mapped, proceed normally
        }
    }

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    unsafe {
        match map_single_page_alloc(&mut page_table, page, flags) {
            Ok::<PhysFrame<Size4KiB>, OSError>(_frame) => {
                // serial_println!("Successfully allocated frames and matched page {}", page.start_address())
                PAGE_FAULT_STATS.record_demand_page();
                serial_println!(
                    "[Kernel] Demand-paged at {:?} [{}]",
                    page.start_address(),
                    PAGE_FAULT_STATS.summary()
                );
            }
            Err(e) => {
                panic!(
                    "PAGE FAULT: Failed to map kernel heap page {:?}\n\
                     Error: {:?}\n\
                     {:#?}\n\
                     {}",
                    page, e, stack_frame,
                    PAGE_FAULT_STATS.summary()
                );
            }
        }
    }
}

fn handle_user_page_fault(
    fault_addr: VirtAddr,
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
    was_instruction_fetch: bool,
    was_user: bool,
    was_write: bool
) {
    let scheduler = SCHEDULER.lock();
    let curr_process = match (*scheduler).current_process() {
        Some(curr_proc) => curr_proc,
        None => panic!("No currently running process!"),
    };

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    unsafe {
        let proc = &*curr_process;
        match proc.check_fault_addr(fault_addr, was_write, was_user, was_instruction_fetch) {
            Ok(_) => {
                let Some(vma) = proc.memory.find_vma(fault_addr) else {
                    panic!(
                        "USER MODE PAGE FAULT but no current VMA could be found!\n\
                         Process (PID): {}\n
                         Fault address: {:?}\n\
                         Stack frame: {:#?}",
                        proc.pid, fault_addr, stack_frame
                    );
                };
                PAGE_FAULT_STATS.record_region(vma.vm_type());
                // Convert VMA flags to page table flags
                flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
                if vma.flags.contains(VmFlags::WRITE) {
                    flags |= PageTableFlags::WRITABLE;
                }
                if !vma.flags.contains(VmFlags::EXEC) {
                    flags |= PageTableFlags::NO_EXECUTE;
                }
                let page = Page::<Size4KiB>::containing_address(fault_addr);

                // get the CURRENTLY ACTIVE page table (from CR3)
                let (current_pml4_frame, _cr_flags): (PhysFrame<Size4KiB>, Cr3Flags) = Cr3::read();
                let current_pml4_phys = current_pml4_frame.start_address();

                // create an OffsetPageTable for the active page table
                let mut page_table = unsafe {
                    page_table_from_addr(current_pml4_phys)
                };

                // double check page is not already mapped
                match page_table.translate_page(page) {
                    Ok(_frame) => {
                        // page IS already mapped
                        panic!("Page fault on already-mapped page {:?}\nError: {:?}", page, error_code);
                    }
                    Err(_) => {
                        // page not mapped, proceed normally
                    }
                }

                unsafe {
                    match map_single_page_alloc(&mut page_table, page, flags) {
                        Ok::<PhysFrame<Size4KiB>, OSError>(_frame) => {
                            // serial_println!("Successfully allocated frames and matched page {}", page.start_address())
                            PAGE_FAULT_STATS.record_demand_page();
                            serial_println!(
                                "[User] Demand-paged at {:?} [{}]",
                                page.start_address(),
                                PAGE_FAULT_STATS.summary()
                            );
                        }
                        Err(e) => {
                            panic!(
                                "PAGE FAULT: Failed to map user page {:?}\n\
                                 Error: {:?}\n\
                                 {:#?}\n\
                                 {}",
                                page, e, stack_frame,
                                PAGE_FAULT_STATS.summary()
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Record the specific error type
                match e {
                    OSError::GuardPageViolation(_, _) => {
                        PAGE_FAULT_STATS.record_guard_page();
                    }
                    OSError::WriteToReadOnly(_) => {
                        PAGE_FAULT_STATS.record_permission_fault();
                    }
                    OSError::InvalidVirtualAddress(_) => {
                        PAGE_FAULT_STATS.record_invalid_address();
                    }
                    _ => {}
                }

                panic!(
                    "FATAL: Process {} page fault violation at {:?}\n\
                     Error: {:#?}\n\
                     Stack frame: {:#?}\n\
                     {}",
                    proc.pid, fault_addr, e, stack_frame,
                    PAGE_FAULT_STATS.summary()
                );
            }
        }
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!("General Protection Fault\n{:#?}", stack_frame);
    serial_println!("Error: {:?}", error_code);
    panic!("General Protection Fault");
}

// helpers
pub fn test_breakpoint() {
    serial_println!("  About to trigger int3 instruction...");

    // Check if interrupts are enabled
    if x86_64::instructions::interrupts::are_enabled() {
        serial_println!("  Interrupts are ENABLED");
    } else {
        serial_println!("  Interrupts are DISABLED (this is OK for exceptions)");
    }

    serial_println!("  Executing int3...");
    // x86_64::instructions::interrupts::int3();
    unsafe {
        core::arch::asm!("int3");
    }
    serial_println!("  Successfully returned from int3!");
}

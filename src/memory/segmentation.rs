use lazy_static::lazy_static;
use x86_64::registers::segmentation::{CS, SS, Segment, DS, ES, FS, GS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::constants::magic::PAGE_SIZE;
use crate::proc::virtual_memory::KERNEL_STACK_SIZE_PAGES;
use crate::serial_println;

// TSS for privilege level transitions and interrupt stack switching
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        // set up a known safe emergency stack for double fault handling
        // this is a panic but its better to panic ourselves instead of triple faulting the CPU
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = PAGE_SIZE * KERNEL_STACK_SIZE_PAGES; // 12kb
            // allocated in .bss -> this confused me a ton initially
            // but as a static this isnt an emergency stack living on our current stack so its safe
            static mut DOUBLE_FAULT_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(unsafe { &raw const DOUBLE_FAULT_STACK });
            let stack_end = stack_start + STACK_SIZE as u64;
            stack_end // grows down
        };

        // privilege stack table for ring transitions (ring 3 -> ring 0)
        // when syscall or interrupt occurs from user mode, CPU switches to this stack
        // 0 initially:
        // - easier
        // - we will just use the bootloader stack for the kernel so this only needs setting in a process swap context
        // - if something does go wrong, and we end up switching to this: fail early (linux)
        tss.privilege_stack_table[0] = VirtAddr::zero();
        tss
    };
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        // entry 0: Null descriptor (required by x86)
        // implicitly added by GlobalDescriptorTable::new()

        // entry 1: Kernel code segment (ring 0, executable)
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());

        // entry 2: Kernel data segment (ring 0, writable)
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());

        // entry 3: User data segment (ring 3, writable)
        // on x86-64, user data has to come before user code for syscall/sysret
        let user_data = gdt.append(Descriptor::user_data_segment());

        // entry 4: User code segment (ring 3, executable)
        let user_code = gdt.append(Descriptor::user_code_segment());

        // entry 5-6: Task State Segment (takes 2 entries on x86-64)
        let tss = gdt.append(Descriptor::tss_segment(&TSS));

        (
            gdt,
            Selectors {
                kernel_code,
                kernel_data,
                user_code,
                user_data,
                tss,
            },
        )
    };
}

#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub user_data: SegmentSelector,
    tss: SegmentSelector,
}

pub unsafe fn init_gdt() {
    serial_println!("Loading GDT...");
    GDT.0.load();
    
    unsafe {
        // set the code segment register
        CS::set_reg(GDT.1.kernel_code);

        // set the stack segment register (and other data segments)
        SS::set_reg(GDT.1.kernel_data);

        DS::set_reg(SegmentSelector(0));
        ES::set_reg(SegmentSelector(0));
        FS::set_reg(SegmentSelector(0));
        GS::set_reg(SegmentSelector(0));

        x86_64::instructions::tables::load_tss(GDT.1.tss);
    }
    
    serial_println!("GDT loaded successfully!");
}

pub unsafe fn set_kernel_stack(stack_top: VirtAddr) {
    let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
    (*tss_ptr).privilege_stack_table[0] = stack_top;

    serial_println!("TSS updated: kernel stack = {:?}", stack_top);
}

pub fn get_selectors() -> &'static Selectors {
    &GDT.1
}
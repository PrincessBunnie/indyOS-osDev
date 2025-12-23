#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

// test harness/runner/etc config
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use crate::proc::process::SCHEDULER;
use crate::proc::virtual_memory::{KernelStackManager, KERNEL_HEAP_SIZE, KERNEL_HEAP_START};
use alloc::vec::Vec;
use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;
use x86_64::registers::control::{Efer, EferFlags};
use x86_64::structures::paging::Mapper;
use x86_64::VirtAddr;

mod constants;
mod io;
mod memory;
mod interrupts;
mod proc;
mod errors;
mod utils;
mod syscalls;

use crate::io::io::init_serial;
use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::info::Optional;

// Kernel will be mapped here by the linker script
// Using standard higher-half address that works with BIOS boot
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut boot_conf = BootloaderConfig::new_default();
    // kernel base
    // boot_conf.mappings.kernel_base = Mapping::FixedAddress(KERNEL_BASE);
    boot_conf.mappings.physical_memory = Some(Mapping::Dynamic);
    boot_conf.kernel_stack_size = 1024 * 1024; // 1 MiB stack
    boot_conf
};

static INIT_PROGRAM: &[u8] = include_bytes!(
    "../userspace/init/target/x86_64-unknown-none/release/init.stripped"
);

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

pub fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        init_serial();
    }
    serial_println!("  INDYOS INITIALIZING...");
    let virtual_offset: VirtAddr = {
        match boot_info.physical_memory_offset {
            Optional::Some(physical_offset) => VirtAddr::new(physical_offset),
            Optional::None => panic!("boot info does not contain physical_memory offset"),
        }
    };
    serial_println!(" bootloader memory info {:#?}", boot_info.memory_regions);
    
    memory::page::PHYSICAL_MEMORY_OFFSET.store(virtual_offset.as_u64(), Ordering::Relaxed);
    // initialize paging structures, inits store into globals
    unsafe { memory::page::init_table(virtual_offset) };
    unsafe { memory::allocator::FrameAllocator::init_global(&boot_info.memory_regions) };
    serial_println!("  PAGING INITIALIZED");
    interrupts::init_idt();
    serial_println!("  IDT INITIALIZED");
    unsafe { memory::segmentation::init_gdt(); }
    serial_println!("  GDT INITIALIZED");
    unsafe { syscalls::management::init_syscall(); }
    serial_println!("  SYSCALL INITIALIZED");

    use x86_64::registers::model_specific::Efer;

    if !Efer::read().contains(EferFlags::SYSTEM_CALL_EXTENSIONS) {
        panic!("System call extensions not enabled!!!!!!");
    }

    use x86_64::registers::model_specific::{LStar, SFMask, Star};

    serial_println!("LSTAR: {:#x}", LStar::read());
    serial_println!("STAR: {:?}", Star::read());
    serial_println!("SFMask: {:?}", SFMask::read());

    // initialize heap allocator
    unsafe {
        memory::allocator::ALLOCATOR.init(
            VirtAddr::new(KERNEL_HEAP_START as u64),
            KERNEL_HEAP_SIZE
        );
    }

    KernelStackManager::init_global();

    serial_println!("Begin process initialization...");
    let process = match proc::process::Process::new_process_from_elf(INIT_PROGRAM) {
        Ok(process) => {
            serial_println!("Process created!");
            process
        }
        Err(e) => panic!("Could not create process from elf file: {}", e)
    };

    serial_println!("Done initializing process");

    let mut scheduler_lock = SCHEDULER.lock();
    let scheduler = &mut (*scheduler_lock);
    scheduler.add_process(process);

    serial_println!("Add process to scheduler -- about to run");
    scheduler.run_current_process();

    
    // pre allocate heap (not demand paging) to make debugging easier later 
    // unsafe {
    //     const HEAP_START: usize = 0x_4444_4444_0000;
    //     const HEAP_SIZE: usize = 100 * 1024; // 100 kb
    // 
    //     // Pre-map all heap pages
    //     let heap_start_addr = VirtAddr::new(HEAP_START as u64);
    //     let heap_end_addr = heap_start_addr + HEAP_SIZE as u64;
    // 
    //     let start_page = Page::<Size4KiB>::containing_address(heap_start_addr);
    //     let end_page = Page::<Size4KiB>::containing_address(heap_end_addr - 1u64);
    //     let page_range = Page::range_inclusive(start_page, end_page);
    // 
    //     let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    // 
    //     let mut page_table_lock = memory::page::PAGE_TABLE.lock();
    //     let page_table = page_table_lock.as_mut().expect("Page table not initialized");
    // 
    //     let mut allocator_lock = memory::allocator::FRAME_ALLOCATOR.lock();
    //     let allocator = allocator_lock.as_mut().expect("Allocator not initialized");
    // 
    //     for page in page_range {
    //         let frame = allocator.alloc_frame().expect("Out of memory");
    //         page_table.map_to(page, frame, flags, &mut *allocator)
    //             .expect("Failed to map heap page")
    //             .flush();
    //     }
    // 
    //     drop(page_table_lock);
    //     drop(allocator_lock);
    //     
    //     serial_println!("locks dropped");
    // 
    //     // Now initialize the heap allocator
    //     memory::allocator::ALLOCATOR.init(heap_start_addr, HEAP_SIZE);
    // }

    serial_println!("  HEAP INITIALIZED");
    
    let mut vec = Vec::new();
    vec.push(1);
    serial_println!("vec {:?}", vec);
    drop(vec);
    

    #[cfg(test)]
    test_main();
    
    loop {}
}

/*
 TEST CODE
 */

#[cfg(test)]
pub trait Testable {
    fn run(&self);
}

#[cfg(test)]
impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

// panic handler specifically for tests
#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    loop {}
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;
    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;

    #[test_case]
    fn test_heap_allocation() {
        extern crate alloc;
        use alloc::boxed::Box;

        let x = Box::new(42);
        assert_eq!(*x, 42);
    }

    #[test_case]
    fn test_aligned_allocation() {
        unsafe {
            let layout = Layout::from_size_align(64, 16).unwrap();
            let ptr = crate::memory::allocator::ALLOCATOR.alloc(layout);

            assert!(!ptr.is_null());
            assert_eq!(ptr as usize % 16, 0);
        }
    }
}
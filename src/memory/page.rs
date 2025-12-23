use crate::errors::OSError;
use crate::memory::allocator;
use crate::serial_println;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate};
use x86_64::{PhysAddr, VirtAddr};

pub(crate) static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

pub static PAGE_TABLE: Mutex<Option<OffsetPageTable<'static>>> = Mutex::new(None);

pub unsafe fn init_table(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let (level_4_table_frame, _cr3_flags) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    let page_table = unsafe {
        OffsetPageTable::new(&mut *page_table_ptr, physical_memory_offset)
    };

    // store in global
    *PAGE_TABLE.lock() = Some(page_table);

    // also return it
    unsafe { OffsetPageTable::new(&mut *page_table_ptr, physical_memory_offset) }
}

#[inline]
pub fn phys_offset() -> VirtAddr {
    VirtAddr::new(PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed))
}

// wrap cr3 interaction to limited scoped helper
pub unsafe fn kernel_page_table() -> OffsetPageTable<'static> {
    let (level_4_frame, _) = Cr3::read();
    unsafe { page_table_from_addr(level_4_frame.start_address()) }
}

pub unsafe fn current_page_table_addr() -> PhysAddr {
    let (level_4_frame, _) = Cr3::read();
    level_4_frame.start_address()
}

pub unsafe fn current_page_table() -> OffsetPageTable<'static> {
    let current_page_table_addr = current_page_table_addr();
    page_table_from_addr(current_page_table_addr)
}

pub unsafe fn page_table_from_addr(page_table_addr: PhysAddr) -> OffsetPageTable<'static> {
    let phys_offset = phys_offset();
    let page_table_virt = phys_offset + page_table_addr.as_u64();
    let pml4_ptr = page_table_virt.as_mut_ptr::<PageTable>();
    unsafe { OffsetPageTable::new(&mut *pml4_ptr, phys_offset) }
}

pub unsafe fn translate_vaddr_to_phys(vaddr: VirtAddr) -> Option<PhysAddr> {
    let table = current_page_table();
    table.translate_addr(vaddr)
}

pub unsafe fn map_page(
    page_table: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), OSError> {
    let mut allocator_lock = allocator::FRAME_ALLOCATOR.lock();
    let allocator = allocator_lock.as_mut()
        .expect("Frame allocator not initialized");

    let flush = unsafe { page_table.map_to(page, frame, flags, allocator)? };
    flush.flush();
    Ok(())
}

pub unsafe fn unmap_page(page_table: &mut OffsetPageTable, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, OSError> {
    let (frame, flush) = page_table.unmap(page)?;
    flush.flush();
    Ok(frame)
}

pub unsafe fn map_pages_alloc(
    page_table: &mut OffsetPageTable,
    pages: impl Iterator<Item = Page<Size4KiB>>,
    flags: PageTableFlags,
) -> Result<Vec<PhysFrame<Size4KiB>>, OSError> {
    let mut allocator_lock = allocator::FRAME_ALLOCATOR.lock();
    let allocator = allocator_lock.as_mut()
        .expect("Frame allocator not initialized");

    let mut allocated_frames = Vec::new();
    let mut mapped_pages = Vec::new();

    for page in pages {
        // allocate frame
        let frame = allocator.alloc_frame()
            .ok_or(OSError::OutOfMemory(crate::errors::Component::FrameAllocator))?;

        // try to map it
        match unsafe { page_table.map_to(page, frame, flags, allocator) } {
            Ok(flush) => {
                flush.flush();
                allocated_frames.push(frame);
                mapped_pages.push(page);
            }
            Err(e) => {
                // cleanup: unmap already mapped pages
                for mapped_page in mapped_pages {
                    let _ = page_table.unmap(mapped_page);
                }
                // free all allocated frames
                for frame in allocated_frames {
                    allocator.free_frame(frame);
                }
                allocator.free_frame(frame); // free the one that just failed
                return Err(e.into());
            }
        }
    }

    Ok(allocated_frames)
}

pub unsafe fn map_single_page_alloc(
    page_table: &mut OffsetPageTable,
    page: Page,
    flags: PageTableFlags
) -> Result<PhysFrame<Size4KiB>, OSError> {
    let mut allocator_lock = allocator::FRAME_ALLOCATOR.lock();
    let allocator = allocator_lock.as_mut()
        .expect("Frame allocator not initialized");

    let frame = allocator.alloc_frame()
        .ok_or(OSError::OutOfMemory(crate::errors::Component::FrameAllocator))?;

    match unsafe { page_table.map_to(page, frame, flags, allocator) } {
        Ok(flush) => {
            flush.flush();
        }
        Err(e) => {
            allocator.free_frame(frame); // free frame we failed to map
            return Err(e.into());
        }
    }
    Ok(frame)

}

pub unsafe fn unmap_and_free_pages(page_table: &mut OffsetPageTable, pages: Vec<Page<Size4KiB>>) -> Result<(), OSError> {
    let mut allocator_lock = allocator::FRAME_ALLOCATOR.lock();
    let allocator = allocator_lock.as_mut()
        .expect("Frame allocator not initialized");

    let mut first_error = None;

    for page in pages {
        match page_table.unmap(page) {
            Ok((frame, flush)) => {
                flush.flush();
                allocator.free_frame(frame);
            }
            Err(e) => {
                serial_println!("Failed to unmap page {:?}: {:?}", page, e);
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    match first_error {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

pub fn unmap_pages_by_table_addr(page_table_addr: PhysAddr, pages: Vec<Page<Size4KiB>>)-> Result<(), OSError> {
    let mut page_table = unsafe { page_table_from_addr(page_table_addr) };
    unsafe { unmap_and_free_pages(&mut page_table, pages) }
}

// map and allocate a contiguous range
pub unsafe fn alloc_and_map_range(
    page_table: &mut OffsetPageTable,
    start_addr: VirtAddr,
    num_pages: usize,
    flags: PageTableFlags,
) -> Result<Vec<PhysFrame<Size4KiB>>, OSError> {
    let pages = (0..num_pages).map(|i| {
        let addr = start_addr + (i * 4096) as u64;
        Page::<Size4KiB>::containing_address(addr)
    });

    unsafe { map_pages_alloc(page_table, pages, flags) }
}

/// Global page fault statistics
pub struct PageFaultStats {
    // Total counts
    total_faults: AtomicU64,
    demand_paged: AtomicU64,

    // By type
    null_pointer_faults: AtomicU64,
    guard_page_faults: AtomicU64,
    permission_faults: AtomicU64,
    invalid_address_faults: AtomicU64,

    // By access type
    read_faults: AtomicU64,
    write_faults: AtomicU64,
    exec_faults: AtomicU64,

    // By mode
    user_faults: AtomicU64,
    kernel_faults: AtomicU64,

    // By region
    heap_faults: AtomicU64,
    stack_faults: AtomicU64,
    text_faults: AtomicU64,
    data_faults: AtomicU64,
    rodata_faults: AtomicU64,
}

impl PageFaultStats {
    pub const fn new() -> Self {
        Self {
            total_faults: AtomicU64::new(0),
            demand_paged: AtomicU64::new(0),
            null_pointer_faults: AtomicU64::new(0),
            guard_page_faults: AtomicU64::new(0),
            permission_faults: AtomicU64::new(0),
            invalid_address_faults: AtomicU64::new(0),
            read_faults: AtomicU64::new(0),
            write_faults: AtomicU64::new(0),
            exec_faults: AtomicU64::new(0),
            user_faults: AtomicU64::new(0),
            kernel_faults: AtomicU64::new(0),
            heap_faults: AtomicU64::new(0),
            stack_faults: AtomicU64::new(0),
            text_faults: AtomicU64::new(0),
            data_faults: AtomicU64::new(0),
            rodata_faults: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_fault(&self) {
        self.total_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_demand_page(&self) {
        self.demand_paged.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_null_pointer(&self) {
        self.null_pointer_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_guard_page(&self) {
        self.guard_page_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_permission_fault(&self) {
        self.permission_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_invalid_address(&self) {
        self.invalid_address_faults.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_access_type(&self, write: bool, exec: bool) {
        if exec {
            self.exec_faults.fetch_add(1, Ordering::Relaxed);
        } else if write {
            self.write_faults.fetch_add(1, Ordering::Relaxed);
        } else {
            self.read_faults.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn record_mode(&self, user: bool) {
        if user {
            self.user_faults.fetch_add(1, Ordering::Relaxed);
        } else {
            self.kernel_faults.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn record_region(&self, vm_type: crate::proc::virtual_memory::VmType) {
        use crate::proc::virtual_memory::VmType;
        match vm_type {
            VmType::Heap => self.heap_faults.fetch_add(1, Ordering::Relaxed),
            VmType::Stack => self.stack_faults.fetch_add(1, Ordering::Relaxed),
            VmType::Text => self.text_faults.fetch_add(1, Ordering::Relaxed),
            VmType::Data => self.data_faults.fetch_add(1, Ordering::Relaxed),
            VmType::ROData => self.rodata_faults.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Print statistics in a formatted way
    pub fn print(&self) {
        serial_println!("\n=== PAGE FAULT STATISTICS ===");
        serial_println!("Total faults:        {}", self.total_faults.load(Ordering::Relaxed));
        serial_println!("Successfully paged:  {}", self.demand_paged.load(Ordering::Relaxed));
        serial_println!();

        serial_println!("Fault Types:");
        serial_println!("  Null pointer:      {}", self.null_pointer_faults.load(Ordering::Relaxed));
        serial_println!("  Guard page:        {}", self.guard_page_faults.load(Ordering::Relaxed));
        serial_println!("  Permission:        {}", self.permission_faults.load(Ordering::Relaxed));
        serial_println!("  Invalid address:   {}", self.invalid_address_faults.load(Ordering::Relaxed));
        serial_println!();

        serial_println!("Access Types:");
        serial_println!("  Read:              {}", self.read_faults.load(Ordering::Relaxed));
        serial_println!("  Write:             {}", self.write_faults.load(Ordering::Relaxed));
        serial_println!("  Execute:           {}", self.exec_faults.load(Ordering::Relaxed));
        serial_println!();

        serial_println!("By Mode:");
        serial_println!("  User:              {}", self.user_faults.load(Ordering::Relaxed));
        serial_println!("  Kernel:            {}", self.kernel_faults.load(Ordering::Relaxed));
        serial_println!();

        serial_println!("By Region:");
        serial_println!("  Heap:              {}", self.heap_faults.load(Ordering::Relaxed));
        serial_println!("  Stack:             {}", self.stack_faults.load(Ordering::Relaxed));
        serial_println!("  Text:              {}", self.text_faults.load(Ordering::Relaxed));
        serial_println!("  Data:              {}", self.data_faults.load(Ordering::Relaxed));
        serial_println!("  RO Data:           {}", self.rodata_faults.load(Ordering::Relaxed));
        serial_println!("=============================\n");
    }

    /// Get a summary string (useful for inline printing)
    pub fn summary(&self) -> PageFaultSummary {
        PageFaultSummary {
            total: self.total_faults.load(Ordering::Relaxed),
            demand_paged: self.demand_paged.load(Ordering::Relaxed),
            failed: self.null_pointer_faults.load(Ordering::Relaxed)
                + self.guard_page_faults.load(Ordering::Relaxed)
                + self.permission_faults.load(Ordering::Relaxed)
                + self.invalid_address_faults.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.total_faults.store(0, Ordering::Relaxed);
        self.demand_paged.store(0, Ordering::Relaxed);
        self.null_pointer_faults.store(0, Ordering::Relaxed);
        self.guard_page_faults.store(0, Ordering::Relaxed);
        self.permission_faults.store(0, Ordering::Relaxed);
        self.invalid_address_faults.store(0, Ordering::Relaxed);
        self.read_faults.store(0, Ordering::Relaxed);
        self.write_faults.store(0, Ordering::Relaxed);
        self.exec_faults.store(0, Ordering::Relaxed);
        self.user_faults.store(0, Ordering::Relaxed);
        self.kernel_faults.store(0, Ordering::Relaxed);
        self.heap_faults.store(0, Ordering::Relaxed);
        self.stack_faults.store(0, Ordering::Relaxed);
        self.text_faults.store(0, Ordering::Relaxed);
        self.data_faults.store(0, Ordering::Relaxed);
        self.rodata_faults.store(0, Ordering::Relaxed);
    }
}

/// Compact summary for inline display
pub struct PageFaultSummary {
    pub total: u64,
    pub demand_paged: u64,
    pub failed: u64,
}

impl core::fmt::Display for PageFaultSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PF: {} total ({} paged, {} failed)",
            self.total, self.demand_paged, self.failed
        )
    }
}

/// Global statistics instance
pub static PAGE_FAULT_STATS: PageFaultStats = PageFaultStats::new();

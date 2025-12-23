use crate::constants::magic::PAGE_SIZE;
use crate::errors::Component::KernelStack as KernelStackComponent;
use crate::errors::OSError::OutOfMemory;
use crate::errors::{Component, OSError};
use crate::memory::allocator::BitMap;
use crate::memory::{allocator, page};
use crate::serial_println;
use alloc::vec::Vec;
use core::ops::Add;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{Mapper, Page, PageTable, PageTableFlags, Size4KiB, Translate};
use x86_64::{PhysAddr, VirtAddr};

use user_layout::*;
use crate::memory::page::{page_table_from_addr, phys_offset};

/// Memory layout & Visualization


pub const KERNEL_HEAP_START: usize = 0x_4444_4444_0000;
pub const KERNEL_HEAP_SIZE: usize = 200 * 1024; // 100 kb

pub mod user_layout {
    // Guard page size
    pub const GUARD_PAGE_SIZE: u64 = 0x1000; // 4KB
    pub const STACK_GUARD_SIZE: u64 = 0x1000;
    pub const HEAP_GUARD_SIZE: u64 = 0x1000;

    // ========================================================================
    // NULL POINTER PROTECTION ZONE
    // ========================================================================
    pub const NULL_GUARD_START: u64 = 0x0000_0000_0000_0000;
    pub const NULL_GUARD_SIZE: u64 = 0x0001_0000; // 64KB
    pub const NULL_GUARD_END: u64 = NULL_GUARD_START + NULL_GUARD_SIZE;

    // ========================================================================
    // TEXT SEGMENT (matches standard Linux ELF base)
    // ========================================================================
    pub const USER_TEXT_BASE: u64 = 0x0000_0000_0040_0000;  // 4MB (standard)
    pub const USER_TEXT_MAX_SIZE: u64 = 0x0020_0000;        // 32MB
    pub const USER_TEXT_END: u64 = USER_TEXT_BASE + USER_TEXT_MAX_SIZE;

    // Guard after text
    pub const TEXT_GUARD_START: u64 = USER_TEXT_END;
    pub const TEXT_GUARD_END: u64 = TEXT_GUARD_START + GUARD_PAGE_SIZE;

    // ========================================================================
    // RODATA SEGMENT (immediately after text, Linux-style)
    // ========================================================================
    pub const USER_RODATA_BASE: u64 = TEXT_GUARD_END;
    pub const USER_RODATA_MAX_SIZE: u64 = 0x0010_0000;      // 16MB
    pub const USER_RODATA_END: u64 = USER_RODATA_BASE + USER_RODATA_MAX_SIZE;

    // Guard after rodata
    pub const RODATA_GUARD_START: u64 = USER_RODATA_END;
    pub const RODATA_GUARD_END: u64 = RODATA_GUARD_START + GUARD_PAGE_SIZE;

    // ========================================================================
    // DATA + BSS SEGMENT (contiguous with rodata, Linux-style)
    // ========================================================================
    pub const USER_DATA_BASE: u64 = RODATA_GUARD_END;
    pub const USER_DATA_MAX_SIZE: u64 = 0x0010_0000;        // 16MB
    pub const USER_DATA_END: u64 = USER_DATA_BASE + USER_DATA_MAX_SIZE;

    // Guard after data/bss (before heap)
    pub const DATA_GUARD_START: u64 = USER_DATA_END;
    pub const DATA_GUARD_END: u64 = DATA_GUARD_START + GUARD_PAGE_SIZE;

    // ========================================================================
    // HEAP SEGMENT (starts right after data, grows up with brk/sbrk)
    // ========================================================================
    pub const USER_HEAP_BASE: u64 = DATA_GUARD_END;
    pub const USER_HEAP_INITIAL_SIZE: u64 = 0x0020_0000;    // 2MB initial
    pub const USER_HEAP_MAX_SIZE: u64 = 0x4000_0000;        // 1GB max
    pub const USER_HEAP_LIMIT: u64 = USER_HEAP_BASE + USER_HEAP_MAX_SIZE;

    // Large guard zone after heap
    pub const HEAP_GUARD_START: u64 = USER_HEAP_LIMIT;
    pub const HEAP_GUARD_SIZE_LARGE: u64 = 0x1000_0000;     // 256MB gap
    pub const HEAP_GUARD_END: u64 = HEAP_GUARD_START + HEAP_GUARD_SIZE_LARGE;

    // ========================================================================
    // MMAP REGION (anonymous mmap, shared libs, etc.)
    // This is where mmap() allocations go, grows downward toward heap
    // ========================================================================
    pub const USER_MMAP_END: u64 = 0x0000_7000_0000_0000;   // ~112TB
    pub const USER_MMAP_SIZE: u64 = 0x0000_1000_0000_0000;  // ~16TB size
    pub const USER_MMAP_BASE: u64 = USER_MMAP_END - USER_MMAP_SIZE;

    // ========================================================================
    // STACK SEGMENT (grows downward from high address, matches Linux)
    // ========================================================================
    pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;  // Matches Linux
    pub const USER_STACK_RESERVED: u64 = 0x0080_0000;       // 8MB max
    pub const USER_STACK_INITIAL: u64 = 0x0020_0000;        // 2MB initial

    pub const fn user_stack_start() -> u64 {
        USER_STACK_TOP - USER_STACK_RESERVED
    }

    pub const fn user_stack_initial_start() -> u64 {
        USER_STACK_TOP - USER_STACK_INITIAL
    }

    // Guard page BELOW stack (critical!)
    pub const fn stack_guard_start() -> u64 {
        user_stack_start() - STACK_GUARD_SIZE
    }

    pub const fn stack_guard_end() -> u64 {
        user_stack_start()
    }

    // ========================================================================
    // LAYOUT SUMMARY (not including 0x1000 sized guard pages)
    // ========================================================================
    // 0x0000_0000_0000_0000 - NULL guard
    // 0x0000_0000_0040_0000 - .text (code)
    // 0x0000_0000_0060_0000 - .rodata (read-only data)
    // 0x0000_0000_0070_0000 - .data + .bss (writable data)
    // 0x0000_0000_0080_0000 - heap (brk/sbrk, grows up)
    // 0x0000_0000_4080_0000 - [large gap]
    // 0x0000_6000_0000_0000 - mmap region (grows down)
    // 0x0000_7000_0000_0000 - [gap]
    // 0x0000_7FFF_FF80_0000 - stack (grows down)
    // 0x0000_7FFF_FFFF_F000 - stack top

    // Validation helpers
    pub const fn is_in_null_guard(addr: u64) -> bool {
        addr >= NULL_GUARD_START && addr < NULL_GUARD_END
    }

    pub const fn is_in_stack_guard(addr: u64) -> bool {
        addr >= stack_guard_start() && addr < stack_guard_end()
    }

    pub const fn is_in_text(addr: u64) -> bool {
        addr >= USER_TEXT_BASE && addr < USER_TEXT_END
    }

    pub const fn is_in_heap(addr: u64) -> bool {
        addr >= USER_HEAP_BASE && addr < USER_HEAP_LIMIT
    }

    pub const fn is_in_stack(addr: u64) -> bool {
        addr >= user_stack_start() && addr < USER_STACK_TOP
    }

    pub const fn is_in_mmap(addr: u64) -> bool {
        addr >= USER_MMAP_BASE && addr < USER_MMAP_END
    }
}

// so I dont forget....
/*
Virtual Address Space (128TB user space):

0x0000_0000_0000_0000 ┌─────────────────┐
                       │  NULL guard     │ 64KB
0x0000_0000_0001_0000 ├─────────────────┤
                       │  [unmapped]     │
0x0000_0000_0040_0000 ├─────────────────┤
                       │  .text          │ 32MB (executable code)
0x0000_0000_0060_0000 ├─────────────────┤
                       │  .rodata        │ 16MB (read-only data)
0x0000_0000_0070_0000 ├─────────────────┤
                       │  .data + .bss   │ 16MB (writable data)
0x0000_0000_0080_0000 ├─────────────────┤
                       │  heap ↓         │ grows up with brk()
                       │                 │ max 1GB
0x0000_0000_4080_0000 ├─────────────────┤
                       │  [large gap]    │ ~96TB
                       │                 │
0x0000_6000_0000_0000 ├─────────────────┤
                       │  mmap ↑         │ grows down
                       │  (libs, anon)   │ ~16TB space
0x0000_7000_0000_0000 ├─────────────────┤
                       │  [gap]          │ ~16TB
0x0000_7FFF_FF80_0000 ├─────────────────┤
                       │  stack ↑        │ grows down
                       │                 │ max 8MB
0x0000_7FFF_FFFF_F000 └─────────────────┘

0xFFFF_8000_0000_0000 ┌─────────────────┐
                       │  Kernel space   │
0xFFFF_FFFF_FFFF_FFFF └─────────────────┘


Virtual Address Space Layout:
0x0000_0000_0000_0000 ─┐
                       │  User space
0x0000_7FFF_FFFF_FFFF ─┤  (PML4 entries 0-255)
                       │
[Non-canonical hole]   │
                       │
0xFFFF_8000_0000_0000 ─┤
                       │  Kernel space
0xFFFF_FFFF_FFFF_FFFF ─┘  (PML4 entries 256-511)

0x0000_0000_0000_0000: User space start
  - 0x0000_0000_0040_0000: User code (.text)
  - 0x0000_0000_0060_0000: User data (.data, .bss)
  - 0x0000_0000_0080_0000: User heap (grows up)
  - 0x0000_7FFF_FFFF_F000: User stack (grows down)

0xFFFF_8000_0000_0000: Kernel space start
  - Kernel code/data (identity mapped or at fixed offset)

0xFFFF_8880_0000_0000: Physical memory direct map
  - All physical RAM mapped here (physical_memory_offset)
  - Makes it easy to access any physical address

0xFFFF_A000_0000_0000: Kernel stacks

0xFFFF_C000_0000_0000: vmalloc region (kernel dynamic allocations)

0xFFFF_FF00_0000_0000: MMIO mappings (hardware devices)

KERNEL PAGE TABLE (master template)
════════════════════════════════════
PML4[0-255]:   (empty - no user space in kernel)
PML4[256]:     -> Kernel code pages
PML4[257]:     -> Physical memory map
PML4[320]:     -> Kernel stacks region
PML4[511]:     -> MMIO

PROCESS 1 PAGE TABLE
════════════════════════════════════
PML4[0-255]:   -> Process 1's user pages (unique)
PML4[256]:     -> Kernel code pages (COPIED pointer)
PML4[257]:     -> Physical memory map (COPIED pointer)
PML4[320]:     -> Kernel stacks region (COPIED pointer)
PML4[511]:     -> MMIO (COPIED pointer)

PROCESS 2 PAGE TABLE
════════════════════════════════════
PML4[0-255]:   -> Process 2's user pages (unique)
PML4[256]:     -> Kernel code pages (SAME pointer as P1)
PML4[257]:     -> Physical memory map (SAME pointer as P1)
PML4[320]:     -> Kernel stacks region (SAME pointer as P1)
PML4[511]:     -> MMIO (SAME pointer as P1)


*/

/// Kernel Stack Management

pub(crate) struct KernelStack {
    start: VirtAddr,
    size: usize,
    // to make it easier to free later just give this stack the returned bit id from the bitmap
    // later just clear that bit instead of relying on calculating it which is easier to go wrong
    id: usize,
}

pub(crate) struct KernelStackManager {
    stack_region: VirtAddr,
    free_stacks: BitMap,
}

const KERNEL_STACK_BASE: u64 = 0xFFFF_A000_0000_0000;
// kernel stack in multiples of pages, alignment and other problems are easier to not worry about
// if we just allocate integer number of pages
pub const KERNEL_STACK_SIZE_PAGES: usize = 3;
const KERNEL_STACK_GUARD_PAGES: usize = 1; // 4KB guard

// total space per stack = stack pages + guard pages
pub const KERNEL_STACK_TOTAL_PAGES: usize = KERNEL_STACK_SIZE_PAGES + KERNEL_STACK_GUARD_PAGES;
// 128 total processes for now
static mut FREE_STACKS_STORAGE: [u64; 16] = [0; 16];

impl KernelStackManager {
    pub unsafe fn new() -> Self {
        let bitmap_storage = unsafe {
            &mut *addr_of_mut!(FREE_STACKS_STORAGE)
        };
        let free_stacks = unsafe {
            let len = bitmap_storage.len();
            BitMap::new(bitmap_storage, len)
        };
        Self {
            stack_region: VirtAddr::new(KERNEL_STACK_BASE),
            free_stacks,
        }
    }
    pub fn init_global() {
        let ksm = unsafe {
            KernelStackManager::new()
        };
        *KERNEL_STACK_MANAGER.lock() = Some(ksm);
    }
    pub fn alloc_stack(&mut self, page_table_addr: PhysAddr) -> Option<KernelStack> {
        let Some(stack_index) = self.free_stacks.find_and_set_first_free() else {
            return None
        };
        let stack_base: u64 = KERNEL_STACK_BASE + ((stack_index * KERNEL_STACK_TOTAL_PAGES * PAGE_SIZE) as u64);

        // stack starts after guard page
        let guard_start = VirtAddr::new(stack_base);
        let guard_end = guard_start + (KERNEL_STACK_GUARD_PAGES * PAGE_SIZE) as u64;

        let stack_start = guard_end;

        // now map the kernel stacks pages into the kernels page table that every process shares
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

        let mut page_table = unsafe { page_table_from_addr(page_table_addr) };

        let pages = (0..KERNEL_STACK_SIZE_PAGES).map(|i| {
            let addr = stack_start + (i * PAGE_SIZE) as u64;
            Page::<Size4KiB>::containing_address(addr)
        });

        match unsafe { page::map_pages_alloc(&mut page_table, pages, flags) } {
            Ok(_frames) => {
                // successfully mapped all pages
                Some(KernelStack::new(
                    stack_start,
                    KERNEL_STACK_SIZE_PAGES * PAGE_SIZE,
                    stack_index,
                ))
            }
            Err(e) => {
                // cleanup is handled by map_pages_alloc
                serial_println!("Failed to allocate kernel stack: {:?}", e);
                self.free_stacks.clear(stack_index);
                None
            }
        }
    }
    pub fn free_stack(&mut self, stack: KernelStack, page_table_addr: PhysAddr) {
        // collect pages to unmap
        // undoing same page building logic from alloc stack
        let pages: Vec<Page<Size4KiB>> = (0..KERNEL_STACK_SIZE_PAGES)
            .map(|i| {
                let addr = stack.start + (i * PAGE_SIZE) as u64;
                Page::<Size4KiB>::containing_address(addr)
            })
            .collect();

        // unmap and free
        if let Err(e) = page::unmap_pages_by_table_addr(page_table_addr, pages) {
            serial_println!("Error freeing kernel stack: {:?}", e);
        }

        // mark stack slot as free
        self.free_stacks.clear(stack.id);
    }
    pub fn clear_stack(&mut self, stack: KernelStack) {
        self.free_stacks.clear(stack.id)
        // implicitly drops stack resource via consumption of owned struct
        // all this really does is clear the stack bit to allow for a new stack
        // page/frame resource cleanup is handled in the page module/abstraction
    }
}

pub static KERNEL_STACK_MANAGER: Mutex<Option<KernelStackManager>> = Mutex::new(None);

impl KernelStack {
    pub const fn new(start: VirtAddr, size: usize, bit_id: usize) -> Self {
        Self {
            start,
            size,
            id: bit_id,
        }
    }
    pub fn top(&self) -> VirtAddr {
        // Stack grows downward, so "top" is the highest valid address
        // which is start + size - 1, but we typically use start + size
        // and subtract when we use it
        self.start + (self.size as u64)
    }
}

/// Per Process Virtual Memory Management

/*
    need to keep track of the specific regions of virtual address space each process is using and
    for what purpose/other info about them as its critical to validate various memory operations
    during process runtime
 */
pub(crate) struct VirtualMemory {
    // eventually stacks will get moved to a thread abstraction and each process will start with a
    // single running thread representing its fundamental execution abstraction
    pub(crate) kernel_stack: KernelStack,
    pub(crate) page_table_addr: PhysAddr,
    ref_count: AtomicUsize,
    vm_areas: Vec<VmArea>,

    // program break for heap management (sbrk/brk syscalls)
    // points to the end of the heap region
    program_break: AtomicU64,
}

// represents a contiguous region of virtual memory
#[derive(Debug, Clone)]
pub(crate) struct VmArea {
    // start virtual address (inclusive)
    start: VirtAddr,

    // end virtual address (exclusive)
    end: VirtAddr,

    // protection flags (read, write, execute, user-accessible)
    pub(crate) flags: VmFlags,

    // what backs this memory region
    backing: VmBacking,

    // what kind of vm area this is, useful for debugging/error handling
    vm_type: VmType
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    Text,
    ROData,
    Data,
    Heap,
    Stack,
    Mmap,
    Guard,  // guard pages
    KernelStack,
}

impl core::fmt::Display for VmType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VmType::Text => write!(f, "TEXT"),
            VmType::ROData => write!(f, "RODATA"),
            VmType::Data => write!(f, "DATA"),
            VmType::Heap => write!(f, "HEAP"),
            VmType::Stack => write!(f, "STACK"),
            VmType::Mmap => write!(f, "MMAP"),
            VmType::Guard => write!(f, "GUARD"),
            VmType::KernelStack => write!(f, "KSTACK"),
        }
    }
}

bitflags::bitflags! {
    #[derive(Clone, Debug)]
    pub struct VmFlags: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
        const USER = 1 << 3;
    }
}

#[derive(Debug, Clone)]
pub enum VmBacking {
    // anonymous memory (heap, stack)
    Anonymous,

    // memory-mapped file (for mmap)
    // File { file_id: FileId, offset: u64 },

    // shared memory
    // Shared { shm_id: ShmId },

    // device memory (framebuffer, etc.)
    // Device { device_id: DeviceId },
}

impl VmArea {
    fn new(start: VirtAddr, end: VirtAddr, flags: VmFlags, backing: VmBacking, vm_type: VmType) -> Self {
        Self {
            start,
            end,
            flags,
            backing,
            vm_type,
        }
    }
    pub fn new_guard(start: VirtAddr, end: VirtAddr) -> Self {
        Self {
            start,
            end,
            flags: VmFlags::empty(),  // no permissions
            backing: VmBacking::Anonymous,
            vm_type: VmType::Guard,
        }
    }
    pub(crate) fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }
    pub(crate) fn overlaps(&self, other: &VmArea) -> bool {
        !(self.end <= other.start || self.start >= other.end)
    }
    pub fn is_guard(&self) -> bool {
        self.vm_type == VmType::Guard
    }
    pub fn vm_type(&self) -> VmType {
        self.vm_type
    }
}

impl VirtualMemory {
    pub(crate) fn new() -> Result<Self, OSError> {
        let (kernel_stack, page_table_addr) = Self::setup_process_address_space()?;
        let mut virtual_memory = Self {
            kernel_stack,
            page_table_addr,
            ref_count: AtomicUsize::new(1),
            vm_areas: Vec::new(),
            program_break: AtomicU64::new(0),
        };
        virtual_memory.setup_user_space()?;
        Ok(virtual_memory)
    }
    // unmap virtual address range from associated page table
    fn unmap_range(&self, start: VirtAddr, end: VirtAddr) -> Result<(), OSError> {
        let start_page = Page::<Size4KiB>::containing_address(start);
        let end_page = Page::<Size4KiB>::containing_address(end - 1u64);
        let pages: Vec<_> = Page::range_inclusive(start_page, end_page).collect();

        page::unmap_pages_by_table_addr(self.page_table_addr, pages)
    }
    /// VMA Management
    pub fn add_vma(&mut self, vma: VmArea) -> Result<(), OSError> {
        // Check for overlaps with existing VMAs
        for existing in &self.vm_areas {
            if vma.overlaps(existing) {
                return Err(OSError::InvalidMemoryRegion);
            }
        }

        self.vm_areas.push(vma);
        Ok(())
    }
    fn map_vma(&self, vma: &VmArea) -> Result<(), OSError> {
        let mut page_table = unsafe { page::page_table_from_addr(self.page_table_addr) };

        // Convert VmFlags to PageTableFlags
        let mut flags = PageTableFlags::PRESENT;
        if vma.flags.contains(VmFlags::WRITE) {
            flags |= PageTableFlags::WRITABLE;
        }
        if vma.flags.contains(VmFlags::USER) {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }
        if !vma.flags.contains(VmFlags::EXEC) {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let pages = {
            let start_page = Page::<Size4KiB>::containing_address(vma.start);
            let end_page = Page::<Size4KiB>::containing_address(vma.end - 1u64);
            Page::range_inclusive(start_page, end_page)
        };

        unsafe { page::map_pages_alloc(&mut page_table, pages, flags) }?;
        Ok(())
    }

    // check if an address is in a valid VMA
    pub fn find_vma(&self, addr: VirtAddr) -> Option<&VmArea> {
        self.vm_areas.iter()
            .find(|vma| vma.contains(addr))
    }

    // remove a VMA and unmap its pages
    pub fn remove_vma(&mut self, start: VirtAddr) -> Result<(), OSError> {
        // Find and remove the VMA
        let idx = self.vm_areas.iter()
            .position(|vma| vma.start == start)
            .ok_or(OSError::InvalidVirtualAddress(start))?;

        let vma = self.vm_areas.remove(idx);

        // unmap all pages in this range
        self.unmap_range(vma.start, vma.end)?;

        Ok(())
    }
    /// initialize a processes user space
    pub(crate) fn setup_user_space(&mut self) -> Result<(), OSError> {

        // protect against null pointers
        let null_guard = VmArea::new_guard(
            VirtAddr::new(NULL_GUARD_START),
            VirtAddr::new(NULL_GUARD_END),
        );
        self.add_vma(null_guard)?;

        // text segment
        // start unmapped and map it during ELF loading
        let text_vma = VmArea::new(
            VirtAddr::new(USER_TEXT_BASE),
            VirtAddr::new(USER_TEXT_END),
            VmFlags::READ | VmFlags::EXEC | VmFlags::USER,
            VmBacking::Anonymous,
            VmType::Text,
        );
        self.add_vma(text_vma)?;

        let text_guard = VmArea::new_guard(
            VirtAddr::new(TEXT_GUARD_START),
            VirtAddr::new(TEXT_GUARD_END),
        );
        self.add_vma(text_guard)?;

        // ro data segment
        let rodata_vma = VmArea::new(
            VirtAddr::new(USER_RODATA_BASE),
            VirtAddr::new(USER_RODATA_END),
            VmFlags::READ | VmFlags::USER,
            VmBacking::Anonymous,
            VmType::ROData,
        );
        self.add_vma(rodata_vma)?;

        let rodata_guard = VmArea::new_guard(
            VirtAddr::new(RODATA_GUARD_START),
            VirtAddr::new(RODATA_GUARD_END),
        );
        self.add_vma(rodata_guard)?;

        // data segment
        let data_vma = VmArea::new(
            VirtAddr::new(USER_DATA_BASE),
            VirtAddr::new(USER_DATA_END),
            VmFlags::READ | VmFlags::WRITE | VmFlags::USER,
            VmBacking::Anonymous,
            VmType::Data,
        );
        self.add_vma(data_vma)?;

        // the data guard page goes right before the heap as they are contiguous (minus the guard)
        let data_guard = VmArea::new_guard(
            VirtAddr::new(DATA_GUARD_START),
            VirtAddr::new(DATA_GUARD_END),
        );
        self.add_vma(data_guard)?;

        let heap_vma = VmArea::new(
            VirtAddr::new(USER_HEAP_BASE),
            VirtAddr::new(USER_HEAP_LIMIT),
            VmFlags::READ | VmFlags::WRITE | VmFlags::USER,
            VmBacking::Anonymous,
            VmType::Heap,
        );
        self.add_vma(heap_vma)?;

        // map initial heap pages
        // just the first few as the average process will use at least a little heap minimum
        let initial_heap_pages = {
            let start = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_HEAP_BASE));
            let end = Page::<Size4KiB>::containing_address(
                VirtAddr::new(USER_HEAP_BASE + USER_HEAP_INITIAL_SIZE - 1)
            );
            Page::range_inclusive(start, end)
        };

        let heap_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;

        let mut page_table = unsafe { page::page_table_from_addr(self.page_table_addr) };
        unsafe { page::map_pages_alloc(&mut page_table, initial_heap_pages, heap_flags) }?;

        self.program_break.store(
            USER_HEAP_BASE + USER_HEAP_INITIAL_SIZE,
            Ordering::SeqCst
        );

        // heap guard zone (large unmapped area)
        let heap_guard = VmArea::new_guard(
            VirtAddr::new(HEAP_GUARD_START),
            VirtAddr::new(HEAP_GUARD_END),
        );
        self.add_vma(heap_guard)?;

        // the heap and stack grow towards each other so this guard is the most important
        // while it is less risky for the others this is a much more common situation
        let stack_guard = VmArea::new_guard(
            VirtAddr::new(stack_guard_start()),
            VirtAddr::new(stack_guard_end()),
        );
        self.add_vma(stack_guard)?;

        // add the stack and like the heap map a small initial portion of it
        let stack_vma = VmArea::new(
            VirtAddr::new(user_stack_start()),
            VirtAddr::new(USER_STACK_TOP),
            VmFlags::READ | VmFlags::WRITE | VmFlags::USER,
            VmBacking::Anonymous,
            VmType::Stack,
        );
        self.add_vma(stack_vma)?;

        // Map initial stack pages (top portion only)
        let initial_stack_pages = {
            let start = Page::<Size4KiB>::containing_address(
                VirtAddr::new(user_stack_initial_start())
            );
            let end = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_TOP - 1));
            Page::range_inclusive(start, end)
        };

        let stack_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;

        unsafe { page::map_pages_alloc(&mut page_table, initial_stack_pages, stack_flags) }?;

        Ok(())
    }
    pub fn setup_process_address_space() -> Result<(KernelStack, PhysAddr), OSError> {
        let physical_memory_offset = phys_offset();
        // first set up the page table for this process as all initial virtual mem needs this as its backing
        let mut allocator_lock = allocator::FRAME_ALLOCATOR.lock();
        let allocator = allocator_lock.as_mut().expect("Allocator not initialized");

        let Some(pml4_frame) = allocator.alloc_frame() else {
            return Err(OutOfMemory(Component::FrameAllocator));
        };

        // later in the call flow and within this context the allocator will be used to alloc pages for the kernel stack
        // for now drop it explicitly but later refactor so implicit drops work
        // TODO: refactor to remove this drop/use the lock better
        drop(allocator_lock);

        let phys_addr = pml4_frame.start_address();
        let virt_addr = physical_memory_offset + phys_addr.as_u64();

        // cast the virtual address to a PageTable reference
        // this is safe to do as there is no hidden state and the struct is repr C
        let page_table: &mut PageTable = unsafe {
            &mut *(virt_addr.as_mut_ptr::<PageTable>())
        };

        // zero it out
        page_table.zero();

        // read the kernel page table out from memory
        let kernel_page_table_addr = unsafe { page::current_page_table_addr() }; // current table during process setup is kernel
        let kernel_page_table = unsafe { page::page_table_from_addr(kernel_page_table_addr) };
        let mut process_page_table = unsafe { page::page_table_from_addr(phys_addr) };


        // now pass the page table addr into the kernel stack manager so it can allocate and map this processes kernel stack
        let mut kernel_stack_manager_lock = KERNEL_STACK_MANAGER.lock();
        let kernel_stack_manager = kernel_stack_manager_lock.as_mut().expect("Kernel stack manager not initialized");
        let kernel_stack = kernel_stack_manager.alloc_stack(kernel_page_table_addr).ok_or(OutOfMemory(KernelStackComponent))?;

        // now copy over the kernel pages into the processes kernel space
        // since the kernel stack is mapped to the kernels page table before the copy happens
        // the process gets the kernel stack as part of its table still
        let kernel_pml4 = kernel_page_table.level_4_table();
        let mut process_pml4 = process_page_table.level_4_table_mut();
        for i in 256..512 {
            if !kernel_pml4[i].is_unused() {
                process_pml4[i] = kernel_pml4[i].clone();
            }
        }

        // just copy the whole lower half (kernel low mapped by bootloader)
        for i in 0..256 {
            if !kernel_pml4[i].is_unused() {
                process_pml4[i] = kernel_pml4[i].clone();
            }
        }

        // previous attempts at making sure the right parts of the kernel are mapped for the process to be able to access import things
        // this is all TERRIBLE and was an incredibly TEMPORARY DEBUG attempt at just seeing if I could get to my syscall entry code

        // // copy the PML4 entry for the kernel heap
        // let kernel_heap_addr = 0x4444_4444_0000u64;
        // let kernel_heap_pml4_index = ((kernel_heap_addr >> 39) & 0x1FF) as usize;
        // if !kernel_pml4[kernel_heap_pml4_index].is_unused() {
        //     process_pml4[kernel_heap_pml4_index] = kernel_pml4[kernel_heap_pml4_index].clone();
        // }
        //
        // const KERNEL_STACK_BASE: u64 = 0xFFFF_A000_0000_0000;
        // let kernel_stack_pml4_index = ((KERNEL_STACK_BASE >> 39) & 0x1FF) as usize;
        // if !kernel_pml4[kernel_stack_pml4_index].is_unused() {
        //     process_pml4[kernel_stack_pml4_index] = kernel_pml4[kernel_stack_pml4_index].clone();
        // }

        serial_println!("\n=== PAGE TABLE COPY VERIFICATION ===");

        // check the syscall handler's PML4 entry specifically
        let syscall_handler_addr = unsafe {
            crate::syscalls::management::syscall_entry as *const () as u64
        };
        let syscall_pml4_idx = ((syscall_handler_addr >> 39) & 0x1FF) as usize;

        serial_println!("Syscall handler address: {:#x}", syscall_handler_addr);
        serial_println!("Syscall handler PML4 index: {}", syscall_pml4_idx);

        if !kernel_pml4[syscall_pml4_idx].is_unused() {
            serial_println!("Kernel PML4[{}]: mapped ✓", syscall_pml4_idx);
            serial_println!("Process PML4[{}]: {}",
            syscall_pml4_idx,
            if process_pml4[syscall_pml4_idx].is_unused() { "UNMAPPED ✗" } else { "mapped ✓" }
        );
        } else {
            serial_println!("WARNING: Kernel PML4[{}] is UNUSED!", syscall_pml4_idx);
        }

        serial_println!("===================================\n");

        Ok((kernel_stack, phys_addr))
    }
    pub(crate) fn check_page_fault(
        &self,
        fault_addr: VirtAddr,
        was_write: bool,
        was_user: bool,
        was_instruction: bool,
    ) -> Result<(), OSError> {
        // find which VMA contains this address
        let Some(vma) = self.find_vma(fault_addr) else {
            return Err(OSError::InvalidVirtualAddress(fault_addr));
        };

        // GUARD PAGE CHECK - this is a fatal error
        if vma.is_guard() {
            return Err(OSError::GuardPageViolation(fault_addr, vma.vm_type()));
        }

        // check if it's a permission violation
        if was_write && !vma.flags.contains(VmFlags::WRITE) {
            return Err(OSError::WriteToReadOnly(fault_addr));
        }

        // if it contains an executable instruction getting fetched
        if was_instruction && !vma.flags.contains(VmFlags::EXEC) {
            return Err(OSError::PermissionDenied);
        }

        // check user/kernel mode mismatch
        if was_user && !vma.flags.contains(VmFlags::USER) {
            return Err(OSError::PermissionDenied);
        }

        Ok(())
    }
}

pub fn translate_user_addr(user_vaddr: u64, user_page_table_addr: PhysAddr) -> Result<*mut u8, OSError> {
    let page_table = unsafe { page_table_from_addr(user_page_table_addr) };
    let phys_addr = page_table.translate_addr(VirtAddr::new(user_vaddr))
    .ok_or(OSError::InvalidVirtualAddress(VirtAddr::new(user_vaddr)))?;

    // convert physical address to kernel-accessible virtual address
    let kernel_vaddr = phys_offset().as_u64() + phys_addr.as_u64();
    Ok(kernel_vaddr as *mut u8)
}


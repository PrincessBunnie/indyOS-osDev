use crate::serial_println;
use crate::utils::IrqSafeMutex;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{addr_of_mut, null_mut, write, write_bytes};
use bootloader_api::info::MemoryRegionKind;
use spin::mutex::Mutex;
use x86_64::structures::paging::{FrameAllocator as FrameAllocatorTrait, FrameDeallocator};
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

static mut BITMAP_STORAGE: [u64; 16384] = [0; 16384];

const FRAME_SIZE: usize = 4096;
const MAX_SUPPORTED_ALIGN: usize = 4096;

#[global_allocator]
pub static ALLOCATOR: LockedAllocator = LockedAllocator::new();
//pub static FRAME_ALLOCATOR: Mutex<Option<FrameAllocator>> = Mutex::new(None);
pub static FRAME_ALLOCATOR: IrqSafeMutex<Option<FrameAllocator>> = IrqSafeMutex::new(None);

// add a helper function for the interrupt handler to use
pub fn alloc_frame() -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.alloc_frame())
}

#[derive(Copy, Clone)]
struct MemoryRegion {
    pub(crate) region_start: PhysAddr,
    pub(crate) region_size: usize,
    pub(crate) num_frames: usize,
}

// exported helper function for memsetting memory to 0
pub fn zero_memory(start: VirtAddr, size: usize) {
    // I had to change the type of ptr from VirtAddr to u8 
    // gave me a pointer arith bug D:
    let ptr: *mut u8 = start.as_mut_ptr();
    unsafe {
        write_bytes(ptr, 0, size);
    }
}

pub struct FrameAllocator {
    allocatable_mem: &'static [MemoryRegion],
    frame_free_list: BitMap,
    total_frames: usize,
}

impl FrameAllocator {
    pub unsafe fn new(memory_map: &'static bootloader_api::info::MemoryRegions) -> Self {
        // find the maximum physical address to determine how many frames we need to track
        // this will be done by keeping track of the starting address of each usable range
        // allocate the right size array
        static mut MEMORY_REGIONS: [MemoryRegion; 16] =
            [MemoryRegion { region_start: PhysAddr::zero(), region_size: 0 , num_frames: 0}; 16];

        let regions = &mut *addr_of_mut!(MEMORY_REGIONS);

        // second pass: fill it
        let mut idx = 0;
        for region in memory_map.iter() {
            if region.kind == MemoryRegionKind::Usable && idx < regions.len() {
                // let region_size = (region.range.end_addr() - region.range.start_addr()) as usize;
                let start = region.start;
                let end = region.end;

                // align start UP to next frame boundary
                let aligned_start = (start + FRAME_SIZE as u64 - 1) & !(FRAME_SIZE as u64 - 1);

                // align end DOWN to frame boundary
                let aligned_end = end & !(FRAME_SIZE as u64 - 1);

                // skip if region is too small after alignment
                if aligned_end <= aligned_start {
                    continue;
                }

                let region_size = (aligned_end - aligned_start) as usize;
                regions[idx] = MemoryRegion {
                    region_start: PhysAddr::new(region.start),
                    region_size,
                    num_frames: region_size / FRAME_SIZE,
                };
                idx += 1;
            }
        }
        // calculate after performing alignment to account for changes in the number of available frames
        let total_frames: usize = regions[..idx].iter()
            .map(|r| r.num_frames)
            .sum();

        let required_words = (total_frames + 63) / 64; // round up division

        let bitmap_storage = &mut *addr_of_mut!(BITMAP_STORAGE);
        let bitmap_words = core::cmp::min(bitmap_storage.len(), required_words);
        let usable_frames = bitmap_words * 64;

        serial_println!("  Frame allocator tracking {} frames ({} KB of memory)",
                       usable_frames, usable_frames * 4);

        let mut frame_free_list = BitMap::new(bitmap_storage, usable_frames);

        Self {
            allocatable_mem: &regions[..idx], // Only the filled portion
            frame_free_list,
            total_frames,
        }
    }
    pub unsafe fn init_global(memory_map: &'static bootloader_api::info::MemoryRegions) {
        let allocator = Self::new(memory_map);
        *FRAME_ALLOCATOR.lock() = Some(allocator);
    }
    pub fn alloc_frame(&mut self) -> Option<PhysFrame> {
        // when using the bitmap we take the index * frame_zie + range_start => physical frame address
        // with multiple regions we index from region 0 -> region 1 logically sequentially
        let Some(mut frame_index) = self.frame_free_list.find_and_set_first_free() else {
            serial_println!("NO FRAMES LEFT!");
            return None;
        };
        // serial_println!("Frame allocator allocating frame: {}", frame_index);
        if frame_index >= self.total_frames {
            return None;
        }
        for region in self.allocatable_mem {
            if frame_index >= region.num_frames {
                frame_index -= region.num_frames;
                continue;
            }
            let addr: PhysAddr = PhysAddr::new((frame_index * FRAME_SIZE) as u64 + region.region_start.as_u64());
            return match PhysFrame::<Size4KiB>::from_start_address(addr) {
                Ok(frame) => Some(frame),
                Err(e) => {
                    serial_println!("Error when allocating frame: {:?}", e);
                    None
                }
            }
        }
        None
    }
    pub fn free_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let phys_addr = frame.start_address();
        
        let mut bitmap_index = 0;
        let mut found = false;

        for region in self.allocatable_mem {
            let region_start = region.region_start.as_u64();
            let region_end = region_start + region.region_size as u64;

            // check if this frame belongs to this region
            if phys_addr.as_u64() >= region_start && phys_addr.as_u64() < region_end {
                // calculate frame index within this region
                let offset_in_region = phys_addr.as_u64() - region_start;
                let frame_index_in_region = (offset_in_region / FRAME_SIZE as u64) as usize;

                bitmap_index += frame_index_in_region;
                found = true;
                break;
            }

            // this frame is not in this region, add all frames from this region
            // and continue to the next region
            bitmap_index += region.num_frames;
        }

        if !found {
            serial_println!("Warning: Attempted to free frame at {:?} which is not in any allocatable region", phys_addr);
            return;
        }

        if bitmap_index >= self.total_frames {
            serial_println!("Warning: Calculated bitmap index {} is out of bounds (max {})", 
                          bitmap_index, self.total_frames);
            return;
        }

        // check if the frame was actually allocated before freeing
        if !self.frame_free_list.is_set(bitmap_index) {
            serial_println!("Warning: Double-free detected for frame at {:?} (bitmap index {})", 
                          phys_addr, bitmap_index);
            return;
        }
        
        self.frame_free_list.clear(bitmap_index);
        
        // TODO: zero physical frame out before allowing frame reuse (security)
    }
}

unsafe impl FrameAllocatorTrait<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.alloc_frame()
    }
}

impl FrameDeallocator<Size4KiB> for FrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.free_frame(frame);
    }
}

#[repr(C)]
struct Node {
    // size of the free block (not including this header)
    size: usize,
    // double linked list for easier removals and coalescing of space
    next: *mut Node,
    prev: *mut Node,
}

impl Node {
    const fn size() -> usize {
        size_of::<Node>()
    }
}

pub struct LinkedListAllocator {
    // pointer to the first free block
    head: *mut Node,
}

pub struct LockedAllocator(Mutex<LinkedListAllocator>);

// need to implement these traits to satisfy the compiler in the case of using static + Mutex
// its safe for one because the kernel is single threaded but even if it wasn't the Mutex protects
// the raw pointers, which are the things annoying the compiler in this case
unsafe impl Send for LinkedListAllocator {}
unsafe impl Sync for LockedAllocator {}

impl LockedAllocator {
    pub const fn new() -> Self {
        LockedAllocator(Mutex::new(LinkedListAllocator::new()))
    }

    /// Initialize the underlying allocator
    pub unsafe fn init(&self, start_addr: VirtAddr, total_size: usize) {
        self.0.lock().init(start_addr, total_size);
    }
}

impl LinkedListAllocator {
    pub const fn new() -> Self {
        Self { head: null_mut() }
    }

    /// Initialize the allocator with a memory region
    pub unsafe fn init(&mut self, start_addr: VirtAddr, total_size: usize) {
        // make sure we have enough space for at least one node and some data
        if total_size < Node::size() + 4 {
            return;
        }
        
        // zero the memory region
        zero_memory(start_addr, total_size);
        
        serial_println!("Zeroed out heap memory region init at {:?} -- amount {}", start_addr, total_size);
        
        // cast the memory address as a pointer to an uninitialized Node raw pointer
        let addr = start_addr.as_u64() as usize as *mut Node;

        // write the initial free node
        write(addr, Node {
            size: total_size - Node::size(),
            next: null_mut(),
            prev: null_mut(),
        });

        self.head = addr;
    }
    // helper function to align an address UP to the next aligned boundary
    fn align_up(addr: usize, align: usize) -> usize {
        // to be honest bit arithmetic is still tough for me
        // This works because align is guaranteed to be a power of 2
        // Example with align = 8:
        // addr = 0x1005
        // align - 1 = 7 = 0b0111
        // !(align - 1) = 0b...11111000 (mask that clears lower 3 bits)
        // 
        // (addr + align - 1) ensures we round UP
        // Then & !(align - 1) clears the lower bits
        (addr + align - 1) & !(align - 1)
    }
    unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        
        // serial_println!("Allocating {} bytes at 0x{:x}", size, align);

        // `Layout` contract forbids making a `Layout` with align=0, or align not power of 2.
        // So we can safely use a mask to ensure alignment without worrying about UB.
        let _align_mask_to_round_down = !(align - 1);

        if align > MAX_SUPPORTED_ALIGN {
            return null_mut();
        }
        // walk free list using a first fit strategy
        let mut curr = self.head;

        let mut data_start = (curr as usize) + Node::size();

        // initialize values outside loop for use later as needed, they will get one extra recalculation on the first iteration
        // TODO: clean up the variable initialization a little
        /*
        let aligned_start: usize;
        let alloc_size: usize;
         */

        // aligned start is the ADDRESS of the beginning of the buffer of heap returned to the user
        let mut aligned_start = Self::align_up(data_start, align);
        // padding represents the AMOUNT of data added in order to achieve propper alignment
        let mut padding = aligned_start - data_start;
        // alloc size represents the total AMOUNT of buffer I have to find room for
        let mut alloc_size = padding + size;
        //                  ^       ^   
        //             alignment  user req
        // going forward comments referencing "size" will mean aligned size

        while !curr.is_null() {
            // recalculate all values on current node
            data_start = (curr as usize) + Node::size();
            aligned_start = Self::align_up(data_start, align);
            padding = aligned_start - data_start;
            alloc_size = padding + size;

            let node = &*curr;
            // serial_println!("Checking node at {:p}, size: {}", curr, node.size);
            if node.size >= alloc_size {
                // serial_println!("Found suitable block!");
                break;
            }
            curr = node.next;
        }

        if curr.is_null() {
            serial_println!("\nNo suitable block found!");
            return null_mut();
        }

        let node = &mut *curr;
        // we have a block that can fit some data
        // if the amount of room left over form our alloc is small enough
        // just alloc the whole chunk instead of splitting it
        if alloc_size + Node::size() + 4 >= node.size {
            if !node.prev.is_null() {
                let prev = &mut *node.prev;
                prev.next = node.next;
            }
            if !node.next.is_null() {
                let next = &mut *node.next;
                next.prev = node.prev;
            }
            if self.head == curr {
                self.head = node.next
            }
            // serial_println!("returning whole free block from list");
            return aligned_start as *mut u8;
        }
        // now we must split
        // first create a new node record to stamp in memory
        /*
        ┌─────────┬──────────────┬─────────┬────────────┐
        │  Node   │  size bytes  │  Node   │ remaining  │
        │(given)  │   (to user)  │ (new)   │            │
        └─────────┴──────────────┴─────────┴────────────┘
        ^curr                    ^next_free should be here
         */
        // this is more of a reminder to myself but -- pointer arithmetic works like so:
        // num_bytes = size_of(type) * num_added 
        // so if I dont cast curr as a u8 the amount added will actually be alloc_size*Node::size()
        let next_free = (curr as *mut u8).add(Node::size() + alloc_size) as *mut Node;
        let new_node = &mut *next_free;
        // split size making room for the new node header
        new_node.size = node.size - (Node::size() + alloc_size);
        if !node.next.is_null() {
            let next = &mut *node.next;
            next.prev = next_free;
            new_node.next = node.next;
        } else {
            new_node.next = null_mut();
        }

        if !node.prev.is_null() {
            let prev = &mut *node.prev;
            prev.next = next_free;
            new_node.prev = node.prev;
        } else {
            new_node.prev = null_mut();
        }
        if self.head == curr {
            self.head = next_free;
        }
        node.next = null_mut();
        node.prev = null_mut();
        aligned_start as *mut u8
    }
    unsafe fn free(&mut self, ptr: *mut u8, layout: Layout) {
        // the record keeping header is before the buffer pointer the user gets
        let free_addr = ptr as usize - Node::size();
        let free_node = free_addr as *mut Node;

        // restore the Node header with size from layout (could have been overwritten -- no guarantee
        write(free_node, Node {
            size: layout.size(),
            next: null_mut(),
            prev: null_mut(),
        });
        
        // serial_println!("Freeing allocated heap memory at {:p}", ptr);

        // walk the free list in order and insert accordingly so coalescing later is easy
        let mut curr = self.head;

        // empty list -- insert as new head
        if curr.is_null() {
            self.head = free_node;
            let node = &mut *free_node;
            node.next = null_mut();
            node.prev = null_mut();
            return;
        }

        // insert before curr as new head
        if free_node < curr {
            let node = &mut *free_node;
            node.next = curr;
            node.prev = null_mut();

            let node = &mut *curr;
            node.prev = free_node;
            self.head = free_node;
            return;
        }

        // the right spot is somewhere else, either at the tail or middle
        while !curr.is_null() && curr < free_node {
            let node = &*curr;
            // curr is at the end of the free list in which case break early so curr is still a valid
            // pointer (otherwise it would be null, and we'd re-walk) and add free_node at the tail
            if node.next.is_null() {
                break;
            }
            curr = node.next;
        }

        let node = &mut *curr;
        
        // last edge case -- insert at tail
        if node.next.is_null() {
            node.next = free_node;

            let node = &mut *free_node;
            node.prev = curr;
            node.next = null_mut();

            return;
        }
        
        // make sure its safe to dereference the prev pointer
        // this should never happen but then again that phrase is famous last words D:
        if curr != self.head {
            // [prev] <-> [curr] <-> [next]
            // [prev] <-> [to_free] <-> [curr] <-> [next]
            let node = &mut *curr;
            let prev = &mut *node.prev;

            prev.next = free_node;

            let to_free = &mut *free_node;
            to_free.prev =  node.prev;
        }
        let to_free = &mut *free_node;
        to_free.next = curr;
        node.prev = free_node;
    
        return;
    }
}

// need to use interior mutability given the GlobalAlloc trait expects shared self references
unsafe impl GlobalAlloc for LockedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut guard = self.0.lock();
        unsafe { guard.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut guard = self.0.lock();
        unsafe{ guard.free(ptr, layout) }
    }
}

/*
    Use u64 as the data type because its the same storage amount as using a smaller integer type but with a couple niceties:
    fewer array elements to iterate through
    better for 64-bit CPUs (natural word size)
    can use u64::trailing_ones() for fast searches
 */
pub(crate) struct BitMap {
    data: &'static mut [u64],
    size_in_bits: usize,
}

impl BitMap {
    pub(crate) unsafe fn new(data: &'static mut [u64], size_in_bits: usize) -> Self {
        // zero out all bits as free initially
        for word in data.iter_mut() {
            *word = 0;
        }
        Self { data, size_in_bits }
    }
    pub(crate) fn is_set(&self, bit: usize) -> bool {
        if bit >= self.size_in_bits {
            return true; // Out of bounds = unavailable
        }
        // Step 1: Which u64 contains this bit?
        let word_index = bit / 64;
        // Step 2: Which bit within that u64?
        let bit_index = bit % 64;
        // Step 3: Check if that bit is set
        (self.data[word_index] & (1u64 << bit_index)) != 0
        //             └─────┬────┘  └────┬────┘
        //                   │            └─ Create mask: e.g. 0b1000
        //                   └─ AND with data[idx]
    }
    pub(crate) fn set(&mut self, bit: usize) {
        if bit >= self.size_in_bits {
            return;
        }
        let word_index = bit / 64;
        let bit_index = bit % 64;
        // create bit mask and or = with that mask to only set the specified bit
        self.data[word_index] |= 1u64 << bit_index;
    }
    pub(crate) fn clear(&mut self, bit: usize) {
        if bit >= self.size_in_bits {
            return;
        }
        let word_index = bit / 64;
        let bit_index = bit % 64;
        self.data[word_index] &= !(1u64 << bit_index);
    }
    pub(crate) fn find_and_set_first_free(&mut self) -> Option<usize> {
        for (word_idx, word) in self.data.iter_mut().enumerate() {
            if *word != u64::MAX {
                // this word has at least one free bit
                let bit_in_word = word.trailing_ones() as usize;
                if word_idx * 64 + bit_in_word >= self.size_in_bits {
                    return None;
                }
                *word |= 1u64 << bit_in_word;
                return Some(word_idx * 64 + bit_in_word);
            }
        }
        None
    }
}
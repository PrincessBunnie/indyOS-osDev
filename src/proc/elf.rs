#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ELFHeader {
    pub ident: ELFIdent,
    pub elf_type: u16,        // Object file type
    pub machine: u16,         // Architecture
    pub version: u32,         // Object file version
    pub entry: u64,           // Entry point virtual address
    pub phoff: u64,           // Program header table file offset
    pub shoff: u64,           // Section header table file offset
    pub flags: u32,           // Processor-specific flags
    pub ehsize: u16,          // ELF header size in bytes
    pub phentsize: u16,       // Program header table entry size
    pub phnum: u16,           // Program header table entry count
    pub shentsize: u16,       // Section header table entry size
    pub shnum: u16,           // Section header table entry count
    pub shstrndx: u16,        // Section header string table index
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ELFIdent {
    pub magic: [u8; 4],       // 0x7f, 'E', 'L', 'F'
    pub class: u8,            // 1 = 32-bit, 2 = 64-bit
    pub data: u8,             // 1 = little endian, 2 = big endian
    pub version: u8,          // ELF version (should be 1)
    pub osabi: u8,            // OS/ABI identification
    pub abiversion: u8,       // ABI version
    pub pad: [u8; 7],         // Padding bytes
}

// Program header for loading segments
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader {
    pub p_type: u32,          // Segment type
    pub p_flags: u32,         // Segment flags
    pub p_offset: u64,        // Segment file offset
    pub p_vaddr: u64,         // Segment virtual address
    pub p_paddr: u64,         // Segment physical address
    pub p_filesz: u64,        // Segment size in file
    pub p_memsz: u64,         // Segment size in memory
    pub p_align: u64,         // Segment alignment
}

// Constants for ELF parsing
pub mod elf_constants {
    // ELF Class
    pub const ELFCLASS64: u8 = 2;

    // ELF Data encoding
    pub const ELFDATA2LSB: u8 = 1;  // Little endian

    // ELF Types
    pub const ET_EXEC: u16 = 2;     // Executable file
    pub const ET_DYN: u16 = 3;      // Shared object file

    // Machine types
    pub const EM_X86_64: u16 = 62;  // AMD x86-64

    // Program header types
    pub const PT_NULL: u32 = 0;     // Unused entry
    pub const PT_LOAD: u32 = 1;     // Loadable segment
    pub const PT_DYNAMIC: u32 = 2;  // Dynamic linking info
    pub const PT_INTERP: u32 = 3;   // Interpreter path
    pub const PT_NOTE: u32 = 4;     // Auxiliary info

    // Program header flags
    pub const PF_X: u32 = 1;        // Execute
    pub const PF_W: u32 = 2;        // Write
    pub const PF_R: u32 = 4;        // Read
}

impl ELFHeader {
    /// Parse an ELF header from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < size_of::<ELFHeader>() {
            return None;
        }

        // safety: checked the length above
        // unsafe block is because we are interpreting raw bytes as a struct
        // beyond the basic bounds check the point of the magic elf header is to help identify a valid header (viz. struct)
        unsafe {
            let header = core::ptr::read(data.as_ptr() as *const ELFHeader);

            // what kind of binaries does Santa use? ELF!
            // you've seen elf on a shelf now prepare for elf loaded into a processes virtual memory!
            if &header.ident.magic != b"\x7fELF" {
                return None;
            }

            Some(header)
        }
    }

    /// Get an iterator over program headers
    pub fn program_headers<'a>(&self, data: &'a [u8]) -> ProgramHeaderIter<'a> {
        ProgramHeaderIter {
            data,
            offset: self.phoff as usize,
            entry_size: self.phentsize as usize,
            count: self.phnum as usize,
            index: 0,
        }
    }

    /// Check if this is a Position Independent Executable
    pub fn is_pie(&self) -> bool {
        self.elf_type == elf_constants::ET_DYN
    }
}

impl ProgramHeader {
    /// Check if this segment is executable (code)
    pub fn is_executable(&self) -> bool {
        self.p_flags & elf_constants::PF_X != 0
    }

    /// Check if this segment is writable (data/bss)
    pub fn is_writable(&self) -> bool {
        self.p_flags & elf_constants::PF_W != 0
    }

    /// Check if this segment is readable
    pub fn is_readable(&self) -> bool {
        self.p_flags & elf_constants::PF_R != 0
    }

    /// Determine segment type for VM area classification
    pub fn segment_type(&self) -> SegmentType {
        match (self.is_readable(), self.is_writable(), self.is_executable()) {
            (true, false, true) => SegmentType::Text,      // R-X: code
            (true, false, false) => SegmentType::RoData,   // R--: read-only data
            (true, true, false) => SegmentType::Data,      // RW-: data/bss
            _ => SegmentType::Unknown,
        }
    }

    /// Validate that p_vaddr and p_offset have same page alignment
    /// This is required by the ELF spec for efficient memory mapping
    pub fn validate_alignment(&self, page_size: u64) -> bool {
        (self.p_vaddr % page_size) == (self.p_offset % page_size)
    }

    /// Get the segment data from the ELF file
    pub fn get_data<'a>(&self, elf_data: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.p_offset as usize;
        let end = start + self.p_filesz as usize;

        if end > elf_data.len() {
            return None;
        }

        Some(&elf_data[start..end])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    Text,      // Executable code
    RoData,    // Read-only data (string literals, const data)
    Data,      // Initialized writable data + BSS
    Unknown,
}

pub struct ProgramHeaderIter<'a> {
    data: &'a [u8],
    offset: usize,
    entry_size: usize,
    count: usize,
    index: usize,
}

impl<'a> Iterator for ProgramHeaderIter<'a> {
    type Item = ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }

        let start = self.offset + (self.index * self.entry_size);
        let end = start + size_of::<ProgramHeader>();

        if end > self.data.len() {
            return None;
        }

        self.index += 1;

        // safety: validated bounds above
        unsafe {
            Some(core::ptr::read(self.data[start..].as_ptr() as *const ProgramHeader))
        }
    }
}

pub mod ELF {
    use core::ops::Add;
    use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB, Translate};
    use x86_64::VirtAddr;
    use crate::constants::magic::PAGE_SIZE;
    use crate::errors::OSError;
    use crate::memory::page;
    use crate::memory::page::phys_offset;
    use crate::proc::elf::{elf_constants, ELFHeader, ProgramHeader, SegmentType};
    use crate::proc::process::Process;
    use crate::proc::virtual_memory::user_layout::{USER_DATA_BASE, USER_DATA_END, USER_RODATA_BASE, USER_RODATA_END, USER_TEXT_BASE, USER_TEXT_END};
    use crate::proc::virtual_memory::VirtualMemory;
    use crate::{dbg, serial_println};

    pub fn load(process: &mut Process, elf_data: &[u8]) -> Result<VirtAddr, OSError> {
        // check magic number first
        let header = ELFHeader::parse(elf_data)
            .ok_or(OSError::InvalidELF)?;

        dbg!(header);
        // needs to match the arch (x86_64) and be an executable [class]
        if header.ident.class != elf_constants::ELFCLASS64
            || header.machine != elf_constants::EM_X86_64 {
            return Err(OSError::InvalidELF);
        }

        // TODO support PIE & ASLR
        // for PIE binaries we need to calculate the load offset
        // let load_offset = if header.is_pie() {
        //     // PIE: find the lowest p_vaddr among PT_LOAD segments
        //     let min_vaddr = header.program_headers(elf_data)
        //         .filter(|ph| ph.p_type == elf_constants::PT_LOAD)
        //         .map(|ph| ph.p_vaddr)
        //         .min()
        //         .unwrap_or(0);
        //
        //     // calculate offset to relocate to TEXT base
        //     // we want: min_vaddr + offset = USER_TEXT_BASE
        //     USER_TEXT_BASE.wrapping_sub(min_vaddr)
        // } else {
        //     // for static binaries, verify they match layout
        //     0
        // };

        // load each PT_LOAD segment into memory
        for phdr in header.program_headers(elf_data) {
            if phdr.p_type != elf_constants::PT_LOAD {
                continue;
            }
            serial_println!("about to validate page alignment....");
            // spec requires the p_vaddr and its offset both be page aligned
            if !phdr.validate_alignment(PAGE_SIZE as u64) {
                return Err(OSError::InvalidELF);
            }
            serial_println!("about to validate segments...");
            validate_segment_bounds(&phdr)?;

            serial_println!("about to load into memory...");
            load_segment_into_memory(
                &mut process.memory,
                elf_data,
                &phdr,
            )?;
        }

        // Ok(VirtAddr::new(header.entry.wrapping_add(load_offset)))

        Ok(VirtAddr::new(header.entry))
    }
    fn validate_segment_bounds(phdr: &ProgramHeader) -> Result<(), OSError> {
        let start = phdr.p_vaddr;
        let end = phdr.p_vaddr + phdr.p_memsz;

        // Check which region this should be in based on permissions
        match phdr.segment_type() {
            SegmentType::Text => {
                if start < USER_TEXT_BASE || end > USER_TEXT_END {
                    serial_println!("Text segment is out of bounds");
                    return Err(OSError::InvalidELF);
                }
            }
            SegmentType::RoData => {
                if start < USER_RODATA_BASE {
                    serial_println!("Ro segment {:?} is below ro base: {:?}", VirtAddr::new(start),  VirtAddr::new(USER_RODATA_BASE));
                    return Err(OSError::InvalidELF);
                }
                if end > USER_RODATA_END {
                    serial_println!("Ro segment is above ro end");
                    return Err(OSError::InvalidELF);
                }
            }
            SegmentType::Data => {
                if start < USER_DATA_BASE || end > USER_DATA_END {
                    serial_println!("Data segment is out of bounds");
                    return Err(OSError::InvalidELF);
                }
            }
            SegmentType::Unknown => {
                serial_println!("Unknown segment type");
                return Err(OSError::InvalidELF);
            }
        }

        Ok(())
    }
    fn load_segment_into_memory(
        memory: &mut VirtualMemory,
        elf_data: &[u8],
        phdr: &ProgramHeader,
    ) -> Result<(), OSError> {

        // pages to map for this segment we want the addr at the beginning of a page boundry
        // offset will be used for loading the data into memory still however
        let segment_start = VirtAddr::new(phdr.p_vaddr);
        let segment_end = VirtAddr::new(phdr.p_vaddr + phdr.p_memsz);

        let start_page = Page::<Size4KiB>::containing_address(segment_start);
        let end_page = Page::<Size4KiB>::containing_address(segment_end - 1u64);

        // convert elf flags into page table flags
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if phdr.p_flags & elf_constants::PF_W != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if phdr.p_flags & elf_constants::PF_X == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let pages = Page::range_inclusive(start_page, end_page);
        let mut page_table = unsafe { page::page_table_from_addr(memory.page_table_addr) };
        unsafe { page::map_pages_alloc(&mut page_table, pages, flags) }?;

        // copy segment data to the correct virtual address
        // (which includes the page offset as I mentioned before)
        if phdr.p_filesz > 0 {
            let file_start = phdr.p_offset as usize;
            let file_end = file_start + phdr.p_filesz as usize;

            if file_end > elf_data.len() {
                return Err(OSError::InvalidELF);
            }

            let mut bytes_copied = 0;
            for page in pages.clone() {
                if bytes_copied >= phdr.p_filesz {
                    break;
                }
                let page_start = page.start_address();
                let Some(destination_phys_addr) = page_table.translate_addr(page_start) else {
                    dbg!("Failed to translate segment header, page", phdr, page);
                    return Err(OSError::InvalidELF);
                };

                let kernel_vaddr = phys_offset().add(destination_phys_addr.as_u64());

                let page_offset = if bytes_copied == 0 {
                    // first page might not start at page boundary
                    (phdr.p_vaddr & 0xFFF) as usize
                } else {
                    0
                };

                let bytes_remaining = (phdr.p_filesz - bytes_copied) as usize;
                let space_in_page = PAGE_SIZE - page_offset;
                let bytes_to_copy = core::cmp::min(bytes_remaining, space_in_page);

                serial_println!(
                    "  Page {:?}: copying {} bytes at offset {}",
                    page, bytes_to_copy, page_offset
                );

                unsafe {
                    let dst = (kernel_vaddr.as_u64() + page_offset as u64) as *mut u8;
                    // Fix: Directly calculate the source pointer from the ELF data
                    let src_ptr = elf_data.as_ptr().add(file_start + bytes_copied as usize);
                    core::ptr::copy_nonoverlapping(src_ptr, dst, bytes_to_copy);
                }
                bytes_copied += bytes_to_copy as u64;

                serial_println!("Copied {} bytes total", bytes_copied);
            }
        }

        // ELF spec says if this case is true we must zero out the mem
        // this, if I understanding it correctly is because this region corresponds to .bss
        if phdr.p_memsz > phdr.p_filesz {
            let bss_start = VirtAddr::new(phdr.p_vaddr + phdr.p_filesz);
            let bss_size = (phdr.p_memsz - phdr.p_filesz) as usize;
            serial_println!("Zeroing {} bytes of BSS at {:?}", bss_size, bss_start);

            // need to do the same handling as above for the addr translation & multi-page handling
            let page_start: Page<Size4KiB> = Page::containing_address(bss_start);
            let page_end: Page<Size4KiB> = page_start + bss_size as u64;

            let mut bytes_zeroed = 0;
            for page in Page::range_inclusive(page_start, page_end) {
                let Some(destination_phys_addr) = page_table.translate_addr(page.start_address()) else {
                    dbg!("Failed to translate segment header, page", phdr, page);
                    return Err(OSError::InvalidELF);
                };

                let kernel_vaddr = phys_offset().add(destination_phys_addr.as_u64());

                // only for the first page calculate the offset
                let page_offset = if bytes_zeroed == 0 {
                    (bss_start.as_u64() & 0xFFF) as usize
                } else {
                    0
                };

                let bytes_remaining = bss_size - bytes_zeroed;
                let space_in_page = PAGE_SIZE - page_offset;
                let bytes_to_zero = core::cmp::min(bytes_remaining, space_in_page);

                // Zero this chunk
                unsafe {
                    let dst = (kernel_vaddr.as_u64() + page_offset as u64) as *mut u8;
                    core::ptr::write_bytes(dst, 0, bytes_to_zero);
                }

                bytes_zeroed += bytes_to_zero;

                serial_println!("Zeroed {} bytes of BSS", bytes_zeroed);
            }
        }

        serial_println!("Successfully loaded program into memory!");
        Ok(())
    }
}
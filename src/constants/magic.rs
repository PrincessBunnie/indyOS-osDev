/// Hardware memory-mapped I/O addresses and special memory regions
/// for x86/x86_64 architecture OS development

// ============================================================================
// VGA Text Mode
// ============================================================================

/// VGA text mode buffer address (80x25 characters, 16 colors)
pub const VGA_BUFFER: usize = 0xB8000;
pub const VGA_WIDTH: usize = 80;
pub const VGA_HEIGHT: usize = 25;

// ============================================================================
// VGA Graphics Mode
// ============================================================================

/// VGA graphics mode frame buffer (Mode 13h - 320x200, 256 colors)
pub const VGA_GRAPHICS_BUFFER: usize = 0xA0000;

// ============================================================================
// BIOS Data Area (BDA)
// ============================================================================

/// BIOS Data Area start
pub const BDA_START: usize = 0x400;
/// BIOS Data Area end
pub const BDA_END: usize = 0x4FF;
/// COM1 port address stored in BDA
pub const BDA_COM1: usize = 0x400;
/// LPT1 port address stored in BDA
pub const BDA_LPT1: usize = 0x408;
/// Number of KB of memory
pub const BDA_MEMORY_SIZE: usize = 0x413;

// ============================================================================
// Extended BIOS Data Area (EBDA)
// ============================================================================

/// Pointer to EBDA (stored at 0x40E)
pub const EBDA_POINTER: usize = 0x40E;

// ============================================================================
// Serial Ports (COM ports)
// ============================================================================

pub const COM1_PORT: u16 = 0x3F8;
pub const COM2_PORT: u16 = 0x2F8;
pub const COM3_PORT: u16 = 0x3E8;
pub const COM4_PORT: u16 = 0x2E8;

// ============================================================================
// Parallel Ports (LPT ports)
// ============================================================================

pub const LPT1_PORT: u16 = 0x378;
pub const LPT2_PORT: u16 = 0x278;

// ============================================================================
// PIC (Programmable Interrupt Controller) - 8259
// ============================================================================

/// Master PIC command port
pub const PIC1_COMMAND: u16 = 0x20;
/// Master PIC data port
pub const PIC1_DATA: u16 = 0x21;
/// Slave PIC command port
pub const PIC2_COMMAND: u16 = 0xA0;
/// Slave PIC data port
pub const PIC2_DATA: u16 = 0xA1;

// ============================================================================
// PIT (Programmable Interval Timer) - 8253/8254
// ============================================================================

pub const PIT_CHANNEL0: u16 = 0x40;
pub const PIT_CHANNEL1: u16 = 0x41;
pub const PIT_CHANNEL2: u16 = 0x42;
pub const PIT_COMMAND: u16 = 0x43;

// ============================================================================
// PS/2 Controller (Keyboard/Mouse) - 8042
// ============================================================================

pub const PS2_DATA_PORT: u16 = 0x60;
pub const PS2_STATUS_PORT: u16 = 0x64;
pub const PS2_COMMAND_PORT: u16 = 0x64;

// ============================================================================
// CMOS/RTC (Real Time Clock) and NMI
// ============================================================================

pub const CMOS_ADDRESS: u16 = 0x70;
pub const CMOS_DATA: u16 = 0x71;

// ============================================================================
// DMA Controller (8237)
// ============================================================================

// DMA channels 0-3
pub const DMA_CHANNEL0_ADDR: u16 = 0x00;
pub const DMA_CHANNEL0_COUNT: u16 = 0x01;
pub const DMA_CHANNEL1_ADDR: u16 = 0x02;
pub const DMA_CHANNEL1_COUNT: u16 = 0x03;
pub const DMA_CHANNEL2_ADDR: u16 = 0x04;
pub const DMA_CHANNEL2_COUNT: u16 = 0x05;
pub const DMA_CHANNEL3_ADDR: u16 = 0x06;
pub const DMA_CHANNEL3_COUNT: u16 = 0x07;

// DMA status/command registers
pub const DMA_STATUS: u16 = 0x08;
pub const DMA_COMMAND: u16 = 0x08;
pub const DMA_REQUEST: u16 = 0x09;
pub const DMA_MASK_SINGLE: u16 = 0x0A;
pub const DMA_MODE: u16 = 0x0B;
pub const DMA_FLIP_FLOP: u16 = 0x0C;
pub const DMA_RESET: u16 = 0x0D;
pub const DMA_MASK_ALL: u16 = 0x0F;

// ============================================================================
// PCI Configuration Space
// ============================================================================

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

// ============================================================================
// IDE/ATA Controllers
// ============================================================================

// Primary IDE
pub const IDE_PRIMARY_DATA: u16 = 0x1F0;
pub const IDE_PRIMARY_ERROR: u16 = 0x1F1;
pub const IDE_PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
pub const IDE_PRIMARY_LBA_LO: u16 = 0x1F3;
pub const IDE_PRIMARY_LBA_MID: u16 = 0x1F4;
pub const IDE_PRIMARY_LBA_HI: u16 = 0x1F5;
pub const IDE_PRIMARY_DRIVE: u16 = 0x1F6;
pub const IDE_PRIMARY_STATUS: u16 = 0x1F7;
pub const IDE_PRIMARY_COMMAND: u16 = 0x1F7;
pub const IDE_PRIMARY_CONTROL: u16 = 0x3F6;

// Secondary IDE
pub const IDE_SECONDARY_DATA: u16 = 0x170;
pub const IDE_SECONDARY_ERROR: u16 = 0x171;
pub const IDE_SECONDARY_SECTOR_COUNT: u16 = 0x172;
pub const IDE_SECONDARY_LBA_LO: u16 = 0x173;
pub const IDE_SECONDARY_LBA_MID: u16 = 0x174;
pub const IDE_SECONDARY_LBA_HI: u16 = 0x175;
pub const IDE_SECONDARY_DRIVE: u16 = 0x176;
pub const IDE_SECONDARY_STATUS: u16 = 0x177;
pub const IDE_SECONDARY_COMMAND: u16 = 0x177;
pub const IDE_SECONDARY_CONTROL: u16 = 0x376;

// ============================================================================
// Floppy Disk Controller
// ============================================================================

pub const FDC_DOR: u16 = 0x3F2;  // Digital Output Register
pub const FDC_MSR: u16 = 0x3F4;  // Main Status Register
pub const FDC_FIFO: u16 = 0x3F5; // Data FIFO
pub const FDC_CCR: u16 = 0x3F7;  // Configuration Control Register

// ============================================================================
// Memory Regions
// ============================================================================

/// Start of conventional memory
pub const CONVENTIONAL_MEMORY_START: usize = 0x0;
/// End of conventional memory (640 KB)
pub const CONVENTIONAL_MEMORY_END: usize = 0x9FFFF;

/// Start of upper memory area (UMA)
pub const UPPER_MEMORY_START: usize = 0xA0000;
/// End of upper memory area
pub const UPPER_MEMORY_END: usize = 0xFFFFF;

/// Start of extended memory (above 1MB)
pub const EXTENDED_MEMORY_START: usize = 0x100000;

/// BIOS ROM area
pub const BIOS_ROM_START: usize = 0xF0000;
pub const BIOS_ROM_END: usize = 0xFFFFF;

// ============================================================================
// APIC (Advanced Programmable Interrupt Controller)
// ============================================================================

/// Default APIC base address (can be relocated)
pub const APIC_BASE: usize = 0xFEE00000;
pub const APIC_ID: usize = APIC_BASE + 0x20;
pub const APIC_VERSION: usize = APIC_BASE + 0x30;
pub const APIC_TPR: usize = APIC_BASE + 0x80;
pub const APIC_EOI: usize = APIC_BASE + 0xB0;
pub const APIC_SIVR: usize = APIC_BASE + 0xF0;

// ============================================================================
// IOAPIC
// ============================================================================

/// Default IOAPIC base address
pub const IOAPIC_BASE: usize = 0xFEC00000;
pub const IOAPIC_REGISTER_SELECT: usize = IOAPIC_BASE + 0x00;
pub const IOAPIC_WINDOW: usize = IOAPIC_BASE + 0x10;

// ============================================================================
// ACPI Tables (typical locations)
// ============================================================================

/// RSDP search area start (BIOS read-only memory space)
pub const RSDP_SEARCH_START: usize = 0xE0000;
/// RSDP search area end
pub const RSDP_SEARCH_END: usize = 0xFFFFF;

// ============================================================================
// Multiboot Information
// ============================================================================

/// Magic value that multiboot-compliant bootloaders pass to kernel
pub const MULTIBOOT_MAGIC: u32 = 0x2BADB002;
pub const MULTIBOOT2_MAGIC: u32 = 0x36D76289;

// ============================================================================
// Page Frame Allocator Constants
// ============================================================================

/// Standard page size (4 KB)
pub const PAGE_SIZE: usize = 4096;
/// Large page size (2 MB)
pub const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
/// Huge page size (1 GB)
pub const HUGE_PAGE_SIZE: usize = 1024 * 1024 * 1024;

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if an address is page-aligned
pub const fn is_page_aligned(addr: usize) -> bool {
    addr % PAGE_SIZE == 0
}

/// Align address up to nearest page boundary
pub const fn align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Align address down to nearest page boundary
pub const fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

/// Convert physical address to VGA buffer index
pub const fn vga_index(row: usize, col: usize) -> usize {
    (row * VGA_WIDTH + col) * 2
}

#[cfg(target_arch = "x86")]
pub use io::*;

use core::fmt;
use core::ops::Neg;
use thiserror_no_std::Error;
use x86_64::structures::paging::mapper::{MapToError, UnmapError};
use x86_64::structures::paging::Size4KiB;
use x86_64::{PhysAddr, VirtAddr};
use crate::proc::virtual_memory::VmType;

#[derive(Error, Debug)]
pub enum OSError {
    #[error("Component {0} is out of memory resources")]
    OutOfMemory(Component),

    #[error("Invalid virtual address: {0:?}")]
    InvalidVirtualAddress(VirtAddr),

    #[error("Invalid physical address: {0:?}")]
    InvalidPhysicalAddress(PhysAddr),

    #[error("Invalid memory region")]
    InvalidMemoryRegion,

    #[error("Page mapping failed: {0}")]
    MapError(MapErrorWrapper),

    #[error("Page unmapping failed: {0}")]
    UnmapError(UnmapErrorWrapper),

    #[error("Guard violation at: {0:?} of type: {1:?}")]
    GuardPageViolation(VirtAddr, VmType),

    #[error("Write to a read only portion of virtual memory at: {0:?}")]
    WriteToReadOnly(VirtAddr),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Invalid ELF binary")]
    InvalidELF
}

#[derive(Debug)]
pub enum Component {
    FrameAllocator,
    PageTable,
    Heap,
    KernelStack,
    Stack,
    PIDAllocator,
}

#[derive(Debug)]
pub enum Errno {
    E2Big = -7,        // Argument list too long
    EAccess = -13,    // Permission denied
    EAddrInUse = -98,  // Address already in use
    EAddrNotAvailable = -99, // Cannot assign requested address
    EBADF = -9,        // Bad file descriptor
    EBUSY = -16,       // Device or resource busy
    EEXIST = -17,      // File exists
    EFAULT = -14,      // Bad address
    EFBIG = -27,       // File too large
    EINVAL = -22,      // Invalid argument
    EIO = -5,          // I/O error
    EISDIR = -21,      // Is a directory
    ENOENT = -2,       // No such file or directory
    ENOSPC = -28,      // No space left on device
    ENOTDIR = -20,     // Not a directory
    EROFS = -30,       // Read-only filesystem
    ETXTBSY = -26,     // Text file busy
    // will extend later as needed
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Component::FrameAllocator => write!(f, "FrameAllocator"),
            Component::PageTable => write!(f, "PageTable"),
            Component::Heap => write!(f, "Heap"),
            Component::KernelStack => write!(f, "KernelStack"),
            Component::Stack => write!(f, "Stack"),
            Component::PIDAllocator => write!(f, "PIDAllocator"),
        }
    }
}

// Wrapper types with Display implementations

#[derive(Debug)]
pub struct MapErrorWrapper(pub MapToError<Size4KiB>);

impl fmt::Display for MapErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            MapToError::FrameAllocationFailed => {
                write!(f, "frame allocation failed")
            }
            MapToError::ParentEntryHugePage => {
                write!(f, "parent entry is a huge page")
            }
            MapToError::PageAlreadyMapped(frame) => {
                write!(f, "page already mapped to frame {:#x}", frame.start_address().as_u64())
            }
        }
    }
}

impl From<MapToError<Size4KiB>> for OSError {
    fn from(e: MapToError<Size4KiB>) -> Self {
        OSError::MapError(MapErrorWrapper(e))
    }
}

#[derive(Debug)]
pub struct UnmapErrorWrapper(pub UnmapError);

impl fmt::Display for UnmapErrorWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            UnmapError::PageNotMapped => {
                write!(f, "page not mapped")
            }
            UnmapError::ParentEntryHugePage => {
                write!(f, "parent entry is a huge page")
            }
            UnmapError::InvalidFrameAddress(addr) => {
                write!(f, "invalid frame address: {:#x}", addr.as_u64())
            }
        }
    }
}

impl From<UnmapError> for OSError {
    fn from(e: UnmapError) -> Self {
        OSError::UnmapError(UnmapErrorWrapper(e))
    }
}
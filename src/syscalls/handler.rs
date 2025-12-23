use crate::errors::Errno::{EBADF, EFAULT, EINVAL};
use crate::io::io::console_write_stdout;
use crate::memory::page::current_page_table_addr;
use crate::proc::virtual_memory::translate_user_addr;
use crate::serial_println;

/// Write syscall writes user bytes to a file abstraction
pub(crate) fn sys_write(fd: i32, buf: *const u8, count: usize) -> i64 {
    // work through validation first, fastest short circuit paths first

    // must be stdin, out, err for now (no fd tables)
    if fd < 0 || fd > 2 {
        return EBADF as i64;
    }

    // can't write negative bytes, must not write too much at once
    if count < 0 || count > 512 {
        return EINVAL as i64;
    }

    // buf must not be null && addr be in a valid vma for the current process
    if !is_valid_user_buffer(buf, count) {
        return EFAULT as i64;
    }

    serial_println!("buffer is valid, about to convert to kernel addr and console write");

    // copy data from userspace, must convert addr to kernel accessible addr
    let user_vaddr = buf as u64;
    let user_page_table_addr = unsafe { current_page_table_addr() };
    let kernel_vaddr: *mut u8 = match translate_user_addr(user_vaddr, user_page_table_addr) {
        Ok(kernel_vaddr) => kernel_vaddr,
        Err(e) => {
            serial_println!("sys_write: failed to translate user page table address: {}", e);
            return EFAULT as i64;
        }
    };
    let bytes_to_write = unsafe { core::slice::from_raw_parts(kernel_vaddr, count) };
    let bytes_written = console_write_stdout(bytes_to_write);
    bytes_written as i64
}

/// helpers
/// Validate a user buffer for read/write operations
fn is_valid_user_buffer(ptr: *const u8, len: usize) -> bool {
    const USER_SPACE_END: usize = 0x0000_8000_0000_0000;

    // Check for null
    if ptr.is_null() {
        return false;
    }

    let addr = ptr as usize;

    // Check it's in user space
    if addr >= USER_SPACE_END {
        return false;
    }

    // Check for overflow
    let end_addr = match addr.checked_add(len) {
        Some(end) => end,
        None => return false,
    };

    // Check end is still in user space
    if end_addr > USER_SPACE_END {
        return false;
    }

    // TODO: Check memory is actually mapped
    // For now, rely on page fault handler

    true
}
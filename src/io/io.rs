#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::fmt;
use core::fmt::Write;
use core::panic::PanicInfo;

/// Read a byte from the specified port
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a byte to the specified port
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
}

/// Read a word (16-bit) from the specified port
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a word (16-bit) to the specified port
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
}

/// Read a long (32-bit) from the specified port
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack));
    value
}

/// Write a long (32-bit) to the specified port
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
}

/// Wait a very small amount of time (1-4 microseconds)
#[inline]
pub unsafe fn io_wait() {
    outb(0x80, 0);
}

// QEMU Exit Device - For Testing/Diagnostics

const QEMU_EXIT_PORT: u16 = 0xf4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

/// Exit QEMU with the given exit code
pub fn qemu_exit(exit_code: QemuExitCode) -> ! {
    unsafe {
        outb(QEMU_EXIT_PORT, exit_code as u8);
    }
    loop {}
}

// Serial Port Constants and Initialization

const COM1_PORT: u16 = 0x3F8;

/// Initialize COM1 serial port
pub unsafe fn init_serial() {
    // Disable interrupts
    outb(COM1_PORT + 1, 0x00);

    // Enable DLAB (set baud rate divisor)
    outb(COM1_PORT + 3, 0x80);

    // Set divisor to 3 (38400 baud)
    outb(COM1_PORT + 0, 0x03);
    outb(COM1_PORT + 1, 0x00);

    // 8 bits, no parity, one stop bit
    outb(COM1_PORT + 3, 0x03);

    // Enable FIFO, clear with 14-byte threshold
    outb(COM1_PORT + 2, 0xC7);

    // Enable IRQs, set RTS/DSR
    outb(COM1_PORT + 4, 0x0B);

    // Test serial chip (loopback mode)
    outb(COM1_PORT + 4, 0x1E);
    outb(COM1_PORT + 0, 0xAE);

    // Check if serial is working
    if inb(COM1_PORT + 0) != 0xAE {
        // Serial is faulty, but we'll continue anyway
        return;
    }

    // Set normal operation mode
    outb(COM1_PORT + 4, 0x0F);
}

// Higher level printing/writing functions

pub unsafe fn serial_print(args: fmt::Arguments) {
    // create a writer that outputs to the serial port
    struct SerialWriter;

    impl Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for byte in s.bytes() {
                unsafe { outb(COM1_PORT, byte); }
            }
            Ok(())
        }
    }

    let _ = SerialWriter.write_fmt(args);
}

#[macro_export]
macro_rules! serial_println {
    () => {
        unsafe { $crate::io::serial_print(format_args!("\n")) }
    };
    ($fmt:expr) => {
        unsafe { $crate::io::serial_print(format_args!(concat!($fmt, "\n"))) }
    };
    ($fmt:expr, $($arg:tt)*) => {
        unsafe { $crate::io::serial_print(format_args!(concat!($fmt, "\n"), $($arg)*)) }
    };
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        unsafe { $crate::io::serial_print(format_args!($($arg)*)); }
    };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(panic_info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC!");

    if let Some(location) = panic_info.location() {
        serial_println!("  Location: {}:{}", location.file(), location.line());
    }

    serial_println!("  Message: {}", panic_info.message());

    // Exit QEMU with failure code for automated testing
    qemu_exit(QemuExitCode::Failed);
}

/// Debug macro similar to std::dbg! but for kernel
/// Prints file, line, expression, and value to serial port
#[macro_export]
macro_rules! serial_dbg {
    () => {
        $crate::serial_println!("[{}:{}]", file!(), line!())
    };
    ($val:expr $(,)?) => {
        match $val {
            tmp => {
                $crate::serial_println!(
                    "[{}:{}] {} = {:#?}",
                    file!(),
                    line!(),
                    stringify!($val),
                    &tmp
                );
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::serial_dbg!($val)),+,)
    };
}

/// Shorter alias
#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => {
        $crate::serial_dbg!($($arg)*)
    };
}

use spin::Mutex;
use lazy_static::lazy_static;

// console abstraction that wraps serial output
pub struct Console {
    port: u16,
}

impl Console {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Write bytes to the console
    /// Returns number of bytes written
    pub fn write(&self, bytes: &[u8]) -> usize {
        let mut written = 0;
        for &byte in bytes {
            // convert \n to \r\n for proper terminal output
            if byte == b'\n' {
                unsafe {
                    outb(self.port, b'\r');
                    outb(self.port, b'\n');
                }
            } else {
                unsafe {
                    outb(self.port, byte);
                }
            }
            written += 1;
        }
        written
    }
}

lazy_static! {
    pub static ref STDOUT: Mutex<Console> = Mutex::new(Console::new(COM1_PORT));
    pub static ref STDERR: Mutex<Console> = Mutex::new(Console::new(COM1_PORT));
}

/// Write to stdout - used by sys_write for fd=1
pub fn console_write_stdout(bytes: &[u8]) -> usize {
    STDOUT.lock().write(bytes)
}

/// Write to stderr - used by sys_write for fd=2
pub fn console_write_stderr(bytes: &[u8]) -> usize {
    STDERR.lock().write(bytes)
}

#[cfg(target_arch = "x86")]
pub use io::*;

// Diagnostic Test Function

pub fn diagnostic_entry_test() {
    unsafe {
        // Initialize serial port
        init_serial();

        // Send a test message
        serial_print(format_args!(">>> KERNEL ENTRY REACHED <<<\n"));

        // Small delay to ensure message is sent
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
    }
}

pub fn diagnostic_success_exit() -> ! {
    unsafe {
        serial_print(format_args!(">>> DIAGNOSTIC SUCCESS - EXITING <<<\n"));
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
    }
    qemu_exit(QemuExitCode::Success);
}
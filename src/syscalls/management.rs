use crate::memory::segmentation::get_selectors;
use crate::syscalls::handler::sys_write;
use crate::serial_println;
use core::arch::{asm, naked_asm};
use x86_64::registers::control::EferFlags;
use x86_64::registers::model_specific::{Efer, LStar, SFMask, Star};
use x86_64::VirtAddr;

const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_FMASK: u32 = 0xC0000084;
const MSR_EFER: u32 = 0xC0000080;

/// Read a Model Specific Register
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    asm!(
        "rdmsr",
        in("ecx") msr,           // MSR number goes in ECX
        out("eax") low,          // Low 32 bits returned in EAX
        out("edx") high,         // High 32 bits returned in EDX
        options(nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Write a Model Specific Register
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;           // Bottom 32 bits
    let high = (value >> 32) as u32;  // Top 32 bits
    asm!(
        "wrmsr",
        in("ecx") msr,           // MSR number in ECX
        in("eax") low,           // Low 32 bits in EAX
        in("edx") high,          // High 32 bits in EDX
        options(nostack, preserves_flags)
    );
}

pub unsafe fn init_syscall() {
    // 1. Configure STAR - segment selectors for syscall/sysret
    // Linux standard:
    // User CS = 0x18 (index 3, RPL 3)
    // Kernel CS = 0x08 (index 1, RPL 0)

    let selectors = get_selectors();

    // if let Err(e) = Star::write(selectors.user_code, selectors.user_data, selectors.kernel_code, selectors.kernel_data) {
    //     panic!("[init_syscall] failed to init kernel: {}", e);
    // }

    use x86_64::registers::model_specific::Star;

    let kernel_cs = selectors.kernel_code.0 as u64;  // 0x08
    let user_base = 0x10u64;  // Base for user segments

    let star_value = (user_base << 48) | (kernel_cs << 32);

    serial_println!("Manual STAR value: {:#x}", star_value);
    serial_println!("  Will set CS to: {:#x}", (user_base + 16) | 3);
    serial_println!("  Will set SS to: {:#x}", (user_base + 8) | 3);

    unsafe {
        // write STAR manually using wrmsr
        let low = star_value as u32;
        let high = (star_value >> 32) as u32;
        asm!(
        "wrmsr",
        in("ecx") 0xC0000081u32,  // MSR_STAR
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags)
        );
    }

    // verify
    let readback = Star::read();
    serial_println!("STAR readback: {:?}", readback.0);

    // // 2. Configure LSTAR - syscall entry point address
    // let handler_ptr = syscall_entry as *const ();
    // let handler_vaddr = VirtAddr::from_ptr(handler_ptr);
    //
    // // Print both the raw pointer value and the VirtAddr
    // serial_println!("Raw syscall_entry ptr: {:#p}", handler_ptr);
    // serial_println!("VirtAddr for syscall_entry: {:#x}", handler_vaddr);
    // LStar::write(handler_vaddr);
    // Configure LSTAR - syscall entry point address
    let handler_ptr = syscall_entry as *const ();
    let handler_vaddr = VirtAddr::from_ptr(handler_ptr);

    LStar::write(handler_vaddr);

    // verify it was written
    let readback = LStar::read();
    serial_println!("LSTAR written: {:#x}", handler_vaddr);
    serial_println!("LSTAR readback: {:#x}", readback);
    serial_println!("Match: {}", handler_vaddr == readback);
    serial_println!("============================\n");

    // 3. eonfigure FMASK - RFLAGS bits to clear on entry
    SFMask::write(x86_64::registers::rflags::RFlags::INTERRUPT_FLAG |
        x86_64::registers::rflags::RFlags::TRAP_FLAG |
        x86_64::registers::rflags::RFlags::DIRECTION_FLAG);

    // 4. enable syscall/sysret in EFER
    Efer::update(|efer| efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
}

// old more raw attempt, above tries to leverage x86_64 crate bc they're smarter than me!

// pub unsafe fn init_syscall() {
//     // 1. Configure STAR - segment selectors for syscall/sysret
//     //
//     // Bits 63-48: User segment base (0x10)
//     //   On sysret: CS = (0x10 + 16) | 3 = 0x23 (user code)
//     //              SS = (0x10 + 8) | 3 = 0x1B (user data)
//     //
//     // Bits 47-32: Kernel CS (0x08)
//     //   On syscall: CS = 0x08 (kernel code)
//     //               SS = 0x08 + 8 = 0x10 (kernel data)
//     let star = (0x10u64 << 48) | (0x08u64 << 32);
//     wrmsr(MSR_STAR, star);
//
//     serial_println!("init syscall star is {:#x}", rdmsr(MSR_STAR));
//
//     // 2. Configure LSTAR - syscall entry point address
//     let handler = syscall_entry as *const () as u64;
//     wrmsr(MSR_LSTAR, handler);
//
//     serial_println!("init syscall l_star is {:#x}", rdmsr(MSR_LSTAR));
//
//     // 3. Configure FMASK - RFLAGS bits to clear on entry
//     //    Clear IF (bit 9) - disable interrupts during stack switch
//     //    Clear TF (bit 8) - disable single-step debugging
//     //    Clear DF (bit 10) - ensure string ops count up
//     const RFLAGS_IF: u64 = 1 << 9;
//     const RFLAGS_TF: u64 = 1 << 8;
//     const RFLAGS_DF: u64 = 1 << 10;
//     let fmask = RFLAGS_IF | RFLAGS_TF | RFLAGS_DF;
//     wrmsr(MSR_FMASK, fmask);
//
//     serial_println!("init syscall fmask is {:#x}", rdmsr(MSR_FMASK));
//
//     // 4. Enable syscall/sysret in EFER
//     let mut efer = rdmsr(MSR_EFER);
//     efer |= 1 << 0;  // Set SCE (System Call Extensions) bit
//     wrmsr(MSR_EFER, efer);
//
//     serial_println!("init syscall efer is {:#x}", rdmsr(MSR_EFER));
// }

// A fixed location to store the current kernel stack
// This needs to be in a section that's always mapped
#[unsafe(no_mangle)]
pub static mut CURRENT_KERNEL_RSP: u64 = 0;
#[unsafe(no_mangle)]
pub static mut CURRENT_USER_RSP: u64 = 0;


/// The syscall entry point
///
/// When userspace executes 'syscall', the CPU:
/// 1. Saves RIP to RCX, RFLAGS to R11
/// 2. Loads RIP from IA32_LSTAR (jumps here)
/// 3. Sets CS from STAR, SS = CS + 8
/// 4. Switches to CPL 0 (ring 0)
/// 5. Clears RFLAGS bits specified in IA32_FMASK
///
/// Note: RSP is NOT changed! We're still on the user stack!

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // should trigger interrupt handler
        "ud2",
        // Save RAX (syscall number) before we clobber it
        "push rax",

        // Use a simple debug output method
        "mov rax, 0xDEADBEEF",  // Magic number
        "out 0xE9, al",  // Simple port I/O for debugging

        // Restore RAX
        "pop rax",

        // Continue with your original code
        "mov [rip + CURRENT_USER_RSP], rsp",
        // At entry:
        // - RSP = user stack (DANGER!)
        // - RCX = user RIP (saved by CPU)
        // - R11 = user RFLAGS (saved by CPU)
        // - RAX = syscall number
        // - RDI, RSI, RDX, R10, R8, R9 = arguments

        // Save user RSP to memory
        "mov [rip + CURRENT_USER_RSP], rsp",

        // Load kernel RSP from memory
        "mov rsp, [rip + CURRENT_KERNEL_RSP]",

        // Save registers for sysret (CPU needs these)
        "push r11",                     // User RFLAGS
        "push rcx",                     // User RIP

        // Save callee-saved registers (System V ABI)
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Save syscall arguments on stack
        "push r9",                      // arg6
        "push r8",                      // arg5
        "push r10",                     // arg4
        "push rdx",                     // arg3
        "push rsi",                     // arg2
        "push rdi",                     // arg1
        "push rax",                     // syscall number

        // we've pushed 15 values (8 bytes each) = 120 bytes
        // need to align to 16 bytes before call

        // Pass stack pointer to wrapper (points to syscall frame)
        "mov rdi, rsp",

        // Align stack to 16 bytes (required by System V ABI)
        // We need to ensure (rsp & 0xF) == 8 before call
        // (call pushes 8-byte return address, making it 16-byte aligned)
        "sub rsp, 8",                   // Add 8 bytes padding

        // Call the Rust dispatcher
        "call {dispatcher}",

        // Remove padding
        "add rsp, 8",

        // Clean up syscall arguments (7 * 8 = 56 bytes)
        "add rsp, 56",

        // RAX contains the return value from dispatcher

        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Restore registers for sysret
        "pop rcx",                      // User RIP
        "pop r11",                      // User RFLAGS

        // Restore user RSP
        "mov rsp, [rip + CURRENT_USER_RSP]",

        // Return to userspace
        "sysretq",

        dispatcher = sym syscall_dispatch_wrapper,
    )
}

#[repr(C)]
#[derive(Debug)]
struct SyscallFrame {
    num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
}

// wrapper to handle arg passing from asm/cpu into rust syscall dispatch management
extern "C" fn syscall_dispatch_wrapper(frame: *const SyscallFrame) -> i64 {
    // This should print if we made it to Rust code
    serial_println!("\n\n=== ENTERED SYSCALL HANDLER ===\n");

    let frame = unsafe { &*frame };
    serial_println!("Syscall frame: num={}, arg1={:#x}, arg2={:#x}, arg3={}",
                    frame.num, frame.arg1, frame.arg2, frame.arg3);

    let result = syscall_dispatch(
        frame.num,
        frame.arg1,
        frame.arg2,
        frame.arg3,
        frame.arg4,
        frame.arg5,
        frame.arg6,
    );

    serial_println!("Syscall returning: {}", result);
    result
}

// actual dispatch for syscalls using registered handlers
fn syscall_dispatch(
    num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i64 {
    match num {
        // 0 => sys_read(arg1 as i32, arg2 as *mut u8, arg3 as usize),
        1 => sys_write(arg1 as i32, arg2 as *const u8, arg3 as usize),
        // 60 => sys_exit(arg1 as i32),
        _ => {
            // ENOSYS - function not implemented
            -38
        }
    }
}
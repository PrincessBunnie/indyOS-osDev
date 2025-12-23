use crate::errors::Component::PIDAllocator;
use crate::errors::OSError;
use crate::proc::elf::ELF;
use crate::proc::virtual_memory::user_layout::USER_STACK_TOP;
use crate::proc::virtual_memory::{translate_user_addr, VirtualMemory};
use crate::{dbg, serial_print, serial_println};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use core::mem;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{AtomicU32, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::rflags::RFlags;
use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{Mapper, Translate};
use crate::memory::page;
use crate::memory::page::{page_table_from_addr, phys_offset};

#[repr(C)]
#[derive(Debug, Clone)]
struct CpuState {
    // callee saved registers persisted across function calls according to x86 spec
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rbx: u64,
    pub rbp: u64,

    // instruction pointer
    pub rip: u64,

    // stack pointer
    pub rsp: u64,

    // flags register
    pub rflags: u64,
}

impl CpuState {
    pub fn setup_initial(entry_point: u64, stack_pointer: u64) -> Self {
        // interrupt flag as interrupts are enabled
        // 0x202 = Interrupt Flag (0x200) + Reserved Bit 1 (0x2)
        // 0x202 = 0x200 (Interrupt Flag) + 0x2 (Reserved Bit 1)
        let rflags = 0x202u64;
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rip: entry_point,
            rsp: stack_pointer,
            rflags,
        }
    }

    /// Jump to userspace using iretq
    ///
    /// # Safety
    /// This function never returns. It switches to user mode and begins executing
    /// the user process at the given entry point with the given stack.
    #[unsafe(naked)]
    pub unsafe extern "C" fn enter_userspace_iretq(_context: *const CpuState) -> ! {
        core::arch::naked_asm!(
            // rdi contains the context pointer (first argument in System V ABI)
            // save it temporarily since we need rdi for other things
            "mov rax, rdi",

            // restore callee-saved registers from CpuState
            "mov r12, [rax + 0]",   // offset 0: r12
            "mov r13, [rax + 8]",   // offset 8: r13
            "mov r14, [rax + 16]",  // offset 16: r14
            "mov r15, [rax + 24]",  // offset 24: r15
            "mov rbx, [rax + 32]",  // offset 32: rbx
            "mov rbp, [rax + 40]",  // offset 40: rbp
            // handle rip, rsp, rflags specially for iretq

            // prepare iretq stack frame
            // iretq expects (from top to bottom): SS, RSP, RFLAGS, CS, RIP

            // push SS (user data segment selector with RPL=3)
            // "push 0x23",
            "push 0x18",

            // push RSP (user stack pointer)
            "push qword ptr [rax + 56]",  // offset 56: rsp

            // push RFLAGS
            "push qword ptr [rax + 64]",  // offset 64: rflags (as u64)

            // push CS (user code segment selector with RPL=3)
            // "push 0x2B",
            "push 0x20",

            // push RIP (entry point)
            "mov rcx, [rax + 48]",   // offset 48: rip (VirtAddr is a wrapper around u64)
            "push rcx",

            // clear remaining registers for security
            // ( already set r12-r15, rbx, rbp above)
            "xor rax, rax",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r11, r11",

            // return to userspace!
            "iretq",
        )
    }
    #[unsafe(no_mangle)]
    extern "C" fn debug_print_rip_fn(rip: u64) {
        serial_println!("!!! ASM DEBUG: RIP about to be loaded = {:#x}", rip);
    }
    #[unsafe(no_mangle)]
    extern "C" fn debug_print_ptr(val: u64) {
        serial_println!("!!! ASM DEBUG: Pointer value = {:#x}", val);
    }

    #[unsafe(naked)]
    unsafe extern "C" fn perform_context_switch(
        kernel_stack: u64,
        page_table: u64,
        cpu_state_ptr: u64,
    ) -> ! {
        core::arch::naked_asm!(
        "mov r15, rdx",
        "mov rsp, rdi",
        "mov rax, rsi",
        "mov cr3, rax",

        // debug: print cpu_state_ptr value
        "mov rdi, r15",
        "call {debug_print_cpu_state_ptr}",

        // restore and jump
        "mov rdi, r15",
        "jmp {enter_userspace}",

        debug_print_cpu_state_ptr = sym Self::debug_print_cpu_state_ptr,
        enter_userspace = sym Self::enter_userspace_debug,
    )
    }
    #[unsafe(naked)]
    pub unsafe extern "C" fn enter_userspace_debug(_context: *const CpuState) -> ! {
        core::arch::naked_asm!(
        "mov rax, rdi",

        // restore callee-saved
        "mov r12, [rax + 0]",
        "mov r13, [rax + 8]",
        "mov r14, [rax + 16]",
        "mov r15, [rax + 24]",
        "mov rbx, [rax + 32]",
        "mov rbp, [rax + 40]",

        // load values
        "mov r8, [rax + 48]",        // RIP
        "mov r9, [rax + 56]",        // RSP
        "mov r10, [rax + 64]",       // RFLAGS

        // build frame
        "sub rsp, 8",
        "mov qword ptr [rsp], 0x1B",

        "sub rsp, 8",
        "mov [rsp], r9",

        "sub rsp, 8",
        "mov [rsp], r10",

        "sub rsp, 8",
        "mov qword ptr [rsp], 0x23",

        "sub rsp, 8",
        "mov [rsp], r8",

        // DEBUG: call one more time to verify frame before clearing registers
        "mov rdi, rsp",
        "mov rsi, r8",   // pass RIP as 2nd arg
        "mov rdx, r9",   // pass RSP as 3rd arg
        "call {debug_final_check}",

        // don't clear registers, don't do iretq - just infinite loop
        "2: jmp 2b",

        debug_final_check = sym Self::debug_final_check,
    )
    }

    #[unsafe(no_mangle)]
    extern "C" fn debug_final_check(frame_ptr: u64, expected_rip: u64, expected_rsp: u64) {
        unsafe {
            let frame = core::slice::from_raw_parts(frame_ptr as *const u64, 5);
            serial_println!("\n=== FINAL CHECK BEFORE IRETQ ===");
            serial_println!("Frame at: {:#x}", frame_ptr);
            serial_println!("  [0] RIP:    {:#x} (expected {:#x})", frame[0], expected_rip);
            serial_println!("  [1] CS:     {:#x} (expected 0x23)", frame[1]);
            serial_println!("  [2] RFLAGS: {:#x} (expected 0x202)", frame[2]);
            serial_println!("  [3] RSP:    {:#x} (expected {:#x})", frame[3], expected_rsp);
            serial_println!("  [4] SS:     {:#x} (expected 0x1B)", frame[4]);

            // check if user stack is mapped
            serial_println!("\nChecking if user stack {:#x} is mapped...", expected_rsp);
        }
    }

    #[unsafe(no_mangle)]
    extern "C" fn debug_stack_frame(rsp: u64) {
        unsafe {
            let frame = core::slice::from_raw_parts(rsp as *const u64, 5);
            serial_println!("iretq frame:");
            serial_println!("  [0] RIP:    {:#x}", frame[0]);
            serial_println!("  [1] CS:     {:#x}", frame[1]);
            serial_println!("  [2] RFLAGS: {:#x}", frame[2]);
            serial_println!("  [3] RSP:    {:#x}", frame[3]);
            serial_println!("  [4] SS:     {:#x}", frame[4]);
        }
    }
    #[unsafe(no_mangle)]
    extern "C" fn debug_print_cpu_state_ptr(ptr: u64) {
        serial_println!("CPU State Ptr: {:#x}", ptr);

        unsafe {
            let cpu_state = &*(ptr as *const CpuState);
            serial_println!("  RIP: {:#x}", cpu_state.rip);
            serial_println!("  RSP: {:#x}", cpu_state.rsp);
            serial_println!("  RFLAGS: {:#x}", cpu_state.rflags);
        }
    }
    #[unsafe(no_mangle)]
    extern "C" fn debug_print_step(step: u64) {
        serial_println!("!!! STEP: {}", step);
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(u32);

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Pid {
    pub const INIT: Pid = Pid(1);

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn new(id: u32) -> Self {
        Pid(id)
    }
}

pub struct PidAllocator {
    next_pid: AtomicU32,
}

impl PidAllocator {
    pub const fn new() -> Self {
        // PID 0 is reserved for the kernel idle process
        // PID 1 will be init
        Self {
            next_pid: AtomicU32::new(1),
        }
    }

    pub fn allocate(&self) -> Option<Pid> {
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        // wraparound
        if pid == u32::MAX {
            None
        } else {
            Some(Pid(pid))
        }
    }
}

// global PID allocator

pub static PID_ALLOCATOR: Mutex<PidAllocator> = Mutex::new(PidAllocator::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Ready to run, waiting for CPU
    Ready,
    /// Currently executing on CPU
    Running,
    /// Blocked waiting for something (future: I/O, sleep, etc)
    Blocked(BlockedReason),
    /// Exited but not yet reaped by parent
    Zombie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedReason {
    Future,
    IO,
    Sleep,
    Network
}

pub(crate) struct Process {
    pub(crate) pid: Pid,
    cpu_state: CpuState,
    parent: Option<Pid>,
    children: Vec<Pid>,
    exit_status: Option<i32>,
    process_state: ProcessState,
    pub(crate) memory: VirtualMemory,
}

impl Process {
    pub(crate) fn new(parent: Option<Pid>, children: Vec<Pid>) -> Result<Self, OSError> {
        let cpu_state = CpuState::setup_initial(0, 0);
        let Some(pid) = (*PID_ALLOCATOR.lock()).allocate() else {
            return Err(OSError::OutOfMemory(PIDAllocator));
        };
        serial_println!("allocated pid: {} -- about to setup virtual memory", pid);
        let memory = VirtualMemory::new()?;
        serial_println!("Created process {}...", pid);
        Ok(Self {
            pid,
            cpu_state,
            parent,
            children,
            exit_status: None,
            process_state: ProcessState::Ready,
            memory,
        })
    }
    pub(crate) fn new_process_from_elf(elf_data: &[u8]) -> Result<Process, OSError> {
        let mut process = Process::new(None, Vec::new())?;

        let entry_point = ELF::load(&mut process, elf_data)?;

        // set up initial CPU state with entry point and stack pointer
        let cpu_state = CpuState::setup_initial(
            entry_point.as_u64(),
            USER_STACK_TOP,  // stack starts at top
        );
        *process.cpu_state_mut() = cpu_state;

        Ok(process)
    }
    fn setup_stack(&mut self, args: &[&str], envp: &[&str], elf_aux_vector: Vec<(u64, u64)> ) -> Result<(u64), OSError> {
        let mut stack_pointer = USER_STACK_TOP;
        /*
            argv strings (with null terminators)
            envp strings (with null terminators)
            align down to 16-byte boundary if needed
            auxiliary vector pairs, ending with AT_NULL (0)
            NULL pointer (for envp)
            envp pointers (point back up to string addrs above)
            NULL pointer (for agv)
            argv pointers (point back up to string addrs above)
            argc
            set RSP to point at argc
         */

        // as each arg gets copied to the stack save its position (i.e. pointer) for later
        let mut argv_ptrs: Vec<u64> = Vec::new();
        for arg in args {
            let arg_bytes = arg.as_bytes();
            let total_size = arg_bytes.len() + 1; // +1 for null terminator

            // move sp down to make room, this is because the stack grows high -> low, but
            // memcpy copies from low to high so we need room or copy will overwrite/go beyond stack top
            stack_pointer -= total_size as u64;
            argv_ptrs.push(stack_pointer);

            // must translate user addresses into kernel accessible addresses for stack setup
            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)?;

            // copy the string bytes and add null terminator
            unsafe {
                copy_nonoverlapping(arg_bytes.as_ptr(), kernel_ptr, arg_bytes.len());
                *(kernel_ptr.add(arg_bytes.len())) = 0; // null terminator
            }
        }
        serial_println!("\nargv_ptrs: {:?}", argv_ptrs);

        // same process for envp
        let mut envp_ptrs: Vec<u64> = Vec::new();
        for env in envp {
            let env_bytes = env.as_bytes();
            let total_size = env_bytes.len() + 1; // +1 for null terminator

            stack_pointer -= total_size as u64;
            envp_ptrs.push(stack_pointer);

            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)?;

            unsafe {
                copy_nonoverlapping(env_bytes.as_ptr(), kernel_ptr, env_bytes.len());
                *(kernel_ptr.add(env_bytes.len())) = 0;
            }
        }
        serial_println!("\nenvp_ptrs: {:?}", envp_ptrs);

        // align stack pointer down to 16-byte boundary
        stack_pointer &= !0xF; // bit math: and with the inverse bits from the hex value to wipe out bits that would make this non 16 byte aligned

        // copy in the elf auxiliary vector of key - value (u64 - u64) pairs
        // initially this is only a couple values but as supported program complexity grows so will the list
        // order is reversed since again these will be read low -> high, but we are copying high -> low
        for &(key, value) in elf_aux_vector.iter().rev() {
            // write value first (higher address)
            stack_pointer -= 8;
            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
            unsafe { *kernel_ptr = value; }

            // write key (lower address)
            stack_pointer -= 8;
            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
            unsafe { *kernel_ptr = key; }
        }
        serial_println!("\nsetup elf aux vector at: {:?}", stack_pointer);

        // 8 byte envp null terminator
        stack_pointer -= 8;
        let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
        unsafe { *kernel_ptr = 0; }

        // envp pointer (addrs saved above)
        // reverse again because we built the list high->low but need to write it low->high
        for &envp_ptr in envp_ptrs.iter().rev() {
            stack_pointer -= 8;
            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
            unsafe { *kernel_ptr = envp_ptr; }
        }

        // 8 byte envp null terminator
        stack_pointer -= 8;
        let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
        unsafe { *kernel_ptr = 0; }

        // same logic as envp
        for &argv_ptr in argv_ptrs.iter().rev() {
            stack_pointer -= 8;
            let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
            unsafe { *kernel_ptr = argv_ptr; }
        }

        // write argc
        let argc = args.len() as u64;
        stack_pointer -= 8;
        let kernel_ptr = translate_user_addr(stack_pointer, self.memory.page_table_addr)? as *mut u64;
        unsafe { *kernel_ptr = argc; }

        // stack pointer now points to argc, which is where RSP should be
        Ok(stack_pointer)
    }
    pub(crate) fn check_fault_addr(&self, fault_addr: VirtAddr, write: bool, user: bool, instruction: bool) -> Result<(), OSError> {
        self.memory.check_page_fault(fault_addr, write, user, instruction)
    }
    pub fn cpu_state(&self) -> &CpuState {
        &self.cpu_state
    }
    pub fn cpu_state_mut(&mut self) -> &mut CpuState {
        &mut self.cpu_state
    }
    pub fn page_table_addr(&self) -> PhysAddr {
        self.memory.page_table_addr
    }
    pub fn kernel_stack_top(&self) -> VirtAddr {
        self.memory.kernel_stack.top()
    }
}

lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub struct Scheduler {
    processes:  Vec<Box<Process>>,
    ready_queue: VecDeque<Pid>,
    current: Option<Pid>,

    // Cached pointer for the hot path
    // TODO: rethink this, raw pointers arent Send
    // current_process: Option<*const Process>,
}

impl Scheduler {
    fn new() -> Self {
        Self {
            processes: Vec::new(),
            ready_queue: VecDeque::new(),
            current: None,
            // current_process: None,
        }
    }
    fn get_process(&self, pid: Pid) -> Option<&Box<Process>> {
        self.processes.iter().find(|p| p.pid == pid)
    }
    // pub(crate) fn current_process(&self) -> Option<*const Process> {
    //     self.current_process
    // }
    pub(crate) fn current_process(&self) -> Option<&Box<Process>> {
        if let Some(pid) = self.current {
            return self.get_process(pid);
        };
        None
    }
    pub fn add_process(&mut self, process: Process) -> Pid {
        let pid = process.pid;
        self.processes.push(Box::new(process));
        self.ready_queue.push_back(pid);
        pid
    }
    // really just decides which process to run, other portions of the OS will actually load & start the process
    pub fn schedule(&mut self) -> Option<&mut Process> {
        let pid = self.ready_queue.pop_front()?;

        let process = self.processes.iter_mut()
            .find(|p| p.pid == pid)?;

        process.process_state = ProcessState::Running;
        self.current = Some(pid);
        // self.current_process = Some(process.as_ref() as *const Process);

        Some(process)
    }
    pub fn run_current_process(&mut self) -> ! {
        let process = self.schedule().expect("No process to run!");
        serial_println!("\nScheduled a process to run");

        let stack_pointer = process.setup_stack(
            &["init"], //args
            &[], //envp
            vec![(6, 4096), (0, 0)], //elf aux vector -- most minimal values possible
        ).expect("Failed to setup stack");

        process.cpu_state_mut().rsp = stack_pointer;
        serial_println!("\nStack has been setup with stack pointer: {:#x}", stack_pointer);

        let kernel_stack_top = process.kernel_stack_top();
        let kernel_stack_ptr = kernel_stack_top.as_u64() - 16;
        let page_table_addr = process.page_table_addr();

        unsafe {
            crate::syscalls::management::CURRENT_KERNEL_RSP = kernel_stack_ptr;
            crate::memory::segmentation::set_kernel_stack(VirtAddr::new(kernel_stack_ptr));
        }

        let entry_point = process.cpu_state().rip;
        let user_stack = stack_pointer;

        serial_println!("About to enter userspace via sysret path");
        serial_println!("  Entry: {:#x}", entry_point);
        serial_println!("  Stack: {:#x}", user_stack);

        unsafe {
            core::arch::asm!(
            // 1: load entry point and stack into the correct registers first
            "mov rcx, {rip}",        // RCX = user RIP (sysret uses this)
            "mov r11, 0x202",        // R11 = user RFLAGS (sysret uses this)

            // 2: now switch to kernel stack
            "mov rsp, {kernel_stack}",

            // 3: Switch page table (CR3)
            // tried doing this outside of the asm but I had issues so...
            "mov rax, {page_table}",
            "mov cr3, rax",

            // 4: Load user stack into rsp
            // saved the user stack value in a temporary because needed
            // to use rsp for the kernel stack first
            "mov rsp, {user_rsp}",

            // 5: clear all other registers for security
            // probably unecesary rn
            "xor rax, rax",
            "xor rbx, rbx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor rbp, rbp",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r12, r12",
            "xor r13, r13",
            "xor r14, r14",
            "xor r15, r15",

            // 6: jump to userspace
            // values /should/ be (based on my debugging):
            // - RCX = user RIP (0x400000)
            // - R11 = user RFLAGS (0x202)
            // - RSP = user stack (0x7fffffffefb0)
            // - CS will be set to 0x23 (user code, RPL=3)
            // - SS will be set to 0x1b (user data, RPL=3)
            "sysretq",

            kernel_stack = in(reg) kernel_stack_ptr,
            page_table = in(reg) page_table_addr.as_u64(),
            rip = in(reg) entry_point,
            user_rsp = in(reg) user_stack,
            options(noreturn)
            );
        }
    }
    pub fn current_process_mut(&mut self) -> Option<&mut Box<Process>> {
        let pid = self.current?;
        self.processes.iter_mut().find(|p| p.pid == pid)
    }
}
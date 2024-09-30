use core::{
    ffi::{c_ulong, c_void},
    ptr::{self, null_mut},
};

use crate::{get_instance, libs::ldrapi::ldr_function};

#[repr(C)]
pub struct SecurityAttributes {
    pub n_length: u32,
    pub lp_security_descriptor: *mut c_void,
    pub b_inherit_handle: bool,
}

#[allow(non_camel_case_types)]
pub type LPSECURITY_ATTRIBUTES = *mut SecurityAttributes;

pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;

#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub lp_reserved: *mut u16,
    pub lp_desktop: *mut u16,
    pub lp_title: *mut u16,
    pub dw_x: u32,
    pub dw_y: u32,
    pub dw_x_size: u32,
    pub dw_y_size: u32,
    pub dw_x_count_chars: u32,
    pub dw_y_count_chars: u32,
    pub dw_fill_attribute: u32,
    pub dw_flags: u32,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: *mut c_void,
    pub h_std_output: *mut c_void,
    pub h_std_error: *mut c_void,
}

impl StartupInfoW {
    pub fn new() -> Self {
        StartupInfoW {
            cb: core::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: ptr::null_mut(),
            lp_desktop: ptr::null_mut(),
            lp_title: ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: ptr::null_mut(),
            h_std_input: ptr::null_mut(),
            h_std_output: ptr::null_mut(),
            h_std_error: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct ProcessInformation {
    pub h_process: *mut c_void,
    pub h_thread: *mut c_void,
    pub dw_process_id: u32,
    pub dw_thread_id: u32,
}

impl ProcessInformation {
    pub fn new() -> Self {
        ProcessInformation {
            h_process: ptr::null_mut(),
            h_thread: ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        }
    }
}

pub type PeekNamedPipe = unsafe extern "system" fn(
    hNamedPipe: *mut c_void,
    lpBuffer: *mut c_void,
    nBufferSize: u32,
    lpBytesRead: *mut u32,
    lpTotalBytesAvail: *mut u32,
    lpBytesLeftThisMessage: *mut u32,
) -> i32;

pub type CreateProcessW = unsafe extern "system" fn(
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: bool,
    dwCreationFlags: c_ulong,
    lpEnvironment: *mut c_void,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: *mut StartupInfoW,
    lpProcessInformation: *mut ProcessInformation,
) -> bool;

pub struct Kernel32 {
    pub module_base: *mut u8,
    pub peek_named_pipe: PeekNamedPipe,
    pub create_process_w: CreateProcessW,
}

impl Kernel32 {
    pub fn new() -> Self {
        Kernel32 {
            module_base: null_mut(),
            peek_named_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_process_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Kernel32 {}
unsafe impl Send for Kernel32 {}

pub fn init_kernel32_funcs() {
    unsafe {
        const PEEKNAMEDPIPE_H: usize = 0xd5312e5d;
        const CREATE_PROCESS_W_H: usize = 0xfbaf90cf;

        let instance = get_instance().unwrap();

        //CreateProcessW
        let create_process_w_addr = ldr_function(instance.k32.module_base, CREATE_PROCESS_W_H);
        instance.k32.create_process_w = core::mem::transmute(create_process_w_addr);

        //PeekNamedPipe
        let k_peek_named_pipe_addr = ldr_function(instance.k32.module_base, PEEKNAMEDPIPE_H);
        instance.k32.peek_named_pipe = core::mem::transmute(k_peek_named_pipe_addr);
    }
}

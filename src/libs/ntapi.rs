use core::{
    ffi::{c_ulong, c_void},
    ptr::null_mut,
};

use crate::{
    get_instance,
    libs::ldrapi::{ldr_function, ldr_module},
    run_syscall,
};

use super::{
    gate::get_ssn,
    ntdef::{IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString},
};

pub struct NtSyscall {
    /// The number of the syscall
    pub number: u16,
    /// The address of the syscall
    pub address: *mut u8,
    /// The hash of the syscall (used for lookup)
    pub hash: usize,
}

unsafe impl Sync for NtSyscall {}

impl NtSyscall {
    pub const fn new(hash: usize) -> Self {
        NtSyscall {
            number: 0,
            address: null_mut(),
            hash: hash,
        }
    }
}

pub struct NtAllocateVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtAllocateVirtualMemory {}

impl NtAllocateVirtualMemory {
    pub const fn new() -> Self {
        NtAllocateVirtualMemory {
            syscall: NtSyscall::new(0xf783b8ec),
        }
    }
}

pub struct NtFreeVirtualMemory {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtFreeVirtualMemory {}

impl NtFreeVirtualMemory {
    pub const fn new() -> Self {
        NtFreeVirtualMemory {
            syscall: NtSyscall::new(0x2802c609),
        }
    }
}

pub struct NtClose {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtClose {}

impl NtClose {
    pub const fn new() -> Self {
        NtClose {
            syscall: NtSyscall::new(0x40d6e69d),
        }
    }

    /// Wrapper function for NtClose to avoid repetitive run_syscall calls.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `handle` A handle to an object. This is a required parameter that must be valid.
    ///   It represents the handle that will be closed by the function.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation, indicating success or failure of the syscall.
    pub fn run(&self, handle: *mut c_void) -> i32 {
        run_syscall!(self.syscall.number, self.syscall.address as usize, handle)
    }
}

pub struct NtCreateNamedPipeFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtCreateNamedPipeFile {}

impl NtCreateNamedPipeFile {
    pub const fn new() -> Self {
        NtCreateNamedPipeFile {
            syscall: NtSyscall::new(0x1da0062e),
        }
    }

    /// Wrapper for the NtCreateNamedPipeFile syscall.
    ///
    /// This function creates a named pipe file and returns a handle to it.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A mutable pointer to a handle that will receive the file handle.
    /// * `[in]` - `desired_access` The desired access rights for the named pipe file.
    /// * `[in]` - `object_attributes` A pointer to an `OBJECT_ATTRIBUTES` structure that specifies the object attributes.
    /// * `[out]` - `io_status_block` A pointer to an `IO_STATUS_BLOCK` structure that receives the status of the I/O operation.
    /// * `[in]` - `share_access` The requested sharing mode of the file.
    /// * `[in]` - `create_disposition` Specifies the action to take on files that exist or do not exist.
    /// * `[in]` - `create_options` Specifies the options to apply when creating or opening the file.
    /// * `[in]` - `named_pipe_type` Specifies the type of named pipe (byte stream or message).
    /// * `[in]` - `read_mode` Specifies the read mode for the pipe.
    /// * `[in]` - `completion_mode` Specifies the completion mode for the pipe.
    /// * `[in]` - `maximum_instances` The maximum number of instances of the pipe.
    /// * `[in]` - `inbound_quota` The size of the input buffer, in bytes.
    /// * `[in]` - `outbound_quota` The size of the output buffer, in bytes.
    /// * `[in, opt]` - `default_timeout` A pointer to a `LARGE_INTEGER` structure that specifies the default time-out value.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut *mut c_void,
        desired_access: c_ulong,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        share_access: c_ulong,
        create_disposition: c_ulong,
        create_options: c_ulong,
        named_pipe_type: c_ulong,
        read_mode: c_ulong,
        completion_mode: c_ulong,
        maximum_instances: c_ulong,
        inbound_quota: c_ulong,
        outbound_quota: c_ulong,
        default_timeout: *const LargeInteger,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            create_disposition,
            create_options,
            named_pipe_type,
            read_mode,
            completion_mode,
            maximum_instances,
            inbound_quota,
            outbound_quota,
            default_timeout
        )
    }
}

pub struct NtOpenFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtOpenFile {}

impl NtOpenFile {
    pub const fn new() -> Self {
        NtOpenFile {
            syscall: NtSyscall::new(0x46dde739),
        }
    }

    /// Wrapper for the NtOpenFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[out]` - `file_handle` A pointer to a handle that receives the file handle.
    /// * `[in]` - `desired_access` The desired access for the file handle.
    /// * `[in]` - `object_attributes` A pointer to the OBJECT_ATTRIBUTES structure.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the status block.
    /// * `[in]` - `share_access` The requested share access for the file.
    /// * `[in]` - `open_options` The options to be applied when opening the file.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: &mut *mut c_void,
        desired_access: c_ulong,
        object_attributes: &mut ObjectAttributes,
        io_status_block: &mut IoStatusBlock,
        share_access: c_ulong,
        open_options: c_ulong,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options
        )
    }
}

pub struct NtWriteFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtWriteFile {}

impl NtWriteFile {
    pub const fn new() -> Self {
        NtWriteFile {
            syscall: NtSyscall::new(0xe0d61db2),
        }
    }

    /// Wrapper for the NtWriteFile syscall.
    ///
    /// This function writes data to a file or I/O device. It wraps the NtWriteFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `file_handle` A handle to the file or I/O device to be written to.
    /// * `[in, opt]` - `event` An optional handle to an event object that will be signaled when the operation completes.
    /// * `[in, opt]` - `apc_routine` An optional pointer to an APC routine to be called when the operation completes.
    /// * `[in, opt]` - `apc_context` An optional pointer to a context for the APC routine.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[in]` - `buffer` A pointer to a buffer that contains the data to be written to the file or device.
    /// * `[in]` - `length` The length, in bytes, of the buffer pointed to by the `buffer` parameter.
    /// * `[in, opt]` - `byte_offset` A pointer to the byte offset in the file where the operation should begin. If this parameter is `None`, the system writes data to the current file position.
    /// * `[in, opt]` - `key` A pointer to a caller-supplied variable to receive the I/O completion key. This parameter is ignored if `event` is not `None`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut c_void,
        event: *mut c_void,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: &mut IoStatusBlock,
        buffer: *mut c_void,
        length: c_ulong,
        byte_offset: *mut u64,
        key: *mut c_ulong,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key
        )
    }
}

pub struct NtReadFile {
    pub syscall: NtSyscall,
}

unsafe impl Sync for NtReadFile {}

impl NtReadFile {
    pub const fn new() -> Self {
        NtReadFile {
            syscall: NtSyscall::new(0xb2d93203),
        }
    }

    /// Wrapper for the NtReadFile syscall.
    ///
    /// This function reads data from a file or I/O device. It wraps the NtReadFile syscall.
    ///
    /// # Arguments
    ///
    /// * `[in]` - `file_handle` A handle to the file or I/O device to be read from.
    /// * `[in, opt]` - `event` An optional handle to an event object that will be signaled when the operation completes.
    /// * `[in, opt]` - `apc_routine` An optional pointer to an APC routine to be called when the operation completes.
    /// * `[in, opt]` - `apc_context` An optional pointer to a context for the APC routine.
    /// * `[out]` - `io_status_block` A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
    /// * `[out]` - `buffer` A pointer to a buffer that receives the data read from the file or device.
    /// * `[in]` - `length` The length, in bytes, of the buffer pointed to by the `buffer` parameter.
    /// * `[in, opt]` - `byte_offset` A pointer to the byte offset in the file where the operation should begin. If this parameter is `None`, the system reads data from the current file position.
    /// * `[in, opt]` - `key` A pointer to a caller-supplied variable to receive the I/O completion key. This parameter is ignored if `event` is not `None`.
    ///
    /// # Returns
    ///
    /// * `i32` - The NTSTATUS code of the operation.
    pub fn run(
        &self,
        file_handle: *mut c_void,
        event: *mut c_void,
        apc_routine: *mut c_void,
        apc_context: *mut c_void,
        io_status_block: &mut IoStatusBlock,
        buffer: *mut c_void,
        length: c_ulong,
        byte_offset: *mut u64,
        key: *mut c_ulong,
    ) -> i32 {
        run_syscall!(
            self.syscall.number,
            self.syscall.address as usize,
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key
        )
    }
}

/// Type definition for the LdrLoadDll function.
///
/// Loads a DLL into the address space of the calling process.
///
/// # Parameters
/// - `[in, opt]` - `DllPath`: A pointer to a `UNICODE_STRING` that specifies the fully qualified path of the DLL to load. This can be `NULL`, in which case the system searches for the DLL.
/// - `[in, opt]` - `DllCharacteristics`: A pointer to a variable that specifies the DLL characteristics (optional, can be `NULL`).
/// - `[in]` - `DllName`: A `UNICODE_STRING` that specifies the name of the DLL to load.
/// - `[out]` - `DllHandle`: A pointer to a variable that receives the handle to the loaded DLL.
///
/// # Returns
/// - `i32` - The NTSTATUS code of the operation.
type LdrLoadDll = unsafe extern "system" fn(
    DllPath: *mut u16,
    DllCharacteristics: *mut u32,
    DllName: UnicodeString,
    DllHandle: *mut c_void,
) -> i32;

pub struct NtDll {
    pub module_base: *mut u8,
    pub ldr_load_dll: LdrLoadDll,
    pub nt_allocate_virtual_memory: NtAllocateVirtualMemory,
    pub nt_free_virtual_memory: NtFreeVirtualMemory,
    pub nt_close: NtClose,
    pub nt_create_named_pipe: NtCreateNamedPipeFile,
    pub nt_open_file: NtOpenFile,
    pub nt_write_file: NtWriteFile,
    pub nt_read_file: NtReadFile,
}

impl NtDll {
    pub fn new() -> Self {
        NtDll {
            module_base: null_mut(),
            ldr_load_dll: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            nt_allocate_virtual_memory: NtAllocateVirtualMemory::new(),
            nt_free_virtual_memory: NtFreeVirtualMemory::new(),
            nt_close: NtClose::new(),
            nt_create_named_pipe: NtCreateNamedPipeFile::new(),
            nt_open_file: NtOpenFile::new(),
            nt_write_file: NtWriteFile::new(),
            nt_read_file: NtReadFile::new(),
        }
    }
}

pub fn init_ntdll_funcs() {
    unsafe {
        const NTDLL_HASH: u32 = 0x1edab0ed;
        const KERNEL32_HASH: u32 = 0x6ddb9555;
        const LDR_LOAD_DLL_H: usize = 0x9e456a43;

        let instance = get_instance().unwrap();

        instance.k32.module_base = ldr_module(KERNEL32_HASH);
        instance.ntdll.module_base = ldr_module(NTDLL_HASH);

        // NtAllocateVirtualMemory
        instance.ntdll.nt_allocate_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_allocate_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_allocate_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_allocate_virtual_memory.syscall.address);

        // NtFreeVirtualMemory
        instance.ntdll.nt_free_virtual_memory.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_free_virtual_memory.syscall.hash,
        );
        instance.ntdll.nt_free_virtual_memory.syscall.number =
            get_ssn(instance.ntdll.nt_free_virtual_memory.syscall.address);

        // NtClose
        instance.ntdll.nt_close.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_close.syscall.hash,
        );
        instance.ntdll.nt_close.syscall.number = get_ssn(instance.ntdll.nt_close.syscall.address);

        // NtCreateNamedPipe
        instance.ntdll.nt_create_named_pipe.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_create_named_pipe.syscall.hash,
        );
        instance.ntdll.nt_create_named_pipe.syscall.number =
            get_ssn(instance.ntdll.nt_create_named_pipe.syscall.address);

        // NtOpenFile
        instance.ntdll.nt_open_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_open_file.syscall.hash,
        );
        instance.ntdll.nt_open_file.syscall.number =
            get_ssn(instance.ntdll.nt_open_file.syscall.address);

        // NtWriteFile
        instance.ntdll.nt_write_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_write_file.syscall.hash,
        );
        instance.ntdll.nt_write_file.syscall.number =
            get_ssn(instance.ntdll.nt_write_file.syscall.address);

        // NtReadFile
        instance.ntdll.nt_read_file.syscall.address = ldr_function(
            instance.ntdll.module_base,
            instance.ntdll.nt_read_file.syscall.hash,
        );
        instance.ntdll.nt_read_file.syscall.number =
            get_ssn(instance.ntdll.nt_read_file.syscall.address);

        // LdrLoadDll
        let ldr_load_dll_addr = ldr_function(instance.ntdll.module_base, LDR_LOAD_DLL_H);
        instance.ntdll.ldr_load_dll = core::mem::transmute(ldr_load_dll_addr);
    }
}

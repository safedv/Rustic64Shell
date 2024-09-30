use core::{
    ffi::{c_ulong, c_void},
    ptr::null_mut,
};

use crate::get_instance;

use super::{
    k32::SecurityAttributes,
    ntdef::{
        nt_current_teb, IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString, FILE_CREATE,
        FILE_GENERIC_WRITE, FILE_NON_DIRECTORY_FILE, FILE_PIPE_BYTE_STREAM_MODE,
        FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_QUEUE_OPERATION, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_ATTRIBUTES, GENERIC_READ, OBJ_CASE_INSENSITIVE,
        OBJ_INHERIT, SYNCHRONIZE,
    },
    utils::format_named_pipe_string,
};

/// Creates a named pipe and returns handles for reading and writing.
///
/// This function sets up a named pipe with specified security attributes, buffer size,
/// and other options. It creates the pipe with both read and write handles, making it
/// ready for inter-process communication using the `NtCreateNamedPipeFile` NT API function.
pub unsafe fn nt_create_named_pipe_file(
    h_read_pipe: &mut *mut c_void,
    h_write_pipe: &mut *mut c_void,
    lp_pipe_attributes: *mut SecurityAttributes,
    n_size: u32,
    pipe_id: u32,
) -> i32 {
    let mut pipe_name: UnicodeString = UnicodeString::new();
    let mut object_attributes: ObjectAttributes = ObjectAttributes::new();
    let mut status_block: IoStatusBlock = IoStatusBlock::new();
    let mut default_timeout: LargeInteger = LargeInteger::new();
    let mut read_pipe_handle: *mut c_void = null_mut();
    let mut write_pipe_handle: *mut c_void = null_mut();
    let mut security_descriptor: *mut c_void = null_mut();

    // Set the default timeout to 120 seconds
    default_timeout.high_part = -1200000000;

    // Use the default buffer size if not provided
    let n_size = if n_size == 0 { 0x1000 } else { n_size };

    // Format the pipe name using the process ID and pipe ID
    let pipe_name_utf16 = format_named_pipe_string(
        nt_current_teb().as_ref().unwrap().client_id.unique_process as usize,
        pipe_id,
    );

    // Initialize the `UnicodeString` with the formatted pipe name
    pipe_name.init(pipe_name_utf16.as_ptr());

    // Use case-insensitive object attributes by default
    let mut attributes: c_ulong = OBJ_CASE_INSENSITIVE;

    // Check if custom security attributes were provided
    if !lp_pipe_attributes.is_null() {
        // Use the provided security descriptor
        security_descriptor = (*lp_pipe_attributes).lp_security_descriptor;

        // Set the OBJ_INHERIT flag if handle inheritance is requested
        if (*lp_pipe_attributes).b_inherit_handle {
            attributes |= OBJ_INHERIT;
        }
    }

    // Initialize the object attributes for the named pipe
    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut pipe_name,
        attributes, // Case-insensitive and possibly inheritable
        null_mut(),
        security_descriptor,
    );

    // Create the named pipe for reading
    let status = get_instance().unwrap().ntdll.nt_create_named_pipe.run(
        &mut read_pipe_handle,
        GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, // Desired access: read, write attributes, sync
        &mut object_attributes,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Share mode: allows read/write by other processes
        FILE_CREATE,                        // Creation disposition: create new, fail if exists
        FILE_SYNCHRONOUS_IO_NONALERT,       // Create options: synchronous I/O, no alerts
        FILE_PIPE_BYTE_STREAM_TYPE,         // Pipe type: byte stream (no message boundaries)
        FILE_PIPE_BYTE_STREAM_MODE,         // Read mode: byte stream mode for reading
        FILE_PIPE_QUEUE_OPERATION,          // Completion mode: operations are queued
        1,                                  // Max instances: only one instance of the pipe
        n_size,                             // Inbound quota: input buffer size
        n_size,                             // Outbound quota: output buffer size
        &default_timeout,                   // Default timeout for pipe operations
    );

    // Check if the pipe creation failed
    if status != 0 {
        get_instance().unwrap().ntdll.nt_close.run(read_pipe_handle);
        return status;
    }

    let mut status_block_2 = IoStatusBlock::new();

    // Open the pipe for writing
    let status = get_instance().unwrap().ntdll.nt_open_file.run(
        &mut write_pipe_handle,
        FILE_GENERIC_WRITE,
        &mut object_attributes,
        &mut status_block_2,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    );

    // Check if the pipe opening failed
    if status != 0 {
        get_instance().unwrap().ntdll.nt_close.run(read_pipe_handle);
        return status;
    }

    // Assign the read and write handles to the output parameters
    *h_read_pipe = read_pipe_handle;
    *h_write_pipe = write_pipe_handle;
    0
}

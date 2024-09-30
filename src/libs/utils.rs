use alloc::vec::Vec;

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];

        if cur == 0 {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    hsh
}

/// Calculates the length of a C-style null-terminated string.
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    (tmp - pointer as u64) as _
}

pub fn string_length_w(string: *const u16) -> usize {
    unsafe {
        let mut string2 = string;
        while !(*string2).is_null() {
            string2 = string2.add(1);
        }
        string2.offset_from(string) as usize
    }
}

// Utility function for checking null terminator for u8 and u16
trait IsNull {
    fn is_null(&self) -> bool;
}

impl IsNull for u16 {
    fn is_null(&self) -> bool {
        *self == 0
    }
}

/// Formats a named pipe string and stores it in a `Vec<u16>`
///
/// This function generates a named pipe path in the format:
/// `\\Device\\NamedPipe\\Win32Pipes.<process_id>.<pipe_id>`
/// and stores the UTF-16 encoded string in a `Vec<u16>`.
///
/// # Parameters
/// - `process_id`: The process ID to be included in the pipe name.
/// - `pipe_id`: The pipe ID to be included in the pipe name.
///
/// # Returns
/// A `Vec<u16>` containing the UTF-16 encoded string, null-terminated.
pub fn format_named_pipe_string(process_id: usize, pipe_id: u32) -> Vec<u16> {
    let mut pipe_name_utf16 = Vec::with_capacity(50); // Pre-allocate space

    // Static part of the pipe name
    let device_part = "\\Device\\NamedPipe\\Win32Pipes.";
    pipe_name_utf16.extend(device_part.encode_utf16());

    // Append process_id as a 16-character hex string
    for i in (0..16).rev() {
        let shift = i * 4;
        let hex_digit = ((process_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Append dot separator
    pipe_name_utf16.push('.' as u16);

    // Append pipe_id as an 8-character hex string
    for i in (0..8).rev() {
        let shift = i * 4;
        let hex_digit = ((pipe_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Null-terminate the buffer
    pipe_name_utf16.push(0);

    // Return the UTF-16 encoded vector
    pipe_name_utf16
}

/// Helper function to convert a hex digit (0-15) into its corresponding ASCII character.
///
/// # Returns
/// The corresponding ASCII character as a `u16`.
fn to_hex_char(digit: u16) -> u16 {
    match digit {
        0..=9 => '0' as u16 + digit,
        10..=15 => 'a' as u16 + (digit - 10),
        _ => 0,
    }
}

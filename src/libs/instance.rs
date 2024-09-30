use super::{k32::Kernel32, ntapi::NtDll, winsock::Winsock};

// A magic number to identify a valid `Instance` struct
pub const INSTANCE_MAGIC: u32 = 0x17171717;

#[repr(C)]
// The main structure holding system API modules and the magic value
pub struct Instance {
    pub magic: u32,       // Unique value to identify a valid instance
    pub k32: Kernel32,    // Kernel32 API functions
    pub ntdll: NtDll,     // NtDll API functions
    pub winsock: Winsock, // Winsock API functions
}

impl Instance {
    pub fn new() -> Self {
        Instance {
            magic: INSTANCE_MAGIC,
            k32: Kernel32::new(),
            ntdll: NtDll::new(),
            winsock: Winsock::new(),
        }
    }
}

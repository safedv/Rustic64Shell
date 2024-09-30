extern "C" {
    // Declaration of an external syscall function with a variadic argument list
    pub fn isyscall(ssn: u16, addr: usize, n_args: u32, ...) -> i32;
}

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! run_syscall {
    ($ssn:expr, $addr:expr, $($y:expr), +) => {
        {
            let mut cnt: u32 = 0;

            // Count the number of arguments passed
            $(
                let _ = $y;
                cnt += 1;
            )+

            // Perform the syscall with the given number, address (offset by 0x12),
            // argument count, and the arguments
            unsafe { $crate::libs::gate::isyscall($ssn, $addr + 0x12, cnt, $($y), +) }
        }
    }
}

const UP: isize = -32; // Constant for upward memory search
const DOWN: usize = 32; // Constant for downward memory search

pub unsafe fn get_ssn(address: *mut u8) -> u16 {
    if address.is_null() {
        return 0;
    }

    // Hell's Gate: Check if the bytes match a typical syscall instruction sequence
    // mov r10, rcx; mov rcx, <syscall>
    if address.read() == 0x4c
        && address.add(1).read() == 0x8b
        && address.add(2).read() == 0xd1
        && address.add(3).read() == 0xb8
        && address.add(6).read() == 0x00
        && address.add(7).read() == 0x00
    {
        let high = address.add(5).read() as u16;
        let low = address.add(4).read() as u16;
        return ((high << 8) | low) as u16;
    }

    // Halo's Gate: Check if the syscall is hooked and attempt to locate a clean syscall
    if address.read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    // Tartarus' Gate: Another method to bypass hooked syscalls
    if address.add(3).read() == 0xe9 {
        for idx in 1..500 {
            // Check downwards for a clean syscall instruction
            if address.add(idx * DOWN).read() == 0x4c
                && address.add(1 + idx * DOWN).read() == 0x8b
                && address.add(2 + idx * DOWN).read() == 0xd1
                && address.add(3 + idx * DOWN).read() == 0xb8
                && address.add(6 + idx * DOWN).read() == 0x00
                && address.add(7 + idx * DOWN).read() == 0x00
            {
                let high = address.add(5 + idx * DOWN).read() as u16;
                let low = address.add(4 + idx * DOWN).read() as u16;
                return (high << 8) | (low.wrapping_sub(idx as u16));
            }

            // Check upwards for a clean syscall instruction
            if address.offset(idx as isize * UP).read() == 0x4c
                && address.offset(1 + idx as isize * UP).read() == 0x8b
                && address.offset(2 + idx as isize * UP).read() == 0xd1
                && address.offset(3 + idx as isize * UP).read() == 0xb8
                && address.offset(6 + idx as isize * UP).read() == 0x00
                && address.offset(7 + idx as isize * UP).read() == 0x00
            {
                let high = address.offset(5 + idx as isize * UP).read() as u16;
                let low = address.offset(4 + idx as isize * UP).read() as u16;
                return (high << 8) | (low.wrapping_add(idx as u16));
            }
        }
    }

    return 0;
}

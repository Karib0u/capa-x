// A small, harmless Windows program for the capa-x web demo. It is never meant to be run: the
// page decompiles it and matches capa rules against it. Built by build.sh with no C runtime, so
// every function in the output is code written here.
#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::{null, null_mut};

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetComputerNameW(buffer: *mut u16, size: *mut u32) -> i32;
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: *const c_void, disposition: u32, flags: u32, template: *const c_void) -> *mut c_void;
    fn WriteFile(file: *mut c_void, data: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn IsDebuggerPresent() -> i32;
    fn Sleep(ms: u32);
    fn GetTickCount() -> u32;
    fn ExitProcess(code: u32) -> !;
}

#[link(name = "advapi32", kind = "raw-dylib")]
extern "system" {
    fn RegOpenKeyExW(key: isize, sub_key: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
    fn RegQueryValueExW(key: isize, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, len: *mut u32) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_ALWAYS: u32 = 2;
const KEY_READ: u32 = 0x2_0019;

/// UTF-16 literal with a terminating NUL.
macro_rules! w {
    ($s:literal) => {{
        const N: usize = $s.len() + 1;
        const fn widen(s: &str) -> [u16; N] {
            let b = s.as_bytes();
            let mut out = [0u16; N];
            let mut i = 0;
            while i < b.len() {
                out[i] = b[i] as u16;
                i += 1;
            }
            out
        }
        static WIDE: [u16; N] = widen($s);
        WIDE.as_ptr()
    }};
}

// Without a C runtime the compiler still expects these symbols. The byte loops are volatile so
// the optimizer cannot turn them back into calls to themselves.
#[no_mangle]
pub static _fltused: i32 = 0;

#[no_mangle]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, value: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), value as u8);
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (core::ptr::read_volatile(a.add(i)), core::ptr::read_volatile(b.add(i)));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(3) }
}

/// Writes the machine's NetBIOS name into `out`; returns the length in characters.
#[inline(never)]
unsafe fn host_name(out: &mut [u16; 64]) -> usize {
    let mut size = out.len() as u32;
    if GetComputerNameW(out.as_mut_ptr(), &mut size) == 0 {
        return 0;
    }
    size as usize
}

/// Reads the product name of the installed Windows from the registry.
#[inline(never)]
unsafe fn windows_product(out: &mut [u8; 128]) -> u32 {
    let mut key = 0isize;
    if RegOpenKeyExW(HKEY_LOCAL_MACHINE, w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), 0, KEY_READ, &mut key) != 0 {
        return 0;
    }
    let mut len = out.len() as u32;
    let status = RegQueryValueExW(key, w!("ProductName"), null_mut(), null_mut(), out.as_mut_ptr(), &mut len);
    RegCloseKey(key);
    if status == 0 { len } else { 0 }
}

/// Writes `data` to a new file named `name`.
#[inline(never)]
unsafe fn write_report(name: *const u16, data: &[u8]) -> bool {
    let file = CreateFileW(name, GENERIC_WRITE, 0, null(), CREATE_ALWAYS, 0x80, null());
    if file as isize == -1 {
        return false;
    }
    let mut written = 0u32;
    let ok = WriteFile(file, data.as_ptr(), data.len() as u32, &mut written, null_mut());
    CloseHandle(file);
    ok != 0 && written as usize == data.len()
}

/// A simple timing check that a debugger or an emulator would disturb.
#[inline(never)]
unsafe fn being_watched() -> bool {
    if IsDebuggerPresent() != 0 {
        return true;
    }
    let before = GetTickCount();
    Sleep(500);
    GetTickCount().wrapping_sub(before) < 450
}

#[no_mangle]
pub unsafe extern "system" fn entry() -> ! {
    if being_watched() {
        ExitProcess(1);
    }
    let mut host = [0u16; 64];
    let host_len = host_name(&mut host);
    let mut product = [0u8; 128];
    let product_len = windows_product(&mut product);

    let mut report = [0u8; 256];
    let mut at = 0;
    for &c in host.iter().take(host_len) {
        report[at] = c as u8;
        at += 1;
    }
    report[at] = b'\n';
    at += 1;
    // The registry value is UTF-16; keep the low byte of each character.
    for pair in product.chunks_exact(2).take(product_len as usize / 2) {
        if at >= report.len() - 1 {
            break;
        }
        report[at] = pair[0];
        at += 1;
    }
    let ok = write_report(w!("capa-x-demo-report.txt"), &report[..at]);
    ExitProcess(if ok { 0 } else { 2 })
}

